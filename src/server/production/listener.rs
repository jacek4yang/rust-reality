//! One accept loop per bound socket, and the admission decision it makes.
//!
//! # The invariant this module exists to hold
//!
//! The descriptor permit is acquired *before* `accept`, never after.
//! Acquiring after would mean the kernel had already created a descriptor
//! this process had not reserved, which is precisely the accounting gap that
//! produced the incident.
//!
//! The second invariant is that the loop does not die. Only a
//! [`AcceptErrorClass::Fatal`] condition leaves it; everything else backs off,
//! logs once, and continues, because a listener that returns `Err` on
//! `EMFILE` takes the whole server with it.

use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use tokio::{sync::watch, task::JoinError, time};

use crate::{
    logging::{LogEvent, RejectionReason},
    runtime::{AdmissionKind, ResourcePressure, connection::ConnectionTasks},
    transport::{
        FdPermit, UNITS_INBOUND_SOCKET,
        tcp::{AcceptBackoff, AcceptErrorClass, EmergencyDescriptor, TcpAcceptor},
    },
};

use super::{
    connection::run_connection,
    event::{emit, emit_admission, emit_debug},
    store::RuntimeStore,
};

/// How long a stopping server waits for live relays before aborting them.
const GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);

/// Runs one listener until shutdown, surviving every recoverable accept error.
///
/// # The invariant this function exists to hold
///
/// The listener task must not return `Err` for any condition the process can
/// recover from. The previous implementation propagated every accept error with
/// `?`, so `accept4(...) = -1 EMFILE` terminated the server. Here only
/// [`AcceptErrorClass::Fatal`] leaves the loop, and it does so with the raw
/// errno attached so the operator can identify it.
///
/// # Ordering
///
/// The descriptor permit is acquired *before* `accept`, never after. Acquiring
/// after would mean the kernel had already created a descriptor the process had
/// not reserved, which is precisely the accounting gap that produced the
/// incident.
pub(super) async fn run_listener(
    acceptor: TcpAcceptor,
    address: SocketAddr,
    runtime: Arc<RuntimeStore>,
    mut shutdown: watch::Receiver<bool>,
) -> io::Result<()> {
    let mut connections = ConnectionTasks::new();
    let fd_budget = runtime.fd_budget.clone();
    let mut backoff = AcceptBackoff::new();
    // Starting without the reserve is a degraded but serviceable state:
    // admission still bounds descriptors, and the reserve only covers pressure
    // that originates outside this process's accounting.
    let mut reserve = EmergencyDescriptor::open().ok();
    let mut last_pressure = fd_budget.pressure();
    loop {
        // At critical resource pressure, pause before touching the listener.
        // The wait is a `Notify` wakeup, never a poll loop, it costs one
        // atomic load in any other state, and it stays cancellable so
        // shutdown is prompt. Established connections are unaffected: their
        // tasks are already running.
        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
                continue;
            }
            () = runtime.pressure.wait_while_critical() => {}
        }

        // Acquire the inbound descriptor permit before touching the listener.
        // When capacity is exhausted this waits on a `Notify` rather than
        // spinning, and it remains cancellable so shutdown is still prompt.
        let fd_permit = tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
                continue;
            }
            permit = fd_budget.acquire(UNITS_INBOUND_SOCKET) => permit,
            completed = connections.join_next(), if !connections.is_empty() => {
                consume_connection_result(completed);
                continue;
            }
        };

        let pressure = fd_budget.pressure();
        if pressure != last_pressure {
            last_pressure = pressure;
            let snapshot = runtime.load();
            emit(
                &snapshot.logger,
                &LogEvent::DescriptorPressureChanged {
                    fd_pressure_state: pressure.as_str(),
                    fd_units_in_use: fd_budget.in_use(),
                    fd_effective_budget: fd_budget.capacity(),
                },
            );
        }

        tokio::select! {
            changed = shutdown.changed() => {
                drop(fd_permit);
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            accepted = acceptor.accept_only() => {
                match accepted {
                    Ok((stream, peer)) => {
                        backoff.reset();
                        if runtime.pressure.state() == ResourcePressure::Critical {
                            // The connection raced the critical transition
                            // while the listener was parked in `accept`. Fail
                            // it fast through the ordinary decline path; the
                            // next loop iteration parks on the pressure gate.
                            drop(stream);
                            drop(fd_permit);
                            let snapshot = runtime.load();
                            emit(
                                &snapshot.logger,
                                &LogEvent::ConnectionRejected {
                                    peer,
                                    reason: RejectionReason::ResourceLimit,
                                },
                            );
                            continue;
                        }
                        admit_accepted_connection(
                            &runtime,
                            &mut connections,
                            address,
                            stream,
                            peer,
                            fd_permit,
                        );
                    }
                    Err(error) => {
                        // Release the reservation immediately: no descriptor was
                        // created, so holding it would shrink capacity on every
                        // failed accept until the listener starved itself.
                        drop(fd_permit);
                        let class = AcceptErrorClass::classify(&error);
                        if class.is_fatal() {
                            return Err(io::Error::new(
                                error.kind(),
                                format!(
                                    "listener {address} cannot accept: {class} \
                                     (errno {errno:?}): {error}",
                                    class = class.as_str(),
                                    errno = error.raw_os_error(),
                                ),
                            ));
                        }
                        if class == AcceptErrorClass::DescriptorPressure
                            && let Some(reserve) = reserve.as_mut()
                        {
                            recover_from_descriptor_pressure(&acceptor, reserve).await;
                        }
                        let delay = if class.needs_backoff() {
                            backoff.next_delay()
                        } else {
                            Duration::ZERO
                        };
                        if class != AcceptErrorClass::WouldBlock {
                            let snapshot = runtime.load();
                            emit(
                                &snapshot.logger,
                                &LogEvent::AcceptErrorRecovered {
                                    address,
                                    accept_error_class: class.as_str(),
                                    errno: error.raw_os_error(),
                                    accept_backoff_ms: backoff.current_ms(),
                                },
                            );
                        }
                        if !delay.is_zero() {
                            tokio::select! {
                                changed = shutdown.changed() => {
                                    if changed.is_err() || *shutdown.borrow() {
                                        break;
                                    }
                                }
                                () = time::sleep(delay) => {}
                            }
                        }
                    }
                }
            }
            completed = connections.join_next(), if !connections.is_empty() => {
                drop(fd_permit);
                consume_connection_result(completed);
            }
        }
    }
    drain_connections(&mut connections).await;
    Ok(())
}

/// Configures and admits one accepted stream.
///
/// A socket-configuration failure closes exactly that stream and releases
/// exactly its permit. It never reaches the listener loop as an error.
fn admit_accepted_connection(
    runtime: &Arc<RuntimeStore>,
    connections: &mut ConnectionTasks,
    address: SocketAddr,
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
    fd_permit: FdPermit,
) {
    let snapshot = runtime.load();
    let Some(state) = snapshot.connections.get(&address).cloned() else {
        // A reload cannot remove a listener, so this is unreachable in practice;
        // dropping the stream is still the correct conservative response.
        drop(stream);
        drop(fd_permit);
        return;
    };
    let logger = snapshot.logger.clone();
    drop(snapshot);

    if let Err(error) = TcpAcceptor::configure_accepted(&stream) {
        let _unused = error;
        drop(stream);
        drop(fd_permit);
        emit(
            &logger,
            &LogEvent::ConnectionRejected {
                peer,
                reason: RejectionReason::SocketConfiguration,
            },
        );
        return;
    }

    let permit = match state.governor.try_acquire(AdmissionKind::Connection) {
        Ok(permit) => permit,
        Err(error) => {
            drop(stream);
            drop(fd_permit);
            emit_admission(&logger, error);
            emit(
                &logger,
                &LogEvent::ConnectionRejected {
                    peer,
                    reason: RejectionReason::ResourceLimit,
                },
            );
            return;
        }
    };
    emit_debug(&logger, || LogEvent::ConnectionAccepted { peer });
    connections.spawn(peer, async move {
        // Both permits move into the task and are released when it ends, on
        // every path including cancellation and abort.
        let _fd_permit = fd_permit;
        run_connection(state, stream, peer, permit, &logger).await
    });
}

/// Drains one backlog entry using the emergency reserve descriptor.
///
/// This runs only when `accept` reported `EMFILE`/`ENFILE` despite strict
/// admission, which means descriptors were consumed outside this process's
/// accounting. Releasing the reserve makes exactly one accept possible; the
/// accepted socket is closed immediately, so the peer observes a reset rather
/// than an indefinite hang and the backlog advances by one.
async fn recover_from_descriptor_pressure(
    acceptor: &TcpAcceptor,
    reserve: &mut EmergencyDescriptor,
) {
    if !reserve.release() {
        return;
    }
    // A single non-blocking attempt. Waiting here would stall the listener for
    // an arbitrary time while holding no reservation.
    if let Ok(Ok((stream, _peer))) =
        time::timeout(Duration::from_millis(1), acceptor.accept_only()).await
    {
        drop(stream);
    }
    // Reacquiring can fail while the process is still at its limit. That is a
    // recoverable state: the next pressure event simply finds no reserve, and
    // admission continues to bound everything this process does account for.
    let _unused = reserve.reacquire();
}

async fn drain_connections(connections: &mut ConnectionTasks) {
    let drain = async {
        while !connections.is_empty() {
            consume_connection_result(connections.join_next().await);
        }
    };
    if time::timeout(GRACEFUL_SHUTDOWN_TIMEOUT, drain)
        .await
        .is_err()
    {
        connections.abort_all();
        while !connections.is_empty() {
            consume_connection_result(connections.join_next().await);
        }
    }
}

fn consume_connection_result(
    completed: Option<Result<crate::runtime::connection::ConnectionTaskResult, JoinError>>,
) {
    if let Some(Ok(result)) = completed {
        let (_, connection_result) = result.into_parts();
        let _ignored = connection_result;
    }
}

pub(super) fn is_degradable_listener_bind_error(address: SocketAddr, error: &io::Error) -> bool {
    match error.raw_os_error() {
        // The kernel cannot create a socket for this protocol family.
        Some(93 | 97) => true,
        // An unspecified family wildcard may be unavailable on this host.
        // The same errno for a concrete address is invalid configuration.
        Some(99) => address.ip().is_unspecified(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    };

    use super::is_degradable_listener_bind_error;
    use crate::config::node::listener::ListenFamily;

    /// Replays the supervisor's bind loop against fabricated `bind` outcomes,
    /// so every errno case is covered without needing a host that lacks a
    /// protocol family.
    fn simulate_listener_startup(
        mode: ListenFamily,
        outcomes: &[(SocketAddr, Option<i32>)],
    ) -> Result<Vec<SocketAddr>, SocketAddr> {
        let mut active = Vec::new();
        for (address, errno) in outcomes {
            let Some(errno) = errno else {
                active.push(*address);
                continue;
            };
            let error = io::Error::from_raw_os_error(*errno);
            if mode != ListenFamily::Auto || !is_degradable_listener_bind_error(*address, &error) {
                return Err(*address);
            }
        }
        if active.is_empty() {
            Err(outcomes[0].0)
        } else {
            Ok(active)
        }
    }

    #[test]
    fn auto_listener_starts_on_simulated_single_family_hosts() {
        let ipv4 = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 443);
        let ipv6 = SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 443);
        assert_eq!(
            simulate_listener_startup(ListenFamily::Auto, &[(ipv4, None), (ipv6, Some(97))]),
            Ok(vec![ipv4])
        );
        assert_eq!(
            simulate_listener_startup(ListenFamily::Auto, &[(ipv4, Some(97)), (ipv6, None)]),
            Ok(vec![ipv6])
        );
    }

    #[test]
    fn dual_stack_requires_both_families_and_auto_never_swallows_real_bind_errors() {
        let ipv4 = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 443);
        let ipv6 = SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 443);
        assert_eq!(
            simulate_listener_startup(ListenFamily::DualStack, &[(ipv4, None), (ipv6, Some(97))]),
            Err(ipv6)
        );
        for errno in [13, 22, 98] {
            assert_eq!(
                simulate_listener_startup(ListenFamily::Auto, &[(ipv4, None), (ipv6, Some(errno))]),
                Err(ipv6),
                "errno {errno} must remain fatal"
            );
        }
        let concrete = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 443);
        assert_eq!(
            simulate_listener_startup(ListenFamily::Auto, &[(ipv4, None), (concrete, Some(99))]),
            Err(concrete),
            "EADDRNOTAVAIL on a configured address is invalid configuration"
        );
    }
}
