//! Bounded zero-byte lifecycle for protocol-unprivileged landing sockets.
//!
//! TCP establishment grants no authority. Handoff and NXR hold only a
//! pre-auth-idle permit until byte one arrives, then atomically leave the long
//! idle phase and enter the existing short handshake budget.

use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use tokio::{
    io::AsyncReadExt,
    net::TcpStream,
    sync::Notify,
    time::{self, Instant},
};

use crate::runtime::{
    AdmissionDenied, AdmissionKind, AdmissionPermit, PressureGauge, ResourceGovernor,
};

/// Generation-owned cancellation for accepted sockets that remain idle.
#[derive(Clone, Default)]
pub(crate) struct PreAuthGeneration {
    inner: Arc<GenerationInner>,
}

struct GenerationInner {
    active: AtomicBool,
    changed: Notify,
}

impl Default for GenerationInner {
    fn default() -> Self {
        Self {
            active: AtomicBool::new(true),
            changed: Notify::new(),
        }
    }
}

impl PreAuthGeneration {
    /// Reclaims every unused socket in this immutable generation.
    /// Reports whether this generation still admits pre-auth work.
    ///
    /// Reload retires a generation by clearing this flag, so a test can assert
    /// that retiring one generation leaves a concurrently published generation
    /// untouched. Production code never needs to ask: `deactivate` is
    /// idempotent and the flag is consulted internally, so this exists purely
    /// to make the generation boundary observable to the tests that guard it.
    #[cfg(test)]
    pub(crate) fn is_active(&self) -> bool {
        self.inner.active.load(std::sync::atomic::Ordering::Acquire)
    }

    pub(crate) fn deactivate(&self) {
        if self.inner.active.swap(false, Ordering::AcqRel) {
            self.inner.changed.notify_waiters();
        }
    }

    async fn wait_deactivated(&self) {
        while self.inner.active.load(Ordering::Acquire) {
            let notified = self.inner.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if !self.inner.active.load(Ordering::Acquire) {
                break;
            }
            notified.await;
        }
    }
}

/// State returned immediately after byte one starts authentication.
pub(crate) struct AuthenticationStart {
    pub(crate) first_byte: u8,
    pub(crate) deadline: Instant,
    pub(crate) _permit: AdmissionPermit,
}

/// A connection failed before or while crossing the first-byte boundary.
#[derive(Debug)]
pub(crate) enum PreAuthError {
    Admission(AdmissionDenied),
    Timeout,
    /// The peer retired an unused zero-byte transport normally.
    PeerClosed,
    Read(io::Error),
    PressureReclaimed,
    GenerationRetired,
}

/// Waits for byte one without allocating protocol state or performing crypto.
pub(crate) async fn begin_authentication(
    stream: &mut TcpStream,
    idle_timeout: Duration,
    authentication_timeout: Duration,
    governor: &ResourceGovernor,
    pressure: &PressureGauge,
    generation: &PreAuthGeneration,
) -> Result<AuthenticationStart, PreAuthError> {
    let idle_permit = governor
        .try_acquire(AdmissionKind::PreAuthIdle)
        .map_err(PreAuthError::Admission)?;
    let idle_deadline = Instant::now()
        .checked_add(idle_timeout)
        .ok_or(PreAuthError::Timeout)?;
    let mut first = [0_u8; 1];
    tokio::select! {
        biased;
        () = generation.wait_deactivated() => return Err(PreAuthError::GenerationRetired),
        () = pressure.wait_until_pressure() => return Err(PreAuthError::PressureReclaimed),
        () = time::sleep_until(idle_deadline) => return Err(PreAuthError::Timeout),
        result = stream.read_exact(&mut first) => {
            match result {
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                    return Err(PreAuthError::PeerClosed);
                }
                Err(error) => return Err(PreAuthError::Read(error)),
            }
        }
    }

    // Byte one is the irreversible lifecycle transition. Anchor the short
    // deadline before touching any other state, then exchange permits without
    // waiting; pressure or a full handshake budget closes silently.
    let deadline = Instant::now()
        .checked_add(authentication_timeout)
        .ok_or(PreAuthError::Timeout)?;
    drop(idle_permit);
    let permit = governor
        .try_acquire(AdmissionKind::Handshake)
        .map_err(PreAuthError::Admission)?;
    Ok(AuthenticationStart {
        first_byte: first[0],
        deadline,
        _permit: permit,
    })
}

#[cfg(test)]
mod tests {
    use crate::runtime::policy::ResourceGovernorPolicy;
    use std::{net::Ipv4Addr, time::Duration};

    use tokio::{
        io::AsyncWriteExt,
        net::{TcpListener, TcpStream},
        task::yield_now,
        time,
    };

    use super::{PreAuthError, PreAuthGeneration, begin_authentication};
    use crate::runtime::{AdmissionKind, PressureGauge, ResourceGovernor, ResourcePressure};

    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("listener must bind");
        let address = listener.local_addr().expect("listener address");
        let client = TcpStream::connect(address);
        let server = listener.accept();
        let (client, server) = tokio::join!(client, server);
        let (server, _) = server.expect("server must accept");
        (client.expect("client must connect"), server)
    }

    #[tokio::test(start_paused = true)]
    async fn first_byte_exchanges_idle_for_handshake_permit() {
        let (mut client, mut server) = tcp_pair().await;
        let governor = ResourceGovernor::new(&ResourceGovernorPolicy::default());
        let pressure = PressureGauge::new();
        let generation = PreAuthGeneration::default();
        let task_governor = governor.clone();
        let task_pressure = pressure.clone();
        let task_generation = generation.clone();
        let task = tokio::spawn(async move {
            begin_authentication(
                &mut server,
                Duration::from_secs(60),
                Duration::from_secs(3),
                &task_governor,
                &task_pressure,
                &task_generation,
            )
            .await
        });
        yield_now().await;
        assert_eq!(governor.in_flight(AdmissionKind::PreAuthIdle), 1);
        assert_eq!(governor.in_flight(AdmissionKind::Handshake), 0);

        time::advance(Duration::from_secs(30)).await;
        assert!(!task.is_finished(), "ordinary warm idle must survive");
        client.write_all(&[0x4e]).await.expect("first byte");
        let authentication = task
            .await
            .expect("task must join")
            .expect("must transition");
        assert_eq!(authentication.first_byte, 0x4e);
        assert_eq!(governor.in_flight(AdmissionKind::PreAuthIdle), 0);
        assert_eq!(governor.in_flight(AdmissionKind::Handshake), 1);
        drop(authentication);
        assert_eq!(governor.in_flight(AdmissionKind::Handshake), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn idle_timeout_releases_all_admission_state() {
        let (_client, mut server) = tcp_pair().await;
        let governor = ResourceGovernor::new(&ResourceGovernorPolicy::default());
        let pressure = PressureGauge::new();
        let generation = PreAuthGeneration::default();
        let task_governor = governor.clone();
        let task = tokio::spawn(async move {
            begin_authentication(
                &mut server,
                Duration::from_secs(60),
                Duration::from_secs(3),
                &task_governor,
                &pressure,
                &generation,
            )
            .await
        });
        yield_now().await;
        time::advance(Duration::from_secs(60)).await;
        assert!(matches!(
            task.await.expect("task must join"),
            Err(PreAuthError::Timeout)
        ));
        assert_eq!(governor.in_flight(AdmissionKind::PreAuthIdle), 0);
    }

    #[tokio::test]
    async fn zero_byte_peer_retirement_is_distinct_from_authentication_failure() {
        let (client, mut server) = tcp_pair().await;
        let governor = ResourceGovernor::new(&ResourceGovernorPolicy::default());
        let pressure = PressureGauge::new();
        let generation = PreAuthGeneration::default();
        drop(client);

        assert!(matches!(
            begin_authentication(
                &mut server,
                Duration::from_secs(60),
                Duration::from_secs(3),
                &governor,
                &pressure,
                &generation,
            )
            .await,
            Err(PreAuthError::PeerClosed)
        ));
        assert_eq!(governor.in_flight(AdmissionKind::PreAuthIdle), 0);
        assert_eq!(governor.in_flight(AdmissionKind::Handshake), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn pressure_and_generation_retirement_reclaim_idle_sockets() {
        for reclaim_by_pressure in [true, false] {
            let (_client, mut server) = tcp_pair().await;
            let governor = ResourceGovernor::new(&ResourceGovernorPolicy::default());
            let pressure = PressureGauge::new();
            let generation = PreAuthGeneration::default();
            let task_governor = governor.clone();
            let task_pressure = pressure.clone();
            let task_generation = generation.clone();
            let task = tokio::spawn(async move {
                begin_authentication(
                    &mut server,
                    Duration::from_secs(60),
                    Duration::from_secs(3),
                    &task_governor,
                    &task_pressure,
                    &task_generation,
                )
                .await
            });
            yield_now().await;
            if reclaim_by_pressure {
                pressure.set(ResourcePressure::Pressure);
            } else {
                generation.deactivate();
            }
            let result = task.await.expect("task must join");
            if reclaim_by_pressure {
                assert!(matches!(result, Err(PreAuthError::PressureReclaimed)));
            } else {
                assert!(matches!(result, Err(PreAuthError::GenerationRetired)));
            }
            assert_eq!(governor.in_flight(AdmissionKind::PreAuthIdle), 0);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn idle_admission_limit_rejects_excess_without_a_wait_queue() {
        let (_first_client, mut first_server) = tcp_pair().await;
        let (_second_client, mut second_server) = tcp_pair().await;
        let policy = ResourceGovernorPolicy {
            max_pre_auth_idle_connections: 1,
            ..ResourceGovernorPolicy::default()
        };
        let governor = ResourceGovernor::new(&policy);
        let pressure = PressureGauge::new();
        let generation = PreAuthGeneration::default();
        let first_governor = governor.clone();
        let first_pressure = pressure.clone();
        let first_generation = generation.clone();
        let first = tokio::spawn(async move {
            begin_authentication(
                &mut first_server,
                Duration::from_secs(60),
                Duration::from_secs(3),
                &first_governor,
                &first_pressure,
                &first_generation,
            )
            .await
        });
        yield_now().await;
        assert_eq!(governor.in_flight(AdmissionKind::PreAuthIdle), 1);
        assert!(matches!(
            begin_authentication(
                &mut second_server,
                Duration::from_secs(60),
                Duration::from_secs(3),
                &governor,
                &pressure,
                &generation,
            )
            .await,
            Err(PreAuthError::Admission(_))
        ));
        generation.deactivate();
        assert!(matches!(
            first.await.expect("first task must join"),
            Err(PreAuthError::GenerationRetired)
        ));
        assert_eq!(governor.in_flight(AdmissionKind::PreAuthIdle), 0);
    }
}
