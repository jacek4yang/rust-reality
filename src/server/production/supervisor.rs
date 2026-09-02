//! Binding, task supervision, and the shutdown sequence.
//!
//! The bind loop runs before any connection is served, so a host missing an
//! address family fails at startup rather than half-serving. Once bound, this
//! is a single `select!` over the four things that can happen to a running
//! server: a signal, a listener dying, a reload request, and a scheduled
//! asset refresh. Exactly one update runs at a time — a second SIGHUP while
//! one is in flight is dropped, not queued, because the newest configuration
//! is the one the operator meant either way.

use std::{future::Future, io, sync::Arc, time::Duration};

use tokio::{
    sync::{mpsc, watch},
    task::JoinSet,
    time::{self, Instant, Sleep},
};

use crate::{
    config::node::listener::ListenFamily,
    logging::LogEvent,
    network::{AddressFamily, DialTuning},
    transport::tcp::TcpAcceptor,
};

use super::{
    ProductionServer,
    error::ProductionServerError,
    event::{emit, emit_rejected},
    listener::{is_degradable_listener_bind_error, run_listener},
    monitor::{
        adaptive_controller, run_adaptive_controller, run_network_refresh, run_resource_monitor,
    },
};

/// Binds every listener, spawns every task, and supervises them until the
/// shutdown future completes.
///
/// # Errors
///
/// Returns a bind, accept, signal, or task-supervision error.
pub(super) async fn supervise<F>(
    server: ProductionServer,
    shutdown: F,
    mut reload_receiver: mpsc::Receiver<()>,
    managed_updates: bool,
) -> Result<(), ProductionServerError>
where
    F: Future<Output = Result<(), io::Error>> + Send,
{
    let initial = server.runtime.load();
    let listener_capacity = server
        .listeners
        .iter()
        .map(|listener| listener.addresses.len())
        .sum();
    let mut bound = Vec::with_capacity(listener_capacity);
    for listener in &server.listeners {
        let mut active_families = Vec::with_capacity(listener.addresses.len());
        let mut unavailable_families = Vec::with_capacity(listener.addresses.len());
        let mut last_degradable = None;
        for address in &listener.addresses {
            match TcpAcceptor::bind(*address).await {
                Ok(acceptor) => {
                    active_families.push(AddressFamily::of(address.ip()).as_str());
                    bound.push((acceptor, *address));
                }
                Err(source)
                    if listener.mode == ListenFamily::Auto
                        && is_degradable_listener_bind_error(*address, &source) =>
                {
                    let family = AddressFamily::of(address.ip()).as_str();
                    unavailable_families.push(family);
                    emit(
                        &initial.logger,
                        &LogEvent::ListenerFamilyUnavailable {
                            tag: listener.tag.clone(),
                            family,
                            address: *address,
                            errno: source.raw_os_error(),
                        },
                    );
                    last_degradable = Some((*address, source));
                }
                Err(source) => {
                    return Err(ProductionServerError::Bind {
                        address: *address,
                        source,
                    });
                }
            }
        }
        if active_families.is_empty() {
            let (address, source) =
                last_degradable.expect("an empty auto listener must have a degradable bind error");
            return Err(ProductionServerError::Bind { address, source });
        }
        emit(
            &initial.logger,
            &LogEvent::ListenerTopologyActive {
                tag: listener.tag.clone(),
                active_families,
                unavailable_families,
            },
        );
    }

    // Listener binding is complete, so this immutable generation may begin
    // speculative cover and fixed-peer dialing without delaying availability.
    initial.activate_warm_pools();
    let (shutdown_sender, shutdown_receiver) = watch::channel(false);
    let mut listener_tasks = JoinSet::new();
    for (acceptor, address) in bound {
        let local_address = acceptor
            .local_addr()
            .map_err(ProductionServerError::ListenerAddress)?;
        let state = initial
            .connections
            .get(&address)
            .ok_or(ProductionServerError::ListenerStopped)?;
        emit(
            &initial.logger,
            &LogEvent::ListenerStarted {
                tag: state.tag.to_string(),
                address: local_address,
            },
        );
        listener_tasks.spawn(run_listener(
            acceptor,
            address,
            Arc::clone(&server.runtime),
            shutdown_receiver.clone(),
        ));
    }
    let monitor_task = server.runtime.memory.clone().map(|watch| {
        tokio::spawn(run_resource_monitor(
            Arc::clone(&server.runtime),
            watch,
            shutdown_receiver.clone(),
        ))
    });
    // The adaptive controller exists only under the `adaptive` tuning
    // mode; under `fixed` and `startup` nothing adjusts the ceilings and
    // behavior is byte-identical to v1.5.
    let adaptive_task = adaptive_controller(
        &initial.node,
        &server.runtime.policy,
        &server.runtime.authorities,
        &server.runtime.pressure,
    )
    .map(|controller| {
        tokio::spawn(run_adaptive_controller(
            Arc::clone(&server.runtime),
            controller,
            shutdown_receiver.clone(),
        ))
    });
    let network_refresh_task = tokio::spawn(run_network_refresh(
        server.runtime.authorities.network_environment.clone(),
        Duration::from_secs(
            DialTuning::for_policy(initial.node.network().ip()).route_refresh_seconds,
        ),
        shutdown_receiver.clone(),
    ));
    drop(initial);

    tokio::pin!(shutdown);
    let refresh_deadline = Instant::now() + server.runtime.reload_interval();
    let mut refresh = Box::pin(time::sleep_until(refresh_deadline));
    let mut update_tasks = JoinSet::new();
    let result = loop {
        tokio::select! {
            signal = &mut shutdown => {
                break signal.map_err(ProductionServerError::Signal);
            }
            completed = listener_tasks.join_next() => {
                break match completed {
                    Some(Ok(Ok(()))) => Err(ProductionServerError::ListenerStopped),
                    Some(Ok(Err(source))) => Err(ProductionServerError::Accept(source)),
                    Some(Err(source)) => Err(ProductionServerError::Task(source)),
                    None => Err(ProductionServerError::ListenerStopped),
                };
            }
            requested = reload_receiver.recv(), if managed_updates && !reload_receiver.is_closed() => {
                if requested.is_some() && update_tasks.is_empty() {
                    if let Some(path) = server.config_path.clone() {
                        let runtime = Arc::clone(&server.runtime);
                        update_tasks.spawn_blocking(move || {
                            ("configuration", runtime.reload_path(&path))
                        });
                    } else {
                        emit_rejected(&server.runtime, "configuration", None);
                    }
                }
                reset_refresh(&mut refresh, server.runtime.reload_interval());
            }
            () = &mut refresh, if managed_updates => {
                if update_tasks.is_empty() {
                    let runtime = Arc::clone(&server.runtime);
                    update_tasks.spawn_blocking(move || ("assets", runtime.refresh()));
                }
                reset_refresh(&mut refresh, server.runtime.reload_interval());
            }
            completed = update_tasks.join_next(), if !update_tasks.is_empty() => {
                match completed {
                    Some(Ok((_, Ok(_)))) => {
                        server.runtime.load().activate_warm_pools();
                    }
                    Some(Ok((field, Err(error)))) => {
                        emit_rejected(&server.runtime, field, Some(&error));
                    }
                    Some(Err(_)) | None => emit_rejected(&server.runtime, "configuration", None),
                }
                reset_refresh(&mut refresh, server.runtime.reload_interval());
            }
        }
    };

    server.runtime.load().deactivate_warm_pools();
    update_tasks.abort_all();
    if let Some(task) = monitor_task {
        task.abort();
    }
    if let Some(task) = adaptive_task {
        task.abort();
    }
    network_refresh_task.abort();
    let _ignored = shutdown_sender.send(true);
    while let Some(completed) = listener_tasks.join_next().await {
        match completed {
            Ok(Ok(())) => {}
            Ok(Err(source)) if result.is_ok() => {
                return Err(ProductionServerError::Accept(source));
            }
            Err(source) if result.is_ok() => {
                return Err(ProductionServerError::Task(source));
            }
            Ok(Err(_)) | Err(_) => {}
        }
    }
    result
}

#[cfg(unix)]
pub(super) async fn forward_reload_signals(
    mut signal: tokio::signal::unix::Signal,
    sender: mpsc::Sender<()>,
) {
    while signal.recv().await.is_some() {
        match sender.try_send(()) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(())) => {}
            Err(mpsc::error::TrySendError::Closed(())) => break,
        }
    }
}

pub(super) async fn shutdown_signal() -> Result<(), io::Error> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result,
            _ = terminate.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await
    }
}

fn reset_refresh(refresh: &mut std::pin::Pin<Box<Sleep>>, interval: Duration) {
    refresh.as_mut().reset(Instant::now() + interval);
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, net::Ipv4Addr, time::Duration};

    use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::TcpListener,
        sync::oneshot,
    };

    use crate::{
        config::{
            SecretString,
            node::fixture,
            node::outbound::{NxrOutboundConfig, OutboundConfig},
        },
        protocol::vless::{Address, Destination},
        runtime::policy::DirectBarrierPolicy,
        server::{
            outbound::{OutboundConnectOutcome, OutboundRegistry},
            production::{
                ProductionServer,
                fixture::{entry_config, unused_loopback_port},
            },
        },
        transport::FdBudget,
    };

    #[tokio::test(flavor = "current_thread")]
    async fn binds_all_listeners_and_stops_on_injected_shutdown() {
        let config = entry_config(unused_loopback_port());
        let server = ProductionServer::from_config(config.clone()).expect("server must compile");

        server
            .run_until(async { Ok(()) })
            .await
            .expect("injected shutdown must stop every listener");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_landing_node_serves_an_authenticated_nxr_session() {
        // Entry and landing are separate nodes now, so this drives a landing
        // the way a line node would: one authenticated NXR connection from an
        // outbound registry to a landing server.
        let landing_port = unused_loopback_port();
        let key_bytes = [0x5a; 32];
        let encoded_key = BASE64_URL_SAFE_NO_PAD.encode(key_bytes);
        let config = fixture::validated(&format!(
            r#"{{
  "role": "landing",
  "listeners": [{{ "port": {landing_port}, "ip": "ipv4Only", "ipv4": "127.0.0.1" }}],
  "landing": {{ "protocol": "nxr", "psk": "{encoded_key}",
                "authenticationTimeoutMs": 1000, "connectTimeoutMs": 1000 }}
}}"#
        ));
        let server = ProductionServer::from_config(config).expect("landing must compile");
        let target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("target must bind");
        let destination = Destination::new(
            Address::Ipv4(Ipv4Addr::LOCALHOST),
            target
                .local_addr()
                .expect("target address must exist")
                .port(),
        );
        let registry = OutboundRegistry::new(
            &BTreeMap::from([(
                "landing".to_owned(),
                OutboundConfig::Nxr(NxrOutboundConfig {
                    address: Ipv4Addr::LOCALHOST.to_string(),
                    port: landing_port,
                    psk: SecretString::new(encoded_key),
                    warm_tcp: Some(false),
                }),
            )]),
            &DirectBarrierPolicy::default(),
            Duration::from_secs(1),
            FdBudget::new(4_096),
        );
        let (shutdown_sender, shutdown_receiver) = oneshot::channel();
        let server_task = tokio::spawn(server.run_until(async move {
            let _ = shutdown_receiver.await;
            Ok(())
        }));

        // Bounded, so a real failure surfaces as an error instead of a hang.
        let mut last_error = None;
        let mut connected = None;
        for _ in 0..200 {
            match registry.connect("landing", &destination).await {
                Ok(OutboundConnectOutcome::Connected(connection)) => {
                    connected = Some(connection);
                    break;
                }
                Ok(other) => panic!("the NXR outbound must connect, got {other:?}"),
                Err(error) => {
                    last_error = Some(error);
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
        let connected =
            connected.unwrap_or_else(|| panic!("the landing never accepted: {last_error:?}"));
        let (mut accepted, _) = target.accept().await.expect("landing must dial the target");

        let (mut stream, _permit) = connected.into_parts();
        stream
            .write_all(b"ping")
            .await
            .expect("uplink must reach the target");
        let mut received = [0_u8; 4];
        accepted
            .read_exact(&mut received)
            .await
            .expect("the target must observe the uplink");
        assert_eq!(&received, b"ping");

        // Close the session before asking the server to stop: graceful
        // shutdown waits for live relays, and an open one would hold it for
        // the full thirty-second window.
        drop(stream);
        drop(accepted);
        let _ = shutdown_sender.send(());
        let _ = server_task.await;
    }
}
