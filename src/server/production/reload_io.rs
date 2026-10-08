//! Real production-listener streams crossing a runtime generation change.

use std::{collections::BTreeMap, net::Ipv4Addr, sync::Arc, time::Duration};

use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
    sync::oneshot,
};

use crate::{
    config::node::outbound::{NxrOutboundConfig, OutboundConfig},
    config::{SecretString, ValidatedConfig, node::fixture},
    protocol::vless::{Address, Destination},
    runtime::policy::DirectBarrierPolicy,
    server::outbound::{OutboundConnectError, OutboundConnectOutcome, OutboundRegistry},
    transport::FdBudget,
};

use super::{ProductionServer, fixture::unused_loopback_port};

fn configuration(port: u16, key: u8) -> ValidatedConfig {
    let encoded = BASE64_URL_SAFE_NO_PAD.encode([key; 32]);
    fixture::validated(&format!(
        r#"{{"role":"landing",
        "listeners":[{{"port":{port},"ip":"ipv4Only","ipv4":"127.0.0.1"}}],
        "landing":{{"protocol":"nxr","psk":"{encoded}",
        "authenticationTimeoutMs":1000,"connectTimeoutMs":1000}}}}"#
    ))
}

fn outbound(port: u16, key: u8) -> OutboundRegistry {
    OutboundRegistry::new(
        &BTreeMap::from([(
            "landing".to_owned(),
            OutboundConfig::Nxr(NxrOutboundConfig {
                address: Ipv4Addr::LOCALHOST.to_string(),
                port,
                psk: SecretString::new(BASE64_URL_SAFE_NO_PAD.encode([key; 32])),
                warm_tcp: Some(false),
            }),
        )]),
        &DirectBarrierPolicy::default(),
        Duration::from_secs(1),
        FdBudget::new(4096),
    )
}

async fn exchange(left: &mut TcpStream, right: &mut TcpStream, salt: u8) {
    let up: Vec<u8> = (0..262_144)
        .map(|index| u8::try_from(index % 251).expect("bounded byte") ^ salt)
        .collect();
    let down: Vec<u8> = up.iter().map(|byte| byte.wrapping_add(73)).collect();
    let (mut left_read, mut left_write) = left.split();
    let (mut right_read, mut right_write) = right.split();
    let mut received_up = vec![0; up.len()];
    let mut received_down = vec![0; down.len()];
    let (a, b, c, d) = tokio::join!(
        left_write.write_all(&up),
        right_write.write_all(&down),
        right_read.read_exact(&mut received_up),
        left_read.read_exact(&mut received_down),
    );
    a.expect("upload write");
    b.expect("download write");
    c.expect("upload read");
    d.expect("download read");
    assert_eq!(received_up, up);
    assert_eq!(received_down, down);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_nxr_stream_survives_key_reload_and_new_connections_use_new_key() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let port = unused_loopback_port();
        let server = ProductionServer::from_config(configuration(port, 0x51)).expect("compile");
        let runtime = Arc::clone(&server.runtime);
        let target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind origin");
        let destination = Destination::new(
            Address::Ipv4(Ipv4Addr::LOCALHOST),
            target.local_addr().unwrap().port(),
        );
        let old_registry = outbound(port, 0x51);
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(server.run_until(async {
            let _ = stopped.await;
            Ok(())
        }));
        // Retry only listener startup; no retry after authenticated bytes or reload.
        let connected = loop {
            match old_registry.connect("landing", &destination).await {
                Ok(OutboundConnectOutcome::Connected(stream)) => break stream,
                Ok(other) => panic!("unexpected outbound: {other:?}"),
                Err(OutboundConnectError::NxrConnect(error))
                    if error.kind() == std::io::ErrorKind::ConnectionRefused =>
                {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                Err(error) => panic!("startup connection failed: {error}"),
            }
        };
        let (mut line, permit) = connected.into_parts();
        let (mut origin, _) = target.accept().await.expect("authenticated old session");
        exchange(&mut line, &mut origin, 1).await;

        // Both directions have unread bytes at publication. The same sockets
        // must deliver those prefixes and subsequent large bidirectional data.
        line.write_all(b"old-generation-upload").await.unwrap();
        origin.write_all(b"old-generation-download").await.unwrap();
        assert_eq!(
            runtime
                .publish(configuration(port, 0x62).into_node())
                .unwrap(),
            1
        );
        let mut up = [0; 21];
        let mut down = [0; 23];
        origin.read_exact(&mut up).await.unwrap();
        line.read_exact(&mut down).await.unwrap();
        assert_eq!(&up, b"old-generation-upload");
        assert_eq!(&down, b"old-generation-download");
        exchange(&mut line, &mut origin, 2).await;

        let new_registry = outbound(port, 0x62);
        let OutboundConnectOutcome::Connected(new) =
            new_registry.connect("landing", &destination).await.unwrap()
        else {
            panic!("new generation must connect");
        };
        let (mut new_line, new_permit) = new.into_parts();
        let (mut new_origin, _) = target.accept().await.expect("new key must authenticate");
        exchange(&mut new_line, &mut new_origin, 3).await;
        line.shutdown().await.unwrap();
        origin.shutdown().await.unwrap();
        new_line.shutdown().await.unwrap();
        new_origin.shutdown().await.unwrap();
        drop((line, origin, new_line, new_origin, permit, new_permit));
        stop.send(()).unwrap();
        task.await.expect("server task").expect("graceful shutdown");
    })
    .await
    .expect("live reload must finish within its fixed deadline");
}
