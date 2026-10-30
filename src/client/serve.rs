//! Client accept loops for loopback SOCKS5 and HTTP CONNECT.

use std::{io, sync::Arc, time::Duration};

use tokio::net::TcpListener;

use crate::config::node::{ClientConfig, InboundProtocol, ListenerConfig};

use super::{
    http_inbound,
    line::LineError,
    selection::{LineGroup, LinePool, SelectionPolicy},
    socks5_inbound,
};

/// Client runtime failure.
#[derive(Debug)]
pub enum ClientRuntimeError {
    /// Configuration could not compile a LINE.
    Line(LineError),
    /// Listener bind failed.
    Bind(io::Error),
    /// Accept failed.
    Accept(io::Error),
}

impl std::fmt::Display for ClientRuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("client runtime failed")
    }
}

impl std::error::Error for ClientRuntimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Line(e) => Some(e),
            Self::Bind(e) | Self::Accept(e) => Some(e),
        }
    }
}

/// Runs the client until the process is cancelled.
pub async fn run_client(config: &ClientConfig) -> Result<(), ClientRuntimeError> {
    let policy = selection_policy(config);
    let pool = if let Some(groups) = &config.line_groups {
        LinePool::from_groups(&config.lines, groups, policy)
    } else {
        LinePool::from_lines(&config.lines, policy)
    }
    .map_err(ClientRuntimeError::Line)?;
    let pool = Arc::new(pool);

    if config.listeners.is_empty() {
        return Err(ClientRuntimeError::Line(LineError::Config("listeners")));
    }

    let mut joins = tokio::task::JoinSet::new();
    for listener_cfg in &config.listeners {
        let group = pool
            .group(listener_cfg.line_group.as_deref())
            .map_err(ClientRuntimeError::Line)?;
        let (listener, bound) = open_listener(listener_cfg).await?;
        let protocol = listener_cfg.protocol.unwrap_or(InboundProtocol::Socks5);
        eprintln!(
            "rust-reality client listening {} on {bound} (lineGroup={})",
            protocol.as_str(),
            group.name()
        );
        joins.spawn(async move { accept_loop(listener, bound, protocol, group).await });
    }

    match joins.join_next().await.expect("at least one listener") {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(error),
        Err(join) => Err(ClientRuntimeError::Accept(io::Error::other(
            join.to_string(),
        ))),
    }
}

fn selection_policy(config: &ClientConfig) -> SelectionPolicy {
    let mut policy = SelectionPolicy::default();
    if let Some(selection) = &config.selection {
        if let Some(ms) = selection.hedge_ms {
            policy.hedge = Duration::from_millis(ms);
        }
        if let Some(ms) = selection.timeout_ms {
            policy.timeout = Duration::from_millis(ms);
        }
    }
    policy
}

async fn open_listener(
    listener_cfg: &ListenerConfig,
) -> Result<(TcpListener, std::net::SocketAddr), ClientRuntimeError> {
    let bind = std::net::SocketAddr::new(
        std::net::IpAddr::V4(listener_cfg.ipv4_address()),
        listener_cfg.port,
    );
    let bind = if bind.ip().is_unspecified() {
        std::net::SocketAddr::from(([127, 0, 0, 1], listener_cfg.port))
    } else {
        bind
    };
    let listener = TcpListener::bind(bind)
        .await
        .map_err(ClientRuntimeError::Bind)?;
    let bound = listener.local_addr().map_err(ClientRuntimeError::Bind)?;
    Ok((listener, bound))
}

async fn accept_loop(
    listener: TcpListener,
    bound: std::net::SocketAddr,
    protocol: InboundProtocol,
    group: Arc<LineGroup>,
) -> Result<(), ClientRuntimeError> {
    let mut connections = crate::runtime::connection::ConnectionTasks::new();
    loop {
        let accepted = tokio::select! {
            biased;
            _ = connections.join_next(), if !connections.is_empty() => continue,
            accepted = listener.accept() => accepted,
        };
        let (stream, peer) = accepted.map_err(ClientRuntimeError::Accept)?;
        if crate::transport::TcpAcceptor::configure_accepted(&stream).is_err() {
            continue;
        }
        let group = Arc::clone(&group);
        connections.spawn(async move {
            match protocol {
                InboundProtocol::Socks5 => {
                    let _ = socks5_inbound::handle_connection(stream, bound, &group).await;
                }
                InboundProtocol::Http => {
                    let _ = http_inbound::handle_connection(stream, &group).await;
                }
            }
            crate::runtime::connection::ConnectionTaskResult::new(peer, Ok(()))
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn pending_socks_request() -> (
        tokio::task::JoinHandle<Result<(), ClientRuntimeError>>,
        tokio::net::TcpStream,
    ) {
        let config = serde_json::from_value(serde_json::json!({
            "address": "127.0.0.1", "port": 1,
            "id": "11111111-1111-4111-8111-111111111111",
            "publicKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "shortId": "0102030405060708", "serverName": "www.example.com"
        }))
        .unwrap();
        let group = LinePool::from_lines(&[config], SelectionPolicy::default())
            .unwrap()
            .group(None)
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bound = listener.local_addr().unwrap();
        let task = tokio::spawn(accept_loop(listener, bound, InboundProtocol::Socks5, group));
        let mut peer = tokio::net::TcpStream::connect(bound).await.unwrap();
        peer.write_all(&[5, 1, 0]).await.unwrap();
        let mut reply = [0; 2];
        tokio::time::timeout(Duration::from_secs(3), peer.read_exact(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply, [5, 0]);
        (task, peer)
    }

    async fn assert_closed(peer: &mut tokio::net::TcpStream) {
        let mut byte = [0];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(3), peer.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn cancelling_listener_closes_its_pending_connections() {
        let (task, mut peer) = pending_socks_request().await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_closed(&mut peer).await;
    }

    #[tokio::test]
    async fn socks_command_stall_is_bounded_after_method_negotiation() {
        let (task, mut peer) = pending_socks_request().await;
        tokio::time::pause();
        tokio::time::advance(super::super::REQUEST_BUDGET).await;
        tokio::time::resume();
        assert_closed(&mut peer).await;
        assert!(
            !task.is_finished(),
            "one stalled peer must not stop the listener"
        );
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
    }
}
