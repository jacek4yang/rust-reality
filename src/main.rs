use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

use rust_reality::{
    protocol::vless::{UserId, UserRegistry},
    runtime::connection::{ConnectionTaskResult, ConnectionTasks},
    server::{config::ServerConfig, handler::ConnectionHandler},
    transport::tcp::TcpAcceptor,
};
use tokio::task::JoinError;

const DEFAULT_LISTEN_PORT: u16 = 8443;

const DEFAULT_USER_ID: UserId = UserId::new([0x11; 16]);

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::main]
async fn main() -> io::Result<()> {
    let config = default_config();

    let acceptor = TcpAcceptor::bind(config.listen_addr()).await?;

    let actual_addr = acceptor.local_addr()?;

    let handler = ConnectionHandler::from_config(&config);

    let mut connections = ConnectionTasks::new();

    eprintln!("plain VLESS TCP server listening on {actual_addr}");

    loop {
        tokio::select! {
            accepted = acceptor.accept() => {
                let (stream, peer_addr) = accepted?;

                eprintln!("accepted VLESS TCP connection from {peer_addr}");

                let connection_handler = handler.clone();

                connections.spawn(peer_addr, async move {
                    connection_handler
                        .handle(stream, peer_addr)
                        .await
                        .map_err(io::Error::other)
                });
            }

            completed = connections.join_next(), if !connections.is_empty() => {
                let completed = completed.expect("connection task set should not be empty");

                report_connection_result(completed);
            }
        }
    }
}

fn default_config() -> ServerConfig {
    ServerConfig::new(
        SocketAddr::from((Ipv4Addr::LOCALHOST, DEFAULT_LISTEN_PORT)),
        UserRegistry::new([DEFAULT_USER_ID]),
        HANDSHAKE_TIMEOUT,
        CONNECT_TIMEOUT,
    )
}

fn report_connection_result(completed: Result<ConnectionTaskResult, JoinError>) {
    match completed {
        Ok(outcome) => {
            let (peer_addr, result) = outcome.into_parts();

            match result {
                Ok(()) => eprintln!("VLESS TCP connection from {peer_addr} closed"),
                Err(error) => eprintln!("VLESS TCP connection from {peer_addr} failed: {error}"),
            }
        }

        Err(error) if error.is_panic() => eprintln!("VLESS TCP connection task panicked: {error}"),

        Err(error) => eprintln!("VLESS TCP connection task was cancelled: {error}"),
    }
}
