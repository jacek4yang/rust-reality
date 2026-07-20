use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
};

use rust_reality::{runtime::connection::ConnectionTasks, transport::tcp::TcpAcceptor};
use tokio::net::TcpStream;

const DEFAULT_LISTEN_PORT: u16 = 8443;
const READ_BUFFER_SIZE: usize = 4 * 1024;

#[tokio::main]
async fn main() -> io::Result<()> {
    let requested_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, DEFAULT_LISTEN_PORT));

    let acceptor = TcpAcceptor::bind(requested_addr).await?;
    let actual_addr = acceptor.local_addr()?;
    let mut connections = ConnectionTasks::new();

    eprintln!("listening on {actual_addr}");

    loop {
        tokio::select! {
            accepted = acceptor.accept() => {
                let (stream, peer_addr) = accepted?;

                eprintln!(
                    "accepted TCP connection from {peer_addr}"
                );

                connections.spawn(peer_addr, wait_for_peer_close(stream));
            }

            completed = connections.join_next(),
                if !connections.is_empty() =>
            {
                let completed = completed.expect(
                    "connection task set should not be empty",
                );
                report_connection_result(completed);
            }
        }
    }
}

async fn wait_for_peer_close(stream: TcpStream) -> io::Result<()> {
    let mut buffer = [0_u8; READ_BUFFER_SIZE];

    loop {
        stream.readable().await?;

        match stream.try_read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
    }
}

fn report_connection_result(
    completed: Result<
        rust_reality::runtime::connection::ConnectionTaskResult,
        tokio::task::JoinError,
    >,
) {
    match completed {
        Ok(outcome) => {
            let (peer_addr, result) = outcome.into_parts();

            match result {
                Ok(()) => {
                    eprintln!("TCP connection from {peer_addr} closed");
                }
                Err(error) => {
                    eprintln!(
                        "TCP connection from {peer_addr} failed: \
                        {error}"
                    );
                }
            }
        }
        Err(error) if error.is_panic() => {
            eprintln!("TCP connection task panicked: {error}");
        }
        Err(error) => {
            eprintln!("TCP connection task was cancelled: {error}");
        }
    }
}
