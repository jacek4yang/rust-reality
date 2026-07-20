use std::{future::Future, io, net::SocketAddr};

use tokio::task::{JoinError, JoinSet};

/// Result produced when one connection task finishes.
#[derive(Debug)]
pub struct ConnectionTaskResult {
    peer_addr: SocketAddr,
    result: io::Result<()>,
}

impl ConnectionTaskResult {
    /// Returns the remote address associated with the connection.
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    /// Splits the task output into its peer address and connection result.
    pub fn into_parts(self) -> (SocketAddr, io::Result<()>) {
        (self.peer_addr, self.result)
    }
}

/// Tracks and reaps spawned connection tasks
#[derive(Default)]
pub struct ConnectionTasks {
    tasks: JoinSet<ConnectionTaskResult>,
}

impl ConnectionTasks {
    /// Creates an empty connection task set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the number of tasks that have not yet been reaped.
    pub fn len(&self) -> usize {
        self.tasks.len()
    }

    /// Returns whether no connection tasks remain in the set.
    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    /// Spawns one connection future and associates it with a peer address.
    pub fn spawn<F>(&mut self, peer_addr: SocketAddr, future: F)
    where
        F: Future<Output = io::Result<()>> + Send + 'static,
    {
        self.tasks.spawn(async move {
            let result = future.await;

            ConnectionTaskResult { peer_addr, result }
        });
    }

    /// Waits for one connection task to finish.
    pub async fn join_next(&mut self) -> Option<Result<ConnectionTaskResult, JoinError>> {
        self.tasks.join_next().await
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future,
        io::{self, ErrorKind},
        net::{Ipv4Addr, SocketAddr},
    };

    use super::ConnectionTasks;

    #[tokio::test(flavor = "current_thread")]
    async fn completed_task_retains_peer_address() {
        let peer_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 40_001));

        let mut tasks = ConnectionTasks::new();

        tasks.spawn(peer_addr, async { Ok(()) });

        assert_eq!(tasks.len(), 1);

        let completed = tasks
            .join_next()
            .await
            .expect("one task should be present")
            .expect("task should not panic or be cancelled");

        assert_eq!(completed.peer_addr(), peer_addr);

        let (_, result) = completed.into_parts();
        result.expect("connection future should succeed");

        assert!(tasks.is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn connection_error_does_not_remove_other_tasks() {
        let failed_peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 40_002));
        let pending_peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 40_003));

        let mut tasks = ConnectionTasks::new();

        tasks.spawn(failed_peer, async {
            Err(io::Error::new(
                ErrorKind::ConnectionReset,
                "simulated connection reset",
            ))
        });

        tasks.spawn(pending_peer, future::pending());

        assert_eq!(tasks.len(), 2);

        let completed = tasks
            .join_next()
            .await
            .expect("one task should complete")
            .expect("task should not panic or be cancelled");

        let (peer_addr, result) = completed.into_parts();

        assert_eq!(peer_addr, failed_peer);
        assert_eq!(
            result.expect_err("connection future should fail").kind(),
            ErrorKind::ConnectionReset
        );
        assert_eq!(tasks.len(), 1);
    }
}
