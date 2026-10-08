use std::{future::Future, io, net::SocketAddr};

use tokio::task::{JoinError, JoinSet};

/// Result produced when one connection task finishes.
#[derive(Debug)]
pub struct ConnectionTaskResult {
    peer_addr: SocketAddr,
    result: io::Result<()>,
}

impl ConnectionTaskResult {
    /// Associates a completed connection's result with its remote address.
    pub fn new(peer_addr: SocketAddr, result: io::Result<()>) -> Self {
        Self { peer_addr, result }
    }

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

    /// Spawns a connection future that produces its peer-aware completion.
    ///
    /// The caller constructs the result in its existing async state. Wrapping
    /// an already large future in another async adapter retains both its
    /// captured input and await state, almost doubling the task allocation.
    pub fn spawn<F>(&mut self, future: F)
    where
        F: Future<Output = ConnectionTaskResult> + Send + 'static,
    {
        self.tasks.spawn(future);
    }

    /// Waits for one connection task to finish.
    pub async fn join_next(&mut self) -> Option<Result<ConnectionTaskResult, JoinError>> {
        self.tasks.join_next().await
    }

    /// Requests cancellation of every tracked task.
    pub fn abort_all(&mut self) {
        self.tasks.abort_all();
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future,
        io::{self, ErrorKind},
        net::{Ipv4Addr, SocketAddr},
    };

    use super::{ConnectionTaskResult, ConnectionTasks};

    #[tokio::test(flavor = "current_thread")]
    async fn completed_task_retains_peer_address() {
        let peer_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 40_001));

        let mut tasks = ConnectionTasks::new();

        tasks.spawn(async move { ConnectionTaskResult::new(peer_addr, Ok(())) });

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

        tasks.spawn(async move {
            ConnectionTaskResult::new(
                failed_peer,
                Err(io::Error::new(
                    ErrorKind::ConnectionReset,
                    "simulated connection reset",
                )),
            )
        });

        tasks.spawn(async move {
            future::pending::<()>().await;
            ConnectionTaskResult::new(pending_peer, Ok(()))
        });

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
    #[tokio::test(flavor = "current_thread")]
    async fn spawning_large_connection_does_not_double_its_allocation() {
        let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 40_010));
        let mut tasks = ConnectionTasks::new();
        let payload = std::hint::black_box([0_u8; 32 * 1024]);
        let work = async move {
            future::pending::<()>().await;
            std::hint::black_box(payload);
            ConnectionTaskResult::new(peer, Ok(()))
        };
        let measured = allocation_counter::measure(|| tasks.spawn(work));
        eprintln!(
            "spawn allocation bytes={} count={}",
            measured.bytes_total, measured.count_total
        );
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        assert!(
            measured.bytes_total < 48 * 1024,
            "a 32 KiB connection must not be copied into a second large async state: {measured:?}"
        );
    }

    struct DropSignal(Option<tokio::sync::oneshot::Sender<()>>);

    impl Drop for DropSignal {
        fn drop(&mut self) {
            if let Some(sender) = self.0.take() {
                let _ = sender.send(());
            }
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn abort_releases_connection_captures_and_reaps_the_task() {
        let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 40_011));
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let signal = DropSignal(Some(sender));
        let mut tasks = ConnectionTasks::new();
        tasks.spawn(async move {
            let _signal = signal;
            future::pending::<()>().await;
            ConnectionTaskResult::new(peer, Ok(()))
        });
        tokio::task::yield_now().await;
        tasks.abort_all();
        let error = tasks
            .join_next()
            .await
            .expect("task is tracked")
            .expect_err("task aborts");
        assert!(error.is_cancelled());
        receiver.await.expect("captured resources are dropped");
        assert!(tasks.is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn dropping_task_set_releases_an_unpolled_capture() {
        let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 40_012));
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let signal = DropSignal(Some(sender));
        let mut tasks = ConnectionTasks::new();
        tasks.spawn(async move {
            let _signal = signal;
            future::pending::<()>().await;
            ConnectionTaskResult::new(peer, Ok(()))
        });
        drop(tasks);
        tokio::time::timeout(std::time::Duration::from_secs(1), receiver)
            .await
            .expect("cancelled task is reaped promptly")
            .expect("unpolled captured resources are dropped");
    }
}
