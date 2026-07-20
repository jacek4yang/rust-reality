use std::{
    future,
    io::{self, ErrorKind},
    net::{Ipv4Addr, SocketAddr},
};

use rust_reality::runtime::connection::ConnectionTasks;

#[tokio::test(flavor = "current_thread")]
async fn isolates_connection_failure_from_sibling_task() {
    let failed_peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 50_001));
    let pending_peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 50_002));
    let later_peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 50_003));

    let mut tasks = ConnectionTasks::new();

    tasks.spawn(failed_peer, async {
        Err(io::Error::new(
            ErrorKind::ConnectionAborted,
            "simulated connection failure",
        ))
    });

    tasks.spawn(pending_peer, future::pending());

    let completed = tasks
        .join_next()
        .await
        .expect("one task should complete")
        .expect("connection task should not panic");

    let (peer_addr, result) = completed.into_parts();

    assert_eq!(peer_addr, failed_peer);
    assert_eq!(
        result.expect_err("connection should fail").kind(),
        ErrorKind::ConnectionAborted
    );

    assert_eq!(tasks.len(), 1);

    tasks.spawn(later_peer, async { Ok(()) });

    assert_eq!(tasks.len(), 2);

    let completed = tasks
        .join_next()
        .await
        .expect("later task should complete")
        .expect("later task should not panic");

    let (peer_addr, result) = completed.into_parts();

    assert_eq!(peer_addr, later_peer);
    result.expect("later connection should succeed");

    assert_eq!(tasks.len(), 1);
}
