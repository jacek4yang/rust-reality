//! Bounded client establishment scheduling above the shared session engine.
//!
//! This adapter selects an authenticated transport before any VLESS request or
//! application bytes are sent. It does not implement REALITY authentication:
//! supplied futures must perform that verification and stop before opening a
//! destination. Losing futures are dropped, not detached as background tasks.

use std::{fmt, future::Future, time::Duration};

use rr_session::{ClientCandidate, ClientRace};
use tokio::time;

/// Why no authenticated client transport was selected.
#[derive(Debug)]
pub enum ClientEstablishError<E> {
    /// Every configured attempt failed, retaining each actual error.
    Attempts { primary: E, alternate: Option<E> },
    /// The connection's single overall deadline expired.
    Deadline,
}
impl<E> fmt::Display for ClientEstablishError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Attempts { .. } => f.write_str("all client authentication candidates failed"),
            Self::Deadline => f.write_str("client authentication deadline expired"),
        }
    }
}
impl<E: std::error::Error + 'static> std::error::Error for ClientEstablishError<E> {}

/// Selects at most one of two authenticated transports without spawning tasks.
///
/// The primary is polled first. The alternate is polled only after `hedge_after`
/// or a primary error. `timeout` bounds the entire operation, including failover;
/// the budget never restarts. At a simultaneously ready deadline and completion,
/// the deadline wins. Simultaneously ready candidates prefer the primary.
///
/// Neither future may send a VLESS request, contact the ultimate destination or
/// send application bytes. Only the returned transport may do that. Each future
/// must release all its resources when dropped and must not detach its own work.
/// This function cannot verify those contracts or authenticate an arbitrary T.
///
/// Dropping this function's future cancels both attempts, without marking either
/// node unhealthy. Errors are evidence for the caller's typed health policy;
/// this adapter does not classify destinations or change global route scores.
/// There is no retry after ownership is returned, even if a later request fails.
pub async fn select_client_transport<P, A, T, E>(
    primary: P,
    alternate: Option<A>,
    hedge_after: Duration,
    timeout: Duration,
) -> Result<(ClientCandidate, T), ClientEstablishError<E>>
where
    P: Future<Output = Result<T, E>>,
    A: Future<Output = Result<T, E>>,
{
    let has_alternate = alternate.is_some();
    let alternate = async move {
        match alternate {
            Some(attempt) => attempt.await,
            None => std::future::pending().await,
        }
    };
    let deadline = time::sleep(timeout);
    let hedge = time::sleep(hedge_after);
    tokio::pin!(primary, alternate, deadline, hedge);
    let mut race = ClientRace::new();
    let mut primary_error = None;
    let mut alternate_error = None;
    let mut alternate_started = false;
    loop {
        tokio::select! {
            biased;
            () = &mut deadline => {
                let _ = race.cancel();
                return Err(ClientEstablishError::Deadline);
            }
            result = &mut primary, if primary_error.is_none() => {
                match result {
                    Ok(transport) => {
                        let grant = race.adopt(ClientCandidate::Primary)
                            .expect("the primary is polled only while pending");
                        return Ok((grant.into_candidate(), transport));
                    }
                    Err(error) => {
                        let accepted = race.fail(ClientCandidate::Primary);
                        debug_assert!(accepted);
                        primary_error = Some(error);
                        if has_alternate && !alternate_started {
                            alternate_started = race.start_alternate();
                        }
                    }
                }
            }
            result = &mut alternate, if alternate_started && alternate_error.is_none() => {
                match result {
                    Ok(transport) => {
                        let grant = race.adopt(ClientCandidate::Alternate)
                            .expect("the alternate is polled only while pending");
                        return Ok((grant.into_candidate(), transport));
                    }
                    Err(error) => {
                        let accepted = race.fail(ClientCandidate::Alternate);
                        debug_assert!(accepted);
                        alternate_error = Some(error);
                    }
                }
            }
            () = &mut hedge, if has_alternate && !alternate_started => {
                alternate_started = race.start_alternate();
            }
        }
        if (!has_alternate || alternate_error.is_some())
            && let Some(primary) = primary_error.take()
        {
            let _ = race.cancel();
            return Err(ClientEstablishError::Attempts {
                primary,
                alternate: alternate_error,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        future::{pending, ready},
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };
    use tokio::time::Instant;

    type Never = std::future::Pending<Result<u8, &'static str>>;
    struct DropCount(Arc<AtomicUsize>);
    impl Drop for DropCount {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    const SECOND: Duration = Duration::from_secs(1);

    #[tokio::test(start_paused = true)]
    async fn primary_success_never_polls_alternate() {
        let alternate = std::future::poll_fn(|_| -> std::task::Poll<Result<u8, &str>> {
            panic!("alternate must stay unpolled")
        });
        let result = select_client_transport(ready(Ok(1)), Some(alternate), SECOND, SECOND * 5)
            .await
            .unwrap();
        assert_eq!(result, (ClientCandidate::Primary, 1));
    }
    #[tokio::test(start_paused = true)]
    async fn failed_primary_starts_fallback_without_waiting_for_hedge() {
        let start = Instant::now();
        let result = select_client_transport(
            ready(Err("primary")),
            Some(ready(Ok(2_u8))),
            SECOND,
            SECOND * 5,
        )
        .await
        .unwrap();
        assert_eq!(result, (ClientCandidate::Alternate, 2));
        assert_eq!(start.elapsed(), Duration::ZERO);
    }
    #[tokio::test(start_paused = true)]
    async fn hedge_waits_then_cancels_pending_primary() {
        let drops = Arc::new(AtomicUsize::new(0));
        let guard = DropCount(drops.clone());
        let primary = async move {
            let _guard = guard;
            pending::<Result<u8, &str>>().await
        };
        let start = Instant::now();
        let result = select_client_transport(primary, Some(ready(Ok(2))), SECOND, SECOND * 5)
            .await
            .unwrap();
        assert_eq!(result, (ClientCandidate::Alternate, 2));
        assert_eq!(start.elapsed(), SECOND);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }
    #[tokio::test(start_paused = true)]
    async fn one_deadline_covers_both_attempts_without_extension() {
        let start = Instant::now();
        let result = select_client_transport(
            pending::<Result<u8, &str>>(),
            Some(pending::<Result<u8, &str>>()),
            SECOND,
            SECOND * 2,
        )
        .await;
        assert!(matches!(result, Err(ClientEstablishError::Deadline)));
        assert_eq!(start.elapsed(), SECOND * 2);
    }
    #[tokio::test(start_paused = true)]
    async fn both_errors_are_retained_without_retry() {
        let result = select_client_transport(
            ready(Err::<u8, _>("primary")),
            Some(ready(Err("alternate"))),
            SECOND,
            SECOND * 5,
        )
        .await;
        assert!(matches!(
            result,
            Err(ClientEstablishError::Attempts {
                primary: "primary",
                alternate: Some("alternate")
            })
        ));
        let single = select_client_transport(
            ready(Err::<u8, _>("only")),
            None::<Never>,
            SECOND,
            SECOND * 5,
        )
        .await;
        assert!(matches!(
            single,
            Err(ClientEstablishError::Attempts {
                primary: "only",
                alternate: None
            })
        ));
    }
    #[tokio::test(start_paused = true)]
    async fn caller_cancellation_drops_both_owned_attempts() {
        let drops = Arc::new(AtomicUsize::new(0));
        let a = DropCount(drops.clone());
        let b = DropCount(drops.clone());
        let primary = async move {
            let _a = a;
            pending::<Result<u8, &str>>().await
        };
        let alternate = async move {
            let _b = b;
            pending::<Result<u8, &str>>().await
        };
        let mut future = Box::pin(select_client_transport(
            primary,
            Some(alternate),
            Duration::ZERO,
            SECOND * 5,
        ));
        assert!(
            std::future::poll_fn(|cx| std::task::Poll::Ready(
                future.as_mut().poll(cx).is_pending()
            ))
            .await
        );
        drop(future);
        assert_eq!(drops.load(Ordering::Relaxed), 2);
    }
    #[tokio::test(start_paused = true)]
    async fn alternate_error_does_not_cancel_a_still_viable_primary() {
        let primary = async {
            time::sleep(SECOND * 2).await;
            Ok::<_, &str>(1_u8)
        };
        let result =
            select_client_transport(primary, Some(ready(Err("alternate"))), SECOND, SECOND * 5)
                .await
                .unwrap();
        assert_eq!(result, (ClientCandidate::Primary, 1));
    }
    #[tokio::test(start_paused = true)]
    async fn expired_budget_does_not_poll_a_ready_candidate() {
        let primary = std::future::poll_fn(|_| -> std::task::Poll<Result<u8, &str>> {
            panic!("expired establishment must not begin authentication")
        });
        let result = select_client_transport(primary, None::<Never>, SECOND, Duration::ZERO).await;
        assert!(matches!(result, Err(ClientEstablishError::Deadline)));
    }

    #[tokio::test(start_paused = true)]
    async fn simultaneous_ready_candidates_prefer_primary() {
        let result = select_client_transport(
            ready(Ok::<_, &str>(1_u8)),
            Some(ready(Ok(2))),
            Duration::ZERO,
            SECOND,
        )
        .await
        .unwrap();
        assert_eq!(result, (ClientCandidate::Primary, 1));
    }
}
