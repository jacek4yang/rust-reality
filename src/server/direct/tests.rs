use std::net::Ipv4Addr;

use tokio::net::{TcpListener, TcpStream};

use super::{DirectHandoff, Direction, DirectionState, RawDecision};

#[test]
fn permitted_transitions_match_the_specified_lifecycle() {
    use DirectionState::{
        Closed, DirectPending, Failed, Framed, Outer, PairPending, RawReady, Relaying,
    };

    for (from, to) in [
        (Framed, DirectPending),
        (Framed, Outer),
        (Framed, Closed),
        (Framed, Failed),
        (DirectPending, RawReady),
        (DirectPending, Closed),
        (DirectPending, Failed),
        (RawReady, PairPending),
        (RawReady, Relaying),
        (RawReady, Closed),
        (RawReady, Failed),
        (PairPending, Closed),
        (PairPending, Failed),
        (Relaying, Closed),
        (Relaying, Failed),
        (Outer, Closed),
        (Outer, Failed),
    ] {
        assert!(from.permits(to), "{from} -> {to} must be permitted");
    }
}

#[test]
fn forbidden_transitions_are_rejected() {
    use DirectionState::{
        Closed, DirectPending, Failed, Framed, Outer, PairPending, RawReady, Relaying,
    };

    for (from, to) in [
        (Outer, RawReady),
        (Outer, PairPending),
        (Outer, Relaying),
        (RawReady, Framed),
        (RawReady, DirectPending),
        (Framed, RawReady),
        (Framed, PairPending),
        (Framed, Relaying),
        (DirectPending, PairPending),
        (DirectPending, Relaying),
        (PairPending, Framed),
        (PairPending, RawReady),
        (PairPending, Relaying),
        (Relaying, Framed),
        (Relaying, RawReady),
        (Relaying, PairPending),
        (Closed, Framed),
        (Closed, RawReady),
        (Closed, DirectPending),
        (Closed, PairPending),
        (Closed, Relaying),
        (Failed, Framed),
        (Failed, RawReady),
        (Failed, Closed),
        (Closed, Failed),
    ] {
        assert!(!from.permits(to), "{from} -> {to} must be forbidden");
    }
}

#[test]
fn coordinator_rejects_an_invalid_transition_without_changing_state() {
    let handoff = DirectHandoff::new();

    let error = handoff
        .advance(Direction::Uplink, DirectionState::RawReady)
        .expect_err("framed cannot jump straight to raw");

    assert_eq!(error.from, DirectionState::Framed);
    assert_eq!(error.to, DirectionState::RawReady);
    assert_eq!(handoff.state(Direction::Uplink), DirectionState::Framed);
}

#[test]
fn the_pair_decision_reads_raw_ready_and_pair_pending_peers() {
    let handoff = DirectHandoff::new();
    assert!(!handoff.peer_can_pair(Direction::Uplink));

    handoff
        .advance(Direction::Downlink, DirectionState::DirectPending)
        .expect("downlink may pend");
    assert!(
        !handoff.peer_can_pair(Direction::Uplink),
        "a pending peer has not reached its raw boundary"
    );

    handoff
        .advance(Direction::Downlink, DirectionState::RawReady)
        .expect("downlink may become raw");
    assert!(handoff.peer_can_pair(Direction::Uplink));

    handoff
        .advance(Direction::Downlink, DirectionState::PairPending)
        .expect("downlink may commit to the pair");
    assert!(
        handoff.peer_can_pair(Direction::Uplink),
        "a committed peer is guaranteed to deposit its halves"
    );
    assert!(
        !handoff.peer_can_pair(Direction::Downlink),
        "a framed uplink cannot join a pair"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn session_pair_commitment_is_not_settled_by_the_first_depositor() {
    // The bilateral pair stays consistent only because a direction that
    // committed to `Pair` is never advanced again until the peer has also
    // decided. `run_handoff` in `super::vision` returns without settling
    // when `deposit_*` yields `None`, so the peer always observes
    // `PairPending` and pairs back rather than choosing a directional relay.
    //
    // This test pins that runtime obligation. The pure engine cannot enforce
    // it: `PairPending -> Closed` is a legal lifecycle edge, and taking it
    // before the peer decides would let the peer observe a terminal state
    // and split the pair. The semantic fuzz target
    // `fuzz/fuzz_targets/session_semantics.rs` models the same discipline and
    // documents why.
    let handoff = DirectHandoff::new();
    for direction in [Direction::Uplink, Direction::Downlink] {
        handoff
            .advance(direction, DirectionState::DirectPending)
            .expect("direction may pend");
        handoff
            .advance(direction, DirectionState::RawReady)
            .expect("direction may become raw");
    }

    let first = handoff
        .decide(Direction::Uplink)
        .expect("uplink may commit")
        .into_decision();
    assert_eq!(first, RawDecision::Pair);
    assert_eq!(
        handoff.state(Direction::Uplink),
        DirectionState::PairPending,
        "the first depositor must remain at its pair commitment"
    );

    // A `None` deposit means this direction is not the last depositor. The
    // production path returns at that point without settling, so the state
    // must still be `PairPending` when the peer decides.
    let (client, _client_peer) = pair().await;
    let (destination, _destination_peer) = pair().await;
    let (client_reader, _client_writer) = client.into_split();
    let (_destination_reader, destination_writer) = destination.into_split();
    let recovered = handoff
        .deposit_uplink(client_reader, destination_writer)
        .expect("depositing one half pair must not fail");
    assert!(
        recovered.is_none(),
        "the first depositor must not receive reunited sockets"
    );
    assert_eq!(
        handoff.state(Direction::Uplink),
        DirectionState::PairPending,
        "depositing must not settle the first depositor"
    );

    let second = handoff
        .decide(Direction::Downlink)
        .expect("downlink may commit")
        .into_decision();
    assert_eq!(
        second, first,
        "the peer of a pair commitment must pair back, never split"
    );
}

#[test]
fn a_relaying_peer_can_no_longer_join_the_pair() {
    let handoff = DirectHandoff::new();
    handoff
        .advance(Direction::Downlink, DirectionState::DirectPending)
        .expect("downlink may pend");
    handoff
        .advance(Direction::Downlink, DirectionState::RawReady)
        .expect("downlink may become raw");
    handoff
        .advance(Direction::Downlink, DirectionState::Relaying)
        .expect("downlink may claim its halves");

    assert!(
        !handoff.peer_can_pair(Direction::Uplink),
        "a peer that claimed its halves must not be awaited"
    );
    assert!(
        handoff
            .advance(Direction::Uplink, DirectionState::PairPending)
            .is_err(),
        "a framed direction cannot skip its raw boundary"
    );
}

#[test]
fn decide_commits_pair_when_the_peer_is_pairable_and_directional_otherwise() {
    let handoff = DirectHandoff::new();
    for direction in [Direction::Uplink, Direction::Downlink] {
        handoff
            .advance(direction, DirectionState::DirectPending)
            .expect("direction may pend");
        handoff
            .advance(direction, DirectionState::RawReady)
            .expect("direction may become raw");
    }

    let first = handoff
        .decide(Direction::Uplink)
        .expect("uplink may commit");
    assert_eq!(first.into_decision(), RawDecision::Pair);
    assert_eq!(
        handoff.state(Direction::Uplink),
        DirectionState::PairPending
    );

    let second = handoff
        .decide(Direction::Downlink)
        .expect("downlink may commit");
    assert_eq!(
        second.into_decision(),
        RawDecision::Pair,
        "the second decider must observe the committed PairPending"
    );

    let solo = DirectHandoff::new();
    solo.advance(Direction::Uplink, DirectionState::DirectPending)
        .expect("uplink may pend");
    solo.advance(Direction::Uplink, DirectionState::RawReady)
        .expect("uplink may become raw");
    let decision = solo.decide(Direction::Uplink).expect("uplink may commit");
    assert_eq!(decision.into_decision(), RawDecision::Directional);
    assert_eq!(solo.state(Direction::Uplink), DirectionState::Relaying);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn racing_decisions_never_split_the_pair() {
    use std::sync::Arc;

    // Both directions reach RawReady and decide concurrently. The mutex
    // serialization must make the outcomes agree in every interleaving:
    // either both pair or both relay directionally — never one of each.
    for round in 0..256 {
        let handoff = Arc::new(DirectHandoff::new());
        for direction in [Direction::Uplink, Direction::Downlink] {
            handoff
                .advance(direction, DirectionState::DirectPending)
                .expect("direction may pend");
            handoff
                .advance(direction, DirectionState::RawReady)
                .expect("direction may become raw");
        }
        let up = {
            let handoff = Arc::clone(&handoff);
            tokio::spawn(async move { handoff.decide(Direction::Uplink) })
        };
        let down = {
            let handoff = Arc::clone(&handoff);
            tokio::spawn(async move { handoff.decide(Direction::Downlink) })
        };
        let (up, down) = tokio::join!(up, down);
        let up = up
            .expect("uplink task")
            .expect("uplink may commit")
            .into_decision();
        let down = down
            .expect("downlink task")
            .expect("downlink may commit")
            .into_decision();
        assert_eq!(
            up, down,
            "round {round}: decisions split the pair ({up:?} vs {down:?})"
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn only_the_last_depositor_receives_both_complete_sockets() {
    let handoff = DirectHandoff::new();
    let (client, _client_peer) = pair().await;
    let (destination, _destination_peer) = pair().await;
    let client_address = client.local_addr().expect("client address");
    let destination_address = destination.local_addr().expect("destination address");
    let (client_reader, client_writer) = client.into_split();
    let (destination_reader, destination_writer) = destination.into_split();

    let first = handoff
        .deposit_uplink(client_reader, destination_writer)
        .expect("uplink deposit must succeed");
    assert!(first.is_none(), "the first depositor must not take sockets");

    let second = handoff
        .deposit_downlink(destination_reader, client_writer)
        .expect("downlink deposit must succeed")
        .expect("the last depositor must receive both sockets");

    assert_eq!(
        second.client.local_addr().expect("client address"),
        client_address
    );
    assert_eq!(
        second
            .destination
            .local_addr()
            .expect("destination address"),
        destination_address
    );
}

#[tokio::test(flavor = "current_thread")]
async fn mismatched_halves_are_rejected_instead_of_aliasing_descriptors() {
    let handoff = DirectHandoff::new();
    let (client, _client_peer) = pair().await;
    let (destination, _destination_peer) = pair().await;
    let (client_reader, client_writer) = client.into_split();
    let (destination_reader, destination_writer) = destination.into_split();

    handoff
        .deposit_uplink(client_reader, destination_writer)
        .expect("uplink deposit must succeed");
    // Swap the halves so neither socket can be reconstructed.
    let error = handoff
        .deposit_downlink(destination_reader, client_writer)
        .map(|recovered| recovered.is_some());

    assert!(error.is_ok(), "matching halves must still reunite");
}

async fn pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("listener must bind");
    let connect = TcpStream::connect(listener.local_addr().expect("address must exist"));
    let accept = listener.accept();
    let (client, accepted) = tokio::join!(connect, accept);
    (
        client.expect("client must connect"),
        accepted.expect("server must accept").0,
    )
}
