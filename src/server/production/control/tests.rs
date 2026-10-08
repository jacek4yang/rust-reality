use std::{
    os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use serde_json::{Value, json};
use tokio::{
    io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader},
    net::UnixStream,
    sync::oneshot,
};

use super::{MAX_CONNECTIONS, generation_at, respond};
use crate::{
    config::{ValidatedConfig, node::fixture},
    control::protocol::MAX_REQUEST_BYTES,
    server::production::{
        ProductionServer, RuntimeUpdateError,
        fixture::{entry_config, unused_loopback_port},
        store::RuntimeStore,
    },
};

/// The user every production fixture starts with.
fn first_uuid() -> String {
    fixture::uuid(0x11)
}

fn scratch_dir(tag: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let directory = std::env::temp_dir().join(format!(
        "rr-control-{tag}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&directory).expect("scratch directory");
    directory
}

fn config_with_control(port: u16, socket: &Path) -> ValidatedConfig {
    fixture::validated(&fixture::entry_without_routing(&format!(
        r#""listeners": [{{ "port": {port}, "ip": "ipv4Only", "ipv4": "127.0.0.1" }}],
  "routing": {{ "default": "direct" }},
  "control": {{ "socket": "{}" }}"#,
        socket.display()
    )))
}

async fn call(runtime: &Arc<RuntimeStore>, request: Value) -> Value {
    call_with_path(runtime, request, None).await
}

async fn call_with_path(runtime: &Arc<RuntimeStore>, request: Value, path: Option<&Path>) -> Value {
    let work = Arc::new(tokio::sync::Semaphore::new(super::MAX_BLOCKING_WORK));
    let line = respond(request.to_string().as_bytes(), runtime, path, &work).await;
    assert_eq!(line.last(), Some(&b'\n'), "a response is one line");
    serde_json::from_slice(&line).expect("a response is JSON")
}

fn ok(response: &Value) -> &Value {
    assert_eq!(response["ok"], true, "{response}");
    &response["result"]
}

fn error_code(response: &Value) -> &str {
    assert_eq!(response["ok"], false, "{response}");
    response["error"]["code"].as_str().expect("an error code")
}

async fn first_handle(runtime: &Arc<RuntimeStore>) -> String {
    let users = call(runtime, json!({"v":1,"op":"users.list"})).await;
    ok(&users)["users"][0]["handle"]
        .as_str()
        .expect("a handle")
        .to_owned()
}

#[test]
fn reload_generation_metadata_stays_bound_to_the_published_generation() {
    let published = generation_at(7, super::GenerationOrigin::Configuration, false);
    let later = generation_at(8, super::GenerationOrigin::Control, true);

    assert_eq!(published["generation"], 7);
    assert_eq!(published["origin"], "configuration");
    assert_eq!(published["controlChanges"], false);
    assert_ne!(published, later);
}

#[tokio::test(flavor = "current_thread")]
async fn status_reports_protocol_build_role_and_capabilities() {
    let server =
        ProductionServer::from_config(entry_config(unused_loopback_port())).expect("server");
    let status = call(
        &server.runtime,
        json!({"v":1,"id":"s","op":"system.status"}),
    )
    .await;

    assert_eq!(status["id"], "s");
    assert_eq!(status["generation"], 0);
    let result = ok(&status);
    assert_eq!(result["protocol"]["version"], 1);
    assert_eq!(result["protocol"]["supported"], json!([1]));
    assert_eq!(result["server"]["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(result["role"], "entry");
    assert_eq!(result["generation"]["origin"], "startup");
    assert_eq!(result["generation"]["controlChanges"], false);
    assert_eq!(result["limits"]["maxRequestBytes"], MAX_REQUEST_BYTES);
    assert!(
        result["capabilities"]
            .as_array()
            .expect("capabilities")
            .contains(&json!("shortIds.rotate"))
    );
}

#[tokio::test(flavor = "current_thread")]
async fn a_mutation_publishes_a_new_generation_and_leaves_the_old_one_intact() {
    let server =
        ProductionServer::from_config(entry_config(unused_loopback_port())).expect("server");
    let runtime = &server.runtime;
    let in_flight = runtime.load();

    let created = call(
        runtime,
        json!({"v":1,"op":"users.create","args":{"label":"phone"},"expectedGeneration":0}),
    )
    .await;
    assert_eq!(created["generation"], 1);
    let uuid = ok(&created)["id"].as_str().expect("uuid").to_owned();

    let live = runtime.load();
    assert_eq!(live.generation, 1);
    assert_eq!(live.provenance.origin.as_str(), "control");
    assert!(live.provenance.control_changes);
    assert_eq!(live.node.as_entry().expect("entry").users.len(), 2);
    assert_eq!(
        in_flight.node.as_entry().expect("entry").users.len(),
        1,
        "a connection holding the earlier generation never observes the change"
    );

    let listed = call(runtime, json!({"v":1,"op":"users.list"})).await;
    assert!(
        !listed.to_string().contains(&uuid),
        "listings never repeat the UUID"
    );
    assert!(!listed.to_string().contains(&first_uuid()));
    assert_eq!(ok(&listed)["users"].as_array().map(Vec::len), Some(2));
}

#[tokio::test(flavor = "current_thread")]
async fn a_stale_expected_generation_changes_nothing() {
    let server =
        ProductionServer::from_config(entry_config(unused_loopback_port())).expect("server");
    let runtime = &server.runtime;
    let handle = first_handle(runtime).await;
    let before = runtime.load();

    let response = call(
        runtime,
        json!({"v":1,"op":"shortIds.add","args":{"user":handle,"shortId":"abcd"},
               "expectedGeneration":7}),
    )
    .await;
    assert_eq!(error_code(&response), "generationConflict");
    assert_eq!(response["generation"], 0);
    assert!(Arc::ptr_eq(&before, &runtime.load()));
    assert_eq!(runtime.generation.load(Ordering::Acquire), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn refused_mutations_keep_the_last_good_generation() {
    let server =
        ProductionServer::from_config(entry_config(unused_loopback_port())).expect("server");
    let runtime = &server.runtime;
    let handle = first_handle(runtime).await;
    let before = runtime.load();

    for (request, code) in [
        (
            json!({"v":1,"op":"users.setEnabled","args":{"user":handle,"enabled":false}}),
            "validationFailed",
        ),
        (
            json!({"v":1,"op":"users.delete","args":{"user":handle}}),
            "validationFailed",
        ),
        (
            json!({"v":1,"op":"users.create","args":{"id":first_uuid()}}),
            "conflict",
        ),
        (
            json!({"v":1,"op":"users.get","args":{"user":first_uuid()}}),
            "invalidArgument",
        ),
        (json!({"v":2,"op":"users.list"}), "unsupportedVersion"),
        (json!({"v":1,"op":"users.purge"}), "unknownOperation"),
    ] {
        let response = call(runtime, request.clone()).await;
        assert_eq!(error_code(&response), code, "{request}");
        assert!(
            !response.to_string().contains(&first_uuid()),
            "an error never echoes a credential: {response}"
        );
    }
    assert!(Arc::ptr_eq(&before, &runtime.load()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_controllers_never_lose_an_update() {
    let server =
        ProductionServer::from_config(entry_config(unused_loopback_port())).expect("server");
    let runtime = Arc::clone(&server.runtime);
    let handle = first_handle(&runtime).await;

    let mut tasks = Vec::new();
    for index in 0..8_u8 {
        let runtime = Arc::clone(&runtime);
        let handle = handle.clone();
        tasks.push(tokio::spawn(async move {
            call(
                &runtime,
                json!({"v":1,"op":"shortIds.add",
                       "args":{"user":handle,"shortId":format!("{index:02x}{index:02x}")}}),
            )
            .await
        }));
    }
    let mut generations = Vec::new();
    for task in tasks {
        let response = task.await.expect("task");
        ok(&response);
        generations.push(response["generation"].as_u64().expect("generation"));
    }
    generations.sort_unstable();
    assert_eq!(generations, (1..=8).collect::<Vec<_>>());
    let live = runtime.load();
    let users = &live.node.as_entry().expect("entry").users;
    assert_eq!(
        users[0].short_ids.len(),
        9,
        "every concurrent change survives: {:?}",
        users[0].short_ids
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn compare_and_publish_admits_exactly_one_racing_writer() {
    let server =
        ProductionServer::from_config(entry_config(unused_loopback_port())).expect("server");
    let runtime = Arc::clone(&server.runtime);
    let handle = first_handle(&runtime).await;

    let mut tasks = Vec::new();
    for index in 0..4_u8 {
        let runtime = Arc::clone(&runtime);
        let handle = handle.clone();
        tasks.push(tokio::spawn(async move {
            call(
                &runtime,
                json!({"v":1,"op":"shortIds.add","expectedGeneration":0,
                       "args":{"user":handle,"shortId":format!("{index:02x}{index:02x}")}}),
            )
            .await
        }));
    }
    let mut accepted = 0;
    for task in tasks {
        let response = task.await.expect("task");
        if response["ok"] == true {
            accepted += 1;
        } else {
            assert_eq!(error_code(&response), "generationConflict");
        }
    }
    assert_eq!(accepted, 1);
    assert_eq!(runtime.load().generation, 1);
}

#[tokio::test(flavor = "current_thread")]
async fn a_file_reload_replaces_control_changes_and_an_asset_refresh_keeps_them() {
    let directory = scratch_dir("reload");
    let path = directory.join("config.json");
    let port = unused_loopback_port();
    std::fs::write(&path, crate::config::canonical(&entry_config(port))).expect("write config");
    let server = ProductionServer::from_path(&path).expect("server");
    let runtime = &server.runtime;

    let created = call(runtime, json!({"v":1,"op":"users.create"})).await;
    ok(&created);

    runtime.refresh().expect("asset refresh");
    let refreshed = runtime.load();
    assert_eq!(refreshed.provenance.origin.as_str(), "assets");
    assert!(refreshed.provenance.control_changes);
    assert_eq!(refreshed.node.as_entry().expect("entry").users.len(), 2);

    let unavailable = call(runtime, json!({"v":1,"op":"config.reload"})).await;
    assert_eq!(error_code(&unavailable), "unavailable");

    let reloaded = call_with_path(runtime, json!({"v":1,"op":"config.reload"}), Some(&path)).await;
    assert_eq!(ok(&reloaded)["origin"], "configuration");
    assert_eq!(ok(&reloaded)["controlChanges"], false);
    assert_eq!(reloaded["generation"], 3);
    assert_eq!(
        runtime.load().node.as_entry().expect("entry").users.len(),
        1
    );

    std::fs::write(&path, "{").expect("write broken config");
    let rejected = call_with_path(runtime, json!({"v":1,"op":"config.reload"}), Some(&path)).await;
    assert_eq!(error_code(&rejected), "updateFailed");
    assert_eq!(runtime.load().generation, 3);
    let _ = std::fs::remove_dir_all(directory);
}

#[test]
fn the_control_socket_is_cold() {
    let directory = scratch_dir("cold");
    let port = unused_loopback_port();
    let server =
        ProductionServer::from_config(config_with_control(port, &directory.join("a.sock")))
            .expect("server");
    assert!(matches!(
        server
            .runtime
            .publish(config_with_control(port, &directory.join("b.sock")).into_node()),
        Err(RuntimeUpdateError::ControlSocketChanged)
    ));
    assert!(matches!(
        server.runtime.publish(entry_config(port).into_node()),
        Err(RuntimeUpdateError::ControlSocketChanged)
    ));
    server
        .runtime
        .publish(config_with_control(port, &directory.join("a.sock")).into_node())
        .expect("an unchanged socket is hot-compatible");
    let _ = std::fs::remove_dir_all(directory);
}

#[test]
fn binding_replaces_a_stale_socket_but_never_another_file() {
    let directory = scratch_dir("bind");
    let socket = directory.join("control.sock");
    let config = crate::config::node::control::ControlConfig {
        socket: socket.clone(),
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let first = super::bind(&config).expect("first bind");
        let metadata = std::fs::metadata(&socket).expect("socket exists");
        assert!(metadata.file_type().is_socket());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        drop(first);
        // The listener is gone but its socket file remains: a crash leftover.
        super::bind(&config).expect("a stale socket is replaced");

        let regular = directory.join("regular");
        std::fs::write(&regular, b"keep").expect("regular file");
        let refused = super::bind(&crate::config::node::control::ControlConfig {
            socket: regular.clone(),
        });
        assert!(refused.is_err());
        assert_eq!(std::fs::read(&regular).expect("untouched"), b"keep");
    });
    let _ = std::fs::remove_dir_all(directory);
}

#[test]
fn a_second_instance_cannot_take_a_live_control_socket() {
    let directory = scratch_dir("exclusive");
    let socket = directory.join("control.sock");
    let config = crate::config::node::control::ControlConfig {
        socket: socket.clone(),
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let first = super::bind(&config).expect("first instance binds");
        let identity = std::fs::symlink_metadata(&socket).expect("socket").ino();

        // A second instance configured with the same path (different data
        // ports) must fail without unlinking or rebinding the live socket.
        let second = super::bind(&config).err().expect("the path is owned");
        assert_eq!(second.kind(), std::io::ErrorKind::WouldBlock);
        assert_eq!(
            std::fs::symlink_metadata(&socket)
                .expect("still there")
                .ino(),
            identity,
            "the live socket must not be replaced"
        );
        UnixStream::connect(&socket)
            .await
            .expect("the first instance still accepts");

        // The first instance's cleanup removes exactly its own socket, after
        // which a new instance may bind.
        first.remove_if_owned();
        drop(first);
        assert!(!socket.exists());
        let third = super::bind(&config).expect("a released path can be bound");
        third.remove_if_owned();
    });
    let _ = std::fs::remove_dir_all(directory);
}

#[test]
fn cleanup_never_removes_a_path_that_no_longer_names_our_socket() {
    let directory = scratch_dir("replaced");
    let socket = directory.join("control.sock");
    let config = crate::config::node::control::ControlConfig {
        socket: socket.clone(),
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let endpoint = super::bind(&config).expect("bind");
        // Someone replaces the path while we run (an operator, or a process
        // that ignores the lock). Our cleanup must leave their file alone.
        std::fs::remove_file(&socket).expect("unlink");
        std::fs::write(&socket, b"theirs").expect("replacement");
        endpoint.remove_if_owned();
        assert_eq!(std::fs::read(&socket).expect("kept"), b"theirs");
    });
    let _ = std::fs::remove_dir_all(directory);
}

#[tokio::test(flavor = "current_thread")]
async fn listings_are_paged_within_one_generation() {
    let server =
        ProductionServer::from_config(entry_config(unused_loopback_port())).expect("server");
    let runtime = &server.runtime;
    for label in ["a", "b", "c", "d"] {
        ok(&call(
            runtime,
            json!({"v":1,"op":"users.create","args":{"label":label}}),
        )
        .await);
    }
    let generation = runtime.load().generation;

    let mut seen = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let mut args = json!({"limit": 2});
        if let Some(cursor) = &cursor {
            args["cursor"] = json!(cursor);
        }
        let page = call(runtime, json!({"v":1,"op":"users.list","args":args})).await;
        assert_eq!(page["generation"], generation);
        let result = ok(&page);
        assert_eq!(result["total"], 5);
        let users = result["users"].as_array().expect("users");
        assert!(users.len() <= 2);
        assert!(users.iter().all(|user| user.get("shortIds").is_none()));
        seen.extend(users.iter().map(|user| user["handle"].clone()));
        match result.get("nextCursor") {
            Some(next) => cursor = Some(next.as_str().expect("cursor").to_owned()),
            None => break,
        }
    }
    assert_eq!(seen.len(), 5);

    // A cursor from a replaced generation is refused, never stitched.
    let stale = call(runtime, json!({"v":1,"op":"users.list","args":{"limit":1}})).await;
    let stale = ok(&stale)["nextCursor"]
        .as_str()
        .expect("cursor")
        .to_owned();
    ok(&call(runtime, json!({"v":1,"op":"users.create","args":{}})).await);
    let expired = call(
        runtime,
        json!({"v":1,"op":"users.list","args":{"cursor":stale}}),
    )
    .await;
    assert_eq!(error_code(&expired), "cursorExpired");

    for args in [
        json!({"limit":0}),
        json!({"limit":1001}),
        json!({"cursor":"x"}),
    ] {
        let refused = call(runtime, json!({"v":1,"op":"users.list","args":args})).await;
        assert_eq!(error_code(&refused), "invalidArgument");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn a_mutation_that_changes_nothing_reports_it_and_keeps_the_generation() {
    let server =
        ProductionServer::from_config(entry_config(unused_loopback_port())).expect("server");
    let runtime = &server.runtime;
    let handle = first_handle(runtime).await;
    let before = runtime.load();
    let unchanged = call(
        runtime,
        json!({"v":1,"op":"users.setEnabled","args":{"user":handle,"enabled":true},
               "expectedGeneration":0}),
    )
    .await;
    assert_eq!(unchanged["generation"], 0);
    assert_eq!(ok(&unchanged)["changed"], false);
    assert!(Arc::ptr_eq(&before, &runtime.load()));

    let created = call(runtime, json!({"v":1,"op":"users.create","args":{}})).await;
    assert_eq!(ok(&created)["changed"], true);
    let changed = call(
        runtime,
        json!({"v":1,"op":"users.setEnabled","args":{"user":handle,"enabled":false}}),
    )
    .await;
    assert_eq!(changed["generation"], 2);
    assert_eq!(ok(&changed)["changed"], true);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_socket_serves_bounded_lines_and_is_removed_at_shutdown() {
    let directory = scratch_dir("serve");
    let socket = directory.join("control.sock");
    let server =
        ProductionServer::from_config(config_with_control(unused_loopback_port(), &socket))
            .expect("server");
    let (stop, stopped) = oneshot::channel::<()>();
    let task = tokio::spawn(server.run_until(async move {
        let _ = stopped.await;
        Ok(())
    }));

    let mut stream = None;
    for _ in 0..200 {
        if let Ok(connected) = UnixStream::connect(&socket).await {
            stream = Some(connected);
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let stream = stream.expect("the control socket accepts");
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    // Two requests on one connection, the second with CRLF framing.
    writer
        .write_all(b"{\"v\":1,\"id\":\"a\",\"op\":\"generation.get\"}\n\n{\"v\":1,\"id\":\"b\",\"op\":\"users.list\"}\r\n")
        .await
        .expect("write");
    let mut line = String::new();
    reader.read_line(&mut line).await.expect("read");
    let first: Value = serde_json::from_str(&line).expect("json");
    assert_eq!(first["id"], "a");
    assert_eq!(first["result"]["generation"], 0);
    line.clear();
    reader.read_line(&mut line).await.expect("read");
    let second: Value = serde_json::from_str(&line).expect("json");
    assert_eq!(second["id"], "b");
    assert_eq!(second["ok"], true);

    // An oversized line is answered once and the connection is closed.
    writer
        .write_all(&vec![b'x'; MAX_REQUEST_BYTES + 2])
        .await
        .expect("write oversized");
    line.clear();
    reader.read_line(&mut line).await.expect("read");
    let too_large: Value = serde_json::from_str(&line).expect("json");
    assert_eq!(too_large["error"]["code"], "requestTooLarge");
    line.clear();
    assert_eq!(reader.read_line(&mut line).await.expect("eof"), 0);

    // Fill every slot; the next connection is told it is busy.
    let mut held = Vec::new();
    for _ in 0..MAX_CONNECTIONS {
        let mut slot = UnixStream::connect(&socket).await.expect("slot");
        // Prove the slot is admitted before opening the next one.
        slot.write_all(b"{\"v\":1,\"op\":\"generation.get\"}\n")
            .await
            .expect("write");
        let mut slot = BufReader::new(slot);
        let mut admitted = String::new();
        slot.read_line(&mut admitted).await.expect("admitted");
        held.push(slot);
    }
    let busy = UnixStream::connect(&socket).await.expect("connect");
    let mut busy = BufReader::new(busy);
    line.clear();
    busy.read_line(&mut line).await.expect("busy line");
    let refused: Value = serde_json::from_str(&line).expect("json");
    assert_eq!(refused["error"]["code"], "busy");
    drop(held);

    let _ = stop.send(());
    task.await.expect("task").expect("clean shutdown");
    assert!(!socket.exists(), "the socket is removed at shutdown");
    let _ = std::fs::remove_dir_all(directory);
}
