//! Serving the local control protocol.
//!
//! One Unix domain socket, created at startup with owner-only permissions,
//! accepting at most [`MAX_CONNECTIONS`] concurrent local clients. Each
//! connection reads one bounded request line at a time and writes exactly one
//! response line for it. There is no TCP listener and no way to configure
//! one.
//!
//! Reads are answered from the generation that is current when the request
//! arrives. Mutations run as one store transaction on the blocking pool: the
//! candidate is derived from the generation current *under the update lock*,
//! validated like a configuration file, compiled, and atomically published —
//! the same path `SIGHUP` takes, so the data plane cannot tell the two
//! apart. Nothing here runs on, or shares a lock with, an accept, handshake,
//! record, or relay path; the only shared state is the store's existing
//! update mutex.
//!
//! Work is bounded independently of connections: reads and mutations both
//! run on the blocking pool behind [`MAX_BLOCKING_WORK`] permits, listings
//! are paged, and a request's work never runs on a Tokio worker thread.
//!
//! The socket is owned, not merely named: a lock file beside it
//! (`<socket>.lock`, held with `flock` for the process lifetime) excludes a
//! second instance configured with the same path, and shutdown unlinks the
//! path only while it still refers to the socket this process bound.

use std::{
    fs::{File, OpenOptions},
    io,
    os::unix::fs::{FileTypeExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use serde_json::{Value, json};
use tokio::{
    io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader},
    net::{UnixListener, UnixStream},
    sync::{Semaphore, watch},
    task::JoinSet,
    time::{self, Instant},
};

use crate::{
    config::{EntryConfig, node::control::ControlConfig},
    control::{
        ControlError, ErrorCode, HandleIndex, Operation, Request, UserHandles, decode_request,
        mutation,
        protocol::{
            self, MAX_PAGE_BYTES, MAX_PAGE_LIMIT, MAX_REQUEST_BYTES, MAX_REQUEST_ID_BYTES,
            OPERATIONS, PROTOCOL_VERSION, SUPPORTED_VERSIONS,
        },
    },
    logging::LogEvent,
};

use super::{
    error::RuntimeUpdateError,
    event::emit,
    snapshot::{GenerationOrigin, RuntimeSnapshot},
    store::RuntimeStore,
};

/// Most concurrent control connections. Controllers are a handful of local
/// programs; the bound keeps a misbehaving one from occupying the blocking
/// pool or the update lock queue.
pub(super) const MAX_CONNECTIONS: usize = 8;

/// How long an open connection may wait between requests.
pub(super) const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// How long writing one response may stall.
pub(super) const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// Most control requests doing work on the blocking pool at once, across
/// every connection. A read indexes or pages the live generation and a
/// mutation compiles one; the bound keeps eight busy controllers from
/// occupying eight blocking threads or eight copies of a large configuration.
pub(super) const MAX_BLOCKING_WORK: usize = 2;

/// Longest human-oriented error message sent back. A configuration
/// diagnostic for a rejected file reload can be long; the journal keeps the
/// full text.
const MAX_ERROR_MESSAGE_BYTES: usize = 4 * 1024;

/// Least time between two refusal events, so a local client looping on
/// connect cannot flood the log.
const REFUSAL_LOG_INTERVAL: Duration = Duration::from_secs(60);

/// A bound control socket and the identity allowed to use it.
pub(super) struct ControlEndpoint {
    listener: UnixListener,
    path: PathBuf,
    owner_uid: u32,
    /// The bound socket's inode identity, so cleanup removes only it.
    identity: (u64, u64),
    /// Held for the endpoint's lifetime; its `flock` is the instance lock.
    _lock: File,
}

/// The lock file guarding `socket`: the same path with `.lock` appended.
pub(super) fn lock_path(socket: &Path) -> PathBuf {
    let mut path = socket.as_os_str().to_owned();
    path.push(".lock");
    PathBuf::from(path)
}

/// Creates the control socket.
///
/// The instance lock is taken first: `<socket>.lock` is opened (created
/// owner-only when absent, never truncated or removed) and locked with a
/// non-blocking exclusive `flock`. A lock held by another process means a
/// live instance owns the path, and startup fails without touching it.
/// Holding the lock, a *socket* found at the path can only be stale — no
/// lock-holding instance exists to have bound it — so removing it races
/// nothing; any other kind of file is refused rather than replaced. The
/// socket is made owner-only before the first accept, and the owning uid is
/// recorded so each connection's peer credentials can be checked against it.
///
/// # Errors
///
/// Returns `WouldBlock` when another instance holds the lock, or the I/O
/// error that prevented creating or securing the socket.
pub(super) fn bind(config: &ControlConfig) -> io::Result<ControlEndpoint> {
    let path = config.socket().to_path_buf();
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(lock_path(&path))?;
    match lock.try_lock() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "another process holds the control socket lock",
            ));
        }
        Err(std::fs::TryLockError::Error(error)) => return Err(error),
    }
    match std::fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_socket() => std::fs::remove_file(&path)?,
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "the control socket path exists and is not a socket",
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let listener = UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    let metadata = std::fs::symlink_metadata(&path)?;
    Ok(ControlEndpoint {
        listener,
        path,
        owner_uid: metadata.uid(),
        identity: (metadata.dev(), metadata.ino()),
        _lock: lock,
    })
}

impl ControlEndpoint {
    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    /// Unlinks the socket path, but only while it is still the socket this
    /// endpoint bound. Runs while the instance lock is held, so no compliant
    /// instance can have rebound the path; a file an operator put there
    /// instead is left alone.
    fn remove_if_owned(&self) {
        if std::fs::symlink_metadata(&self.path)
            .is_ok_and(|metadata| (metadata.dev(), metadata.ino()) == self.identity)
        {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Serves the control socket until shutdown, then removes it.
pub(super) async fn run(
    endpoint: ControlEndpoint,
    runtime: Arc<RuntimeStore>,
    config_path: Option<PathBuf>,
    mut shutdown: watch::Receiver<bool>,
) {
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let work = Arc::new(Semaphore::new(MAX_BLOCKING_WORK));
    let config_path = config_path.map(Arc::<Path>::from);
    let mut connections = JoinSet::new();
    let mut last_refusal: Option<Instant> = None;
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            // Reap finished connection tasks so the set stays bounded.
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
            accepted = endpoint.listener.accept() => {
                let Ok((stream, _)) = accepted else {
                    // Accept failures on a local socket are transient
                    // (descriptor pressure); back off briefly and continue.
                    time::sleep(Duration::from_millis(50)).await;
                    continue;
                };
                let refusal = if !peer_allowed(&stream, endpoint.owner_uid) {
                    Some(("peerCredentials", None))
                } else {
                    match Arc::clone(&slots).try_acquire_owned() {
                        Ok(permit) => {
                            let runtime = Arc::clone(&runtime);
                            let config_path = config_path.clone();
                            let work = Arc::clone(&work);
                            connections.spawn(async move {
                                serve_connection(stream, &runtime, config_path.as_deref(), &work)
                                    .await;
                                drop(permit);
                            });
                            None
                        }
                        Err(_) => Some(("capacity", Some(stream))),
                    }
                };
                if let Some((reason, stream)) = refusal {
                    let now = Instant::now();
                    if last_refusal.is_none_or(|last| now.duration_since(last) >= REFUSAL_LOG_INTERVAL) {
                        last_refusal = Some(now);
                        emit(
                            &runtime.load().logger,
                            &LogEvent::ControlConnectionRefused { reason },
                        );
                    }
                    if let Some(mut stream) = stream {
                        let line = protocol::encode_error(
                            None,
                            Some(runtime.load().generation),
                            ErrorCode::Busy,
                            "the control endpoint is at its connection limit",
                            None,
                        );
                        let _ = time::timeout(WRITE_TIMEOUT, stream.write_all(&line)).await;
                    }
                }
            }
        }
    }
    // Aborting a connection cancels its async waiter only. A request already
    // running on the blocking pool finishes there; it cannot publish, because
    // the supervisor closed the store's commit boundary before signalling
    // shutdown, and it activates pools only through that same boundary.
    connections.abort_all();
    endpoint.remove_if_owned();
}

/// The socket is owner-only already; this is the second gate. Only the uid
/// that owns the socket, or root, may speak to it.
fn peer_allowed(stream: &UnixStream, owner_uid: u32) -> bool {
    stream
        .peer_cred()
        .is_ok_and(|credentials| credentials.uid() == owner_uid || credentials.uid() == 0)
}

async fn serve_connection(
    stream: UnixStream,
    runtime: &Arc<RuntimeStore>,
    config_path: Option<&Path>,
    work: &Arc<Semaphore>,
) {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = Vec::new();
    loop {
        line.clear();
        let limit = u64::try_from(MAX_REQUEST_BYTES)
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        let read = time::timeout(
            IDLE_TIMEOUT,
            (&mut reader).take(limit).read_until(b'\n', &mut line),
        )
        .await;
        let response = match read {
            Err(_) | Ok(Err(_)) | Ok(Ok(0)) => return,
            Ok(Ok(_)) => {
                if line.last() == Some(&b'\n') {
                    line.pop();
                } else if line.len() > MAX_REQUEST_BYTES {
                    let response = protocol::encode_error(
                        None,
                        Some(runtime.load().generation),
                        ErrorCode::RequestTooLarge,
                        &format!("a request must not exceed {MAX_REQUEST_BYTES} bytes"),
                        None,
                    );
                    // The rest of the oversized line is unread; the stream
                    // can no longer be framed, so answer and close.
                    let _ = time::timeout(WRITE_TIMEOUT, writer.write_all(&response)).await;
                    return;
                }
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                if line.iter().all(u8::is_ascii_whitespace) {
                    continue;
                }
                respond(&line, runtime, config_path, work).await
            }
        };
        match time::timeout(WRITE_TIMEOUT, writer.write_all(&response)).await {
            Ok(Ok(())) => {}
            Err(_) | Ok(Err(_)) => return,
        }
    }
}

/// Answers one request line with one response line.
pub(super) async fn respond(
    line: &[u8],
    runtime: &Arc<RuntimeStore>,
    config_path: Option<&Path>,
    work: &Arc<Semaphore>,
) -> Vec<u8> {
    let request = match decode_request(line) {
        Ok(request) => request,
        Err(error) => {
            return protocol::encode_error(
                error.id.as_deref(),
                Some(runtime.load().generation),
                error.code,
                &error.message,
                None,
            );
        }
    };
    let id = request.id.clone();
    match execute(request, runtime, config_path, work).await {
        Ok((generation, result)) => protocol::encode_success(id.as_deref(), generation, &result),
        Err(error) => protocol::encode_error(
            id.as_deref(),
            Some(runtime.load().generation),
            error.code,
            bounded(&error.message),
            error.path.as_deref(),
        ),
    }
}

fn bounded(message: &str) -> &str {
    if message.len() <= MAX_ERROR_MESSAGE_BYTES {
        return message;
    }
    let mut end = MAX_ERROR_MESSAGE_BYTES;
    while !message.is_char_boundary(end) {
        end -= 1;
    }
    &message[..end]
}

async fn execute(
    request: Request,
    runtime: &Arc<RuntimeStore>,
    config_path: Option<&Path>,
    work: &Arc<Semaphore>,
) -> Result<(u64, Value), ControlError> {
    let Request {
        operation,
        expected_generation,
        ..
    } = request;
    match &operation {
        Operation::SystemStatus => {
            let snapshot = runtime.load();
            return Ok((snapshot.generation, status(&snapshot)));
        }
        Operation::GenerationGet => {
            let snapshot = runtime.load();
            return Ok((snapshot.generation, generation(&snapshot)));
        }
        _ => {}
    }
    // Everything else does work proportional to the configuration: run it on
    // the blocking pool, at most `MAX_BLOCKING_WORK` requests at a time.
    let permit = Arc::clone(work)
        .acquire_owned()
        .await
        .map_err(|_| ControlError::new(ErrorCode::Internal, "the control work queue closed"))?;
    let store = Arc::clone(runtime);
    let config_path = config_path.map(Path::to_path_buf);
    tokio::task::spawn_blocking(move || {
        let result = execute_blocking(
            &store,
            config_path.as_deref(),
            operation,
            expected_generation,
        );
        drop(permit);
        result
    })
    .await
    .map_err(|_| ControlError::new(ErrorCode::Internal, "the control task failed"))?
}

/// Runs one request on the blocking pool.
///
/// Everything that must follow a publication — pool activation and the
/// change event — happens here, on the thread that published, so a waiter
/// cancelled by shutdown cannot leave a published generation without its
/// pools. Activation goes through the store's commit boundary and is a no-op
/// once the store has closed.
fn execute_blocking(
    store: &RuntimeStore,
    config_path: Option<&Path>,
    operation: Operation,
    expected_generation: Option<u64>,
) -> Result<(u64, Value), ControlError> {
    match &operation {
        Operation::ConfigReload => {
            let path = config_path.ok_or_else(|| {
                ControlError::new(
                    ErrorCode::Unavailable,
                    "this process was not started from a configuration file",
                )
            })?;
            let published = store.reload_path(path).map_err(update_error)?;
            store.activate_current();
            Ok((
                published,
                generation_at(published, GenerationOrigin::Configuration, false),
            ))
        }
        Operation::UsersList(_) | Operation::UsersGet(_) | Operation::ShortIdsList(_) => {
            let snapshot = store.load();
            let entry = entry_config(&snapshot)?;
            let index = snapshot
                .handle_index
                .get_or_init(|| {
                    UserHandles::from_entry(entry)
                        .and_then(|handles| HandleIndex::build(entry, &handles))
                        .map(Arc::new)
                })
                .clone()
                .ok_or_else(|| {
                    ControlError::new(ErrorCode::Internal, "the user handle key cannot be derived")
                })?;
            Ok((
                snapshot.generation,
                mutation::read(entry, &index, snapshot.generation, &operation)?,
            ))
        }
        _ => {
            let name = operation.name();
            let (published, mut result) = store.publish_derived(
                GenerationOrigin::Control,
                expected_generation,
                |current| -> Result<_, ControlError> {
                    let (entry, handles) = entry_of(current)?;
                    let outcome = mutation::mutate(entry, &handles, &operation)?;
                    Ok((outcome.config.into_node(), outcome.result))
                },
            )?;
            if let Value::Object(fields) = &mut result {
                fields.insert("changed".to_owned(), Value::Bool(published.changed));
            }
            if published.changed {
                store.activate_current();
                emit(
                    &store.load().logger,
                    &LogEvent::ControlChangePublished {
                        operation: name,
                        generation: published.generation,
                    },
                );
            }
            Ok((published.generation, result))
        }
    }
}

fn entry_config(snapshot: &RuntimeSnapshot) -> Result<&EntryConfig, ControlError> {
    snapshot.node.as_entry().ok_or_else(|| {
        ControlError::new(
            ErrorCode::Unavailable,
            "users and short IDs exist only on an entry node",
        )
    })
}

fn entry_of(snapshot: &RuntimeSnapshot) -> Result<(&EntryConfig, UserHandles), ControlError> {
    let entry = entry_config(snapshot)?;
    let handles = UserHandles::from_entry(entry).ok_or_else(|| {
        ControlError::new(ErrorCode::Internal, "the user handle key cannot be derived")
    })?;
    Ok((entry, handles))
}

fn status(snapshot: &RuntimeSnapshot) -> Value {
    json!({
        "server": {
            "name": "rust-reality",
            "version": env!("CARGO_PKG_VERSION"),
            "commit": crate::BUILD_COMMIT,
        },
        "protocol": {
            "version": PROTOCOL_VERSION,
            "supported": SUPPORTED_VERSIONS,
        },
        "role": snapshot.node.role().as_str(),
        "generation": generation(snapshot),
        "capabilities": OPERATIONS,
        "limits": {
            "maxRequestBytes": MAX_REQUEST_BYTES,
            "maxRequestIdBytes": MAX_REQUEST_ID_BYTES,
            "maxConnections": MAX_CONNECTIONS,
            "maxConcurrentWork": MAX_BLOCKING_WORK,
            "maxPageLimit": MAX_PAGE_LIMIT,
            "maxPageBytes": MAX_PAGE_BYTES,
            "idleTimeoutMs": IDLE_TIMEOUT.as_millis(),
        },
    })
}

fn generation(snapshot: &RuntimeSnapshot) -> Value {
    generation_at(
        snapshot.generation,
        snapshot.provenance.origin,
        snapshot.provenance.control_changes,
    )
}

fn generation_at(generation: u64, origin: GenerationOrigin, control_changes: bool) -> Value {
    json!({
        "generation": generation,
        "origin": origin.as_str(),
        "controlChanges": control_changes,
    })
}

impl From<RuntimeUpdateError> for ControlError {
    fn from(error: RuntimeUpdateError) -> Self {
        update_error(error)
    }
}

fn update_error(error: RuntimeUpdateError) -> ControlError {
    let code = match &error {
        RuntimeUpdateError::GenerationConflict { .. } => ErrorCode::GenerationConflict,
        RuntimeUpdateError::Unavailable => ErrorCode::Internal,
        RuntimeUpdateError::ShuttingDown => ErrorCode::Unavailable,
        _ => ErrorCode::UpdateFailed,
    };
    ControlError::new(code, error.to_string())
}

#[cfg(test)]
mod measure;
#[cfg(test)]
mod tests;
