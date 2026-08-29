//! Isolated, self-cleaning benchmark run workspaces.
//!
//! Every benchmark run gets one ephemeral directory that holds its generated
//! configs, helper logs and scratch payloads. The directory lives under a runtime
//! root (`$XDG_RUNTIME_DIR/rust-reality` or `/tmp/rust-reality-<uid>`), never in
//! the repository, so repeated runs cannot silently accumulate clutter in the
//! source tree — the outer-workspace exhaustion problem the scripts caused.
//!
//! A [`Workspace`] removes its directory on drop unless [`Workspace::keep`] is
//! set, which is the typed form of the legacy `KEEP_WORK=1` debugging escape.

use std::{
    net::TcpListener,
    path::{Path, PathBuf},
};

/// An ephemeral run directory, removed on drop unless kept.
#[derive(Debug)]
pub struct Workspace {
    root: PathBuf,
    keep: bool,
}

impl Workspace {
    /// Creates a uniquely named workspace for `suite` under the runtime root.
    ///
    /// # Errors
    ///
    /// Returns a message when the directory cannot be created.
    pub fn create(suite: &str) -> Result<Self, String> {
        let root = runtime_root().join(format!(
            "{suite}-{}-{}",
            std::process::id(),
            monotonic_suffix()
        ));
        std::fs::create_dir_all(&root)
            .map_err(|error| format!("could not create workspace {}: {error}", root.display()))?;
        Ok(Self { root, keep: false })
    }

    /// The workspace root directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.root
    }

    /// Joins a relative path inside the workspace.
    #[must_use]
    pub fn join(&self, relative: &str) -> PathBuf {
        self.root.join(relative)
    }

    /// Retains the directory on drop, for post-mortem debugging.
    pub const fn keep(&mut self) {
        self.keep = true;
    }

    /// Whether the directory will be retained on drop.
    #[must_use]
    pub const fn is_kept(&self) -> bool {
        self.keep
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        if self.keep {
            eprintln!("benchmark workspace retained: {}", self.root.display());
        } else {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }
}

/// The runtime root for ephemeral benchmark state.
///
/// Prefers `$XDG_RUNTIME_DIR/rust-reality`; falls back to a per-uid directory
/// under the system temp root so two users cannot collide.
#[must_use]
pub fn runtime_root() -> PathBuf {
    if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR")
        && !dir.is_empty()
    {
        return PathBuf::from(dir).join("rust-reality");
    }
    std::env::temp_dir().join(format!("rust-reality-{}", user_namespace()))
}

/// The durable cache root for pinned downloaded artifacts.
///
/// Prefers `$XDG_CACHE_HOME/rust-reality`, then `$HOME/.cache/rust-reality`.
/// Unlike the runtime root, cache contents survive a run: pinned historical
/// binaries and payloads are expensive to fetch and are content-identified.
#[must_use]
pub fn cache_root() -> PathBuf {
    if let Some(dir) = std::env::var_os("XDG_CACHE_HOME")
        && !dir.is_empty()
    {
        return PathBuf::from(dir).join("rust-reality");
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join(".cache/rust-reality");
    }
    std::env::temp_dir().join("rust-reality-cache")
}

/// Reserves `count` free loopback TCP ports by binding and immediately releasing.
///
/// The ports are returned for the caller to hand to child processes. There is an
/// unavoidable race between release and re-bind, but the benchmark host is
/// single-tenant under the host-exclusive lock, so it does not occur in practice;
/// this mirrors the legacy `rr_next_port` block allocation.
///
/// # Errors
///
/// Returns a message when the ports cannot be reserved.
pub fn reserve_ports(count: usize) -> Result<Vec<u16>, String> {
    let mut listeners = Vec::with_capacity(count);
    let mut ports = Vec::with_capacity(count);
    for _ in 0..count {
        let listener = TcpListener::bind("127.0.0.1:0")
            .map_err(|error| format!("could not reserve a loopback port: {error}"))?;
        let port = listener
            .local_addr()
            .map_err(|error| format!("could not read reserved port: {error}"))?
            .port();
        ports.push(port);
        listeners.push(listener);
    }
    // Listeners drop here, releasing the ports for the children to bind.
    drop(listeners);
    Ok(ports)
}

/// Reserves a contiguous loopback port block **above** the ephemeral range.
///
/// [`reserve_ports`] asks the kernel for arbitrary free ports, which come from
/// `ip_local_port_range` — the same pool the benchmark's own load driver draws its
/// outbound source ports from. A block allocated there can collide mid-run with a
/// socket the driver wanted, which does not fail cleanly.
///
/// So this scans upward from 61000 in the stride the harnesses used, binding every
/// port of a candidate block before accepting it. The whole block is held until
/// this returns, so a partially-free block is never reported as free.
///
/// # Errors
///
/// Returns a message when no block of `width` ports is available above the range.
pub fn reserve_block(width: usize) -> Result<u16, String> {
    /// First port considered; above the default `ip_local_port_range` ceiling.
    const FLOOR: u32 = 61_000;
    /// Stride between candidate bases, as `benchmark-setup-rate-xray.sh` used.
    const STRIDE: u32 = 37;

    if width == 0 {
        return Err("a port block needs at least one port".to_owned());
    }
    let width32 = u32::try_from(width).unwrap_or(u32::MAX);
    let mut base = FLOOR;
    while base + width32 <= 65_536 {
        let mut held = Vec::with_capacity(width);
        let mut usable = true;
        for offset in 0..width32 {
            let port = u16::try_from(base + offset).unwrap_or(u16::MAX);
            if let Ok(listener) = TcpListener::bind(("127.0.0.1", port)) {
                held.push(listener);
            } else {
                usable = false;
                break;
            }
        }
        drop(held);
        if usable {
            return Ok(u16::try_from(base).unwrap_or(u16::MAX));
        }
        base += STRIDE;
    }
    Err(format!(
        "no free loopback port block of {width} ports above {FLOOR}"
    ))
}

/// A per-user namespace component for the fallback runtime root.
///
/// Uses `$USER`, falling back to the process id, so two users on one host do not
/// collide. This avoids a `getuid` FFI call, which the crate's `unsafe_code =
/// "forbid"` policy would reject.
fn user_namespace() -> String {
    std::env::var("USER")
        .ok()
        .filter(|user| user.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'))
        .filter(|user| !user.is_empty())
        .unwrap_or_else(|| std::process::id().to_string())
}

fn monotonic_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_workspace_is_removed_on_drop() {
        let path;
        {
            let workspace = Workspace::create("test-suite").expect("workspace creates");
            path = workspace.path().to_path_buf();
            assert!(path.is_dir(), "the workspace directory must exist");
            std::fs::write(workspace.join("scratch"), b"data").unwrap();
        }
        assert!(!path.exists(), "the workspace must be removed on drop");
    }

    #[test]
    fn a_kept_workspace_survives_drop() {
        let path;
        {
            let mut workspace = Workspace::create("test-keep").expect("workspace creates");
            workspace.keep();
            assert!(workspace.is_kept());
            path = workspace.path().to_path_buf();
        }
        assert!(path.exists(), "a kept workspace must survive drop");
        std::fs::remove_dir_all(&path).unwrap();
    }

    #[test]
    fn reserved_ports_are_distinct_and_in_range() {
        let ports = reserve_ports(4).expect("ports reserve");
        assert_eq!(ports.len(), 4);
        let unique: std::collections::BTreeSet<u16> = ports.iter().copied().collect();
        assert_eq!(unique.len(), 4, "reserved ports must be distinct");
        assert!(ports.iter().all(|&port| port >= 1024));
    }

    #[test]
    fn the_runtime_root_is_outside_any_repository() {
        let root = runtime_root();
        let name = root.file_name().unwrap().to_string_lossy();
        assert!(
            name == "rust-reality" || name.starts_with("rust-reality-"),
            "runtime root must be namespaced: {}",
            root.display()
        );
    }

    /// The block must sit above the ephemeral range the load driver draws from,
    /// and must be contiguous and actually bindable.
    #[test]
    fn a_reserved_block_is_contiguous_and_above_the_ephemeral_range() {
        let base = reserve_block(8).expect("a block of eight ports is available");
        assert!(base >= 61_000, "base {base} must sit above the ephemeral range");
        assert!(u32::from(base) + 8 <= 65_536);
        // Every port in the block binds now that the probe released them.
        let held: Vec<TcpListener> = (0..8)
            .map(|offset| TcpListener::bind(("127.0.0.1", base + offset)).unwrap())
            .collect();
        assert_eq!(held.len(), 8);

        assert!(reserve_block(0).is_err());
        assert!(reserve_block(70_000).is_err());
    }
}
