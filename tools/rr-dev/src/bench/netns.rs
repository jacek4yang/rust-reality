//! The shaped cover leg: a private namespace with a measured one-way delay.
//!
//! Loopback has no latency worth speaking of, which makes it a poor place to ask
//! whether cover-connection *pooling* helps — the cost pooling removes is a real
//! round trip. So `COVER_NETEM_RTT_MS` moves only the TLS cover origin behind a
//! veth pair into its own network namespace and applies `netem delay` to the host
//! side. The proxy and the measured HTTP origin stay on loopback; exactly one leg
//! is shaped, and the report says so (`model: "one-leg-veth-netem"`).
//!
//! ## This mutates host networking, so it is fail-closed and self-verifying
//!
//! Every resource is named from the run id, so two runs cannot collide by
//! accident. Before creating anything, [`CoverLeg::create`] checks that no
//! namespace or link of that name already exists and **refuses** rather than
//! reclaiming it: a name collision means something else is using it, or a previous
//! run left state a person should look at. Nothing is ever deleted by pattern.
//!
//! Teardown runs from [`Drop`], removing the qdisc, the link and the namespace,
//! and then [`CoverLeg::verify_removed`] re-reads the host to confirm they are
//! actually gone rather than merely asked to go.

use std::path::Path;

use crate::process::Tool;

/// The host side of the veth pair.
const HOST_ADDRESS: &str = "10.204.0.1/30";

/// The namespace side, where the cover origin listens.
pub const COVER_ADDRESS: &str = "10.204.0.2";

/// The namespace-side address with its prefix.
const COVER_ADDRESS_CIDR: &str = "10.204.0.2/30";

/// Names derived from a run id, so concurrent runs cannot collide.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegNames {
    /// The network namespace, `rrc-<suffix>`.
    pub namespace: String,
    /// The host-side veth device, `rch<suffix>`.
    pub host_veth: String,
    /// The namespace-side veth device, `rcn<suffix>`.
    pub namespace_veth: String,
}

impl LegNames {
    /// Derives the names from a run id, as the script's `sha256 | cut -c1-8` did.
    #[must_use]
    pub fn for_run(run_id: &str) -> Self {
        let digest = crate::hash::sha256_hex(run_id.as_bytes());
        let suffix = &digest[..8];
        Self {
            namespace: format!("rrc-{suffix}"),
            host_veth: format!("rch{suffix}"),
            namespace_veth: format!("rcn{suffix}"),
        }
    }
}

/// A shaped cover leg, torn down on drop.
#[derive(Debug)]
pub struct CoverLeg {
    names: LegNames,
    rtt_ms: u32,
    namespace_created: bool,
    link_created: bool,
}

/// Runs one privileged `ip`/`tc` command.
fn privileged(args: &[&str]) -> Result<(), String> {
    let mut elevated = vec!["-n".to_owned()];
    // Resolve the leading tool: sudo has its own secure_path, but being explicit
    // keeps the recorded command and the executed one identical.
    elevated.push(
        args.first()
            .map_or_else(String::new, |first| iproute2(first)),
    );
    elevated.extend(args.iter().skip(1).map(|arg| (*arg).to_owned()));
    let outcome = Tool::new("sudo")
        .args(elevated)
        .probe()
        .map_err(|error| format!("could not run sudo {}: {error}", args.join(" ")))?;
    if outcome.success() {
        return Ok(());
    }
    Err(format!(
        "sudo {} exited {:?}: {}",
        args.join(" "),
        outcome.code,
        outcome.stderr.trim_end()
    ))
}

/// Resolves an iproute2 tool, which lives in `/sbin` and is often off `PATH`.
///
/// `tc` in particular is not on a normal user's `PATH` on Debian, and silently
/// skipping it would drop the qdisc line from the recorded evidence.
fn iproute2(program: &str) -> String {
    if Tool::exists(program) {
        return program.to_owned();
    }
    for directory in ["/sbin", "/usr/sbin"] {
        let candidate = Path::new(directory).join(program);
        if candidate.is_file() {
            return candidate.display().to_string();
        }
    }
    program.to_owned()
}

/// Whether a network namespace of this name already exists.
fn namespace_exists(name: &str) -> bool {
    Path::new("/var/run/netns").join(name).exists() || Path::new("/run/netns").join(name).exists()
}

/// Whether a link of this name already exists.
fn link_exists(name: &str) -> bool {
    Path::new("/sys/class/net").join(name).exists()
}

impl CoverLeg {
    #[allow(
        clippy::too_many_lines,
        reason = "canonical formatting expands it; the body is one sequence"
    )]
    /// Creates the namespace, veth pair, addresses and `netem` delay.
    ///
    /// # Errors
    ///
    /// Returns a message when a required tool is missing, a name is already taken,
    /// or any `ip`/`tc` step fails. On a partial failure the guard drops and
    /// removes whatever was created.
    pub fn create(run_id: &str, rtt_ms: u32) -> Result<Self, String> {
        for program in ["ip", "tc", "setpriv"] {
            if !Tool::exists(program) && !Path::new(&iproute2(program)).is_file() {
                return Err(format!("COVER_NETEM_RTT_MS requires {program}"));
            }
        }
        let names = LegNames::for_run(run_id);
        // Fail closed on a collision. Reclaiming a namespace or link we did not
        // create could tear down something else's networking.
        if namespace_exists(&names.namespace) {
            return Err(format!(
                "network namespace {} already exists; remove it deliberately before rerunning",
                names.namespace
            ));
        }
        for device in [&names.host_veth, &names.namespace_veth] {
            if link_exists(device) {
                return Err(format!(
                    "network device {device} already exists; remove it deliberately before rerunning"
                ));
            }
        }

        let mut leg = Self {
            names,
            rtt_ms,
            namespace_created: false,
            link_created: false,
        };
        privileged(&["ip", "netns", "add", &leg.names.namespace])?;
        leg.namespace_created = true;
        privileged(&[
            "ip",
            "link",
            "add",
            &leg.names.host_veth,
            "type",
            "veth",
            "peer",
            "name",
            &leg.names.namespace_veth,
        ])?;
        leg.link_created = true;
        privileged(&[
            "ip",
            "link",
            "set",
            &leg.names.namespace_veth,
            "netns",
            &leg.names.namespace,
        ])?;
        privileged(&[
            "ip",
            "addr",
            "add",
            HOST_ADDRESS,
            "dev",
            &leg.names.host_veth,
        ])?;
        privileged(&["ip", "link", "set", &leg.names.host_veth, "up"])?;
        privileged(&[
            "ip",
            "netns",
            "exec",
            &leg.names.namespace,
            "ip",
            "addr",
            "add",
            COVER_ADDRESS_CIDR,
            "dev",
            &leg.names.namespace_veth,
        ])?;
        privileged(&[
            "ip",
            "netns",
            "exec",
            &leg.names.namespace,
            "ip",
            "link",
            "set",
            &leg.names.namespace_veth,
            "up",
        ])?;
        privileged(&[
            "ip",
            "netns",
            "exec",
            &leg.names.namespace,
            "ip",
            "link",
            "set",
            "lo",
            "up",
        ])?;
        // Only the host side is shaped, so the delay is one-way and recorded as
        // such rather than being mistaken for a round trip.
        privileged(&[
            "tc",
            "qdisc",
            "replace",
            "dev",
            &leg.names.host_veth,
            "root",
            "netem",
            "delay",
            &format!("{rtt_ms}ms"),
        ])?;
        Ok(leg)
    }

    /// The names this leg owns.
    #[must_use]
    pub const fn names(&self) -> &LegNames {
        &self.names
    }

    /// The `setpriv` prefix that runs a command inside the namespace as this user.
    ///
    /// The origin must not run as root just because the namespace needed root to
    /// build, so its privileges are dropped back before it execs.
    ///
    /// # Errors
    ///
    /// Returns a message when the current uid/gid cannot be read.
    pub fn exec_prefix(&self) -> Result<Vec<String>, String> {
        let uid = Tool::new("id")
            .arg("-u")
            .probe()
            .map_err(|error| format!("could not read the user id: {error}"))?;
        let gid = Tool::new("id")
            .arg("-g")
            .probe()
            .map_err(|error| format!("could not read the group id: {error}"))?;
        if !uid.success() || !gid.success() {
            return Err("could not read the current user and group id".to_owned());
        }
        Ok(vec![
            "-n".to_owned(),
            "ip".to_owned(),
            "netns".to_owned(),
            "exec".to_owned(),
            self.names.namespace.clone(),
            "setpriv".to_owned(),
            "--reuid".to_owned(),
            uid.trimmed_stdout().to_owned(),
            "--regid".to_owned(),
            gid.trimmed_stdout().to_owned(),
            "--clear-groups".to_owned(),
        ])
    }

    /// Records the shaped leg's observable state as run evidence.
    ///
    /// # Errors
    ///
    /// Returns a message when the description cannot be written.
    pub fn describe(&self, cover_target: &str, path: &Path) -> Result<(), String> {
        let mut text = format!(
            "coverTarget={cover_target}\nrequestedCoverRttMs={}\n",
            self.rtt_ms
        );
        for (program, args) in [
            (
                "ip",
                vec!["-brief", "address", "show", "dev", &self.names.host_veth],
            ),
            ("tc", vec!["qdisc", "show", "dev", &self.names.host_veth]),
        ] {
            let outcome = Tool::new(iproute2(program))
                .args(args.iter().map(|arg| (*arg).to_owned()))
                .probe()
                .map_err(|error| format!("could not describe the shaped leg: {error}"))?;
            if !outcome.success() {
                return Err(format!(
                    "{program} {} exited {:?}",
                    args.join(" "),
                    outcome.code
                ));
            }
            text.push_str(outcome.trimmed_stdout());
            text.push('\n');
        }
        if let Ok(outcome) = Tool::new("ping")
            .args(["-n", "-c", "3", "-i", "0.1", "-w", "3", COVER_ADDRESS])
            .probe()
        {
            text.push_str(outcome.trimmed_stdout());
            text.push('\n');
        }
        std::fs::write(path, text)
            .map_err(|error| format!("could not write {}: {error}", path.display()))
    }

    /// Removes everything this leg created, best effort.
    fn remove(&mut self) {
        if self.link_created {
            // Deleting the host side removes the peer with it, and the qdisc with
            // the device.
            let _ = privileged(&["ip", "link", "del", &self.names.host_veth]);
            self.link_created = false;
        }
        if self.namespace_created {
            let _ = privileged(&["ip", "netns", "del", &self.names.namespace]);
            self.namespace_created = false;
        }
    }

    /// Re-reads the host and confirms nothing this leg created remains.
    ///
    /// Restoration is asserted rather than assumed: an `ip` command that reported
    /// success but left state behind would otherwise go unnoticed until the next
    /// run failed on a name collision.
    ///
    /// # Errors
    ///
    /// Returns a message naming whatever survived.
    pub fn verify_removed(names: &LegNames) -> Result<(), String> {
        let mut leftover = Vec::new();
        if namespace_exists(&names.namespace) {
            leftover.push(format!("namespace {}", names.namespace));
        }
        for device in [&names.host_veth, &names.namespace_veth] {
            if link_exists(device) {
                leftover.push(format!("device {device}"));
            }
        }
        if leftover.is_empty() {
            return Ok(());
        }
        Err(format!(
            "the shaped cover leg was not fully removed: {}",
            leftover.join(", ")
        ))
    }
}

impl Drop for CoverLeg {
    fn drop(&mut self) {
        self.remove();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_derived_from_the_run_id_and_are_stable() {
        let first = LegNames::for_run("setup-rate-1");
        let again = LegNames::for_run("setup-rate-1");
        assert_eq!(first, again, "the same run id must name the same resources");

        let other = LegNames::for_run("setup-rate-2");
        assert_ne!(first.namespace, other.namespace);
        assert_ne!(first.host_veth, other.host_veth);

        assert!(first.namespace.starts_with("rrc-"));
        assert!(first.host_veth.starts_with("rch"));
        assert!(first.namespace_veth.starts_with("rcn"));
        // Linux caps interface names at 15 characters.
        assert!(first.host_veth.len() <= 15, "{}", first.host_veth);
        assert!(first.namespace_veth.len() <= 15);
    }

    /// A name already in use means something else owns it, or a previous run left
    /// state a person should look at. Either way, reclaiming it could tear down
    /// networking this run does not own.
    #[test]
    fn an_existing_device_name_is_refused_rather_than_reclaimed() {
        // `lo` always exists, so a run id whose names collided with it would be
        // refused. Assert the predicate directly, since we cannot force a
        // collision without creating one.
        assert!(link_exists("lo"));
        assert!(!link_exists("rr-dev-definitely-not-a-device"));
        assert!(!namespace_exists("rr-dev-definitely-not-a-namespace"));
    }

    #[test]
    fn removal_verification_reports_what_survived() {
        let names = LegNames::for_run("a-run-that-never-created-anything");
        CoverLeg::verify_removed(&names).expect("nothing was created, so nothing survives");

        let colliding = LegNames {
            namespace: "rrc-none".to_owned(),
            host_veth: "lo".to_owned(),
            namespace_veth: "rcn-none".to_owned(),
        };
        let error = CoverLeg::verify_removed(&colliding).unwrap_err();
        assert!(error.contains("device lo"), "{error}");
    }
}
