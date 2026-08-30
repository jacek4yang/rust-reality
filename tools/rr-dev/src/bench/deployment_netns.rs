//! Owned one-leg network namespace for deployment RTT characterization.
//!
//! Only the LINE-to-peer leg crosses this veth pair. Both directions carry half
//! the requested delay and the requested per-direction loss, so the benchmark
//! can compare warm and cold transport acquisition without shaping the client,
//! REALITY cover, or peer-to-origin legs.

use std::{
    os::unix::fs::MetadataExt as _,
    path::Path,
    time::Duration,
};

use crate::process::Tool;

const HOST_ADDRESS: &str = "10.203.0.1/30";
const PEER_ADDRESS_CIDR: &str = "10.203.0.2/30";

/// Address used by host-side LINE processes to reach namespace peers.
pub const PEER_ADDRESS: &str = "10.203.0.2";

/// Exact names of every privileged object owned by one run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Names {
    /// Network namespace.
    pub namespace: String,
    /// Host side of the veth pair.
    pub host_veth: String,
    /// Namespace side of the veth pair.
    pub namespace_veth: String,
}

impl Names {
    /// Derives Linux-safe, stable names from a run ID.
    #[must_use]
    pub fn for_run(run_id: &str) -> Self {
        let digest = crate::hash::sha256_hex(run_id.as_bytes());
        let suffix = &digest[..8];
        Self {
            namespace: format!("rrd-{suffix}"),
            host_veth: format!("rdh{suffix}"),
            namespace_veth: format!("rdn{suffix}"),
        }
    }
}

/// Collision-checked namespace and veth pair, removed by exact identity.
#[derive(Debug)]
pub struct Topology {
    names: Names,
    namespace_identity: Option<(u64, u64)>,
    host_ifindex: Option<u32>,
    namespace_created: bool,
    link_created: bool,
    shaped: bool,
}

impl Topology {
    /// Creates the namespace, veth pair, addresses, and loopback state.
    #[expect(
        clippy::too_many_lines,
        reason = "partial privileged creation remains contiguous with its exact cleanup state"
    )]
    pub fn create(run_id: &str) -> Result<Self, String> {
        for program in ["ip", "tc", "setpriv", "ping"] {
            if !Tool::exists(program) && !Path::new(&iproute2(program)).is_file() {
                return Err(format!("deployment RTT characterization requires {program}"));
            }
        }
        if !super::ipv6_netns::sudo_available() {
            return Err("deployment RTT characterization requires passwordless sudo".to_owned());
        }
        let names = Names::for_run(run_id);
        if namespace_exists(&names.namespace) {
            return Err(format!(
                "owned namespace {} already exists; inspect it before rerunning",
                names.namespace
            ));
        }
        for link in [&names.host_veth, &names.namespace_veth] {
            if link_exists(link) {
                return Err(format!(
                    "owned network link {link} already exists; inspect it before rerunning"
                ));
            }
        }
        let mut topology = Self {
            names,
            namespace_identity: None,
            host_ifindex: None,
            namespace_created: false,
            link_created: false,
            shaped: false,
        };
        let creation = (|| {
            sudo(
                "ip",
                &["netns".to_owned(), "add".to_owned(), topology.names.namespace.clone()],
            )?;
            topology.namespace_created = true;
            topology.namespace_identity = namespace_identity(&topology.names.namespace);
            if topology.namespace_identity.is_none() {
                return Err("could not capture the owned namespace identity".to_owned());
            }
            sudo(
                "ip",
                &[
                    "link".to_owned(),
                    "add".to_owned(),
                    topology.names.host_veth.clone(),
                    "type".to_owned(),
                    "veth".to_owned(),
                    "peer".to_owned(),
                    "name".to_owned(),
                    topology.names.namespace_veth.clone(),
                ],
            )?;
            topology.link_created = true;
            topology.host_ifindex = link_ifindex(&topology.names.host_veth);
            if topology.host_ifindex.is_none() {
                return Err("could not capture the owned veth identity".to_owned());
            }
            sudo(
                "ip",
                &[
                    "link".to_owned(),
                    "set".to_owned(),
                    topology.names.namespace_veth.clone(),
                    "netns".to_owned(),
                    topology.names.namespace.clone(),
                ],
            )?;
            sudo(
                "ip",
                &[
                    "addr".to_owned(),
                    "add".to_owned(),
                    HOST_ADDRESS.to_owned(),
                    "dev".to_owned(),
                    topology.names.host_veth.clone(),
                ],
            )?;
            sudo(
                "ip",
                &[
                    "link".to_owned(),
                    "set".to_owned(),
                    topology.names.host_veth.clone(),
                    "up".to_owned(),
                ],
            )?;
            for args in [
                vec![
                    "addr".to_owned(),
                    "add".to_owned(),
                    PEER_ADDRESS_CIDR.to_owned(),
                    "dev".to_owned(),
                    topology.names.namespace_veth.clone(),
                ],
                vec![
                    "link".to_owned(),
                    "set".to_owned(),
                    topology.names.namespace_veth.clone(),
                    "up".to_owned(),
                ],
                vec!["link".to_owned(), "set".to_owned(), "lo".to_owned(), "up".to_owned()],
            ] {
                ip_in(&topology.names.namespace, &args)?;
            }
            Ok(())
        })();
        if let Err(error) = creation {
            let cleanup = topology.remove();
            return Err(match cleanup {
                Ok(()) => error,
                Err(cleanup) => format!("{error}; safety cleanup failed: {cleanup}"),
            });
        }
        Ok(topology)
    }

    /// Exact resource names owned by this topology.
    #[must_use]
    pub const fn names(&self) -> &Names {
        &self.names
    }

    /// Namespace name used for child process placement.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.names.namespace
    }

    /// Replaces the qdisc on both directions with half-delay plus loss.
    pub fn apply_profile(&mut self, rtt_ms: u32, loss_percent: f64) -> Result<(), String> {
        if !loss_percent.is_finite() || !(0.0..=100.0).contains(&loss_percent) {
            return Err(format!("invalid per-direction loss percentage: {loss_percent}"));
        }
        let delay = format!("{:.3}ms", f64::from(rtt_ms) / 2.0);
        let loss = format!("{loss_percent}%");
        sudo(
            "tc",
            &[
                "qdisc".to_owned(),
                "replace".to_owned(),
                "dev".to_owned(),
                self.names.host_veth.clone(),
                "root".to_owned(),
                "netem".to_owned(),
                "delay".to_owned(),
                delay.clone(),
                "loss".to_owned(),
                loss.clone(),
            ],
        )?;
        command_in(
            &self.names.namespace,
            "tc",
            &[
                "qdisc".to_owned(),
                "replace".to_owned(),
                "dev".to_owned(),
                self.names.namespace_veth.clone(),
                "root".to_owned(),
                "netem".to_owned(),
                "delay".to_owned(),
                delay,
                "loss".to_owned(),
                loss,
            ],
        )?;
        self.shaped = true;
        Ok(())
    }

    /// Measures the shaped veth RTT using five bounded ICMP samples.
    pub fn observed_rtt_ms(&self) -> Result<f64, String> {
        if !self.shaped {
            return Err("deployment RTT cannot be measured before applying a profile".to_owned());
        }
        let outcome = Tool::new("ping")
            .args(["-n", "-c", "5", "-i", "0.2", "-w", "8", PEER_ADDRESS])
            .probe()
            .map_err(|error| format!("could not measure deployment RTT: {error}"))?;
        if !outcome.success() {
            return Err(format!(
                "deployment RTT ping exited {:?}: {}",
                outcome.code,
                outcome.stderr.trim_end()
            ));
        }
        outcome
            .stdout
            .lines()
            .find(|line| line.starts_with("rtt ") || line.starts_with("round-trip "))
            .and_then(|line| line.split_once(" = ").map(|(_, values)| values))
            .and_then(|values| values.split('/').nth(1))
            .and_then(|average| average.parse::<f64>().ok())
            .filter(|average| average.is_finite() && *average > 0.0)
            .ok_or_else(|| "deployment RTT ping did not publish a positive average".to_owned())
    }

    /// Captures exact link and qdisc state for the evidence bundle.
    pub fn describe(&self) -> Result<String, String> {
        let mut output = format!(
            "namespace={}\nhostVeth={}\nnamespaceVeth={}\n",
            self.names.namespace, self.names.host_veth, self.names.namespace_veth
        );
        for (program, args) in [
            (
                "ip",
                vec!["-details", "link", "show", "dev", &self.names.host_veth],
            ),
            (
                "tc",
                vec!["qdisc", "show", "dev", &self.names.host_veth],
            ),
        ] {
            let outcome = Tool::new(iproute2(program))
                .args(args.iter().map(|value| (*value).to_owned()))
                .probe()
                .map_err(|error| format!("could not describe deployment netem: {error}"))?;
            if !outcome.success() {
                return Err(format!("{program} description failed: {}", outcome.stderr));
            }
            output.push_str(outcome.trimmed_stdout());
            output.push('\n');
        }
        let namespace_qdisc = command_in(
            &self.names.namespace,
            "tc",
            &[
                "qdisc".to_owned(),
                "show".to_owned(),
                "dev".to_owned(),
                self.names.namespace_veth.clone(),
            ],
        )?;
        output.push_str(&namespace_qdisc);
        Ok(output)
    }

    /// Explicitly removes the topology and verifies absence.
    pub fn teardown(&mut self) -> Result<(), String> {
        self.remove()?;
        Self::verify_removed(&self.names)
    }

    /// Confirms every exact owned object is absent.
    pub fn verify_removed(names: &Names) -> Result<(), String> {
        let mut leftovers = Vec::new();
        if namespace_exists(&names.namespace) {
            leftovers.push(format!("namespace {}", names.namespace));
        }
        for link in [&names.host_veth, &names.namespace_veth] {
            if link_exists(link) {
                leftovers.push(format!("link {link}"));
            }
        }
        if leftovers.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "owned deployment netem topology survived teardown: {}",
                leftovers.join(", ")
            ))
        }
    }

    fn remove(&mut self) -> Result<(), String> {
        let mut errors = Vec::new();
        if self.link_created {
            if link_ifindex(&self.names.host_veth) == self.host_ifindex {
                if let Err(error) = sudo(
                    "ip",
                    &["link".to_owned(), "del".to_owned(), self.names.host_veth.clone()],
                ) {
                    errors.push(error);
                } else {
                    self.link_created = false;
                    self.shaped = false;
                }
            } else if link_exists(&self.names.host_veth) {
                errors.push(format!(
                    "refusing to remove {} because its ifindex changed",
                    self.names.host_veth
                ));
            } else {
                self.link_created = false;
                self.shaped = false;
            }
        }
        if self.namespace_created {
            if namespace_identity(&self.names.namespace) == self.namespace_identity {
                terminate_namespace_processes(&self.names.namespace);
                if let Err(error) = sudo(
                    "ip",
                    &["netns".to_owned(), "del".to_owned(), self.names.namespace.clone()],
                ) {
                    errors.push(error);
                } else {
                    self.namespace_created = false;
                }
            } else if namespace_exists(&self.names.namespace) {
                errors.push(format!(
                    "refusing to remove {} because its identity changed",
                    self.names.namespace
                ));
            } else {
                self.namespace_created = false;
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }
}

impl Drop for Topology {
    fn drop(&mut self) {
        let _ = self.remove();
    }
}

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

fn sudo(program: &str, args: &[String]) -> Result<String, String> {
    let mut elevated = vec!["-n".to_owned(), iproute2(program)];
    elevated.extend_from_slice(args);
    let outcome = Tool::new("sudo")
        .args(elevated)
        .probe()
        .map_err(|error| format!("could not run sudo {program}: {error}"))?;
    if outcome.success() {
        Ok(outcome.stdout)
    } else {
        Err(format!(
            "sudo {program} {} exited {:?}: {}",
            args.join(" "),
            outcome.code,
            outcome.stderr.trim_end()
        ))
    }
}

fn ip_in(namespace: &str, args: &[String]) -> Result<String, String> {
    command_in(namespace, "ip", args)
}

fn command_in(namespace: &str, program: &str, args: &[String]) -> Result<String, String> {
    let mut command = vec![
        "netns".to_owned(),
        "exec".to_owned(),
        namespace.to_owned(),
        iproute2(program),
    ];
    command.extend_from_slice(args);
    sudo("ip", &command)
}

fn namespace_exists(name: &str) -> bool {
    Path::new("/run/netns").join(name).exists()
        || Path::new("/var/run/netns").join(name).exists()
}

fn namespace_identity(name: &str) -> Option<(u64, u64)> {
    [Path::new("/run/netns"), Path::new("/var/run/netns")]
        .into_iter()
        .map(|root| root.join(name))
        .find_map(|path| std::fs::metadata(path).ok().map(|metadata| (metadata.dev(), metadata.ino())))
}

fn link_exists(name: &str) -> bool {
    Path::new("/sys/class/net").join(name).exists()
}

fn link_ifindex(name: &str) -> Option<u32> {
    std::fs::read_to_string(Path::new("/sys/class/net").join(name).join("ifindex"))
        .ok()?
        .trim()
        .parse()
        .ok()
}

fn terminate_namespace_processes(namespace: &str) {
    let Ok(output) = sudo(
        "ip",
        &["netns".to_owned(), "pids".to_owned(), namespace.to_owned()],
    ) else {
        return;
    };
    let processes = output
        .split_whitespace()
        .filter_map(|value| value.parse::<u32>().ok())
        .map(|pid| (pid, super::process::proc_starttime(pid)))
        .collect::<Vec<_>>();
    for signal in ["-TERM", "-KILL"] {
        for (pid, identity) in &processes {
            if identity.is_some() && super::process::proc_starttime(*pid).as_ref() == identity.as_ref() {
                let _ = sudo("kill", &[signal.to_owned(), "--".to_owned(), pid.to_string()]);
            }
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_stable_distinct_and_linux_safe() {
        let first = Names::for_run("deployment-a");
        assert_eq!(first, Names::for_run("deployment-a"));
        assert_ne!(first, Names::for_run("deployment-b"));
        assert!(first.namespace.starts_with("rrd-"));
        assert!(first.host_veth.len() <= 15);
        assert!(first.namespace_veth.len() <= 15);
    }

    #[test]
    fn absence_verification_is_exact() {
        let names = Names::for_run("never-created-deployment");
        Topology::verify_removed(&names).unwrap();
        let colliding = Names {
            host_veth: "lo".to_owned(),
            ..names
        };
        let error = Topology::verify_removed(&colliding).unwrap_err();
        assert!(error.contains("link lo"), "{error}");
    }
}
