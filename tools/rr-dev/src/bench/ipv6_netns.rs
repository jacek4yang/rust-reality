//! Owned IPv6 namespace topology for the end-to-end resilience phase.
//!
//! Every namespace and veth name is derived from the run id. Creation refuses
//! collisions, teardown names each resource exactly, and removal is re-read from
//! the host. No host route or address is changed: all addresses, qdiscs and route
//! loss live inside namespaces that this guard owns.

use std::path::{Path, PathBuf};

use crate::process::Tool;

/// Names of every privileged resource the topology owns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Names {
    /// Client namespace.
    pub client_namespace: String,
    /// Server namespace.
    pub server_namespace: String,
    /// Origin namespace.
    pub origin_namespace: String,
    /// Client-side interface of the client/server veth.
    pub client_veth: String,
    /// Server-side interface of the client/server veth.
    pub server_client_veth: String,
    /// Origin-side interface of the server/origin veth.
    pub origin_veth: String,
    /// Server-side interface of the server/origin veth.
    pub server_origin_veth: String,
}

impl Names {
    /// Derives Linux-safe names from a run id.
    #[must_use]
    pub fn for_run(run_id: &str) -> Self {
        let digest = crate::hash::sha256_hex(run_id.as_bytes());
        let suffix = &digest[..7];
        Self {
            client_namespace: format!("rr6c-{suffix}"),
            server_namespace: format!("rr6s-{suffix}"),
            origin_namespace: format!("rr6o-{suffix}"),
            client_veth: format!("r6c{suffix}"),
            server_client_veth: format!("r60{suffix}"),
            origin_veth: format!("r6o{suffix}"),
            server_origin_veth: format!("r61{suffix}"),
        }
    }

    fn namespaces(&self) -> [&str; 3] {
        [
            &self.client_namespace,
            &self.server_namespace,
            &self.origin_namespace,
        ]
    }

    fn links(&self) -> [&str; 4] {
        [
            &self.client_veth,
            &self.server_client_veth,
            &self.origin_veth,
            &self.server_origin_veth,
        ]
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

fn namespace_exists(name: &str) -> bool {
    Path::new("/run/netns").join(name).exists() || Path::new("/var/run/netns").join(name).exists()
}

fn link_exists(name: &str) -> bool {
    Path::new("/sys/class/net").join(name).exists()
}

fn terminate_namespace_processes(name: &str) {
    let Ok(output) = sudo(
        "ip",
        &["netns".to_owned(), "pids".to_owned(), name.to_owned()],
    ) else {
        return;
    };
    let identities: Vec<(u32, Option<String>)> = output
        .split_whitespace()
        .filter_map(|field| field.parse::<u32>().ok())
        .map(|pid| (pid, crate::bench::process::proc_starttime(pid)))
        .collect();
    for signal in ["-TERM", "-KILL"] {
        for (pid, starttime) in &identities {
            if starttime.is_some()
                && crate::bench::process::proc_starttime(*pid).as_ref() == starttime.as_ref()
            {
                let _ = sudo(
                    "kill",
                    &[signal.to_owned(), "--".to_owned(), pid.to_string()],
                );
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
}

fn sudo(program: &str, args: &[String]) -> Result<String, String> {
    let mut elevated = vec!["-n".to_owned(), iproute2(program)];
    elevated.extend_from_slice(args);
    let outcome = Tool::new("sudo")
        .args(elevated)
        .probe()
        .map_err(|error| format!("could not run sudo {program}: {error}"))?;
    if !outcome.success() {
        return Err(format!(
            "sudo {program} {} exited {:?}: {}",
            args.join(" "),
            outcome.code,
            outcome.stderr.trim_end()
        ));
    }
    Ok(outcome.stdout)
}

/// Runs an `ip` command inside an owned namespace.
pub fn ip_in(namespace: &str, args: &[&str]) -> Result<String, String> {
    let mut command = vec![
        "netns".to_owned(),
        "exec".to_owned(),
        namespace.to_owned(),
        iproute2("ip"),
    ];
    command.extend(args.iter().map(|arg| (*arg).to_owned()));
    sudo("ip", &command)
}

/// Runs an arbitrary program inside an owned namespace, retaining root only for
/// the namespace transition and dropping back to the invoking uid/gid first.
pub fn command_in(
    namespace: &str,
    program: &Path,
    args: &[String],
    env: &[(String, String)],
) -> Result<crate::process::Outcome, String> {
    let uid = Tool::new("id")
        .arg("-u")
        .probe()
        .map_err(|error| format!("could not read uid: {error}"))?;
    let gid = Tool::new("id")
        .arg("-g")
        .probe()
        .map_err(|error| format!("could not read gid: {error}"))?;
    if !uid.success() || !gid.success() {
        return Err("could not read the invoking uid/gid".to_owned());
    }
    let mut command = vec![
        "-n".to_owned(),
        iproute2("ip"),
        "netns".to_owned(),
        "exec".to_owned(),
        namespace.to_owned(),
        "setpriv".to_owned(),
        "--reuid".to_owned(),
        uid.trimmed_stdout().to_owned(),
        "--regid".to_owned(),
        gid.trimmed_stdout().to_owned(),
        "--clear-groups".to_owned(),
        "env".to_owned(),
    ];
    command.extend(env.iter().map(|(key, value)| format!("{key}={value}")));
    command.push(program.display().to_string());
    command.extend_from_slice(args);
    Tool::new("sudo").args(command).probe().map_err(|error| {
        format!(
            "could not run {} in {namespace}: {error}",
            program.display()
        )
    })
}

/// Spawns a long-lived unprivileged child inside an owned namespace.
pub fn spawn_in(
    namespace: &str,
    label: &str,
    program: &Path,
    args: &[String],
    cwd: &Path,
    env: &[(String, String)],
    log: &Path,
) -> Result<crate::bench::process::Child, String> {
    let uid = Tool::new("id")
        .arg("-u")
        .probe()
        .map_err(|error| format!("could not read uid: {error}"))?;
    let gid = Tool::new("id")
        .arg("-g")
        .probe()
        .map_err(|error| format!("could not read gid: {error}"))?;
    if !uid.success() || !gid.success() {
        return Err("could not read the invoking uid/gid".to_owned());
    }
    let mut command = vec![
        "-n".to_owned(),
        iproute2("ip"),
        "netns".to_owned(),
        "exec".to_owned(),
        namespace.to_owned(),
        "setpriv".to_owned(),
        "--reuid".to_owned(),
        uid.trimmed_stdout().to_owned(),
        "--regid".to_owned(),
        gid.trimmed_stdout().to_owned(),
        "--clear-groups".to_owned(),
        "env".to_owned(),
    ];
    command.extend(env.iter().map(|(key, value)| format!("{key}={value}")));
    command.push(program.display().to_string());
    command.extend_from_slice(args);
    crate::bench::process::Child::spawn(label, Path::new("sudo"), &command, cwd, &[], log)
        .map_err(|error| error.to_string())
}

/// Whether passwordless sudo is available without prompting.
#[must_use]
pub fn sudo_available() -> bool {
    Tool::new("sudo")
        .args(["-n", "true"])
        .probe()
        .is_ok_and(|outcome| outcome.success())
}

/// Whether the traffic-control binary needed by the netem subcase is installed.
#[must_use]
pub fn tc_available() -> bool {
    Tool::exists("tc") || Path::new(&iproute2("tc")).is_file()
}

/// Three-namespace IPv6-only topology, removed on drop.
#[derive(Debug)]
pub struct Topology {
    names: Names,
    namespaces_created: Vec<String>,
    host_links_created: Vec<String>,
    netem: bool,
    route_removed: bool,
}

impl Topology {
    /// Creates the namespaces, veth pairs and documentation-prefix addresses.
    pub fn create(run_id: &str) -> Result<Self, String> {
        for program in ["ip", "setpriv"] {
            if !Tool::exists(program) && !Path::new(&iproute2(program)).is_file() {
                return Err(format!("IPv6 resilience requires {program}"));
            }
        }
        let names = Names::for_run(run_id);
        for namespace in names.namespaces() {
            if namespace_exists(namespace) {
                return Err(format!(
                    "owned namespace name {namespace} already exists; inspect it before rerunning"
                ));
            }
        }
        for link in names.links() {
            if link_exists(link) {
                return Err(format!(
                    "owned link name {link} already exists; inspect it before rerunning"
                ));
            }
        }
        let mut topology = Self {
            names,
            namespaces_created: Vec::new(),
            host_links_created: Vec::new(),
            netem: false,
            route_removed: false,
        };
        let creation = (|| {
            let namespaces = topology
                .names
                .namespaces()
                .map(std::borrow::ToOwned::to_owned);
            for namespace in namespaces {
                sudo(
                    "ip",
                    &["netns".to_owned(), "add".to_owned(), namespace.clone()],
                )?;
                topology.namespaces_created.push(namespace);
            }
            topology.add_veth(
                topology.names.client_veth.clone(),
                topology.names.server_client_veth.clone(),
            )?;
            topology.add_veth(
                topology.names.origin_veth.clone(),
                topology.names.server_origin_veth.clone(),
            )?;
            topology.move_link(
                &topology.names.client_veth.clone(),
                &topology.names.client_namespace.clone(),
            )?;
            topology.move_link(
                &topology.names.server_client_veth.clone(),
                &topology.names.server_namespace.clone(),
            )?;
            topology.move_link(
                &topology.names.origin_veth.clone(),
                &topology.names.origin_namespace.clone(),
            )?;
            topology.move_link(
                &topology.names.server_origin_veth.clone(),
                &topology.names.server_namespace.clone(),
            )?;
            topology.configure()
        })();
        if let Err(error) = creation {
            let names = topology.names.clone();
            topology.remove();
            Self::verify_removed(&names)
                .map_err(|cleanup| format!("{error}; safety cleanup failed: {cleanup}"))?;
            return Err(error);
        }
        Ok(topology)
    }

    fn add_veth(&mut self, first: String, second: String) -> Result<(), String> {
        sudo(
            "ip",
            &[
                "link".to_owned(),
                "add".to_owned(),
                first.clone(),
                "type".to_owned(),
                "veth".to_owned(),
                "peer".to_owned(),
                "name".to_owned(),
                second,
            ],
        )?;
        self.host_links_created.push(first);
        Ok(())
    }

    fn move_link(&mut self, link: &str, namespace: &str) -> Result<(), String> {
        sudo(
            "ip",
            &[
                "link".to_owned(),
                "set".to_owned(),
                link.to_owned(),
                "netns".to_owned(),
                namespace.to_owned(),
            ],
        )?;
        self.host_links_created.retain(|owned| owned != link);
        Ok(())
    }

    fn configure(&self) -> Result<(), String> {
        for namespace in self.names.namespaces() {
            ip_in(namespace, &["link", "set", "lo", "up"])?;
        }
        for (namespace, address, link) in [
            (
                &self.names.client_namespace,
                "2001:db8:a::1/64",
                &self.names.client_veth,
            ),
            (
                &self.names.server_namespace,
                "2001:db8:a::2/64",
                &self.names.server_client_veth,
            ),
            (
                &self.names.server_namespace,
                "2001:db8:b::2/64",
                &self.names.server_origin_veth,
            ),
            (
                &self.names.origin_namespace,
                "2001:db8:b::1/64",
                &self.names.origin_veth,
            ),
        ] {
            ip_in(namespace, &["-6", "addr", "add", address, "dev", link])?;
            ip_in(namespace, &["link", "set", link, "up"])?;
        }
        Ok(())
    }

    /// Names of the resources owned by this topology.
    #[must_use]
    pub const fn names(&self) -> &Names {
        &self.names
    }

    /// Waits until Duplicate Address Detection has completed everywhere.
    pub fn wait_for_dad(&self) -> Result<(), String> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        while std::time::Instant::now() < deadline {
            let mut tentative = 0;
            for namespace in self.names.namespaces() {
                tentative += crate::bench::ipv6::tentative_addresses(&ip_in(
                    namespace,
                    &["-6", "addr", "show", "tentative"],
                )?);
            }
            if tentative == 0 {
                return Ok(());
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        Err("IPv6 namespace addresses remained tentative after 15 seconds".to_owned())
    }

    /// Adds the exact netem qdisc used by the legacy resilience case.
    pub fn add_netem(&mut self) -> Result<(), String> {
        if !tc_available() {
            return Err("IPv6 netem acceptance requires tc".to_owned());
        }
        let args = [
            "netns".to_owned(),
            "exec".to_owned(),
            self.names.client_namespace.clone(),
            iproute2("tc"),
            "qdisc".to_owned(),
            "add".to_owned(),
            "dev".to_owned(),
            self.names.client_veth.clone(),
            "root".to_owned(),
            "netem".to_owned(),
            "delay".to_owned(),
            "100ms".to_owned(),
            "loss".to_owned(),
            "1%".to_owned(),
        ];
        sudo("ip", &args)?;
        self.netem = true;
        Ok(())
    }

    /// Removes only this topology's qdisc.
    pub fn remove_netem(&mut self) -> Result<(), String> {
        if !self.netem {
            return Ok(());
        }
        let args = [
            "netns".to_owned(),
            "exec".to_owned(),
            self.names.client_namespace.clone(),
            iproute2("tc"),
            "qdisc".to_owned(),
            "del".to_owned(),
            "dev".to_owned(),
            self.names.client_veth.clone(),
            "root".to_owned(),
        ];
        sudo("ip", &args)?;
        self.netem = false;
        Ok(())
    }

    /// Deletes the server→origin route inside the owned server namespace.
    pub fn remove_origin_route(&mut self) -> Result<(), String> {
        ip_in(
            &self.names.server_namespace,
            &[
                "-6",
                "route",
                "del",
                "2001:db8:b::/64",
                "dev",
                &self.names.server_origin_veth,
            ],
        )?;
        self.route_removed = true;
        Ok(())
    }

    /// Restores the exact route removed by [`Self::remove_origin_route`].
    pub fn restore_origin_route(&mut self) -> Result<(), String> {
        if !self.route_removed {
            return Ok(());
        }
        ip_in(
            &self.names.server_namespace,
            &[
                "-6",
                "route",
                "add",
                "2001:db8:b::/64",
                "dev",
                &self.names.server_origin_veth,
            ],
        )?;
        self.route_removed = false;
        Ok(())
    }

    fn remove(&mut self) {
        let _ = self.restore_origin_route();
        let _ = self.remove_netem();
        for link in self.host_links_created.iter().rev() {
            let _ = sudo("ip", &["link".to_owned(), "del".to_owned(), link.clone()]);
        }
        self.host_links_created.clear();
        for namespace in self.namespaces_created.iter().rev() {
            terminate_namespace_processes(namespace);
            let _ = sudo(
                "ip",
                &["netns".to_owned(), "del".to_owned(), namespace.clone()],
            );
        }
        self.namespaces_created.clear();
    }

    /// Confirms no namespace or host-visible link with an owned name remains.
    pub fn verify_removed(names: &Names) -> Result<(), String> {
        let mut leftovers = Vec::new();
        for namespace in names.namespaces() {
            if namespace_exists(namespace) {
                leftovers.push(format!("namespace {namespace}"));
            }
        }
        for link in names.links() {
            if link_exists(link) {
                leftovers.push(format!("link {link}"));
            }
        }
        if leftovers.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "owned IPv6 topology was not fully removed: {}",
                leftovers.join(", ")
            ))
        }
    }
}

impl Drop for Topology {
    fn drop(&mut self) {
        self.remove();
    }
}

/// A single owned namespace used to characterize `disable_ipv6=1` listeners.
#[derive(Debug)]
pub struct DisabledIpv6 {
    name: String,
    created: bool,
}

impl DisabledIpv6 {
    /// Creates one collision-checked namespace and disables IPv6 inside it.
    pub fn create(run_id: &str) -> Result<Self, String> {
        let digest = crate::hash::sha256_hex(format!("disabled-{run_id}").as_bytes());
        let name = format!("rr6n-{}", &digest[..7]);
        if namespace_exists(&name) {
            return Err(format!(
                "owned namespace name {name} already exists; inspect it before rerunning"
            ));
        }
        sudo("ip", &["netns".to_owned(), "add".to_owned(), name.clone()])?;
        let mut owned = Self {
            name,
            created: true,
        };
        let configuration = (|| {
            ip_in(&owned.name, &["link", "set", "lo", "up"])?;
            let arguments = [
                "netns".to_owned(),
                "exec".to_owned(),
                owned.name.clone(),
                iproute2("sysctl"),
                "-q".to_owned(),
                "-w".to_owned(),
                "net.ipv6.conf.all.disable_ipv6=1".to_owned(),
                "net.ipv6.conf.default.disable_ipv6=1".to_owned(),
            ];
            sudo("ip", &arguments).map(|_| ())
        })();
        if let Err(error) = configuration {
            let name = owned.name.clone();
            owned.remove();
            Self::verify_removed(&name)
                .map_err(|cleanup| format!("{error}; safety cleanup failed: {cleanup}"))?;
            return Err(error);
        }
        Ok(owned)
    }

    /// Namespace name owned by this guard.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    fn remove(&mut self) {
        if self.created {
            terminate_namespace_processes(&self.name);
            let _ = sudo(
                "ip",
                &["netns".to_owned(), "del".to_owned(), self.name.clone()],
            );
            self.created = false;
        }
    }

    /// Confirms the namespace is absent after drop.
    pub fn verify_removed(name: &str) -> Result<(), String> {
        if namespace_exists(name) {
            Err(format!(
                "owned disabled-IPv6 namespace {name} survived teardown"
            ))
        } else {
            Ok(())
        }
    }
}

impl Drop for DisabledIpv6 {
    fn drop(&mut self) {
        self.remove();
    }
}

/// Returns a log path suitable for one namespaced child.
#[must_use]
pub fn log_path(run: &crate::bench::evidence::RunDirectory, label: &str) -> PathBuf {
    run.join(&format!("{label}.log"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_stable_unique_and_fit_linux_limits() {
        let names = Names::for_run("ipv6-run-a");
        assert_eq!(names, Names::for_run("ipv6-run-a"));
        assert_ne!(names, Names::for_run("ipv6-run-b"));
        for link in names.links() {
            assert!(link.len() <= 15, "{link}");
        }
        for namespace in names.namespaces() {
            assert!(namespace.starts_with("rr6"));
        }
    }

    #[test]
    fn removal_verification_is_exact() {
        let names = Names::for_run("never-created");
        Topology::verify_removed(&names).unwrap();
        let colliding = Names {
            client_veth: "lo".to_owned(),
            ..names
        };
        let error = Topology::verify_removed(&colliding).unwrap_err();
        assert!(error.contains("link lo"), "{error}");
    }
}
