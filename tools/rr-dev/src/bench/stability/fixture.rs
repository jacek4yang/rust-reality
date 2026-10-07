//! Execution of the validated, owned local system-VM fixture.

use std::{
    fs,
    net::{Ipv4Addr, SocketAddrV4, TcpListener},
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

use super::{
    schema::{self, VmFixture},
    vm,
};
use crate::bench::{host_lock::HostLock, runner};

use crate::{
    bench::process::{Child, proc_starttime},
    hash,
    process::Tool,
};

/// Three owned QEMU processes. Existing guest disks are read through temporary
/// QEMU snapshots; all mutable controller output belongs to the fresh case path.
pub struct Machines {
    root: PathBuf,
    output: PathBuf,
    fixture: VmFixture,
    children: Vec<Child>,
    qemu_sha256: Option<String>,
    _lock: HostLock,
}

fn save(path: &Path, value: &serde_json::Value) -> Result<(), String> {
    fs::write(
        path,
        serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?,
    )
    .map_err(|error| format!("write fixture receipt: {error}"))
}

impl Machines {
    /// Start only the validated local fixture; preserve launch failures and an
    /// attempted final process/image census before owned children are dropped.
    ///
    /// # Errors
    /// Returns validation, occupied-port, boot, SSH or evidence-write errors.
    pub fn start(root: &Path, output: &Path, constrained: bool) -> Result<Self, String> {
        let root = root
            .canonicalize()
            .map_err(|error| format!("fixture root: {error}"))?;
        let fixture = schema::parse_vm_fixture(
            &fs::read(root.join("guests.json"))
                .map_err(|error| format!("fixture metadata: {error}"))?,
        )?;
        vm::validate(&root, &fixture)?;
        fs::create_dir(output).map_err(|error| format!("create fresh fixture output: {error}"))?;
        let output = output
            .canonicalize()
            .map_err(|error| format!("fixture output: {error}"))?;
        let lock = HostLock::acquire(&runner::default_lock_path())?;
        let mut machines = Self {
            root,
            output,
            fixture,
            children: Vec::new(),
            qemu_sha256: None,
            _lock: lock,
        };
        let attempted = machines.boot(constrained);
        let census = machines.identities();
        let finalization = save(
            &machines.output.join("boot-terminal.json"),
            &serde_json::json!({
                "primary_error":attempted.as_ref().err(),"processes":census,"completed":attempted.is_ok()
            }),
        );
        match (attempted, finalization) {
            (Ok(()), Ok(())) => Ok(machines),
            (Err(primary), Ok(())) => Err(primary),
            (Ok(()), Err(finalization)) => Err(finalization),
            (Err(primary), Err(finalization)) => Err(format!(
                "{primary}; evidence finalization also failed: {finalization}"
            )),
        }
    }

    fn boot(&mut self, constrained: bool) -> Result<(), String> {
        // Refuse a fixture already in use, rather than contacting an unknown
        // process that happens to answer one of its historical SSH ports.
        let mut reserved = Vec::new();
        for spec in [
            &self.fixture.landing,
            &self.fixture.line_a,
            &self.fixture.line_b,
        ] {
            for port in [spec.ssh_port, spec.socks_port] {
                reserved.push(
                    TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
                        .map_err(|error| format!("fixture port {port} occupied: {error}"))?,
                );
            }
        }
        let commands = vm::launch_commands(&self.root, &self.fixture, &self.output, constrained)?;
        let qemu = self.root.join("qemu/usr/bin/qemu-system-x86_64");
        let qemu_sha256 = hash::sha256_file(&qemu)?;
        self.qemu_sha256 = Some(qemu_sha256.clone());
        save(
            &self.output.join("launch.json"),
            &serde_json::json!({
                "constrained":constrained,"commands":commands,"qemu_sha256":qemu_sha256,
                "fixture_sha256":hash::sha256_file(&self.root.join("guests.json"))?,
                "provision_attestation_sha256":hash::sha256_file(&self.root.join("provision-attestation.json"))?
            }),
        )?;
        drop(reserved);
        let mut boots = std::collections::BTreeSet::new();
        for (role, argv) in commands {
            let (program, args) = argv.split_first().expect("validated argv");
            let child = Child::spawn(
                &role,
                Path::new(program),
                args,
                &self.root,
                &[(
                    "LD_LIBRARY_PATH".to_owned(),
                    self.root
                        .join("qemu/usr/lib/x86_64-linux-gnu")
                        .display()
                        .to_string(),
                )],
                &self.output.join(format!("{role}-qemu.log")),
            )
            .map_err(|error| error.to_string())?;
            self.children.push(child);
            let started = Instant::now();
            loop {
                if !self.children.last_mut().expect("owned child").is_alive() {
                    return Err(format!("{role}: QEMU exited during boot; raw log retained"));
                }
                if self
                    .ssh(&role, &["true"])?
                    .probe()
                    .is_ok_and(|outcome| outcome.success())
                {
                    break;
                }
                if started.elapsed() >= Duration::from_mins(2) {
                    return Err(format!("{role}: fixture SSH boot deadline exceeded"));
                }
                thread::sleep(Duration::from_secs(1));
            }
            let child = self.children.last().expect("owned child");
            crate::bench::slot::verify_running_image(child.pid(), &qemu_sha256, &role)?;
            let boot = self
                .ssh(&role, &["cat", "/proc/sys/kernel/random/boot_id"])?
                .run()
                .map_err(|error| error.to_string())?;
            let boot_id = boot.stdout.trim().to_owned();
            if boot_id.is_empty() || !boots.insert(boot_id) {
                return Err("guests did not expose distinct system boot identities".to_owned());
            }
            fs::write(
                self.output.join(format!("{role}-boot-id.txt")),
                &boot.stdout,
            )
            .map_err(|error| error.to_string())?;
            self.verify_guest_resources(&role, constrained)?;
        }
        Ok(())
    }

    fn verify_guest_resources(&self, role: &str, constrained: bool) -> Result<(), String> {
        let cpus = self
            .ssh(role, &["nproc"])?
            .run()
            .map_err(|error| error.to_string())?;
        let expected_cpus = if role == "landing" && !constrained {
            2
        } else {
            1
        };
        if cpus.stdout.trim().parse::<u16>().ok() != Some(expected_cpus) {
            return Err(format!("{role}: guest CPU count differs from its profile"));
        }
        for (name, argv) in [
            ("memory", vec!["cat", "/proc/meminfo"]),
            ("swap", vec!["cat", "/proc/swaps"]),
            ("kernel", vec!["uname", "-a"]),
        ] {
            let receipt = self
                .ssh(role, &argv)?
                .run()
                .map_err(|error| error.to_string())?;
            fs::write(
                self.output.join(format!("{role}-{name}.txt")),
                &receipt.stdout,
            )
            .map_err(|error| error.to_string())?;
            if name == "swap" && receipt.stdout.lines().count() != 1 {
                return Err(format!("{role}: unexpected guest swap"));
            }
        }
        Ok(())
    }

    /// A bounded SSH command to one of the owned guests, ignoring operator SSH
    /// configuration. Every argument is quoted for the unavoidable SSH command
    /// string; local execution remains typed argv.
    ///
    /// # Errors
    /// Rejects unknown roles and commands containing a NUL byte.
    pub fn ssh(&self, role: &str, argv: &[&str]) -> Result<Tool, String> {
        let port = match role {
            "landing" => self.fixture.landing.ssh_port,
            "line-a" => self.fixture.line_a.ssh_port,
            "line-b" => self.fixture.line_b.ssh_port,
            _ => return Err("unknown owned guest role".to_owned()),
        };
        if argv.is_empty() || argv.iter().any(|arg| arg.contains('\0')) {
            return Err("invalid guest argv".to_owned());
        }
        let command = argv
            .iter()
            .map(|arg| format!("'{}'", arg.replace('\'', "'\\''")))
            .collect::<Vec<_>>()
            .join(" ");
        Ok(Tool::new("ssh")
            .args([
                "-F".to_owned(),
                "/dev/null".to_owned(),
                "-i".to_owned(),
                self.root.join("test-key").display().to_string(),
                "-o".to_owned(),
                format!(
                    "UserKnownHostsFile={}",
                    self.root.join("known_hosts").display()
                ),
                "-o".to_owned(),
                "StrictHostKeyChecking=yes".to_owned(),
                "-o".to_owned(),
                "BatchMode=yes".to_owned(),
                "-o".to_owned(),
                "IdentitiesOnly=yes".to_owned(),
                "-o".to_owned(),
                "ConnectTimeout=3".to_owned(),
                "-o".to_owned(),
                "ServerAliveInterval=5".to_owned(),
                "-o".to_owned(),
                "ServerAliveCountMax=2".to_owned(),
                "-p".to_owned(),
                port.to_string(),
                "rrtest@127.0.0.1".to_owned(),
                command,
            ])
            .timeout(Duration::from_secs(15)))
    }

    fn identities(&self) -> Vec<serde_json::Value> {
        self.children.iter().map(|child| {
            let image = hash::sha256_file(Path::new(&format!("/proc/{}/exe",child.pid())));
            serde_json::json!({"role":child.label(),"pid":child.pid(),"start_ticks":proc_starttime(child.pid()),
                "image_sha256":image.as_ref().ok(),"image_error":image.err()})
        }).collect()
    }

    /// Write final identities while the owned QEMU processes are still alive.
    /// Dropping this guard then shuts down exactly those owned children.
    ///
    /// # Errors
    /// Returns an evidence-write error; callers preserve their primary failure.
    pub fn finalize(&mut self) -> Result<(), String> {
        let mut errors = Vec::new();
        for child in &mut self.children {
            if !child.is_alive() {
                errors.push(format!("{} exited unexpectedly", child.label()));
            }
            if let Some(expected) = &self.qemu_sha256 {
                if let Err(error) =
                    crate::bench::slot::verify_running_image(child.pid(), expected, child.label())
                {
                    errors.push(error);
                }
            } else {
                errors.push("QEMU image was not bound".to_owned());
            }
        }
        let written = save(
            &self.output.join("final-processes.json"),
            &serde_json::json!({
                "processes":self.identities(),"errors":errors
            }),
        );
        if let Err(error) = written {
            errors.push(error);
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }
}
