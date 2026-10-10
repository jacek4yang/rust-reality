//! Execution of the validated, owned local system-VM fixture.

use std::{
    collections::BTreeMap,
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
use crate::bench::{host_lock::HostLock, runner, workspace::Workspace};

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
    boots: BTreeMap<String, String>,
    starts: BTreeMap<String, String>,
    qemu_sha256: Option<String>,
    _lock: HostLock,
}

fn save(path: &Path, value: &impl serde::Serialize) -> Result<(), String> {
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
            boots: BTreeMap::new(),
            starts: BTreeMap::new(),
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
            let child = self.children.last().expect("owned child");
            self.starts.insert(
                role.clone(),
                proc_starttime(child.pid()).ok_or("missing owned QEMU identity")?,
            );
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
            if boot_id.is_empty() || !boots.insert(boot_id.clone()) {
                return Err("guests did not expose distinct system boot identities".to_owned());
            }
            self.boots.insert(role.clone(), boot_id);
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
        self.ssh_channel(role, argv, None)
    }

    fn ssh_channel(
        &self,
        role: &str,
        argv: &[&str],
        socket: Option<&Path>,
    ) -> Result<Tool, String> {
        if argv.is_empty() || argv.iter().any(|arg| arg.contains('\0')) {
            return Err("invalid guest argv".to_owned());
        }
        let command = argv
            .iter()
            .map(|arg| format!("'{}'", arg.replace('\'', "'\\''")))
            .collect::<Vec<_>>()
            .join(" ");
        let mut tool = Tool::new("ssh").args(self.transport_options(role, false)?);
        if let Some(socket) = socket {
            tool = tool.args([
                "-S".to_owned(),
                socket.display().to_string(),
                "-oControlMaster=no".to_owned(),
            ]);
        }
        Ok(tool
            .args(["rrtest@127.0.0.1".to_owned(), command])
            .timeout(Duration::from_secs(15)))
    }

    fn clock_channel(&self, role: &str, socket: &Path, before: bool) -> Result<Child, String> {
        if socket.as_os_str().as_encoded_bytes().len() + 17 >= 108 {
            return Err("clock ControlPath exceeds the Unix socket limit including OpenSSH's temporary suffix".to_owned());
        }
        let mut argv = self.transport_options(role, false)?;
        argv.extend([
            "-M".to_owned(),
            "-N".to_owned(),
            "-oControlPersist=no".to_owned(),
            "-S".to_owned(),
            socket.display().to_string(),
            "rrtest@127.0.0.1".to_owned(),
        ]);
        let phase = if before { "before" } else { "after" };
        let mut child = Child::spawn(
            format!("clock-{role}"),
            Path::new("ssh"),
            &argv,
            &self.root,
            &[],
            &self
                .output
                .join(format!("{role}-clock-transport-{phase}.log")),
        )
        .map_err(|error| error.to_string())?;
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if !child.is_alive() || Instant::now() >= deadline {
                return Err(format!(
                    "{role}: owned clock transport did not become ready"
                ));
            }
            if socket.exists() {
                let outcome = Tool::new("ssh")
                    .args(self.transport_options(role, false)?)
                    .args([
                        "-S".to_owned(),
                        socket.display().to_string(),
                        "-O".to_owned(),
                        "check".to_owned(),
                        "rrtest@127.0.0.1".to_owned(),
                    ])
                    .timeout(Duration::from_secs(2))
                    .probe()
                    .map_err(|error| error.to_string())?;
                if outcome.success() {
                    return Ok(child);
                }
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn transport_options(&self, role: &str, scp: bool) -> Result<Vec<String>, String> {
        let port = match role {
            "landing" => self.fixture.landing.ssh_port,
            "line-a" => self.fixture.line_a.ssh_port,
            "line-b" => self.fixture.line_b.ssh_port,
            _ => return Err("unknown owned guest role".to_owned()),
        };
        Ok(vec![
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
            if scp { "-P" } else { "-p" }.to_owned(),
            port.to_string(),
        ])
    }

    /// Recheck the owned QEMU process and the guest's boot identity before
    /// staging inputs or executing workload operations.
    ///
    /// # Errors
    /// Rejects replaced/exited QEMU processes, guest reboots and failed SSH.
    pub fn verify_guest(&self, role: &str) -> Result<&str, String> {
        let child = self
            .children
            .iter()
            .find(|child| child.label() == role)
            .ok_or("unknown owned QEMU role")?;
        if proc_starttime(child.pid()).as_ref() != self.starts.get(role) {
            return Err(format!("{role}: owned QEMU identity changed"));
        }
        crate::bench::slot::verify_running_image(
            child.pid(),
            self.qemu_sha256.as_deref().ok_or("unbound QEMU image")?,
            role,
        )?;
        let expected = self.boots.get(role).ok_or("missing guest boot identity")?;
        let observed = self
            .ssh(role, &["cat", "/proc/sys/kernel/random/boot_id"])?
            .run()
            .map_err(|error| error.to_string())?;
        if observed.stdout.trim() != expected {
            return Err(format!("{role}: guest boot identity changed"));
        }
        Ok(expected)
    }

    /// Create the campaign's private input directory in one verified guest.
    /// Existing campaign state is rejected, never overwritten.
    ///
    /// # Errors
    /// Returns identity, SSH or pre-existing-directory errors.
    pub fn prepare_inputs(&self, role: &str) -> Result<(), String> {
        self.verify_guest(role)?;
        self.ssh(role, &["mkdir", "-m", "700", "/home/rrtest/rr-stability"])?
            .run()
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    /// Bind the owned guest clock to the host before product startup, or verify
    /// that binding after execution. Clock changes never occur during workload.
    ///
    /// # Errors
    /// Retains command/probe receipts before reporting setup, skew or I/O failure.
    pub fn clock_probe(&self, role: &str, before: bool) -> Result<(), String> {
        use super::{clock, collect};
        let boot = self.verify_guest(role)?.to_owned();
        // Authentication precedes the one measured exchange. The master is an
        // owned foreground child and its private socket cannot reuse an operator
        // connection. Dropping the guard closes it on success and failure.
        let transport = Workspace::create_socket()?;
        let socket = transport.join("control");
        let mut channel = self.clock_channel(role, &socket, before)?;
        let contract: schema::Contract =
            serde_json::from_str(schema::CONTRACT).expect("compiled contract");
        let mut commands = Vec::new();
        let mut errors = Vec::new();
        if before {
            // Disable NTP, one-shot REALTIME bind, then witness kvm-clock (ADR 0050).
            // kvm-clock tracks after bind; it does not correct a wrong wall clock
            // from the guest image (Frozen 38045882781 line-b start skew).
            for step in 0..3 {
                let started = collect::unix_ms()?;
                let argv = match step {
                    0 => ["sudo", "-n", "timedatectl", "set-ntp", "false"]
                        .map(str::to_owned)
                        .to_vec(),
                    1 => clock::set_argv(started),
                    _ => clock::clocksource_argv(),
                };
                let outcome = self
                    .ssh_channel(
                        role,
                        &argv.iter().map(String::as_str).collect::<Vec<_>>(),
                        Some(&socket),
                    )?
                    .probe();
                let completed = collect::unix_ms()?;
                let mut command = clock::Command {
                    argv,
                    started_unix_ms: started,
                    completed_unix_ms: completed,
                    exit_code: None,
                    stdout: String::new(),
                    stderr: String::new(),
                    errors: Vec::new(),
                };
                match outcome {
                    Ok(outcome) => {
                        command.exit_code = outcome.code;
                        command.stdout = outcome.stdout;
                        command.stderr = outcome.stderr;
                    }
                    Err(error) => command.errors.push(error.to_string()),
                }
                let failed = command.exit_code != Some(0) || !command.errors.is_empty();
                commands.push(command);
                if failed {
                    errors.push(format!("{role}: guest clock setup step {step} failed"));
                    break;
                }
            }
        }
        let host_before_unix_ms = collect::unix_ms()?;
        let outcome = self
            .ssh_channel(role, &["date", "--utc", "+%s%3N"], Some(&socket))?
            .probe();
        let host_after_unix_ms = collect::unix_ms()?;
        if !channel.is_alive() {
            errors.push("owned clock transport exited during observation".to_owned());
        }
        let mut probe = clock::Probe {
            role: role.to_owned(),
            phase: if before { "before" } else { "after" }.to_owned(),
            boot_id: boot,
            host_before_unix_ms,
            host_after_unix_ms,
            date_exit_code: None,
            date_stdout: String::new(),
            date_stderr: String::new(),
            commands,
            errors,
        };
        match outcome {
            Ok(outcome) => {
                probe.date_exit_code = outcome.code;
                probe.date_stdout = outcome.stdout;
                probe.date_stderr = outcome.stderr;
            }
            Err(error) => probe.errors.push(error.to_string()),
        }
        let checked = probe.errors.first().map_or_else(
            || clock::verify(&probe, &contract),
            |error| Err(error.clone()),
        );
        let written = save(
            &self
                .output
                .join(format!("{role}-clock-{}.json", probe.phase)),
            &probe,
        );
        match (checked, written) {
            (Err(primary), Err(secondary)) => Err(format!(
                "{primary}; clock evidence finalization also failed: {secondary}"
            )),
            (Err(error), _) | (_, Err(error)) => Err(error),
            _ => Ok(()),
        }
    }

    /// Stage one fixed campaign asset through SFTP-backed scp. Operator SSH
    /// configuration is ignored; no remote command or arbitrary path is accepted.
    ///
    /// # Errors
    /// Rejects invalid asset names, changed guests and transfer failures.
    pub fn stage(&self, role: &str, source: &Path, name: &str) -> Result<(), String> {
        if name.is_empty()
            || name.starts_with('.')
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-._".contains(&byte))
        {
            return Err("invalid guest campaign asset name".to_owned());
        }
        self.verify_guest(role)?;
        Tool::new("scp")
            .args(self.transport_options(role, true)?)
            .arg("--")
            .args([
                source.display().to_string(),
                format!("rrtest@127.0.0.1:/home/rrtest/rr-stability/{name}"),
            ])
            .timeout(Duration::from_mins(2))
            .run()
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    /// Retrieve the guest's evidence tree, which is separate from private inputs.
    ///
    /// # Errors
    /// Rejects changed guests, an existing destination or a failed transfer.
    pub fn retrieve(&self, role: &str, destination: &Path) -> Result<(), String> {
        if destination.exists() {
            return Err("guest evidence destination already exists".to_owned());
        }
        self.verify_guest(role)?;
        Tool::new("scp")
            .args(self.transport_options(role, true)?)
            .arg("-r")
            .arg("--")
            .args([
                "rrtest@127.0.0.1:/home/rrtest/rr-stability/output".to_owned(),
                destination.display().to_string(),
            ])
            .timeout(Duration::from_mins(2))
            .run()
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    /// Host loopback SOCKS port forwarded to the selected owned LINE guest.
    ///
    /// # Errors
    /// Rejects LANDING and unknown roles.
    pub fn socks_port(&self, role: &str) -> Result<u16, String> {
        match role {
            "line-a" => Ok(self.fixture.line_a.socks_port),
            "line-b" => Ok(self.fixture.line_b.socks_port),
            _ => Err("SOCKS workload requires a LINE guest".to_owned()),
        }
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
