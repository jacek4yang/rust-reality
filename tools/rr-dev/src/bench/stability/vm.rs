//! The owned three-system-VM qualification fixture, with loopback-only control.
//!
//! This is deliberately limited to the retained LINE-A/LINE-B/LANDING fixture.
//! Imported argv is verified against this exact topology before any execution.

use std::{collections::BTreeSet, path::Path};

use super::schema::{VmFixture, VmSpec};

const ROLES: [&str; 3] = ["landing", "line-a", "line-b"];

fn link_port(spec: &VmSpec, id: &str, direction: &str) -> Result<u16, String> {
    let prefix = format!("socket,id={id},{direction}=127.0.0.1:");
    let mut matches = spec.command.windows(2).filter_map(|pair| {
        (pair[0] == "-netdev")
            .then(|| pair[1].strip_prefix(&prefix))
            .flatten()
    });
    let port: u16 = matches
        .next()
        .ok_or("missing isolated data link")?
        .parse()
        .map_err(|_| "invalid data-link port")?;
    if port == 0 || matches.next().is_some() {
        return Err("invalid or duplicated data link".to_owned());
    }
    Ok(port)
}

fn expected_command(root: &Path, role: &str, spec: &VmSpec, links: [u16; 2]) -> Vec<String> {
    let mut command: Vec<String> = [
        "taskset".to_owned(),
        "-c".to_owned(),
        spec.cores.clone(),
        root.join("qemu/usr/bin/qemu-system-x86_64")
            .display()
            .to_string(),
        "-accel".to_owned(),
        "kvm".to_owned(),
        "-cpu".to_owned(),
        "host".to_owned(),
        "-smp".to_owned(),
        spec.cpus.to_string(),
        "-m".to_owned(),
        spec.ram_mib.to_string(),
        "-nodefaults".to_owned(),
        "-display".to_owned(),
        "none".to_owned(),
        "-no-reboot".to_owned(),
        "-bios".to_owned(),
        root.join("qemu/usr/share/seabios/bios-256k.bin")
            .display()
            .to_string(),
        "-L".to_owned(),
        root.join("qemu/usr/share/qemu").display().to_string(),
        "-drive".to_owned(),
        format!(
            "file={},if=virtio,format=qcow2",
            root.join(role).join("disk.qcow2").display()
        ),
        "-drive".to_owned(),
        format!(
            "file={},media=cdrom,readonly=on",
            root.join(role).join("seed.iso").display()
        ),
        "-serial".to_owned(),
        format!("file:{}", root.join(role).join("serial.log").display()),
        "-qmp".to_owned(),
        format!(
            "unix:{},server=on,wait=off",
            root.join(role).join("qmp.sock").display()
        ),
        "-netdev".to_owned(),
        format!(
            "user,id=mgmt,hostfwd=tcp:127.0.0.1:{}-:22,hostfwd=tcp:127.0.0.1:{}-:1080",
            spec.ssh_port, spec.socks_port
        ),
    ]
    .into();
    let index = ROLES
        .iter()
        .position(|name| *name == role)
        .expect("fixed fixture role");
    command.extend([
        "-device".to_owned(),
        format!("virtio-net-pci,netdev=mgmt,mac=52:54:00:26:{index:02}:00,romfile="),
    ]);
    if role == "landing" {
        for (index, port) in links.into_iter().enumerate() {
            command.extend([
                "-netdev".to_owned(),
                format!("socket,id=data{index},listen=127.0.0.1:{port}"),
                "-device".to_owned(),
                format!(
                    "virtio-net-pci,netdev=data{index},mac=52:54:00:26:00:{:02},romfile=",
                    index + 1
                ),
            ]);
        }
    } else {
        let port = links[index - 1];
        command.extend([
            "-netdev".to_owned(),
            format!("socket,id=data0,connect=127.0.0.1:{port}"),
            "-device".to_owned(),
            format!("virtio-net-pci,netdev=data0,mac=52:54:00:26:{index:02}:01,romfile="),
        ]);
    }
    command
}

/// Validate that imported metadata describes only the owned isolated topology.
///
/// # Errors
/// Rejects arbitrary commands, extra devices, non-loopback control/data links,
/// duplicate ports, unknown resource profiles or malformed affinity assignments.
pub fn validate(root: &Path, fixture: &VmFixture) -> Result<(), String> {
    if !root.is_absolute()
        || root.to_str().is_none()
        || root.to_string_lossy().contains([',', '\n', '\r'])
    {
        return Err("fixture root must be an absolute QEMU-safe UTF-8 path".to_owned());
    }
    let links = [
        link_port(&fixture.landing, "data0", "listen")?,
        link_port(&fixture.landing, "data1", "listen")?,
    ];
    if link_port(&fixture.line_a, "data0", "connect")? != links[0]
        || link_port(&fixture.line_b, "data0", "connect")? != links[1]
    {
        return Err("LINE data links do not terminate at owned LANDING".to_owned());
    }
    let mut ports: BTreeSet<u16> = links.into_iter().collect();
    if ports.len() != 2 {
        return Err("duplicated data ports".to_owned());
    }
    let mut cores = BTreeSet::new();
    for (role, spec) in roles(fixture) {
        if (spec.cpus, spec.ram_mib)
            != if role == "landing" {
                (2, 2048)
            } else {
                (1, 1024)
            }
        {
            return Err(format!("{role}: unexpected ordinary resource profile"));
        }
        for core in spec.cores.split(',') {
            let core: u16 = core.parse().map_err(|_| "invalid CPU affinity")?;
            if !cores.insert(core) {
                return Err("VM CPU affinities overlap".to_owned());
            }
        }
        if spec.cores.split(',').count() != usize::from(spec.cpus) {
            return Err(format!("{role}: CPU affinity does not match vCPUs"));
        }
        if spec.ssh_port == 0
            || spec.socks_port == 0
            || !ports.insert(spec.ssh_port)
            || !ports.insert(spec.socks_port)
        {
            return Err("missing or duplicated control port".to_owned());
        }
        if spec.command != expected_command(root, role, spec, links) {
            return Err(format!(
                "{role}: argv differs from the isolated owned-fixture contract"
            ));
        }
    }
    Ok(())
}

fn roles(fixture: &VmFixture) -> [(&str, &VmSpec); 3] {
    [
        ("landing", &fixture.landing),
        ("line-a", &fixture.line_a),
        ("line-b", &fixture.line_b),
    ]
}

/// Produce the bounded qualification launch commands after validation.
///
/// Disks use QEMU's temporary snapshot mode: previous fixture evidence and guest
/// files remain immutable. Each invocation uses fresh serial paths and disables the unused QMP/monitor endpoints.
///
/// # Errors
/// Returns the same fixture-validation errors as [`validate`].
pub fn launch_commands(
    root: &Path,
    fixture: &VmFixture,
    output: &Path,
    constrained: bool,
) -> Result<Vec<(String, Vec<String>)>, String> {
    validate(root, fixture)?;
    if !output.is_absolute()
        || output.to_str().is_none()
        || output.to_string_lossy().contains([',', '\n', '\r'])
    {
        return Err("fixture output must be an absolute QEMU-safe UTF-8 path".to_owned());
    }
    let mut commands = Vec::new();
    for (role, spec) in roles(fixture) {
        let mut command = spec.command.clone();
        for index in 0..command.len().saturating_sub(1) {
            match command[index].as_str() {
                "-serial" => {
                    command[index + 1] = format!(
                        "file:{}",
                        output.join(format!("{role}-serial.log")).display()
                    );
                }
                "-smp" if constrained && role == "landing" => {
                    "1".clone_into(&mut command[index + 1]);
                }
                "-m" if constrained && role == "landing" => {
                    "1024".clone_into(&mut command[index + 1]);
                }
                "-c" if constrained && role == "landing" => {
                    spec.cores
                        .split(',')
                        .next()
                        .expect("validated affinity")
                        .clone_into(&mut command[index + 1]);
                }
                _ => {}
            }
        }
        let qmp = command
            .iter()
            .position(|arg| arg == "-qmp")
            .expect("validated QMP argv");
        command.drain(qmp..qmp + 2);
        command.extend([
            "-monitor".to_owned(),
            "none".to_owned(),
            "-snapshot".to_owned(),
        ]);
        commands.push((role.to_owned(), command));
    }
    Ok(commands)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(root: &Path) -> VmFixture {
        let spec = |cpus, ram_mib, cores: &str, ssh_port, socks_port| VmSpec {
            cpus,
            ram_mib,
            cores: cores.to_owned(),
            ssh_port,
            socks_port,
            command: Vec::new(),
        };
        let mut fixture = VmFixture {
            landing: spec(2, 2048, "4,6", 2201, 1081),
            line_a: spec(1, 1024, "0", 2202, 1082),
            line_b: spec(1, 1024, "2", 2203, 1083),
        };
        fixture.landing.command = expected_command(root, "landing", &fixture.landing, [3101, 3102]);
        fixture.line_a.command = expected_command(root, "line-a", &fixture.line_a, [3101, 3102]);
        fixture.line_b.command = expected_command(root, "line-b", &fixture.line_b, [3101, 3102]);
        fixture
    }

    #[test]
    fn launch_profiles_preserve_disks_and_disable_unused_control_endpoints() {
        let root = Path::new("/fixture");
        let fixture = fixture(root);
        let original = fixture.landing.command.clone();
        for constrained in [false, true] {
            let commands =
                launch_commands(root, &fixture, Path::new("/fresh-run"), constrained).unwrap();
            let landing = &commands[0].1;
            assert!(landing.iter().any(|arg| arg == "-snapshot"));
            assert!(!landing.iter().any(|arg| arg == "-qmp"));
            assert!(landing.windows(2).any(|pair| pair == ["-monitor", "none"]));
            assert!(
                landing
                    .windows(2)
                    .any(|pair| pair == ["-smp", if constrained { "1" } else { "2" }])
            );
            assert!(
                landing
                    .windows(2)
                    .any(|pair| pair == ["-m", if constrained { "1024" } else { "2048" }])
            );
            assert!(
                landing
                    .windows(2)
                    .any(|pair| pair == ["-serial", "file:/fresh-run/landing-serial.log"])
            );
            assert!(
                landing
                    .iter()
                    .any(|arg| arg == "file=/fixture/landing/disk.qcow2,if=virtio,format=qcow2")
            );
        }
        assert_eq!(fixture.landing.command, original);
        assert!(launch_commands(root, &fixture, Path::new("/unsafe,run"), false).is_err());
    }

    #[test]
    fn only_the_owned_loopback_fixture_can_execute() {
        let root = Path::new("/fixture");
        validate(root, &fixture(root)).unwrap();
        for injected in ["-incoming", "-daemonize", "-chardev", "-monitor"] {
            let mut changed = fixture(root);
            changed.landing.command.push(injected.to_owned());
            assert!(validate(root, &changed).is_err(), "{injected}");
        }
        let mut changed = fixture(root);
        for arg in &mut changed.line_a.command {
            *arg = arg.replace("127.0.0.1", "192.0.2.100");
        }
        assert!(validate(root, &changed).is_err());
        let mut changed = fixture(root);
        changed.line_a.cores = "4".to_owned();
        assert!(validate(root, &changed).is_err());
    }
}
