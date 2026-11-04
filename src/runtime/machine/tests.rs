use super::{
    MachineReport, MemoryPlan, ResourcePressure, effective_memory_total, parse_cgroup_limit,
    parse_cpu_max, parse_meminfo_total, soft_limit_raise_target,
};

#[cfg(target_os = "linux")]
#[test]
fn an_unreadable_cgroup_sample_falls_back_to_resident_set_size() {
    let sampler = super::MemorySampler::CgroupV2(std::path::PathBuf::from(
        "/nonexistent/rust-reality/memory.current",
    ));
    let sample = sampler.sample();
    assert!(
        sample.is_some_and(|reading| {
            reading.bytes > 0 && reading.source == super::MemorySampleSource::ResidentSet
        }),
        "a missing cgroup file must fall back to a live RSS sample, got {sample:?}"
    );
}

#[test]
fn effective_cpus_apply_a_finite_cgroup_quota() {
    let mut report = MachineReport::conservative();
    report.available_cpus = 16;
    report.cpu_quota_us = Some(250_000);
    report.cpu_period_us = Some(100_000);
    assert_eq!(report.effective_cpus(), 3, "the quota rounds up");

    report.cpu_quota_us = Some(50_000);
    assert_eq!(
        report.effective_cpus(),
        1,
        "a sub-CPU quota still leaves one CPU"
    );

    report.cpu_quota_us = Some(1_600_000);
    assert_eq!(
        report.effective_cpus(),
        16,
        "a quota above the visible count never inflates it"
    );
}

#[test]
fn effective_cpus_ignore_an_unusable_quota() {
    let mut report = MachineReport::conservative();
    report.available_cpus = 8;
    assert_eq!(report.effective_cpus(), 8, "no quota detected");

    report.cpu_quota_us = Some(200_000);
    assert_eq!(
        report.effective_cpus(),
        8,
        "a quota without a period is unusable"
    );

    report.cpu_period_us = Some(0);
    assert_eq!(
        report.effective_cpus(),
        8,
        "a zero period cannot divide and is ignored"
    );
}

#[test]
fn the_raise_target_is_the_hard_limit_only_when_it_is_higher() {
    assert_eq!(soft_limit_raise_target(1_024, 1_048_576), Some(1_048_576));
    assert_eq!(soft_limit_raise_target(1_048_576, 1_048_576), None);
    assert_eq!(
        soft_limit_raise_target(65_536, u64::MAX),
        Some(u64::MAX),
        "an unlimited hard limit is still a valid raise target"
    );
    assert_eq!(soft_limit_raise_target(2_048, 1_024), None);
}

#[test]
fn cgroup_limits_treat_max_as_unbounded() {
    assert_eq!(parse_cgroup_limit("max\n"), None);
    assert_eq!(parse_cgroup_limit("2147483648\n"), Some(2_147_483_648));
    assert_eq!(parse_cgroup_limit("garbage"), None);
}

#[test]
fn cpu_max_parses_quota_and_period() {
    assert_eq!(
        parse_cpu_max("200000 100000"),
        (Some(200_000), Some(100_000))
    );
    assert_eq!(parse_cpu_max("max 100000"), (None, Some(100_000)));
    assert_eq!(parse_cpu_max("garbage"), (None, None));
}

#[test]
fn meminfo_total_is_reported_in_bytes() {
    let contents = "MemTotal:       16384000 kB\nMemFree:         1024000 kB\n";
    assert_eq!(parse_meminfo_total(contents), Some(16_384_000 * 1_024));
    assert_eq!(parse_meminfo_total("MemFree: 1 kB\n"), None);
}

#[test]
fn the_effective_total_prefers_the_tighter_boundary() {
    assert_eq!(effective_memory_total(Some(1_000), Some(4_000)), 1_000);
    assert_eq!(effective_memory_total(Some(8_000), Some(4_000)), 4_000);
    assert_eq!(effective_memory_total(None, Some(4_000)), 4_000);
    assert_eq!(effective_memory_total(Some(8_000), None), 8_000);
    assert_eq!(effective_memory_total(None, None), 0);
}

#[test]
fn the_memory_plan_uses_the_documented_fractions() {
    let plan = MemoryPlan::derive(1_000_000).expect("a known total must produce a plan");
    assert_eq!(plan.usable(), 800_000);
    assert_eq!(plan.pressure_enter(), 600_000);
    assert_eq!(plan.pressure_exit(), 500_000);
    assert_eq!(plan.critical_enter(), 900_000);
    assert_eq!(plan.critical_exit(), 800_000);
    assert!(MemoryPlan::derive(0).is_none());
}

#[test]
fn the_memory_plan_watermarks_are_strictly_ordered() {
    for total in [1_u64, 64, 1_000, 1 << 20, 1 << 30, u64::MAX / 2] {
        let Some(plan) = MemoryPlan::derive(total) else {
            continue;
        };
        assert!(plan.pressure_exit() <= plan.pressure_enter());
        assert!(plan.pressure_enter() <= plan.critical_exit());
        assert!(plan.critical_exit() <= plan.critical_enter());
        assert!(plan.critical_enter() <= plan.total());
    }
}

#[test]
fn memory_hysteresis_does_not_flap_around_any_threshold() {
    let plan = MemoryPlan::derive(1_000_000).expect("a known total must produce a plan");

    let mut state = ResourcePressure::Normal;
    state = plan.classify(state, 599_999);
    assert_eq!(state, ResourcePressure::Normal);
    state = plan.classify(state, 600_000);
    assert_eq!(state, ResourcePressure::Pressure);

    // Hovering exactly on the enter threshold must not oscillate.
    state = plan.classify(state, 600_000);
    assert_eq!(state, ResourcePressure::Pressure);
    state = plan.classify(state, 550_000);
    assert_eq!(
        state,
        ResourcePressure::Pressure,
        "the exit watermark is 50%, not the 60% enter point"
    );
    state = plan.classify(state, 500_000);
    assert_eq!(state, ResourcePressure::Normal);

    state = plan.classify(state, 900_000);
    assert_eq!(
        state,
        ResourcePressure::Pressure,
        "escalation also advances one tier per sample"
    );
    state = plan.classify(state, 900_000);
    assert_eq!(state, ResourcePressure::Critical);
    state = plan.classify(state, 850_000);
    assert_eq!(
        state,
        ResourcePressure::Critical,
        "critical holds until usage returns inside the usable budget"
    );
    state = plan.classify(state, 800_000);
    assert_eq!(state, ResourcePressure::Pressure);
}

#[test]
fn memory_transitions_never_skip_a_tier_downward() {
    let plan = MemoryPlan::derive(1_000_000).expect("a known total must produce a plan");
    let state = plan.classify(ResourcePressure::Critical, 0);
    assert_eq!(
        state,
        ResourcePressure::Pressure,
        "recovery de-escalates one tier per sample, never straight to normal"
    );
}

#[test]
fn a_conservative_report_disables_the_memory_dimension() {
    let report = MachineReport::conservative();
    assert_eq!(report.memory_total, 0);
    assert!(MemoryPlan::derive(report.memory_total).is_none());
}

#[test]
fn cgroup_detection_reads_synthetic_files() {
    let root = test_directory("cgroup");
    let cgroup_dir = root.join("sys/fs/cgroup/machine.slice/rust-reality.service");
    std::fs::create_dir_all(&cgroup_dir).expect("cgroup directory must be created");
    std::fs::write(cgroup_dir.join("cpu.max"), "200000 100000\n").expect("cpu.max");
    std::fs::write(cgroup_dir.join("cpuset.cpus.effective"), "0-3\n").expect("cpuset");
    std::fs::write(cgroup_dir.join("memory.current"), "1048576\n").expect("memory.current");
    std::fs::write(cgroup_dir.join("memory.high"), "max\n").expect("memory.high");
    std::fs::write(cgroup_dir.join("memory.max"), "2147483648\n").expect("memory.max");
    let proc_cgroup = root.join("proc/self/cgroup");
    std::fs::create_dir_all(proc_cgroup.parent().expect("parent exists"))
        .expect("proc directory must be created");
    std::fs::write(&proc_cgroup, "0::/machine.slice/rust-reality.service\n").expect("proc cgroup");

    let reading = super::read_cgroup_v2(&proc_cgroup, &root.join("sys/fs/cgroup"))
        .expect("a v2 cgroup must be detected");
    assert_eq!(reading.cpu_quota_us, Some(200_000));
    assert_eq!(reading.cpu_period_us, Some(100_000));
    assert_eq!(reading.cpuset_effective.as_deref(), Some("0-3"));
    assert_eq!(reading.memory_current, Some(1_048_576));
    assert_eq!(reading.memory_high, None, "max is unbounded");
    assert_eq!(reading.memory_max, Some(2_147_483_648));
    cleanup(&root);
}

#[test]
fn cgroup_detection_degrades_when_the_hierarchy_is_absent() {
    let root = test_directory("no-cgroup");
    let proc_cgroup = root.join("proc/self/cgroup");
    std::fs::create_dir_all(proc_cgroup.parent().expect("parent exists"))
        .expect("proc directory must be created");
    std::fs::write(&proc_cgroup, "1:name=systemd:/\n0::/\n").expect("proc cgroup");

    assert!(
        super::read_cgroup_v2(&proc_cgroup, &root.join("sys/fs/cgroup")).is_none(),
        "a missing cgroup directory must not fabricate readings"
    );
    cleanup(&root);
}

#[test]
fn assembly_combines_readings_without_touching_the_host() {
    let cgroup = super::CgroupReading {
        cpu_quota_us: Some(400_000),
        cpu_period_us: Some(100_000),
        cpuset_effective: Some("0-7".to_owned()),
        memory_current: Some(65_536),
        memory_high: None,
        memory_max: Some(8_000_000),
    };
    let report = MachineReport::assemble(
        Some((1_024, 1_048_576)),
        Some((8_388_608, 8_388_608)),
        Some(16_000_000),
        Some(cgroup),
        8,
    );
    assert_eq!(report.fd_soft_limit, 1_024);
    assert_eq!(report.fd_hard_limit, 1_048_576);
    assert_eq!(report.memlock_soft_limit, 8_388_608);
    assert_eq!(report.available_cpus, 8);
    assert_eq!(report.cpu_quota_us, Some(400_000));
    assert_eq!(report.cpuset_effective.as_deref(), Some("0-7"));
    assert_eq!(report.memory_source, "cgroup_v2");
    assert_eq!(report.memory_total, 8_000_000, "the cgroup cap is tighter");
    assert_eq!(report.memory_current, Some(65_536));

    let fallback = MachineReport::assemble(None, None, Some(16_000_000), None, 2);
    assert_eq!(
        fallback.fd_soft_limit, 1_024,
        "unreadable limits stay conservative"
    );
    assert_eq!(fallback.memory_source, "proc_meminfo");
    assert_eq!(fallback.memory_total, 16_000_000);
}

#[cfg(target_os = "linux")]
#[test]
fn host_detection_produces_a_coherent_report() {
    let report = MachineReport::detect();
    assert!(report.fd_soft_limit > 0);
    assert!(
        report.fd_soft_limit <= report.fd_hard_limit,
        "a soft limit above the hard limit would make every derived budget unsound"
    );
    assert!(report.available_cpus > 0);
    match report.memory_source {
        "cgroup_v2" | "proc_meminfo" => assert!(report.memory_total > 0),
        "unavailable" => assert_eq!(report.memory_total, 0),
        other => panic!("unexpected memory source {other}"),
    }
}

fn test_directory(name: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "rust-reality-machine-test-{name}-{}",
        std::process::id()
    ));
    let _ignored = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("unique test directory must be created");
    path
}

fn cleanup(directory: &std::path::Path) {
    std::fs::remove_dir_all(directory).expect("test directory must be removed");
}
