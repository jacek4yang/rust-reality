//! CLI dispatch for `cargo dev bench` subcommands.
//!
//! Keeps typed clap command handling out of `main` so bench domain modules
//! (`bench::*`) stay focused on suites, evidence, and measurement while this
//! module owns `ExitCode` mapping and flag gating for the bench surface.

use std::{
    path::{Path, PathBuf},
    process::ExitCode,
};

use crate::bench;
use crate::cli::BenchCommand;
use crate::perf;
use crate::process;

/// Dispatches a `cargo dev bench` subcommand.
///
/// `list` shows the suite catalogue and the legacy scripts each supersedes.
/// `environment` runs the typed preflight that every suite depends on: tool
/// availability, host-exclusive lock acquire/release, an ephemeral workspace and
/// loopback port reservation. It exits non-zero when the host cannot run a
/// benchmark, so it doubles as a CI-safe readiness probe.
#[allow(clippy::too_many_lines)]
pub(crate) fn run_bench(repo: &Path, command: &BenchCommand) -> ExitCode {
    match command {
        BenchCommand::StabilityBindPackage(plan) => match bench::stability::package_bind::run(plan)
        {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        },
        BenchCommand::StabilityCheck(plan) => {
            match bench::stability::qualification::run(repo, plan) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("{error}");
                    ExitCode::FAILURE
                }
            }
        }
        BenchCommand::StabilityRun(plan) => match bench::stability::campaign::run(repo, plan) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        },
        BenchCommand::StabilityUdpGuest(plan) => {
            match bench::stability::udp_guest::run(repo, plan) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("{error}");
                    ExitCode::FAILURE
                }
            }
        }
        BenchCommand::StabilityGuest(plan) => match bench::stability::guest::run(plan) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        },
        BenchCommand::StabilityFixture {
            fixture,
            output,
            constrained,
        } => {
            match bench::stability::fixture::Machines::start(fixture, output, *constrained)
                .and_then(|mut machines| machines.finalize())
            {
                Ok(()) => {
                    println!(
                        "Owned fixture boot and process identities verified; candidate qualification NOT RUN."
                    );
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("{error}");
                    ExitCode::FAILURE
                }
            }
        }
        BenchCommand::StabilityObserve { pid, log } => {
            match bench::stability::collect::observe(*pid, log) {
                Ok(observation) => {
                    println!(
                        "{}",
                        serde_json::to_string(&observation).expect("serializable observation")
                    );
                    if observation.errors.is_empty() && observation.closed_during_read.is_empty() {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::FAILURE
                    }
                }
                Err(error) => {
                    eprintln!("{error}");
                    ExitCode::FAILURE
                }
            }
        }
        BenchCommand::StabilityEvaluate { evidence } => {
            match bench::stability::evaluate_path(evidence) {
                Ok(report) => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&report).expect("serializable verdict")
                    );
                    if report.verdict == bench::stability::evaluate::Verdict::Pass {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::FAILURE
                    }
                }
                Err(error) => {
                    println!(
                        "{}",
                        serde_json::json!({"verdict": "INVALID", "error": error})
                    );
                    ExitCode::FAILURE
                }
            }
        }
        BenchCommand::StabilityRepro(plan) => match bench::stability::repro::run(plan) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("bench stability-repro: {error}");
                ExitCode::FAILURE
            }
        },
        BenchCommand::StabilityMergeCells(plan) => match bench::stability::merge::run(plan) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("bench stability-merge-cells: {error}");
                ExitCode::FAILURE
            }
        },
        BenchCommand::ShapeProxy {
            listen_port,
            upstream_port,
            max_shaped,
            max_accepted,
        } => match bench::tls_shape::run_shape_proxy(
            *listen_port,
            *upstream_port,
            *max_shaped,
            *max_accepted,
        ) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("bench shape-proxy: {error}");
                ExitCode::FAILURE
            }
        },
        BenchCommand::Origin {
            listen_address,
            port,
            payload_dir,
            put_log,
            access_log,
            label,
            tls_cert,
            tls_key,
            tls_alpn,
        } => {
            let tls = match (tls_cert, tls_key) {
                (None, None) => None,
                (Some(cert), Some(key)) => {
                    let (certificate_pem, key_pem) = match (std::fs::read(cert), std::fs::read(key))
                    {
                        (Ok(certificate_pem), Ok(key_pem)) => (certificate_pem, key_pem),
                        (error, other) => {
                            let failed = match (error.is_err(), other.is_err()) {
                                (true, _) => error.unwrap_err(),
                                (_, true) => other.unwrap_err(),
                                _ => std::io::Error::other("unreadable TLS material"),
                            };
                            eprintln!("bench origin: could not read TLS material: {failed}");
                            return ExitCode::FAILURE;
                        }
                    };
                    let alpn = tls_alpn
                        .split(',')
                        .map(str::trim)
                        .filter(|protocol| !protocol.is_empty())
                        .map(str::to_owned)
                        .collect();
                    Some(bench::origin_server::TlsOptions {
                        certificate_pem,
                        key_pem,
                        alpn,
                    })
                }
                _ => {
                    eprintln!("bench origin: --tls-cert and --tls-key must be given together");
                    return ExitCode::from(2);
                }
            };
            let address = match listen_address.parse::<std::net::IpAddr>() {
                Ok(address) => address,
                Err(error) => {
                    eprintln!("bench origin: --listen-address must be numeric: {error}");
                    return ExitCode::from(2);
                }
            };
            if let Some(options) = tls.as_ref()
                && let Err(error) = bench::origin_server::tls_acceptor(options)
            {
                eprintln!("bench origin: {error}");
                return ExitCode::from(2);
            }
            let listener = match std::net::TcpListener::bind((address, *port)) {
                Ok(listener) => listener,
                Err(error) => {
                    eprintln!("bench origin: could not bind {address}:{port}: {error}");
                    return ExitCode::FAILURE;
                }
            };
            if let Ok(address) = listener.local_addr() {
                println!("READY {address}");
                let _ = std::io::Write::flush(&mut std::io::stdout());
            }
            match bench::origin_server::serve_with_tls(
                &listener,
                payload_dir,
                Some(put_log),
                access_log.as_deref(),
                label,
                tls.as_ref(),
            ) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("bench origin: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        BenchCommand::Echo { port } => {
            let listener = match std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, *port))
            {
                Ok(listener) => listener,
                Err(error) => {
                    eprintln!("bench echo: could not bind 127.0.0.1:{port}: {error}");
                    return ExitCode::FAILURE;
                }
            };
            if let Ok(address) = listener.local_addr() {
                println!("READY {address}");
                let _ = std::io::Write::flush(&mut std::io::stdout());
            }
            match bench::echo::serve(&listener) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("bench echo: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        BenchCommand::SocksServer {
            listen,
            port,
            fixed_target,
        } => {
            let listener = match std::net::TcpListener::bind((*listen, *port)) {
                Ok(listener) => listener,
                Err(error) => {
                    eprintln!("bench socks-server: could not bind {listen}:{port}: {error}");
                    return ExitCode::FAILURE;
                }
            };
            if let Ok(address) = listener.local_addr() {
                println!("READY {address}");
                let _ = std::io::Write::flush(&mut std::io::stdout());
            }
            match bench::socks_server::serve_with_target(&listener, *fixed_target) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("bench socks-server: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        BenchCommand::Deployment {
            rust_bin,
            xray_bin,
            out_dir,
            run_id,
            plan,
            keep_work,
        } => {
            let kind = match bench::deployment::PlanKind::parse(plan) {
                Ok(kind) => kind,
                Err(error) => {
                    eprintln!("bench deployment: {error}");
                    return ExitCode::from(2);
                }
            };
            let run = bench::deployment::RunPlan {
                repo: repo.to_path_buf(),
                rust_bin: rust_bin.clone(),
                xray_bin: xray_bin.clone(),
                out_dir: out_dir.clone(),
                run_id: run_id.clone(),
                program: bench::deployment::Plan::reviewed(kind),
                keep_work: *keep_work,
            };
            match bench::deployment::run(&run) {
                Ok(outcome) => {
                    println!("summary: {}", outcome.summary_path.display());
                    println!("completion: {}", outcome.marker_path.display());
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("bench deployment: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        BenchCommand::Profiles {
            rust_bin,
            rust_sha256,
            expected_source_commit,
            xray_bin,
            xray_sha256,
            out_dir,
            run_id,
            asset_cache_dir,
            classes,
            only,
            standard_comparison,
            connections,
            churn_samples,
            download_samples,
            download_mib,
            hold_seconds,
            settle_seconds,
            ladder_levels,
            tuned_levels,
            identity_check_only,
            keep_work,
        } => run_bench_profiles(&bench::profiles::Plan {
            repo: repo.to_path_buf(),
            rust_bin: rust_bin.clone(),
            rust_sha256: rust_sha256.clone(),
            expected_source_commit: expected_source_commit.clone(),
            xray_bin: xray_bin.clone(),
            xray_sha256: xray_sha256.clone(),
            out_dir: out_dir.clone(),
            run_id: run_id.clone(),
            asset_cache_dir: asset_cache_dir.clone(),
            classes: classes.clone(),
            only: only.clone(),
            standard_comparison: *standard_comparison,
            connections: *connections,
            churn_samples: *churn_samples,
            download_samples: *download_samples,
            download_mib: *download_mib,
            hold_seconds: *hold_seconds,
            settle_seconds: *settle_seconds,
            ladder_levels: ladder_levels.clone(),
            tuned_levels: tuned_levels.clone(),
            identity_check_only: *identity_check_only,
            keep_work: *keep_work,
        }),
        BenchCommand::Workload {
            socks_port,
            origin_port,
            connections,
            concurrencies,
            samples,
            implementation,
            block,
            position,
            record_latencies,
            output,
        } => run_bench_workload(
            &bench::workload::SetupRatePlan {
                socks_port: *socks_port,
                origin_port: *origin_port,
                connections: *connections,
                concurrencies: concurrencies
                    .split_whitespace()
                    .filter_map(|word| word.parse().ok())
                    .collect(),
                samples: *samples,
                implementation: implementation.clone(),
                block: *block,
                position: *position,
                record_latencies: *record_latencies,
            },
            output.as_deref(),
        ),
        BenchCommand::FallbackWorkload {
            server_port,
            payload_mib,
            concurrencies,
            samples,
            implementation,
            block,
            position,
            output,
        } => run_bench_fallback_workload(
            &bench::throughput::ThroughputPlan {
                server_port: *server_port,
                payload_mib: *payload_mib,
                concurrencies: concurrencies
                    .split_whitespace()
                    .filter_map(|word| word.parse().ok())
                    .collect(),
                samples: *samples,
                implementation: implementation.clone(),
                block: *block,
                position: *position,
            },
            output.as_deref(),
        ),
        BenchCommand::List => {
            println!("{:<20} supersedes            summary", "suite");
            println!("{}", "-".repeat(80));
            for suite in &bench::runner::SUITES {
                println!(
                    "{:<20} {:<20}  {}",
                    suite.id,
                    suite.supersedes.unwrap_or("native Rust"),
                    suite.summary
                );
            }
            ExitCode::SUCCESS
        }
        BenchCommand::Environment => {
            let report = bench::runner::preflight(&bench::runner::COMMON_TOOLS);
            println!("tools present : {}", report.present_tools.join(", "));
            if report.missing_tools.is_empty() {
                println!("tools missing : none");
            } else {
                println!("tools missing : {}", report.missing_tools.join(", "));
            }
            println!(
                "host lock     : {}",
                report.lock_identity.as_deref().map_or_else(
                    || if report.lock_ok { "ok" } else { "unavailable" }.to_owned(),
                    |identity| format!("ok (device:inode {identity})")
                )
            );
            println!(
                "workspace     : {}",
                if report.workspace_ok {
                    "ok"
                } else {
                    "unavailable"
                }
            );
            println!("ports reserved: {}", report.reserved_ports);
            if report.is_ready() {
                println!("\nthis host can run benchmarks");
                ExitCode::SUCCESS
            } else {
                eprintln!("\nthe benchmark environment is not ready");
                ExitCode::FAILURE
            }
        }
        BenchCommand::Run {
            suite,
            rust_bin,
            xray_bin,
            setup_server_bin,
            client_fingerprint,
            baseline_client_fingerprint,
            client_data_mib,
            runs,
            bytes,
            url,
            cover_target,
            cover_sni,
            max_time,
            out_dir,
            samples,
            concurrency,
            payload_mib,
            blocks,
            connections,
            concurrencies,
            abba_start,
            measure_mode,
            profile,
            profile_record_seconds,
            profile_event,
            profile_frequency,
            profile_call_graph,
            run_id,
            baseline_bin,
            baseline_identity,
            baseline_commit,
            baseline_cover_mode,
            candidate_cover_mode,
            cover_netem_rtt_ms,
            payload_mib_fallback,
            relay_splice,
            relay_pipe_pool,
            relay_buffer_kib,
            payloads,
            large_concurrencies,
            large_payload_mib,
            samples_large,
            integrity_mib,
            cells,
            skip,
            manage_pipe_pages,
            warm_samples,
            burst_conns,
            rule_scales,
            setup_connections,
            setup_concurrency,
            internet_url,
            openssl_bin,
            tls_shape_samples,
            tls_ciphersuites,
            tls_groups,
            tls_alpn,
            tls_middlebox,
            tls_max_fragment,
            tls_split_fragment,
            tls_padding,
            tls_tcp_nodelay,
            ipv6_phases,
            global_v6,
            nofile_limit,
            max_held_connections,
            storm_connections,
            soak_implementation,
            soak_seconds,
            soak_round_sleep_ms,
            soak_min_rounds,
            soak_distributed_interval_seconds,
            deployment_plan,
            keep_work,
        } => {
            if suite != "client-setup-rate"
                && (setup_server_bin.is_some()
                    || client_fingerprint.is_some()
                    || baseline_client_fingerprint.is_some()
                    || client_data_mib.is_some())
            {
                eprintln!("client setup options require --suite client-setup-rate");
                return ExitCode::from(2);
            }
            if *profile && !matches!(suite.as_str(), "setup-rate" | "vision-direct") {
                eprintln!(
                    "bench run: --profile is supported only for setup-rate and vision-direct"
                );
                return ExitCode::from(2);
            }
            let profile = profile.then(|| perf::hotspot::BenchmarkProfile {
                record_seconds: *profile_record_seconds,
                event: profile_event.clone(),
                frequency: *profile_frequency,
                call_graph: profile_call_graph.clone(),
            });
            if let Some(profile) = &profile
                && let Err(error) = perf::hotspot::validate_benchmark_profile(profile)
            {
                eprintln!("bench run: {error}");
                return ExitCode::from(2);
            }
            if suite == "tls-shape" {
                return run_bench_tls_shape(
                    repo,
                    rust_bin,
                    xray_bin,
                    openssl_bin,
                    out_dir.as_deref(),
                    run_id.as_deref(),
                    *tls_shape_samples,
                    bench::tls_shape_suite::ReferenceOptions {
                        ciphersuites: tls_ciphersuites.clone(),
                        groups: tls_groups.clone(),
                        alpn: tls_alpn.clone(),
                        middlebox: *tls_middlebox,
                        max_fragment: *tls_max_fragment,
                        split_fragment: *tls_split_fragment,
                        padding: *tls_padding,
                        tcp_nodelay: *tls_tcp_nodelay,
                    },
                );
            }
            if suite == "ipv6" {
                return run_bench_ipv6(
                    repo,
                    rust_bin,
                    xray_bin,
                    openssl_bin,
                    out_dir.as_deref(),
                    run_id.as_deref(),
                    ipv6_phases,
                    global_v6.as_deref(),
                    *payload_mib,
                    internet_url.as_deref(),
                );
            }
            if suite == "no-ccs-interop" {
                return run_bench_no_ccs(
                    repo,
                    rust_bin,
                    xray_bin,
                    openssl_bin,
                    out_dir.as_deref(),
                    run_id.as_deref(),
                );
            }
            if suite == "descriptor-pressure" {
                return run_bench_pressure(
                    repo,
                    rust_bin,
                    xray_bin,
                    openssl_bin,
                    out_dir.as_deref(),
                    run_id.as_deref(),
                    *nofile_limit,
                    *max_held_connections,
                    *storm_connections,
                );
            }
            if suite == "soak" {
                if !matches!(soak_implementation.as_str(), "rust" | "xray") {
                    eprintln!("bench run soak: --soak-implementation must be rust or xray");
                    return ExitCode::from(2);
                }
                return run_bench_soak(
                    soak_implementation,
                    rust_bin,
                    xray_bin,
                    openssl_bin,
                    out_dir.as_deref(),
                    run_id.as_deref(),
                    *soak_seconds,
                    *soak_round_sleep_ms,
                    *soak_min_rounds,
                    *soak_distributed_interval_seconds,
                );
            }
            if suite == "deployment" {
                let kind = match bench::deployment::PlanKind::parse(deployment_plan) {
                    Ok(kind) => kind,
                    Err(error) => {
                        eprintln!("bench run deployment: {error}");
                        return ExitCode::from(2);
                    }
                };
                let stamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |duration| duration.as_secs());
                let run_id = run_id.clone().unwrap_or_else(|| {
                    format!("deployment-{}-{stamp}-{}", kind.name(), std::process::id())
                });
                let out_dir = out_dir.clone().unwrap_or_else(|| {
                    std::env::current_dir()
                        .unwrap_or_else(|_| PathBuf::from("."))
                        .join("benchmarks/evidence/releases")
                        .join(&run_id)
                });
                let run = bench::deployment::RunPlan {
                    repo: repo.to_path_buf(),
                    rust_bin: rust_bin.clone(),
                    xray_bin: xray_bin.clone(),
                    out_dir,
                    run_id,
                    program: bench::deployment::Plan::reviewed(kind),
                    keep_work: *keep_work,
                };
                return match bench::deployment::run(&run) {
                    Ok(outcome) => {
                        println!("summary: {}", outcome.summary_path.display());
                        println!("completion: {}", outcome.marker_path.display());
                        ExitCode::SUCCESS
                    }
                    Err(error) => {
                        eprintln!("bench run deployment: {error}");
                        ExitCode::FAILURE
                    }
                };
            }
            if suite == "xray-interop" {
                return run_bench_interop(
                    repo,
                    rust_bin,
                    xray_bin,
                    out_dir.as_deref(),
                    run_id.as_deref(),
                    cover_target,
                    cover_sni,
                    internet_url.as_deref(),
                );
            }
            if suite == "vless-encryption" {
                return run_bench_vless(
                    repo,
                    xray_bin,
                    out_dir.as_deref(),
                    run_id.as_deref(),
                    *samples,
                    *concurrency,
                    *payload_mib,
                    *setup_connections,
                    *setup_concurrency,
                    cover_target,
                    cover_sni,
                );
            }
            if suite == "routing" {
                return run_bench_routing(
                    repo,
                    rust_bin,
                    xray_bin,
                    out_dir.as_deref(),
                    run_id.as_deref(),
                    rule_scales,
                    *blocks,
                    *samples,
                    *connections,
                    concurrencies,
                );
            }
            if suite == "dns" {
                return run_bench_dns(
                    repo,
                    rust_bin,
                    xray_bin,
                    out_dir.as_deref(),
                    run_id.as_deref(),
                    *samples,
                    *warm_samples,
                    *connections,
                    concurrencies,
                    *burst_conns,
                );
            }
            if suite == "matrix" {
                return run_bench_matrix(
                    repo,
                    &MatrixArgs {
                        baseline_bin: baseline_bin.as_deref(),
                        final_bin: rust_bin,
                        xray_bin,
                        out_dir: out_dir.as_deref(),
                        run_id: run_id.as_deref(),
                        cover_target,
                        cover_sni,
                        payloads,
                        concurrencies,
                        large_concurrencies,
                        large_payload_mib: *large_payload_mib,
                        samples: *samples,
                        samples_large: *samples_large,
                        integrity_mib: *integrity_mib,
                        cells,
                        skip,
                        abba_start,
                        manage_pipe_pages: *manage_pipe_pages,
                    },
                );
            }
            if suite == "fallback" {
                return run_bench_fallback(
                    repo,
                    &FallbackArgs {
                        baseline_bin: baseline_bin.as_deref(),
                        candidate_bin: rust_bin,
                        baseline_identity: baseline_identity.as_deref(),
                        baseline_commit: baseline_commit.as_deref(),
                        out_dir: out_dir.as_deref(),
                        run_id: run_id.as_deref(),
                        blocks: *blocks,
                        samples: *samples,
                        concurrencies,
                        payload_mib: *payload_mib_fallback,
                        abba_start,
                        measure_mode,
                        relay_splice: *relay_splice,
                        relay_pipe_pool: *relay_pipe_pool,
                        relay_buffer_kib: *relay_buffer_kib,
                    },
                );
            }
            if matches!(suite.as_str(), "setup-rate" | "client-setup-rate") {
                let peer = if suite == "client-setup-rate" {
                    let Some(server) = setup_server_bin else {
                        eprintln!("client-setup-rate requires --setup-server-bin");
                        return ExitCode::from(2);
                    };
                    bench::paired::SetupPeer::RustServer {
                        binary: server.clone(),
                        baseline_fingerprint: baseline_client_fingerprint.clone(),
                        candidate_fingerprint: client_fingerprint
                            .clone()
                            .unwrap_or_else(|| "chrome".to_owned()),
                    }
                } else {
                    bench::paired::SetupPeer::XrayClient(xray_bin.clone())
                };
                return run_bench_setup_rate(
                    repo,
                    &SetupRateArgs {
                        baseline_bin: baseline_bin.as_deref(),
                        candidate_bin: rust_bin,
                        peer,
                        client_data_mib: *client_data_mib,
                        baseline_identity: baseline_identity.as_deref(),
                        baseline_commit: baseline_commit.as_deref(),
                        out_dir: out_dir.as_deref(),
                        run_id: run_id.as_deref(),
                        blocks: *blocks,
                        samples: *samples,
                        connections: *connections,
                        concurrencies,
                        abba_start,
                        baseline_cover_mode,
                        candidate_cover_mode,
                        measure_mode,
                        cover_netem_rtt_ms: *cover_netem_rtt_ms,
                        profile: profile.clone(),
                    },
                );
            }
            if suite == "setup-rate-xray" {
                return run_bench_setup_rate_xray(
                    repo,
                    rust_bin,
                    xray_bin,
                    out_dir.as_deref(),
                    run_id.as_deref(),
                    *blocks,
                    *samples,
                    *connections,
                    concurrencies,
                    abba_start,
                    measure_mode,
                );
            }
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |duration| duration.as_secs());
            let out_dir = out_dir.clone().unwrap_or_else(|| {
                std::env::current_dir()
                    .unwrap_or_else(|_| PathBuf::from("."))
                    .join(format!(
                        "benchmarks/benchmark-real-path-{stamp}-{}",
                        std::process::id()
                    ))
            });
            let benchmark_run_id = run_id.clone().unwrap_or_else(|| {
                format!(
                    "benchmark-{}-{stamp}-{}",
                    suite.replace('_', "-"),
                    std::process::id()
                )
            });
            let context = bench::suites::SuiteContext {
                rust_bin,
                xray_bin,
                cover_target: cover_target.clone(),
                cover_sni: cover_sni.clone(),
                runs: *runs,
                expected_bytes: *bytes,
                suite_id: match suite.as_str() {
                    "xray" => "benchmark-xray".to_owned(),
                    "vision-direct" => "benchmark-vision-direct".to_owned(),
                    _ => "benchmark-real-path".to_owned(),
                },
                transfer_url: url.clone().unwrap_or_else(|| {
                    format!("https://speed.cloudflare.com/__down?bytes={bytes}")
                }),
                transfer_max_time_secs: *max_time,
                out_dir,
                allow_private: suite == "xray" || suite == "vision-direct",
            };
            match suite.as_str() {
                "real-path" => run_bench_run(&context),
                "xray" => run_bench_xray(
                    &context,
                    &bench::loopback::LoopbackPlan {
                        samples: *samples,
                        concurrency: *concurrency,
                        payload_mib: *payload_mib,
                        tls_origin: false,
                        harness: "benchmark-xray".to_owned(),
                        run_id: benchmark_run_id.clone(),
                        profile: None,
                    },
                ),
                "vision-direct" => run_bench_xray(
                    &context,
                    &bench::loopback::LoopbackPlan {
                        samples: *samples,
                        concurrency: *concurrency,
                        payload_mib: *payload_mib,
                        tls_origin: true,
                        harness: "benchmark-vision-direct".to_owned(),
                        run_id: benchmark_run_id,
                        profile: profile.clone(),
                    },
                ),
                other => {
                    eprintln!(
                        "bench run: unknown suite {other} (known: real-path, xray, vision-direct)"
                    );
                    ExitCode::from(2)
                }
            }
        }
    }
}

fn run_bench_profiles(plan: &bench::profiles::Plan) -> ExitCode {
    if let Err(error) = bench::profiles::validate(plan) {
        eprintln!("bench profiles: {error}");
        return ExitCode::from(2);
    }
    match bench::profiles::run(plan) {
        Ok(outcome) if outcome.identity_only => {
            println!("profile identity preflight: PASS");
            ExitCode::SUCCESS
        }
        Ok(outcome) => {
            println!(
                "profile validation: {} ({} classes) -> {}",
                if outcome.passed { "PASS" } else { "FAIL" },
                outcome.classes,
                outcome.out_dir.display()
            );
            if outcome.passed {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(error) => {
            eprintln!("bench profiles: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Drives one fallback slot's throughput set as a child process.
fn run_bench_fallback_workload(
    plan: &bench::throughput::ThroughputPlan,
    output: Option<&std::path::Path>,
) -> ExitCode {
    if plan.concurrencies.is_empty() {
        eprintln!("bench fallback-workload: at least one concurrency level is required");
        return ExitCode::from(2);
    }
    if plan.samples == 0 {
        return match bench::throughput::warm_up(plan) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("bench fallback-workload: {error}");
                ExitCode::FAILURE
            }
        };
    }
    let rows = match bench::throughput::run_slot(plan) {
        Ok(rows) => rows,
        Err(error) => {
            eprintln!("bench fallback-workload: {error}");
            return ExitCode::FAILURE;
        }
    };
    let Some(output) = output else {
        eprintln!("bench fallback-workload: --output is required when samples are measured");
        return ExitCode::from(2);
    };
    match std::fs::write(output, bench::throughput::rows_json(&rows).to_python_json()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!(
                "bench fallback-workload: could not write {}: {error}",
                output.display()
            );
            ExitCode::FAILURE
        }
    }
}

/// Drives the DNS cold/warm/burst comparison.
#[expect(
    clippy::too_many_arguments,
    reason = "these are the suite's command-line parameters, one per flag"
)]
fn run_bench_dns(
    repo: &Path,
    rust_bin: &Path,
    xray_bin: &Path,
    out_dir: Option<&Path>,
    run_id: Option<&str>,
    samples: usize,
    warm_samples: usize,
    connections: usize,
    concurrencies: &str,
    burst_conns: usize,
) -> ExitCode {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let run_id = run_id.map_or_else(
        || format!("benchmark-dns-comparison-{stamp}-{}", std::process::id()),
        str::to_owned,
    );
    let out_dir = out_dir.map_or_else(
        || {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join("benchmarks")
                .join(&run_id)
        },
        Path::to_path_buf,
    );
    // The DNS phases run at one concurrency; the first value is the one used.
    let concurrency = concurrencies
        .split_whitespace()
        .find_map(|word| word.parse().ok())
        .unwrap_or(8);
    let suite = bench::dns::DnsSuite {
        repo: repo.to_path_buf(),
        rust_bin: rust_bin.to_path_buf(),
        xray_bin: xray_bin.to_path_buf(),
        out_dir,
        run_id,
        samples,
        warm_samples,
        connections,
        concurrency,
        burst_connections: burst_conns,
    };
    if let Err(error) = bench::dns::validate(&suite) {
        eprintln!("bench run dns: {error}");
        return ExitCode::from(2);
    }
    match bench::dns::run(&suite) {
        Ok(outcome) => {
            println!("dns comparison complete: {}", outcome.out_dir.display());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("bench run dns: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Drives the routing-rule scaling comparison.
#[expect(
    clippy::too_many_arguments,
    reason = "these are the suite's command-line parameters, one per flag"
)]
fn run_bench_routing(
    repo: &Path,
    rust_bin: &Path,
    xray_bin: &Path,
    out_dir: Option<&Path>,
    run_id: Option<&str>,
    rule_scales: &str,
    blocks: usize,
    samples: usize,
    connections: usize,
    concurrencies: &str,
) -> ExitCode {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let run_id = run_id.map_or_else(
        || {
            format!(
                "benchmark-routing-comparison-{stamp}-{}",
                std::process::id()
            )
        },
        str::to_owned,
    );
    let out_dir = out_dir.map_or_else(
        || {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join("benchmarks")
                .join(&run_id)
        },
        Path::to_path_buf,
    );
    let suite = bench::routing::RoutingSuite {
        repo: repo.to_path_buf(),
        rust_bin: rust_bin.to_path_buf(),
        xray_bin: xray_bin.to_path_buf(),
        out_dir,
        run_id,
        scales: rule_scales
            .split_whitespace()
            .filter_map(|word| word.parse().ok())
            .collect(),
        blocks,
        samples,
        connections,
        concurrency: concurrencies
            .split_whitespace()
            .find_map(|word| word.parse().ok())
            .unwrap_or(8),
    };
    if let Err(error) = bench::routing::validate(&suite) {
        eprintln!("bench run routing: {error}");
        return ExitCode::from(2);
    }
    match bench::routing::run(&suite) {
        Ok(outcome) => {
            println!("routing comparison complete: {}", outcome.out_dir.display());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("bench run routing: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Drives the VLESS-encryption A/B.
#[expect(
    clippy::too_many_arguments,
    reason = "these are the suite's command-line parameters, one per flag"
)]
fn run_bench_vless(
    repo: &Path,
    xray_bin: &Path,
    out_dir: Option<&Path>,
    run_id: Option<&str>,
    samples: usize,
    concurrency: usize,
    payload_mib: u64,
    setup_connections: usize,
    setup_concurrency: usize,
    cover_target: &str,
    cover_sni: &str,
) -> ExitCode {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let run_id = run_id.map_or_else(
        || format!("benchmark-vless-encryption-{stamp}-{}", std::process::id()),
        str::to_owned,
    );
    let out_dir = out_dir.map_or_else(
        || {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join("benchmarks")
                .join(&run_id)
        },
        Path::to_path_buf,
    );
    let suite = bench::vless::VlessSuite {
        repo: repo.to_path_buf(),
        xray_bin: xray_bin.to_path_buf(),
        out_dir,
        run_id,
        samples,
        concurrency,
        payload_mib,
        setup_connections,
        setup_concurrency,
        cover_target: cover_target.to_owned(),
        cover_sni: cover_sni.to_owned(),
    };
    if let Err(error) = bench::vless::validate(&suite) {
        eprintln!("bench run vless-encryption: {error}");
        return ExitCode::from(2);
    }
    match bench::vless::run(&suite) {
        Ok(outcome) => {
            println!(
                "vless encryption comparison complete: {}",
                outcome.out_dir.display()
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("bench run vless-encryption: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Drives the Xray interoperability gate.
#[expect(
    clippy::too_many_arguments,
    reason = "these are the gate's command-line parameters, one per flag"
)]
fn run_bench_interop(
    repo: &Path,
    rust_bin: &Path,
    xray_bin: &Path,
    out_dir: Option<&Path>,
    run_id: Option<&str>,
    cover_target: &str,
    cover_sni: &str,
    internet_url: Option<&str>,
) -> ExitCode {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let run_id = run_id.map_or_else(
        || format!("test-xray-interop-{stamp}-{}", std::process::id()),
        str::to_owned,
    );
    let out_dir = out_dir.map_or_else(
        || {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join("diagnostics")
                .join(&run_id)
        },
        Path::to_path_buf,
    );
    let suite = bench::interop::InteropSuite {
        repo: repo.to_path_buf(),
        rust_bin: rust_bin.to_path_buf(),
        xray_bin: xray_bin.to_path_buf(),
        out_dir,
        run_id,
        cover_target: cover_target.to_owned(),
        cover_sni: cover_sni.to_owned(),
        internet_url: internet_url.map(str::to_owned),
    };
    if let Err(error) = bench::interop::validate(&suite) {
        eprintln!("bench run xray-interop: {error}");
        return ExitCode::from(2);
    }
    match bench::interop::run(&suite) {
        Ok(report) => {
            println!(
                "Xray interoperability: PASS ({} bytes, internet {})",
                report.local_bytes, report.internet
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("bench run xray-interop: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Drives the no-CCS interoperability gate.
fn run_bench_no_ccs(
    repo: &Path,
    rust_bin: &Path,
    xray_bin: &Path,
    openssl_bin: &Path,
    out_dir: Option<&Path>,
    run_id: Option<&str>,
) -> ExitCode {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let run_id = run_id.map_or_else(
        || format!("test-openssl-no-ccs-interop-{stamp}-{}", std::process::id()),
        str::to_owned,
    );
    let out_dir = out_dir.map_or_else(
        || {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join("diagnostics")
                .join(&run_id)
        },
        Path::to_path_buf,
    );
    let suite = bench::no_ccs::NoCcsSuite {
        repo: repo.to_path_buf(),
        rust_bin: rust_bin.to_path_buf(),
        xray_bin: xray_bin.to_path_buf(),
        openssl_bin: openssl_bin.to_path_buf(),
        out_dir,
        run_id,
    };
    match bench::no_ccs::run(&suite) {
        Ok(_) => {
            println!("no-CCS interoperability: PASS");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("bench run no-ccs-interop: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Drives the real-socket descriptor-pressure recovery gate.
#[expect(
    clippy::too_many_arguments,
    reason = "the bounded gate inputs are explicit command-line policy"
)]
fn run_bench_pressure(
    repo: &Path,
    rust_bin: &Path,
    xray_bin: &Path,
    openssl_bin: &Path,
    out_dir: Option<&Path>,
    run_id: Option<&str>,
    nofile_limit: u64,
    max_held: usize,
    storm_connections: usize,
) -> ExitCode {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let run_id = run_id.map_or_else(
        || format!("descriptor-pressure-{stamp}-{}", std::process::id()),
        str::to_owned,
    );
    let out_dir = out_dir.map_or_else(
        || {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join("diagnostics/final")
                .join(&run_id)
        },
        Path::to_path_buf,
    );
    let suite = bench::pressure::PressureSuite {
        repo: repo.to_path_buf(),
        rust_bin: rust_bin.to_path_buf(),
        xray_bin: xray_bin.to_path_buf(),
        openssl_bin: openssl_bin.to_path_buf(),
        out_dir: out_dir.clone(),
        run_id,
        nofile_limit,
        max_held,
        storm_connections,
    };
    if let Err(error) = bench::pressure::validate(&suite) {
        eprintln!("bench run descriptor-pressure: {error}");
        return ExitCode::from(2);
    }
    match bench::pressure::run(&suite) {
        Ok(result) => {
            println!(
                "descriptor-pressure recovery: PASS ({} held, {} storm failures; {})",
                result.successful_held,
                result.storm_failures,
                out_dir.display()
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("bench run descriptor-pressure: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Drives the selected side of the shared mixed-traffic soak lifecycle.
#[expect(
    clippy::too_many_arguments,
    reason = "the soak CLI fields map directly to the bounded native plan"
)]
fn run_bench_soak(
    implementation: &str,
    rust_bin: &Path,
    xray_bin: &Path,
    openssl_bin: &Path,
    out_dir: Option<&Path>,
    run_id: Option<&str>,
    duration_seconds: u64,
    round_sleep_ms: u64,
    minimum_rounds: usize,
    distributed_interval_seconds: u64,
) -> ExitCode {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let run_id = run_id.map_or_else(
        || format!("soak-xray-{stamp}-{}", std::process::id()),
        str::to_owned,
    );
    let out_dir = out_dir.map_or_else(
        || {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join("benchmarks/evidence/releases")
                .join(&run_id)
        },
        Path::to_path_buf,
    );
    let plan = bench::soak::SoakPlan {
        rust_bin: rust_bin.to_path_buf(),
        xray_bin: xray_bin.to_path_buf(),
        openssl_bin: openssl_bin.to_path_buf(),
        out_dir: out_dir.clone(),
        run_id,
        duration: std::time::Duration::from_secs(duration_seconds),
        round_sleep: std::time::Duration::from_millis(round_sleep_ms),
        minimum_rounds,
        distributed_interval: std::time::Duration::from_secs(distributed_interval_seconds),
    };
    if let Err(error) = bench::soak::validate(&plan) {
        eprintln!("bench run soak: {error}");
        return ExitCode::from(2);
    }
    if implementation == "rust" {
        match bench::soak::run_rust(&plan) {
            Ok(outcome) => {
                println!(
                    "rust-reality soak: PASS ({} rounds, {} distributed attempts, aggregate PSS/RSS growth {:.1} MiB; {})",
                    outcome.rounds,
                    outcome.distributed_attempts,
                    outcome
                        .resources
                        .pss_growth_mib
                        .unwrap_or(outcome.resources.rss_growth_mib),
                    out_dir.display()
                );
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("bench run soak: {error}");
                ExitCode::FAILURE
            }
        }
    } else {
        match bench::soak::run_xray(&plan) {
            Ok(outcome) => {
                println!(
                    "Xray soak: PASS ({} rounds, RSS growth {:.1} MiB; {})",
                    outcome.rounds,
                    outcome.resources.rss_growth_mib,
                    out_dir.display()
                );
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("bench run soak: {error}");
                ExitCode::FAILURE
            }
        }
    }
}

/// Drives the dynamic TLS first-flight shape suite.
#[expect(
    clippy::too_many_arguments,
    reason = "the suite's CLI inputs map one-for-one to these typed fields"
)]
fn run_bench_tls_shape(
    repo: &Path,
    rust_bin: &Path,
    xray_bin: &Path,
    openssl_bin: &Path,
    out_dir: Option<&Path>,
    run_id: Option<&str>,
    samples: usize,
    reference: bench::tls_shape_suite::ReferenceOptions,
) -> ExitCode {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let run_id = run_id.map_or_else(
        || format!("benchmark-tls-shape-{stamp}-{}", std::process::id()),
        str::to_owned,
    );
    let out_dir = out_dir.map_or_else(
        || {
            bench::workspace::cache_root()
                .join("evidence/tls-shape")
                .join(&run_id)
        },
        Path::to_path_buf,
    );
    let suite = bench::tls_shape_suite::TlsShapeSuite {
        repo: repo.to_path_buf(),
        rust_bin: rust_bin.to_path_buf(),
        xray_bin: xray_bin.to_path_buf(),
        openssl_bin: openssl_bin.to_path_buf(),
        out_dir: out_dir.clone(),
        run_id,
        samples,
        reference,
    };
    if let Err(error) = bench::tls_shape_suite::validate(&suite) {
        eprintln!("bench run tls-shape: {error}");
        return ExitCode::from(2);
    }
    match bench::tls_shape_suite::run(&suite) {
        Ok(_) => {
            println!("TLS shape: PASS ({})", out_dir.display());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("bench run tls-shape: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Drives the IPv6 end-to-end gate.
#[expect(
    clippy::too_many_arguments,
    reason = "these are the IPv6 gate's command-line parameters"
)]
fn run_bench_ipv6(
    repo: &Path,
    rust_bin: &Path,
    xray_bin: &Path,
    openssl_bin: &Path,
    out_dir: Option<&Path>,
    run_id: Option<&str>,
    phases: &str,
    global_v6: Option<&str>,
    transfer_mib: u64,
    internet_url: Option<&str>,
) -> ExitCode {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let run_id = run_id.map_or_else(
        || format!("validate-ipv6-e2e-{stamp}-{}", std::process::id()),
        str::to_owned,
    );
    let out_dir = out_dir.map_or_else(
        || {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join("diagnostics")
                .join(&run_id)
        },
        Path::to_path_buf,
    );
    let suite = bench::ipv6::Ipv6Suite {
        repo: repo.to_path_buf(),
        rust_bin: rust_bin.to_path_buf(),
        xray_bin: xray_bin.to_path_buf(),
        openssl_bin: openssl_bin.to_path_buf(),
        out_dir: out_dir.clone(),
        run_id,
        phases: phases.to_owned(),
        global_ipv6: global_v6.map(str::to_owned),
        transfer_mib,
        internet_url: internet_url.unwrap_or("https://example.com/").to_owned(),
    };
    match bench::ipv6::run(&suite) {
        Ok(summary) => {
            println!(
                "IPv6 validation: PASS ({}; evidence {})",
                summary.to_python_json(),
                out_dir.display()
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("bench run ipv6: {error}");
            ExitCode::FAILURE
        }
    }
}

/// The matrix suite's command-line inputs.
struct MatrixArgs<'a> {
    baseline_bin: Option<&'a Path>,
    final_bin: &'a Path,
    xray_bin: &'a Path,
    out_dir: Option<&'a Path>,
    run_id: Option<&'a str>,
    cover_target: &'a str,
    cover_sni: &'a str,
    payloads: &'a str,
    concurrencies: &'a str,
    large_concurrencies: &'a str,
    large_payload_mib: u64,
    samples: usize,
    samples_large: usize,
    integrity_mib: u64,
    cells: &'a str,
    skip: &'a str,
    abba_start: &'a str,
    manage_pipe_pages: bool,
}

/// Splits a comma- or space-separated pattern list.
fn pattern_list(raw: &str) -> Vec<String> {
    raw.split([',', ' '])
        .filter(|word| !word.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Drives the three-implementation matrix.
fn run_bench_matrix(repo: &Path, args: &MatrixArgs<'_>) -> ExitCode {
    let Some(baseline_bin) = args.baseline_bin else {
        eprintln!("bench run matrix: --baseline-bin is required");
        return ExitCode::from(2);
    };
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let run_id = args.run_id.map_or_else(
        || format!("benchmark-matrix-{stamp}-{}", std::process::id()),
        str::to_owned,
    );
    let out_dir = args.out_dir.map_or_else(
        || {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join("benchmarks")
                .join(&run_id)
        },
        Path::to_path_buf,
    );
    let numbers = |raw: &str| -> Vec<usize> {
        raw.split_whitespace()
            .filter_map(|word| word.parse().ok())
            .collect()
    };
    let suite = bench::matrix::MatrixSuite {
        repo: repo.to_path_buf(),
        baseline_bin: baseline_bin.to_path_buf(),
        final_bin: args.final_bin.to_path_buf(),
        xray_bin: args.xray_bin.to_path_buf(),
        out_dir,
        run_id,
        cover_target: args.cover_target.to_owned(),
        cover_sni: args.cover_sni.to_owned(),
        plan: bench::matrix::CellPlan {
            payloads_mib: args
                .payloads
                .split_whitespace()
                .filter_map(|word| word.parse().ok())
                .collect(),
            concurrencies: numbers(args.concurrencies),
            large_concurrencies: numbers(args.large_concurrencies),
            large_payload_mib: args.large_payload_mib,
            include: pattern_list(args.cells),
            exclude: pattern_list(args.skip),
        },
        samples: args.samples,
        samples_large: args.samples_large,
        integrity_mib: args.integrity_mib,
        abba_start: if args.abba_start.is_empty() {
            "baseline".to_owned()
        } else {
            args.abba_start.to_owned()
        },
        manage_pipe_pages: args.manage_pipe_pages,
    };
    if let Err(error) = bench::matrix::validate(&suite) {
        eprintln!("bench run matrix: {error}");
        return ExitCode::from(2);
    }
    match bench::matrix::run(&suite) {
        Ok(outcome) => {
            println!(
                "matrix complete: {} samples, {} invalid -> {}",
                outcome.samples,
                outcome.invalid,
                outcome.out_dir.display()
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("bench run matrix: {error}");
            ExitCode::FAILURE
        }
    }
}

/// The paired fallback suite's command-line inputs.
struct FallbackArgs<'a> {
    baseline_bin: Option<&'a Path>,
    candidate_bin: &'a Path,
    baseline_identity: Option<&'a Path>,
    baseline_commit: Option<&'a str>,
    out_dir: Option<&'a Path>,
    run_id: Option<&'a str>,
    blocks: usize,
    samples: usize,
    concurrencies: &'a str,
    payload_mib: u64,
    abba_start: &'a str,
    measure_mode: &'a str,
    relay_splice: bool,
    relay_pipe_pool: bool,
    relay_buffer_kib: u32,
}

/// Drives the paired fallback A/B suite.
fn run_bench_fallback(repo: &Path, args: &FallbackArgs<'_>) -> ExitCode {
    let Some(baseline_bin) = args.baseline_bin else {
        eprintln!("bench run fallback: --baseline-bin is required for a paired comparison");
        return ExitCode::from(2);
    };
    let attribution = match args.measure_mode {
        "perf" => bench::slot::Attribution::Perf(&bench::attribution::REQUIRED_EVENTS),
        "wall" => bench::slot::Attribution::Wall,
        other => {
            eprintln!("bench run fallback: MEASURE_MODE must be perf or wall, got {other}");
            return ExitCode::from(2);
        }
    };
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let run_id = args.run_id.map_or_else(
        || format!("benchmark-fallback-ab-{stamp}-{}", std::process::id()),
        str::to_owned,
    );
    let out_dir = args.out_dir.map_or_else(
        || {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join("benchmarks")
                .join(&run_id)
        },
        Path::to_path_buf,
    );
    let suite = bench::paired::FallbackSuite {
        repo: repo.to_path_buf(),
        baseline_bin: baseline_bin.to_path_buf(),
        candidate_bin: args.candidate_bin.to_path_buf(),
        baseline_identity: args.baseline_identity.map(Path::to_path_buf),
        baseline_commit: args.baseline_commit.map(str::to_owned),
        out_dir,
        run_id,
        blocks: args.blocks,
        samples: args.samples,
        concurrencies: args
            .concurrencies
            .split_whitespace()
            .filter_map(|word| word.parse().ok())
            .collect(),
        payload_mib: args.payload_mib,
        abba_start: if args.abba_start.is_empty() {
            "baseline".to_owned()
        } else {
            args.abba_start.to_owned()
        },
        relay: bench::relay::RelayPolicy {
            splice: args.relay_splice,
            pipe_pool: args.relay_pipe_pool,
            buffer_kib: args.relay_buffer_kib,
        },
        attribution,
    };
    if let Err(error) = bench::paired::validate_fallback(&suite) {
        eprintln!("bench run fallback: {error}");
        return ExitCode::from(2);
    }
    match bench::paired::run_fallback(&suite) {
        Ok(outcome) => {
            println!(
                "fallback ABBA complete: {} ({} slots)",
                outcome.out_dir.display(),
                outcome.slot_count
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("bench run fallback: {error}");
            ExitCode::FAILURE
        }
    }
}

/// The paired setup-rate suite's command-line inputs.
struct SetupRateArgs<'a> {
    baseline_bin: Option<&'a Path>,
    candidate_bin: &'a Path,
    peer: bench::paired::SetupPeer,
    client_data_mib: Option<u64>,
    baseline_identity: Option<&'a Path>,
    baseline_commit: Option<&'a str>,
    out_dir: Option<&'a Path>,
    run_id: Option<&'a str>,
    blocks: usize,
    samples: usize,
    connections: usize,
    concurrencies: &'a str,
    abba_start: &'a str,
    baseline_cover_mode: &'a str,
    candidate_cover_mode: &'a str,
    measure_mode: &'a str,
    cover_netem_rtt_ms: Option<u32>,
    profile: Option<perf::hotspot::BenchmarkProfile>,
}

/// Drives the paired baseline-versus-candidate setup-rate suite.
fn run_bench_setup_rate(repo: &Path, args: &SetupRateArgs<'_>) -> ExitCode {
    let Some(baseline_bin) = args.baseline_bin else {
        eprintln!("bench run setup-rate: --baseline-bin is required for a paired comparison");
        return ExitCode::from(2);
    };
    let attribution = match args.measure_mode {
        "perf" => bench::slot::Attribution::Perf(&bench::attribution::REQUIRED_EVENTS),
        "wall" => bench::slot::Attribution::Wall,
        "strace" => bench::slot::Attribution::Strace,
        "schedstat" => bench::slot::Attribution::Schedstat,
        other => {
            eprintln!(
                "bench run setup-rate: MEASURE_MODE must be perf, schedstat, strace or wall, \
                 got {other}"
            );
            return ExitCode::from(2);
        }
    };
    let (Ok(baseline_cover_mode), Ok(candidate_cover_mode)) = (
        bench::cover::CoverMode::parse(args.baseline_cover_mode),
        bench::cover::CoverMode::parse(args.candidate_cover_mode),
    ) else {
        eprintln!("bench run setup-rate: cover modes must be default, cold, warm or prebuilt");
        return ExitCode::from(2);
    };
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let run_id = args.run_id.map_or_else(
        || format!("benchmark-setup-rate-{stamp}-{}", std::process::id()),
        str::to_owned,
    );
    let out_dir = args.out_dir.map_or_else(
        || {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join("benchmarks")
                .join(&run_id)
        },
        Path::to_path_buf,
    );
    let suite = bench::paired::SetupRateSuite {
        repo: repo.to_path_buf(),
        baseline_bin: baseline_bin.to_path_buf(),
        candidate_bin: args.candidate_bin.to_path_buf(),
        peer: args.peer.clone(),
        client_data_mib: args.client_data_mib,
        baseline_identity: args.baseline_identity.map(Path::to_path_buf),
        baseline_commit: args.baseline_commit.map(str::to_owned),
        out_dir,
        run_id,
        blocks: args.blocks,
        samples: args.samples,
        connections: args.connections,
        concurrencies: args
            .concurrencies
            .split_whitespace()
            .filter_map(|word| word.parse().ok())
            .collect(),
        abba_start: if args.abba_start.is_empty() {
            "baseline".to_owned()
        } else {
            args.abba_start.to_owned()
        },
        baseline_cover_mode,
        candidate_cover_mode,
        attribution,
        cover_netem_rtt_ms: args.cover_netem_rtt_ms,
        profile: args.profile.clone(),
    };
    if let Err(error) = bench::paired::validate(&suite) {
        eprintln!("bench run setup-rate: {error}");
        return ExitCode::from(2);
    }
    match bench::paired::run_setup_rate(&suite) {
        Ok(outcome) => {
            println!(
                "setup ABBA complete: {} ({} slots)",
                outcome.out_dir.display(),
                outcome.slot_count
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("bench run setup-rate: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Drives the Xray setup-rate comparator.
///
/// Exit status follows the family contract: 0 when the run published, 1 when a
/// measurement failed, and 2 when the request itself was inadmissible.
#[expect(
    clippy::too_many_arguments,
    reason = "these are the suite's command-line parameters, one per flag"
)]
fn run_bench_setup_rate_xray(
    repo: &Path,
    rust_bin: &Path,
    xray_bin: &Path,
    out_dir: Option<&Path>,
    run_id: Option<&str>,
    blocks: usize,
    samples: usize,
    connections: usize,
    concurrencies: &str,
    abba_start: &str,
    measure_mode: &str,
) -> ExitCode {
    let attribution = match measure_mode {
        "perf" => bench::slot::Attribution::Perf(&bench::attribution::TASK_CLOCK_ONLY),
        "wall" => bench::slot::Attribution::Wall,
        other => {
            eprintln!("bench run: MEASURE_MODE must be perf or wall, got {other}");
            return ExitCode::from(2);
        }
    };
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let run_id = run_id.map_or_else(
        || format!("benchmark-setup-rate-xray-{stamp}-{}", std::process::id()),
        str::to_owned,
    );
    let out_dir = out_dir.map_or_else(
        || {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join("benchmarks")
                .join(&run_id)
        },
        Path::to_path_buf,
    );
    let plan = bench::ab_suites::ComparatorPlan {
        repo: repo.to_path_buf(),
        rust_bin: rust_bin.to_path_buf(),
        xray_bin: xray_bin.to_path_buf(),
        out_dir,
        run_id,
        blocks,
        samples,
        connections,
        concurrencies: concurrencies
            .split_whitespace()
            .filter_map(|word| word.parse().ok())
            .collect(),
        abba_start: if abba_start.is_empty() {
            "rust".to_owned()
        } else {
            abba_start.to_owned()
        },
        attribution,
    };
    if let Err(error) = bench::ab_suites::validate(&plan) {
        eprintln!("bench run setup-rate-xray: {error}");
        return ExitCode::from(2);
    }
    match bench::ab_suites::run_setup_rate_xray(&plan) {
        Ok(outcome) => {
            println!(
                "setup-rate xray comparison complete: {} ({} slots)",
                outcome.out_dir.display(),
                outcome.slot_count
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("bench run setup-rate-xray: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Drives one slot's setup-rate workload as a child process.
///
/// With `samples == 0` this only warms the path up, exactly as the legacy driver
/// did; a warm-up failure is fatal because measuring a tunnel that never carried
/// traffic would record setup times for a path that does not work.
fn run_bench_workload(
    plan: &bench::workload::SetupRatePlan,
    output: Option<&std::path::Path>,
) -> ExitCode {
    if plan.concurrencies.is_empty() {
        eprintln!("bench workload: at least one concurrency level is required");
        return ExitCode::from(2);
    }
    if plan.samples == 0 {
        return match bench::workload::warm_up(plan.socks_port, plan.origin_port) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("bench workload: {error}");
                ExitCode::FAILURE
            }
        };
    }
    let Some(output) = output else {
        eprintln!("bench workload: --output is required when samples are measured");
        return ExitCode::from(2);
    };
    let result = bench::workload::run_slot(plan);
    let rows = match &result {
        Ok(rows) => rows,
        Err(error) => {
            eprintln!("bench workload: {error}");
            &error.rows
        }
    };
    let document = bench::workload::rows_json(rows, plan.record_latencies).to_python_json();
    if let Err(error) = std::fs::write(output, document) {
        eprintln!(
            "bench workload: could not write {}: {error}",
            output.display()
        );
        return ExitCode::FAILURE;
    }
    if result.is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Validates the `bench run` parameters and drives the real-path suite.
///
/// Exit codes mirror the legacy contract: 0 when every transfer succeeded, 1
/// when the report completed with failed transfers, 3 when direct egress is
/// unavailable (the gate is NOT RUN), and 2 on a hard setup/process error that
/// prevented a report.
fn run_bench_run(context: &bench::suites::SuiteContext<'_>) -> ExitCode {
    if context.runs == 0 || context.expected_bytes == 0 {
        eprintln!("bench run: runs and bytes must be positive");
        return ExitCode::from(2);
    }
    // The real-path gate requires direct Internet egress: the servers dial the
    // destination themselves. Probe with a tiny download and fail closed with
    // the legacy NOT RUN semantics.
    if let Err(error) = probe_egress() {
        eprintln!(
            "direct Internet egress to speed.cloudflare.com is unavailable; real-path gate NOT RUN ({error})"
        );
        return ExitCode::from(3);
    }
    match bench::suites::run_suite(context) {
        Ok(outcome) => {
            println!(
                "bench run: {} transfers, {} failures -> PASS",
                outcome.samples.len(),
                outcome.report.failures
            );
            ExitCode::SUCCESS
        }
        Err(bench::suites::RunError::Workload(report)) => {
            eprintln!(
                "bench run: {} transfer(s) failed; report records the details",
                report.failures
            );
            ExitCode::FAILURE
        }
        Err(error) => {
            eprintln!("bench run: {error}");
            ExitCode::from(2)
        }
    }
}

/// Drives the loopback concurrent xray suite.
fn run_bench_xray(
    context: &bench::suites::SuiteContext<'_>,
    plan: &bench::loopback::LoopbackPlan,
) -> ExitCode {
    match bench::loopback::run_loopback(context, plan) {
        Ok(outcome) => {
            println!(
                "bench run xray: {} measurements -> PASS",
                outcome.measurements.len()
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("bench run xray: {error}");
            ExitCode::from(2)
        }
    }
}

/// Probes direct egress to the real-path speed endpoint.
///
/// # Errors
///
/// Returns the curl failure text when the probe fails.
fn probe_egress() -> Result<(), String> {
    let mut curl = process::Tool::new("curl");
    for name in [
        "ALL_PROXY",
        "all_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "NO_PROXY",
        "no_proxy",
    ] {
        curl = curl.env(name, "");
    }
    let outcome = curl
        .args([
            "--fail",
            "--silent",
            "--max-time",
            "30",
            "-o",
            "/dev/null",
            "https://speed.cloudflare.com/__down?bytes=100000",
        ])
        .probe()
        .map_err(|error| error.to_string())?;
    if outcome.success() {
        Ok(())
    } else {
        Err(format!("curl exited {:?}", outcome.code))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_setup_workload_retains_rows_and_returns_failure() {
        let workspace = bench::workspace::Workspace::create("failed-setup-rows").unwrap();
        let output = workspace.join("samples.json");
        let plan = bench::workload::SetupRatePlan {
            socks_port: 0,
            origin_port: 0,
            connections: 1,
            concurrencies: vec![1],
            samples: 1,
            implementation: "candidate".to_owned(),
            block: 1,
            position: 1,
            record_latencies: true,
        };
        assert_eq!(run_bench_workload(&plan, Some(&output)), ExitCode::FAILURE);
        let rows: serde_json::Value =
            serde_json::from_slice(&std::fs::read(output).unwrap()).unwrap();
        assert_eq!(rows.as_array().unwrap().len(), 1);
        assert_eq!(rows[0]["failed"], 1);
        assert_eq!(rows[0]["connections"], 0);
        assert_eq!(rows[0]["latenciesSeconds"], serde_json::json!([]));
    }
}
