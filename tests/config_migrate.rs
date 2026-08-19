//! Golden v1.5 → v1.6 `config migrate` fixtures.
//!
//! Every fixture pair pins the exact migrated document; the round-trip
//! assertions prove the output loads through the same validation as
//! `config check`, stays v1.6-native, and preserves the effective resource
//! policy and posture of its v1.5 source.

use std::{
    fs,
    path::{Path, PathBuf},
};

use rust_reality::config::{
    Config, MigrateFrom, Migration, MigrationNoteKind, ResourceMode, RuntimeProfile, TuningMode,
    load_config_with_report, migrate_config_bytes,
};

struct Fixture {
    name: &'static str,
    v15: &'static str,
    v16: &'static str,
}

const FIXTURES: &[Fixture] = &[
    Fixture {
        name: "full-policy",
        v15: include_str!("fixtures/migrate/full-policy.v1.5.json"),
        v16: include_str!("fixtures/migrate/full-policy.v1.6.json"),
    },
    Fixture {
        name: "minimal",
        v15: include_str!("fixtures/migrate/minimal.v1.5.json"),
        v16: include_str!("fixtures/migrate/minimal.v1.6.json"),
    },
    Fixture {
        name: "dedicated-resource-mode",
        v15: include_str!("fixtures/migrate/dedicated-resource-mode.v1.5.json"),
        v16: include_str!("fixtures/migrate/dedicated-resource-mode.v1.6.json"),
    },
    Fixture {
        name: "dns-cache",
        v15: include_str!("fixtures/migrate/dns-cache.v1.5.json"),
        v16: include_str!("fixtures/migrate/dns-cache.v1.6.json"),
    },
];

fn migrate(fixture: &Fixture) -> Migration {
    migrate_config_bytes(
        MigrateFrom::V15,
        Path::new(&format!("{}.v1.5.json", fixture.name)),
        fixture.v15.as_bytes(),
    )
    .unwrap_or_else(|error| panic!("{} must migrate: {error}", fixture.name))
}

/// Writes `contents` to a unique temporary file and loads it through the
/// same validation `config check` runs.
fn load_checked(name: &str, contents: &str) -> (Config, rust_reality::config::ConfigLoadReport) {
    let path: PathBuf = std::env::temp_dir().join(format!(
        "rust-reality-migrate-test-{}-{name}.json",
        std::process::id()
    ));
    fs::write(&path, contents).expect("temporary fixture must be writable");
    let loaded = load_config_with_report(&path);
    let _ = fs::remove_file(&path);
    loaded.unwrap_or_else(|error| panic!("{name} must pass config check: {error}"))
}

#[test]
fn migrated_output_matches_the_golden_document() {
    for fixture in FIXTURES {
        assert_eq!(
            migrate(fixture).json(),
            fixture.v16,
            "{}: regenerated migration drifted from the golden v1.6 document",
            fixture.name
        );
    }
}

#[test]
fn migrated_output_checks_cleanly_and_preserves_behavior() {
    for fixture in FIXTURES {
        let migration = migrate(fixture);
        let (migrated, report) = load_checked(&format!("{}-out", fixture.name), migration.json());
        assert!(
            !report.policy_alias_used,
            "{}: the migrated document must be v1.6-native",
            fixture.name
        );
        let (source, _) = load_checked(&format!("{}-in", fixture.name), fixture.v15);
        assert_eq!(
            migrated.advanced.limits, source.advanced.limits,
            "{}: the effective resource and relay policy must not change",
            fixture.name
        );
        if let Some(mode) = source.runtime.resource_mode {
            assert_eq!(
                migrated.runtime.profile.resource_mode(),
                Some(mode),
                "{}: the resource posture must survive the translation",
                fixture.name
            );
        }
    }
}

#[test]
fn minimal_config_migrates_to_an_identical_configuration() {
    let fixture = &FIXTURES[1];
    assert_eq!(fixture.name, "minimal");
    let migration = migrate(fixture);
    assert!(
        migration.notes().is_empty(),
        "a v1.5 config without policy or resourceMode needs no report: {:?}",
        migration.notes()
    );
    let (migrated, _) = load_checked("minimal-out", migration.json());
    let (source, _) = load_checked("minimal-in", fixture.v15);
    assert_eq!(migrated, source, "nothing may change for a minimal config");
    assert!(!migration.json().contains("\"policy\""));
    assert!(!migration.json().contains("\"runtime\""));
    assert!(!migration.json().contains("\"advanced\""));
}

#[test]
fn full_policy_forces_fixed_mode_and_reports_every_defaulted_value() {
    let fixture = &FIXTURES[0];
    assert_eq!(fixture.name, "full-policy");
    let migration = migrate(fixture);
    let (migrated, _) = load_checked("full-policy-out", migration.json());

    assert_eq!(
        migrated.runtime.tuning.mode(),
        TuningMode::Fixed,
        "pinned limits must force the fixed tuning mode"
    );
    assert!(
        migration
            .notes()
            .iter()
            .any(|note| note.kind() == MigrationNoteKind::Context
                && note.message().contains("startup")),
        "the fixed-mode note must point at the derived modes: {:?}",
        migration.notes()
    );
    let redundant: Vec<_> = migration
        .notes()
        .iter()
        .filter(|note| note.kind() == MigrationNoteKind::Redundant)
        .collect();
    assert_eq!(
        redundant.len(),
        2,
        "splice and pipePool are explicit defaults: {redundant:?}"
    );
    assert!(
        redundant.iter().any(
            |note| note.path() == "policy.relay.pipePool" && note.message().contains("omitted")
        )
    );
    assert!(
        redundant
            .iter()
            .any(|note| note.path() == "policy.relay.splice" && note.message().contains("kept"))
    );
    assert!(
        migration
            .notes()
            .iter()
            .any(|note| note.kind() == MigrationNoteKind::Discarded && note.path() == "policy")
    );
}

#[test]
fn dedicated_resource_mode_translates_to_the_profile() {
    let fixture = &FIXTURES[2];
    assert_eq!(fixture.name, "dedicated-resource-mode");
    let migration = migrate(fixture);
    let (migrated, _) = load_checked("dedicated-out", migration.json());

    assert_eq!(migrated.runtime.profile, RuntimeProfile::Dedicated);
    assert_eq!(migrated.runtime.resource_mode, None);
    assert!(
        migration
            .notes()
            .iter()
            .any(|note| note.kind() == MigrationNoteKind::Translated
                && note.path() == "runtime.resourceMode"
                && note
                    .message()
                    .contains("\"dedicated\" became runtime.profile \"dedicated\"")),
        "the translation must be reported: {:?}",
        migration.notes()
    );
}

#[test]
fn dns_cache_tuning_is_preserved_verbatim() {
    let fixture = &FIXTURES[3];
    assert_eq!(fixture.name, "dns-cache");
    let migration = migrate(fixture);
    let (migrated, _) = load_checked("dns-cache-out", migration.json());
    let (source, _) = load_checked("dns-cache-in", fixture.v15);

    assert_eq!(
        migrated.dns, source.dns,
        "DNS trust selection must not move"
    );
    assert_eq!(migrated.inbounds, source.inbounds);
    assert_eq!(migrated.outbounds, source.outbounds);
    assert_eq!(migrated.routing, source.routing);
    assert!(!migrated.advanced.limits.relay.splice);
    assert_eq!(
        migrated.advanced.limits.relay.buffer_bytes,
        32 * 1024,
        "the default buffer size is filled back in from the default"
    );
}

#[test]
fn from_v16_rejects_obsolete_policy_placement() {
    let error = migrate_config_bytes(
        MigrateFrom::V16,
        Path::new("obsolete.json"),
        FIXTURES[0].v15.as_bytes(),
    )
    .expect_err("a v1.6 re-run with a policy object must fail");
    assert!(
        error.to_string().contains("advanced.limits"),
        "the error must name the new location: {error}"
    );
}

#[test]
fn unknown_fields_are_rejected_with_a_clear_error() {
    let json = FIXTURES[1].v15.replace(
        "\"routing\"",
        "\"policy\": {}, \"metrics\": {}, \"routing\"",
    );
    let error = migrate_config_bytes(MigrateFrom::V15, Path::new("unknown.json"), json.as_bytes())
        .expect_err("unknown fields must fail the migration");
    assert!(
        error.to_string().contains("unknown.json"),
        "the error must name the file: {error}"
    );
}

#[test]
fn standard_resource_mode_translates_to_shared_profile() {
    let json = FIXTURES[2].v15.replace("\"dedicated\"", "\"standard\"");
    let migration = migrate_config_bytes(
        MigrateFrom::V15,
        Path::new("standard.json"),
        json.as_bytes(),
    )
    .expect("standard must migrate");
    let (migrated, _) = load_checked("standard-out", migration.json());
    assert_eq!(migrated.runtime.profile, RuntimeProfile::Shared);
    assert_eq!(
        migrated.runtime.profile.resource_mode(),
        Some(ResourceMode::Standard)
    );
}
