//! Exercise the publisher's executable byte-binding guard with hostile receipts.
use std::{
    fs,
    path::PathBuf,
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
};

use serde_json::{Value, json};

const SOURCE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const TAG: &str = "v2.3.0";
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "rr-release-publication-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let fixture = Self(root);
        fs::create_dir(fixture.0.join("dist")).unwrap();
        fs::create_dir(fixture.0.join("receipts")).unwrap();
        let artifacts: Vec<_> = super::matrix::Tier::ids()
            .into_iter()
            .map(|tier| {
                let archive = format!("rust-reality-{TAG}-{tier}.tar.gz");
                let bytes = format!("synthetic archive bytes for {tier}");
                fs::write(fixture.0.join("dist").join(&archive), &bytes).unwrap();
                let digest = crate::hash::sha256_hex(bytes.as_bytes());
                fs::create_dir(fixture.0.join("receipts").join(tier)).unwrap();
                // Native execution validity is established by the successful
                // Frozen coordinator. These fixtures exercise only byte binding.
                fixture.write(
                    &format!("receipts/{tier}/receipt.json"),
                    &json!({"schema":"rr-package-execution/v1", "source_commit":SOURCE,
                        "tag":TAG,"tier":tier,"archive":{"path":archive,
                        "before":digest,"after":digest}}),
                );
                json!({"tier":tier,"artifact":archive})
            })
            .collect();
        fixture.write(
            "dist/release-manifest.json",
            &json!({"commit":SOURCE,"artifacts":artifacts}),
        );
        fixture
    }
    fn write(&self, name: &str, value: &Value) {
        fs::write(self.0.join(name), serde_json::to_vec(value).unwrap()).unwrap();
    }
    fn run(&self, index: usize) -> Output {
        Command::new("python3")
            .args(["-c", &script(index)])
            .env("QUALIFIED_DIRECTORY", &self.0)
            .env("QUALIFIED_SOURCE", SOURCE)
            .env("RELEASE_TAG", TAG)
            .current_dir(&self.0)
            .output()
            .expect("execute the actual workflow guard")
    }
}

fn script(index: usize) -> String {
    let workflow = include_str!("../../../../.github/workflows/release.yml");
    let step = workflow
        .split_once("      - name: Match rebuilt archives to exact-main Frozen qualification\n")
        .unwrap()
        .1
        .split_once("      - name: Publish GitHub Release\n")
        .unwrap()
        .0;
    let blocks: Vec<_> = step.split("python3 - <<'PY'\n").skip(1).collect();
    assert_eq!(blocks.len(), 3);
    let mut script = String::new();
    for line in blocks[index]
        .split_once("\n          PY")
        .unwrap()
        .0
        .lines()
    {
        script.push_str(line.strip_prefix("          ").unwrap());
        script.push('\n');
    }
    script
}

#[test]
fn publisher_requires_unchanged_complete_native_archives() {
    let fixture = Fixture::new();
    assert!(fixture.run(2).status.success());
    let tier = super::matrix::Tier::ids()[0];
    let archive = fixture
        .0
        .join(format!("dist/rust-reality-{TAG}-{tier}.tar.gz"));
    let original = fs::read(&archive).unwrap();
    fs::write(&archive, b"modified after qualification").unwrap();
    assert!(!fixture.run(2).status.success());
    fs::write(&archive, original).unwrap();
    fs::remove_file(fixture.0.join(format!("receipts/{tier}/receipt.json"))).unwrap();
    assert!(!fixture.run(2).status.success());
}

#[test]
fn publisher_rejects_substituted_and_duplicate_receipts() {
    let fixture = Fixture::new();
    let tier = super::matrix::Tier::ids()[0];
    let path = format!("receipts/{tier}/receipt.json");
    let bytes = fs::read(fixture.0.join(&path)).unwrap();
    let mut receipt: Value = serde_json::from_slice(&bytes).unwrap();
    receipt["source_commit"] = json!("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    fixture.write(&path, &receipt);
    assert!(!fixture.run(2).status.success());
    fs::write(fixture.0.join(&path), &bytes).unwrap();
    fs::create_dir(fixture.0.join("receipts/duplicate")).unwrap();
    fs::write(fixture.0.join("receipts/duplicate/receipt.json"), bytes).unwrap();
    assert!(!fixture.run(2).status.success());
}

#[test]
fn publisher_does_not_select_an_older_pass_over_a_newer_frozen_failure() {
    let fixture = Fixture::new();
    let run = |id, branch, conclusion| {
        json!({"id":id,"head_sha":SOURCE,"head_branch":branch,
            "event":"workflow_dispatch","status":"completed","conclusion":conclusion})
    };
    fixture.write(
        "runs.json",
        &json!({"workflow_runs":[
        run(1, "main", "success"), run(2, "main", "failure"),
        run(3, "feature/example", "success")]}),
    );
    assert!(!fixture.run(1).status.success());
    fixture.write(
        "runs.json",
        &json!({"workflow_runs":[
        run(1, "main", "success"), run(2, "main", "success"),
        run(3, "feature/example", "success")]}),
    );
    let accepted = fixture.run(1);
    assert!(accepted.status.success());
    assert_eq!(String::from_utf8(accepted.stdout).unwrap().trim(), "2");
    fixture.write("runs.json", &json!({"workflow_runs":[]}));
    assert!(!fixture.run(1).status.success());
}
