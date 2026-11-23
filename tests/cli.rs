use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::symlink,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

fn run(args: &[&Path]) -> (Output, Value) {
    let result = Command::new(env!("CARGO_BIN_EXE_veil-keeper"))
        .args(args)
        .env("PATH", "/path-with-no-external-tools")
        .output()
        .unwrap();
    let report = serde_json::from_slice(&result.stdout).unwrap();
    (result, report)
}

const REQUEST: &str = "tests/fixtures/e1-cgroup-request.json";
const SNAPSHOT: &str = "tests/fixtures/e1-cgroup-snapshot.json";

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!("cli-test-{}-{unique}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        Self(root)
    }
    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn plan(request: &Path, snapshot: &Path) -> (Output, Value) {
    run(&[Path::new("plan"), request, snapshot])
}

#[test]
fn preflight_requires_no_external_command() {
    let (output, report) = run(&[]);
    assert_eq!(report["system_changes"], false);
    assert_eq!(report["enforcement_verified"], false);
    assert_eq!(report["kernel_socket_cgroupv2"], "unverified");
    if cfg!(target_os = "linux") {
        assert!(matches!(
            report["status"].as_str(),
            Some("prerequisites_unconfirmed" | "candidate_for_diagnosis")
        ));
        assert_eq!(
            output.status.success(),
            report["status"] == "candidate_for_diagnosis"
        );
    } else {
        assert!(!output.status.success());
        assert_eq!(report["status"], "unsupported_platform");
    }
}

#[test]
fn guest_commands_fail_closed_outside_the_fixture() {
    for mode in ["b", "c"] {
        let (output, report) = run(&[Path::new("verify"), Path::new(mode)]);
        assert!(!output.status.success());
        assert_eq!(report["status"], "verification_incomplete");
    }
}

#[test]
fn proposal_is_offline_and_has_no_apply_commands() {
    let (output, report) = plan(Path::new(REQUEST), Path::new(SNAPSHOT));
    assert!(output.status.success());
    assert_eq!(report["status"], "offline_candidate_for_review");
    assert_eq!(report["origin"], "unverified_offline_snapshot");
    for key in [
        "apply_supported",
        "enforcement_verified",
        "scope_verified",
        "system_changes",
    ] {
        assert_eq!(report[key], false);
    }
    assert_eq!(report["proposal"]["commands"], json!([]));
    assert_eq!(
        report["input_sha256"]["request"].as_str().unwrap().len(),
        64
    );
}

#[test]
fn unknown_and_unsafe_claims_produce_no_proposal() {
    let scratch = Scratch::new();
    let snapshot = scratch.path("snapshot.json");
    let mut facts: Value = serde_json::from_slice(&fs::read(SNAPSHOT).unwrap()).unwrap();
    facts["checks"]["external_inet_fds"] = json!(null);
    fs::write(&snapshot, serde_json::to_vec(&facts).unwrap()).unwrap();
    let (output, report) = plan(Path::new(REQUEST), &snapshot);
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(report["status"], "unknown");
    assert!(report["proposal"].is_null());
    facts["checks"]["external_inet_fds"] = json!(true);
    fs::write(&snapshot, serde_json::to_vec(&facts).unwrap()).unwrap();
    let (output, report) = plan(Path::new(REQUEST), &snapshot);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(report["blockers"], json!(["external_inet_fds_unsupported"]));
    assert!(report["proposal"].is_null());
}

#[test]
fn malformed_and_ambiguous_input_is_rejected() {
    let scratch = Scratch::new();
    let request = scratch.path("request.json");
    let valid = fs::read_to_string(REQUEST).unwrap();
    let variants = [
        valid.replacen(
            "\n  \"schema_version\": 2,",
            "\n  \"schema_version\": 2, \"schema_version\": 2,",
            1,
        ),
        valid.replace("5432", "5432.0"),
        valid.replace("5432", "true"),
        valid.replace("192.0.2.10", "localhost"),
        valid.replace("veilkeepertrial.slice", "system.slice"),
        valid.replace("192.0.2.10", "0.0.0.0"),
    ];
    for data in variants {
        fs::write(&request, &data).unwrap();
        let (out, report) = plan(&request, Path::new(SNAPSHOT));
        assert_eq!(out.status.code(), Some(2), "{report}");
        assert!(report["proposal"].is_null());
    }
    let link = scratch.path("input-link");
    symlink(&request, &link).unwrap();
    let (out, report) = plan(&link, Path::new(SNAPSHOT));
    assert_eq!(out.status.code(), Some(3));
    assert_eq!(report["status"], "unavailable");
}

#[test]
fn saves_only_new_reports_in_real_trusted_directories() {
    let scratch = Scratch::new();
    let output = scratch.path("report.json");
    let invoke = |path: &Path| {
        run(&[
            Path::new("plan"),
            Path::new(REQUEST),
            Path::new(SNAPSHOT),
            Path::new("--report"),
            path,
        ])
    };
    let (result, report) = invoke(&output);
    assert!(result.status.success(), "{report}");
    let original = fs::read(&output).unwrap();
    assert_eq!(serde_json::from_slice::<Value>(&original).unwrap(), report);
    assert!(!invoke(&output).0.status.success());
    let dangling = scratch.path("dangling");
    let uncreated = scratch.path("must-stay-absent");
    symlink(&uncreated, &dangling).unwrap();
    assert!(!invoke(&dangling).0.status.success());
    assert!(!uncreated.exists());
    let link = scratch.path("link");
    symlink(&output, &link).unwrap();
    assert!(!invoke(&link).0.status.success());
    let linked_parent = scratch.path("linked-dir");
    symlink(&scratch.0, &linked_parent).unwrap();
    assert!(
        !invoke(&linked_parent.join("through-link.json"))
            .0
            .status
            .success()
    );
    assert!(!scratch.path("through-link.json").exists());
    assert_eq!(fs::read(&output).unwrap(), original);
}
