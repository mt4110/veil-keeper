mod evidence;
mod guest;
mod io;
mod plan;
mod preflight;

use serde_json::{Value, json};
use std::{path::Path, process::ExitCode};

const HELP: &str = "Usage: veil-keeper [plan REQUEST SNAPSHOT [--report FILE] | verify b|c | check b|c REPORT]\n\nNo arguments: read-only Linux preflight. Exit 0 means eligible for further\ndiagnosis, with enforcement unverified.\nplan: offline JSON proposal. check: independent evidence validation.\nverify: dedicated NIC-less Linux guest only.";

fn print(report: &Value) {
    println!(
        "{}",
        serde_json::to_string_pretty(report).expect("JSON value")
    );
}

fn run() -> u8 {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    let args: Vec<_> = arguments.iter().map(|arg| arg.to_str()).collect();
    match args.as_slice() {
        [] => {
            let report = preflight::inspect();
            print(&report);
            if report["status"] == "candidate_for_diagnosis" {
                0
            } else {
                3
            }
        }
        [Some("--help" | "-h")] => {
            println!("{HELP}");
            0
        }
        [Some("plan"), Some(request), Some(snapshot), tail @ ..] => {
            let output = match tail {
                [] => None,
                [Some("--report"), Some(path)] => Some(path),
                _ => return usage(),
            };
            let result = io::read(Path::new(request), 1024 * 1024).and_then(|(req, req_hash)| {
                let (facts, snapshot_hash) = io::read(Path::new(snapshot), 1024 * 1024)?;
                let mut report = plan::inspect(&req, &facts)?;
                report["input_sha256"] = json!({"request":req_hash, "snapshot":snapshot_hash});
                Ok(report)
            });
            let report = result.unwrap_or_else(|error| {
                let mut report = plan::base(if error == "input_unavailable" {
                    "unavailable"
                } else {
                    "invalid_input"
                });
                report["error"] = json!(error);
                report
            });
            if let Some(path) = output
                && io::save(Path::new(path), &report).is_err()
            {
                print(&json!({"error":"report_create_or_save_failed","system_changes":false}));
                return 3;
            }
            print(&report);
            match report["status"].as_str() {
                Some("offline_candidate_for_review") => 0,
                Some("blocked") => 1,
                Some("invalid_input") => 2,
                _ => 3,
            }
        }
        [Some("check"), Some(mode @ ("b" | "c")), Some(path)] => {
            match io::read(Path::new(path), 24 * 1024 * 1024)
                .and_then(|(report, _)| evidence::verify(mode, &report))
            {
                Ok(report) => {
                    print(&report);
                    0
                }
                Err(reason) => {
                    print(
                        &json!({"status":"evidence_rejected","reason":reason,"runtime_acceptance":false}),
                    );
                    1
                }
            }
        }
        [Some("verify"), Some(mode @ ("b" | "c"))] => match guest::run(mode) {
            Ok(report) => {
                print(&report);
                0
            }
            Err(reason) => {
                print(
                    &json!({"status":"verification_incomplete","reason":reason,"enforcement_verified":false}),
                );
                3
            }
        },
        [Some("__fixture_sender"), args @ ..] => match guest::sender(args) {
            Ok(()) => 0,
            Err(reason) => {
                eprintln!("{reason}");
                3
            }
        },
        _ => usage(),
    }
}

fn usage() -> u8 {
    eprintln!("{HELP}");
    2
}

fn main() -> ExitCode {
    run().into()
}
