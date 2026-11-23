use regex::Regex;
use serde_json::{Value, json};
use std::{collections::BTreeSet, net::IpAddr};

const SCOPE: &str = "socket_cgroup_v1";
const REVIEWS: &[&str] = &[
    "required_traffic",
    "management_outside_scope",
    "inbound_replies",
    "local_proxy_and_dns_paths",
    "controlled_start",
    "boundary_lifetime",
];
const REQUIRED: &[&str] = &[
    "trusted_system_manager",
    "cgroup_v2_mount",
    "initial_namespaces",
    "host_network",
    "container_absent",
    "parent_held_before_start",
    "parent_identity_stable",
    "parent_exclusive",
    "config_stable",
    "no_new_privileges",
    "capabilities_zero",
    "cgroup_write_denied",
    "manager_control_denied",
    "namespace_changes_denied",
    "socket_origin_reviewed",
    "children_absent",
    "existing_firewall_clear",
    "ipv4_routes_readable",
    "ipv6_routes_readable",
];
const UNSUPPORTED: &[&str] = &[
    "delegated",
    "socket_activation",
    "fd_store",
    "external_inet_fds",
    "external_socket_helpers",
];
const UNIT: &str = r"\A[A-Za-z0-9][A-Za-z0-9_.-]{0,110}\.service\z";
const SLICE: &str =
    r"\A[A-Za-z0-9][A-Za-z0-9_]{0,31}(?:-[A-Za-z0-9][A-Za-z0-9_]{0,31}){0,7}\.slice\z";
const UUID: &str = r"\A[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\z";
const HASH: &str = r"\A[0-9a-f]{64}\z";

fn require(ok: bool, code: &'static str) -> Result<(), &'static str> {
    ok.then_some(()).ok_or(code)
}
fn keys(v: &Value, names: &[&str], code: &'static str) -> Result<(), &'static str> {
    require(
        v.as_object()
            .is_some_and(|m| m.len() == names.len() && names.iter().all(|n| m.contains_key(*n))),
        code,
    )
}
fn pattern(v: &Value, p: &str) -> bool {
    v.as_str()
        .is_some_and(|s| Regex::new(p).expect("static expression").is_match(s))
}
fn number(v: &Value, lo: u64, hi: u64) -> bool {
    v.as_u64().is_some_and(|n| (lo..=hi).contains(&n))
}
fn path(v: &Value) -> bool {
    v.as_str()
        .and_then(|s| s.strip_prefix('/'))
        .is_some_and(|s| {
            s.len() < 512
                && !s.chars().any(|c| c <= ' ' || c == '\u{7f}')
                && s.split('/').all(|part| !matches!(part, "" | "." | ".."))
        })
}
fn identity(v: &Value, path_key: &str) -> Result<(), &'static str> {
    for (key, valid) in [
        (path_key, path(&v[path_key])),
        ("ancestor_level", number(&v["ancestor_level"], 1, 8)),
        ("cgroup_id", number(&v["cgroup_id"], 1, u64::MAX)),
        ("config_sha256", pattern(&v["config_sha256"], HASH)),
    ] {
        require(v[key].is_null() || valid, "invalid_boundary_identity")?;
    }
    Ok(())
}
fn booleans(v: &Value) -> Result<(), &'static str> {
    require(
        v.as_object()
            .is_some_and(|m| m.values().all(|x| x.is_null() || x.is_boolean())),
        "invalid_check_value",
    )
}
fn allow_list(v: &Value) -> Result<Vec<Value>, &'static str> {
    let rows = v
        .as_array()
        .filter(|a| (1..=64).contains(&a.len()))
        .ok_or("allow_count")?;
    let mut normalized = BTreeSet::new();
    for row in rows {
        keys(row, &["address", "protocol", "port"], "allow_fields")?;
        let mut ip: IpAddr = row["address"]
            .as_str()
            .filter(|s| s.len() <= 45)
            .and_then(|s| s.parse().ok())
            .ok_or("literal_ip_required")?;
        if let IpAddr::V6(v6) = ip
            && let Some(mapped) = v6.to_ipv4_mapped()
        {
            ip = mapped.into();
        }
        require(
            !ip.is_unspecified() && !ip.is_multicast() && ip != std::net::Ipv4Addr::BROADCAST,
            "unicast_ip_required",
        )?;
        let protocol = row["protocol"]
            .as_str()
            .filter(|s| matches!(*s, "tcp" | "udp"))
            .ok_or("transport")?;
        let port = row["port"]
            .as_u64()
            .filter(|p| (1..=65535).contains(p))
            .ok_or("port")?;
        require(
            normalized.insert((
                if ip.is_ipv4() { 4 } else { 6 },
                ip.to_string(),
                protocol,
                port,
            )),
            "duplicate_allow",
        )?;
    }
    Ok(normalized.into_iter().map(|(family,address,protocol,port)| json!({ "family": family, "address": address, "protocol": protocol, "port": port })).collect())
}
pub fn base(status: &str) -> Value {
    json!({"schema_version":2,"stage":"E1-cgroup-A","scope":SCOPE,"status":status,
    "origin":"unverified_offline_snapshot","system_changes":false,"apply_supported":false,
    "enforcement_verified":false,"enterprise_ready":false,"scope_verified":false,
    "socket_ownership_verified":false,"packet_selection_verified":false,"commands":[],
    "input_contract_consistent":false,"uid_inventory_required":false,"uid_inventory_complete":null,"proposal":null})
}

pub fn inspect(req: &Value, facts: &Value) -> Result<Value, &'static str> {
    keys(
        req,
        &["schema_version", "scope", "target", "allow", "owner_review"],
        "request_fields",
    )?;
    keys(
        facts,
        &[
            "schema_version",
            "scope",
            "environment",
            "boundary",
            "service",
            "checks",
        ],
        "snapshot_fields",
    )?;
    require(
        req["schema_version"].as_u64() == Some(2) && req["scope"] == SCOPE,
        "request_contract",
    )?;
    require(
        facts["schema_version"].as_u64() == Some(2) && facts["scope"] == SCOPE,
        "snapshot_contract",
    )?;
    let t = &req["target"];
    let e = &facts["environment"];
    let b = &facts["boundary"];
    let s = &facts["service"];
    let checks = &facts["checks"];
    let reviews = &req["owner_review"];
    keys(
        t,
        &[
            "service",
            "parent_slice",
            "parent_path",
            "ancestor_level",
            "boot_id",
            "cgroup_id",
            "config_sha256",
        ],
        "target_fields",
    )?;
    keys(
        e,
        &[
            "system",
            "os_id",
            "os_version",
            "machine",
            "boot_id",
            "manager",
        ],
        "environment_fields",
    )?;
    keys(
        b,
        &[
            "slice",
            "path",
            "cgroup_id",
            "ancestor_level",
            "config_sha256",
        ],
        "boundary_fields",
    )?;
    keys(
        s,
        &[
            "canonical_name",
            "parent_slice",
            "cgroup_path",
            "state",
            "launch_mode",
            "uid",
            "main_pid",
        ],
        "service_fields",
    )?;
    keys(checks, &[REQUIRED, UNSUPPORTED].concat(), "check_fields")?;
    keys(reviews, REVIEWS, "owner_review_fields")?;
    booleans(checks)?;
    booleans(reviews)?;
    require(pattern(&t["service"], UNIT), "service_name")?;
    require(pattern(&t["parent_slice"], SLICE), "parent_slice_name")?;
    let slice = t["parent_slice"]
        .as_str()
        .unwrap()
        .strip_suffix(".slice")
        .unwrap();
    let parts: Vec<_> = slice.split('-').collect();
    require(
        !matches!(parts[0], "system" | "user" | "machine"),
        "dedicated_parent_required",
    )?;
    identity(t, "parent_path")?;
    identity(b, "path")?;
    let expected_path = (1..=parts.len())
        .map(|i| format!("/{}.slice", parts[..i].join("-")))
        .collect::<String>();
    for (value, valid) in [
        (&t["boot_id"], pattern(&t["boot_id"], UUID)),
        (&e["boot_id"], pattern(&e["boot_id"], UUID)),
        (&b["slice"], pattern(&b["slice"], SLICE)),
        (&s["canonical_name"], pattern(&s["canonical_name"], UNIT)),
        (&s["parent_slice"], pattern(&s["parent_slice"], SLICE)),
        (&s["cgroup_path"], path(&s["cgroup_path"])),
        (
            &s["state"],
            matches!(
                s["state"].as_str(),
                Some("inactive" | "active" | "failed" | "activating")
            ),
        ),
        (
            &s["launch_mode"],
            matches!(
                s["launch_mode"].as_str(),
                Some("new_systemd" | "existing_pid" | "pid_move")
            ),
        ),
        (&s["uid"], number(&s["uid"], 0, u32::MAX as u64 - 1)),
        (&s["main_pid"], number(&s["main_pid"], 0, u32::MAX as u64)),
    ] {
        require(value.is_null() || valid, "invalid_snapshot_field")?;
    }
    let allowed = allow_list(&req["allow"])?;
    let mut blockers = BTreeSet::new();
    let mut unknown = BTreeSet::new();
    let mut check = |code: String, result: Option<bool>| match result {
        None => {
            unknown.insert(code);
        }
        Some(false) => {
            blockers.insert(code);
        }
        Some(true) => {}
    };
    let mut same = |code: &str, values: &[&Value]| {
        check(
            code.into(),
            (!values.iter().any(|v| v.is_null())).then(|| values.windows(2).all(|p| p[0] == p[1])),
        );
    };
    // Keep the original offline acceptance matrix. A different platform needs its own evidence.
    for (key, wanted) in [
        ("system", "Linux"),
        ("os_id", "ubuntu"),
        ("os_version", "24.04"),
        ("machine", "x86_64"),
        ("manager", "system"),
    ] {
        require(
            e[key].is_null() || pattern(&e[key], r"\A[A-Za-z0-9_.-]{1,64}\z"),
            "environment_value",
        )?;
        same(&format!("environment_{key}"), &[&e[key], &json!(wanted)]);
    }
    same(
        "parent_path_mismatch",
        &[&t["parent_path"], &b["path"], &json!(expected_path)],
    );
    same(
        "parent_slice_mismatch",
        &[&t["parent_slice"], &b["slice"], &s["parent_slice"]],
    );
    same(
        "ancestor_level_mismatch",
        &[
            &t["ancestor_level"],
            &b["ancestor_level"],
            &json!(parts.len()),
        ],
    );
    same("boot_identity_mismatch", &[&t["boot_id"], &e["boot_id"]]);
    same(
        "parent_identity_mismatch",
        &[&t["cgroup_id"], &b["cgroup_id"]],
    );
    same(
        "config_identity_mismatch",
        &[&t["config_sha256"], &b["config_sha256"]],
    );
    same(
        "service_identity_mismatch",
        &[&t["service"], &s["canonical_name"]],
    );
    same(
        "service_path_mismatch",
        &[
            &s["cgroup_path"],
            &json!(format!(
                "{expected_path}/{}",
                t["service"].as_str().unwrap()
            )),
        ],
    );
    same(
        "stopped_service_required",
        &[&s["state"], &json!("inactive")],
    );
    same(
        "controlled_new_start_required",
        &[&s["launch_mode"], &json!("new_systemd")],
    );
    same("existing_pid_not_supported", &[&s["main_pid"], &json!(0)]);
    check(
        "nonroot_service_required".into(),
        s["uid"].as_u64().map(|uid| !matches!(uid, 0 | 65534)),
    );
    for key in REQUIRED {
        check((*key).into(), checks[key].as_bool());
    }
    for key in UNSUPPORTED {
        check(
            format!("{key}_unsupported"),
            checks[key].as_bool().map(|v| !v),
        );
    }
    for key in REVIEWS {
        check(format!("owner_review_{key}"), reviews[key].as_bool());
    }
    let status = if !blockers.is_empty() {
        "blocked"
    } else if !unknown.is_empty() {
        "unknown"
    } else {
        "offline_candidate_for_review"
    };
    let mut result = base(status);
    result["blockers"] = json!(blockers);
    result["unknown"] = json!(unknown);
    if status == "offline_candidate_for_review" {
        result["input_contract_consistent"] = json!(true);
        result["proposal"] = json!({
          "target":t,"allow":allowed,"families":[4,6],"backend_candidate":"nftables_socket_cgroupv2",
          "commands":[],"apply_supported":false,"controlled_start_required":true,"default_tcp_udp_intent":"deny",
          "inbound_replies":"requires_E2_acceptance","existing_outbound_flows":"no_blanket_established_allow",
          "next_gate":"separately_authorized_counter_only_VM_acceptance",
          "limitations":["offline_claims_not_authenticated","no_live_collector","not_DLP_or_RCE_containment",
            "parent_recreation_invalidates_plan","external_socket_and_helper_paths_excluded","backend_and_OS_runtime_support_unverified"]
        });
    }
    Ok(result)
}
