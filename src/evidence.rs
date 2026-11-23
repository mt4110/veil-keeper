use regex::Regex;
use serde_json::{Value, json};
use std::sync::LazyLock;

type Result<T> = std::result::Result<T, &'static str>;
pub const PROTOCOLS: [&str; 3] = ["tcp", "udp", "udp-connected"];
pub const KINDS: [&str; 7] = [
    "target", "child", "outside", "restart", "wrong", "imported", "moved",
];
pub const STEPS: [&str; 11] = [
    "baseline-allow",
    "baseline-deny",
    "active-allow",
    "active-health-before",
    "active-deny",
    "active-health-after",
    "active-after-allow",
    "active-outside-allow",
    "removed-allow",
    "removed-deny",
    "wrong-deny",
];
const COMMENTS: [&str; 3] = ["keeper-c-allow", "keeper-c-deny-tcp", "keeper-c-deny-udp"];

fn require(ok: bool, reason: &'static str) -> Result<()> {
    ok.then_some(()).ok_or(reason)
}
fn array(v: &Value) -> Result<&[Value]> {
    v.as_array().map(Vec::as_slice).ok_or("expected array")
}
fn num(v: &Value) -> Result<u64> {
    v.as_u64().ok_or("expected unsigned integer")
}
fn port(v: &Value) -> Result<u64> {
    let n = num(v)?;
    require((1..=65535).contains(&n), "invalid port")?;
    Ok(n)
}
fn string(v: &Value) -> Result<&str> {
    v.as_str().ok_or("expected string")
}
fn hex(s: &Value, length: usize) -> bool {
    s.as_str().is_some_and(|s| {
        s.len() == length
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}
fn under(v: &Value, path: &str) -> bool {
    v.as_str().is_some_and(|s| {
        s.strip_prefix(path)
            .is_some_and(|tail| tail.starts_with('/'))
    })
}
fn address(family: u64) -> &'static str {
    if family == 4 { "127.0.0.1" } else { "::1" }
}
fn transport(proto: &str) -> &str {
    if proto == "tcp" { "tcp" } else { "udp" }
}

pub fn rows(ruleset: &Value) -> Result<&[Value]> {
    array(&ruleset["nftables"])
}
pub fn empty(ruleset: &Value) -> Result<()> {
    require(
        rows(ruleset)?.iter().all(|r| {
            r.as_object()
                .is_some_and(|m| m.len() == 1 && m.contains_key("metainfo"))
        }),
        "ruleset not empty",
    )
}

fn selectors(text: &str, byteorder: &Value, expected: u64, count: usize) -> Result<()> {
    static NETLINK: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
        r"\[ socket load cgroupv2 => reg ([0-9]+)\s*\]\s*\[ cmp eq reg ([0-9]+) 0x([0-9a-fA-F]{8}) 0x([0-9a-fA-F]{8})\s*\]"
    ).unwrap()
    });
    require(byteorder == "little", "unknown netlink byte order")?;
    require(
        text.matches("socket load cgroupv2").count() == count,
        "netlink selector count",
    )?;
    let mut found = 0;
    for c in NETLINK.captures_iter(text) {
        let hex = format!("{}{}", &c[3], &c[4]);
        let mut bytes = [0; 8];
        for (i, slot) in bytes.iter_mut().enumerate() {
            *slot = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|_| "netlink hex")?;
        }
        require(
            c[1] == c[2] && u64::from_le_bytes(bytes) == expected,
            "netlink cgroup identity",
        )?;
        found += 1;
    }
    require(found == count, "missing netlink comparisons")
}

fn text_shape(text: &str, n: usize, forbidden: &[&str]) -> Result<()> {
    static LEVEL: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\bsocket cgroupv2 level 1\b").unwrap());
    require(
        LEVEL.find_iter(text).count() == n
            && text.matches("socket cgroupv2").count() == n
            && !text
                .split(|c: char| !c.is_ascii_alphanumeric() && c != '-')
                .any(|s| forbidden.contains(&s)),
        "unexpected level or rule text",
    )
}

fn rules<'a>(doc: &'a Value, table: &str, count: usize) -> Result<Vec<&'a Value>> {
    let mut tables = Vec::new();
    let mut chains = Vec::new();
    let mut rules = Vec::new();
    for row in rows(doc)? {
        let m = row
            .as_object()
            .filter(|m| m.len() == 1)
            .ok_or("unexpected nft row")?;
        let (kind, body) = m.iter().next().unwrap();
        match kind.as_str() {
            "metainfo" => {}
            "table" => tables.push(body),
            "chain" => chains.push(body),
            "rule" => rules.push(body),
            _ => return Err("unexpected nft object"),
        }
    }
    require(
        tables.len() == 1 && chains.len() == 1 && rules.len() == count,
        "owned rule structure",
    )?;
    let c = chains[0];
    require(
        tables[0]["name"] == table
            && tables[0]["family"] == "inet"
            && c["table"] == table
            && c["family"] == "inet"
            && c["name"] == "output"
            && c["type"] == "filter"
            && c["hook"] == "output"
            && c["policy"] == "accept"
            && c["prio"].as_u64() == Some(0),
        "owned chain identity",
    )?;
    require(
        rules
            .iter()
            .all(|r| r["family"] == "inet" && r["table"] == table && r["chain"] == "output"),
        "owned rule identity",
    )?;
    Ok(rules)
}

fn matches(left: Value, right: Value) -> Value {
    json!({"match":{"op":"==","left":left,"right":right}})
}
fn destination(family: u64) -> Value {
    matches(
        json!({"payload":{"protocol":if family == 4 {"ip"} else {"ip6"},"field":"daddr"}}),
        json!(address(family)),
    )
}
fn dport(proto: &str, port: u64) -> Value {
    matches(
        json!({"payload":{"protocol":transport(proto),"field":"dport"}}),
        json!(port),
    )
}
fn socket(path: &str) -> Value {
    matches(json!({"socket":{"key":"cgroupv2"}}), json!(path))
}
fn packets(v: &Value) -> Result<u64> {
    require(
        v.as_object()
            .is_some_and(|m| m.len() == 1 && m.contains_key("counter")),
        "counter expression",
    )?;
    num(&v["counter"]["bytes"])?;
    num(&v["counter"]["packets"])
}
fn b_counter(doc: &Value, family: u64, proto: &str, port: u64, path: &str) -> Result<u64> {
    let rule = rules(doc, "keeper_b", 1)?[0];
    let expr = array(&rule["expr"])?;
    let [ip, dst, selector, counter] = expr else {
        return Err("counter-only expressions");
    };
    require(
        rule["comment"] == "keeper-b-selection"
            && *ip == destination(family)
            && *dst == dport(proto, port)
            && *selector == socket(path),
        "counter-only selector",
    )?;
    packets(counter)
}

fn c_counters(
    doc: &Value,
    family: u64,
    proto: &str,
    port: u64,
    path: &str,
    id: u64,
) -> Result<[u64; 3]> {
    let rules = rules(&doc["json"], "keeper_c", 3)?;
    text_shape(
        string(&doc["text"])?,
        3,
        &["ct", "established", "related", "jump", "goto", "queue"],
    )?;
    selectors(string(&doc["netlink"])?, &json!("little"), id, 3)?;
    let mut counts = [0; 3];
    for (index, rule) in rules.into_iter().enumerate() {
        require(rule["comment"] == COMMENTS[index], "policy order")?;
        let expr = array(&rule["expr"])?;
        counts[index] = match (index, expr) {
            (0, [ip, dst, sel, count, verdict]) => {
                require(
                    *ip == destination(family)
                        && *dst == dport(proto, port)
                        && *sel == socket(path)
                        && *verdict == json!({"accept":null}),
                    "allow rule",
                )?;
                packets(count)?
            }
            (1 | 2, [protocol, sel, count, verdict]) => {
                check_l4(protocol, if index == 1 { 6 } else { 17 })?;
                require(
                    *sel == socket(path) && *verdict == json!({"drop":null}),
                    "deny rule",
                )?;
                packets(count)?
            }
            _ => return Err("policy expressions"),
        };
    }
    Ok(counts)
}

fn check_l4(expr: &Value, expected: u64) -> Result<()> {
    require(
        *expr == matches(json!({"meta":{"key":"l4proto"}}), json!(expected))
            && expr["match"]["right"].as_u64() == Some(expected),
        "integer policy protocol",
    )
}

fn process(a: &Value) -> Result<(u64, u64)> {
    let ready = &a["ready"];
    let pid = num(&ready["pid"])?;
    let start = num(&ready["start_ticks"])?;
    let unit = &a["unit"];
    require(
        ready == &a["observed"]
            && ready == &a["sent"]["identity"]
            && pid >= 2
            && start > 0
            && ready["uid"].as_u64() == Some(19101)
            && ready["caps"].as_u64() == Some(0)
            && ready["no_new_privs"].as_u64() == Some(1),
        "sender observation or privileges",
    )?;
    require(
        hex(&unit["InvocationID"], 32)
            && unit["ActiveState"] == "active"
            && string(&unit["MainPID"])?
                .parse::<u32>()
                .is_ok_and(|p| p > 1),
        "unit instance",
    )?;
    require(
        a["sender_gone"] == true
            && a["unit_empty"] == true
            && a["parent_empty"] == true
            && a["terminal"]
                == json!({"ExecMainCode":"1","ExecMainStatus":"0","Result":"success","ActiveState":"active","SubState":"exited"}),
        "native service exit or retained process",
    )?;
    Ok((pid, start))
}

fn endpoint(v: &Value, family: u64) -> Result<u64> {
    let a = array(v)?;
    require(a.len() == if family == 4 { 2 } else { 4 }, "endpoint shape")?;
    require(a[0] == address(family), "endpoint must be loopback")?;
    port(&a[1])
}

fn b_prefix(report: &Value, parent: u64, other: u64) -> Result<Vec<Value>> {
    let phases = array(&report["phases"])?;
    require(phases.len() <= 42, "unexpected B phases")?;
    let mut results = Vec::new();
    let mut phases_iter = phases.iter();
    'cases: for kind in KINDS {
        for family in [4, 6] {
            for proto in PROTOCOLS {
                let Some(phase) = phases_iter.next() else {
                    break 'cases;
                };
                let trial = format!("{kind}-{family}-{proto}");
                let selected = if kind == "wrong" { other } else { parent };
                require(
                    phase["trial_id"] == trial
                        && phase["kind"] == kind
                        && num(&phase["family"])? == family
                        && phase["protocol"] == proto
                        && num(&phase["parent_id"])? == parent
                        && num(&phase["selected_id"])? == selected,
                    "B phase identity",
                )?;
                let port = port(&phase["port"])?;
                let path = if kind == "wrong" {
                    "veilkeepercontrol.slice"
                } else {
                    "veilkeepertrial.slice"
                };
                let before = b_counter(&phase["rule_before"], family, proto, port, path)?;
                let after = b_counter(&phase["rule_after"], family, proto, port, path)?;
                selectors(
                    string(&phase["rule_netlink"])?,
                    &phase["byteorder"],
                    selected,
                    1,
                )?;
                text_shape(
                    string(&phase["rule_text"])?,
                    1,
                    &["drop", "reject", "queue", "jump", "goto"],
                )?;
                require(
                    before == 0 && (after > 0) == matches!(kind, "target" | "child" | "restart"),
                    "B counter selection",
                )?;
                let (pid, ticks) = process(phase)?;
                let ready_path = if kind == "outside" {
                    "/veilkeepercontrol.slice"
                } else {
                    "/veilkeepertrial.slice"
                };
                let unit_path = if matches!(kind, "outside" | "imported" | "moved") {
                    "/veilkeepercontrol.slice"
                } else {
                    "/veilkeepertrial.slice"
                };
                require(
                    phase["ready"]["cgroup"] == ready_path
                        || under(&phase["ready"]["cgroup"], ready_path),
                    "B sender cgroup",
                )?;
                require(
                    under(&phase["unit"]["ControlGroup"], unit_path),
                    "B unit cgroup",
                )?;
                if matches!(kind, "target" | "restart" | "outside" | "wrong") {
                    require(
                        phase["unit"]["MainPID"] == pid.to_string().as_str(),
                        "B main PID",
                    )?;
                }
                if kind == "restart" {
                    let old = &phases[results.len() % 6];
                    require(
                        old["unit"]["ControlGroup"] == phase["unit"]["ControlGroup"]
                            && old["unit"]["InvocationID"] != phase["unit"]["InvocationID"]
                            && (
                                num(&old["ready"]["pid"])?,
                                num(&old["ready"]["start_ticks"])?,
                            ) != (pid, ticks),
                        "B restart evidence",
                    )?;
                }
                let receiver = &phase["receiver"];
                require(
                    phase["sent"]["trial_id"] == trial
                        && phase["sent"]["returncode"].as_u64() == Some(0)
                        && receiver["trial_id"] == trial
                        && num(&receiver["identity"]["uid"])? == 0
                        && !string(&receiver["identity"]["cgroup"])?
                            .starts_with("/veilkeepertrial.slice"),
                    "B receiver evidence",
                )?;
                endpoint(&receiver["peer"], family)?;
                results.push(json!({"trial_id":trial,"counter_delta":after,
                    "negative_control_detected":kind=="wrong","excluded_socket_observed":matches!(kind,"imported"|"moved")}));
            }
        }
    }
    Ok(results)
}

#[cfg(target_os = "linux")]
pub fn validate_b_prefix(report: &Value, parent: u64, other: u64) -> Result<()> {
    b_prefix(report, parent, other).map(|_| ())
}

fn check_b(report: &Value, parent: u64, other: u64) -> Result<Value> {
    let results = b_prefix(report, parent, other)?;
    require(results.len() == 42, "required B phases")?;
    empty(&report["initial_ruleset"])?;
    empty(&report["final_ruleset"])?;
    require(
        report["initial_ruleset"] == report["final_ruleset"],
        "B ruleset restoration",
    )?;
    Ok(json!({"phases":results}))
}

fn check_c(report: &Value, parent: u64, other: u64) -> Result<Value> {
    let controller = &report["controller"];
    require(
        num(&controller["pid"])? >= 2
            && num(&controller["start_ticks"])? > 0
            && num(&controller["uid"])? == 0
            && controller["cgroup"] == "/system.slice/keeper-cgroup-c.service",
        "C controller identity",
    )?;
    let groups = array(&report["groups"])?;
    let ([ipv4, ipv6], []) = groups.as_chunks::<3>() else {
        return Err("required C groups");
    };
    for (family, family_groups) in [(4, ipv4), (6, ipv6)] {
        for (proto, group) in PROTOCOLS.into_iter().zip(family_groups) {
            validate_c_group(group, family, proto, parent, other)?;
        }
    }
    empty(&report["initial"]["json"])?;
    empty(&report["final"]["json"])?;
    require(
        report["initial"]["json"] == report["final"]["json"],
        "C ruleset restoration",
    )?;
    Ok(json!({"attempts":66,"denied_attempts":6,"negative_controls":6}))
}

pub fn validate_c_prefix(
    group: &Value,
    family: u64,
    proto: &str,
    parent: u64,
    other: u64,
) -> Result<()> {
    let id = format!("{family}-{proto}");
    let policy = &group["policy"];
    let allow = port(&policy["allow_port"])?;
    let deny = port(&group["deny_port"])?;
    require(
        group["group_id"] == id
            && num(&group["family"])? == family
            && group["protocol"] == proto
            && allow != deny
            && *policy
                == json!({"schema_version":1,"parent_id":parent,"family":family,
            "protocol":transport(proto),"allow_port":allow}),
        "C policy identity",
    )?;
    let attempts = array(&group["attempts"])?;
    require(
        !attempts.is_empty() && attempts.len() <= STEPS.len(),
        "unexpected C lifecycle",
    )?;
    let mut previous_end = 0;
    let mut previous_counts = [0; 3];
    let receivers = &attempts[0]["receiver_before"];
    let receiver_set = array(receivers)?;
    require(receiver_set.len() == 2, "C receiver set")?;
    for (r, (role, port)) in receiver_set.iter().zip([("allow", allow), ("deny", deny)]) {
        require(
            r["role"] == role
                && num(&r["port"])? == port
                && r["thread_alive"] == true
                && r.get("error") == Some(&Value::Null)
                && num(&r["inode"])? > 0,
            "C receiver continuity",
        )?;
    }
    require(
        receiver_set[0]["inode"] != receiver_set[1]["inode"],
        "C distinct receiver sockets",
    )?;
    for (step, a) in STEPS.into_iter().zip(attempts) {
        let trial = format!("{id}-{step}");
        let (role, port) = if step.ends_with("allow") {
            ("allow", allow)
        } else {
            ("deny", deny)
        };
        let sent = &a["sent"];
        require(
            a["step"] == step
                && num(&a["family"])? == family
                && a["protocol"] == proto
                && a["byteorder"] == "little"
                && a["trial_id"] == trial
                && sent["trial_id"] == trial
                && a["destination"] == role
                && num(&a["port"])? == port
                && num(&a["parent_id"])? == parent,
            "C attempt identity",
        )?;
        let (pid, _) = process(a)?;
        let outside = matches!(
            step,
            "active-health-before" | "active-health-after" | "active-outside-allow"
        );
        let path = if outside {
            "veilkeeperccontrol.slice"
        } else {
            "veilkeeperctrial.slice"
        };
        let cgroup = format!("/{path}/keeper-c-{trial}.service");
        require(
            a["ready"]["cgroup"] == cgroup
                && a["unit"]["ControlGroup"] == cgroup
                && a["unit"]["MainPID"] == pid.to_string().as_str(),
            "C unit boundary",
        )?;
        let start = num(&a["start_ns"])?;
        let end = num(&a["end_ns"])?;
        let finished = num(&sent["finished_ns"])?;
        require(
            previous_end < start
                && start <= finished
                && end.checked_sub(finished).is_some_and(|n| n >= 500_000_000)
                && &a["receiver_before"] == receivers
                && &a["receiver_after"] == receivers,
            "C receive window or continuity",
        )?;
        previous_end = end;
        let denied = step == "active-deny";
        if step.starts_with("active-") || step == "wrong-deny" {
            let (path, selected) = if step == "wrong-deny" {
                ("veilkeeperccontrol.slice", other)
            } else {
                ("veilkeeperctrial.slice", parent)
            };
            let before = c_counters(&a["before"], family, proto, allow, path, selected)?;
            let after = c_counters(&a["after"], family, proto, allow, path, selected)?;
            let increments = match step {
                "active-allow" | "active-after-allow" => Some(0),
                "active-deny" => Some(if proto == "tcp" { 1 } else { 2 }),
                _ => None,
            };
            require(
                before
                    == if step == "wrong-deny" {
                        [0; 3]
                    } else {
                        previous_counts
                    },
                "C counter continuity",
            )?;
            for index in 0..3 {
                require(
                    if increments == Some(index) {
                        after[index] > before[index]
                    } else {
                        after[index] == before[index]
                    },
                    "C counter delta",
                )?;
            }
            previous_counts = after;
        } else {
            empty(&a["before"]["json"])?;
            empty(&a["after"]["json"])?;
        }
        let received = array(&a["received"])?;
        let errno = sent["socket_errno"].as_u64();
        let deadline = sent["connect_deadline"] == true;
        let bytes = num(&sent["sent_bytes"])?;
        if denied {
            require(
                received.is_empty()
                    && bytes
                        == (if errno == Some(0) {
                            trial.len() as u64
                        } else {
                            0
                        })
                    && if proto == "tcp" {
                        matches!(errno, Some(1 | 13 | 110)) && !deadline
                            || sent.get("socket_errno") == Some(&Value::Null) && deadline
                    } else {
                        matches!(errno, Some(0 | 1 | 13)) && !deadline
                    },
                "C denial evidence",
            )?;
        } else {
            let [event] = received else {
                return Err("C single expected receive");
            };
            require(
                errno == Some(0)
                    && !deadline
                    && bytes == trial.len() as u64
                    && event["trial_id"] == trial
                    && event["role"] == role
                    && num(&event["port"])? == port
                    && (start..=end).contains(&num(&event["received_ns"])?)
                    && endpoint(&sent["local"], family)? == endpoint(&event["peer"], family)?,
                "C delivery evidence",
            )?;
        }
    }
    Ok(())
}

pub fn validate_c_group(
    group: &Value,
    family: u64,
    proto: &str,
    parent: u64,
    other: u64,
) -> Result<()> {
    require(
        array(&group["attempts"])?.len() == STEPS.len(),
        "required C lifecycle",
    )?;
    validate_c_prefix(group, family, proto, parent, other)?;
    let invalid = &group["invalid_policy"];
    let mut malformed = group["policy"].clone();
    malformed["parent_id"] = json!(true);
    require(
        invalid["request"] == malformed
            && invalid["rejected"] == true
            && num(&invalid["validation_code"])? == 2
            && num(&invalid["commands_before"])? == num(&invalid["commands_after"])?,
        "C invalid policy host command evidence",
    )?;
    empty(&group["final"]["json"])
}

pub fn verify(mode: &str, report: &Value) -> Result<Value> {
    static BOOT: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\A[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\z").unwrap());
    require(
        report["schema_version"].as_u64() == Some(1)
            && report["scenario"] == format!("keeper-cgroup-{mode}")
            && report["completed"] == true
            && report["enforcement_verified"] == false
            && report["enterprise_ready"] == false
            && BOOT.is_match(string(&report["boot_id"])?),
        "incomplete or overstated evidence",
    )?;
    let parent = num(&report["parent_id"])?;
    let other = num(&report["other_id"])?;
    require(
        parent > 0 && other > 0 && parent != other,
        "distinct cgroup identities",
    )?;
    let mut result = if mode == "b" {
        check_b(report, parent, other)?
    } else {
        check_c(report, parent, other)?
    };
    result["status"] = json!("evidence_consistent");
    result["runtime_acceptance"] = json!(false);
    result["enforcement_verified"] = json!(false);
    result["enterprise_ready"] = json!(false);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integer_protocol_fixture() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../tests/fixtures/c-nft-117-numeric-protocol.json"
        ))
        .unwrap();
        let mut found = 0;
        for row in rows(&fixture["before"]["json"]).unwrap() {
            if let Some(expressions) = row["rule"]["expr"].as_array() {
                for expr in expressions {
                    if expr["match"]["left"]["meta"]["key"] == "l4proto" {
                        let n = expr["match"]["right"].as_u64().unwrap();
                        assert!([6, 17].contains(&n));
                        assert!(check_l4(expr, n).is_ok());
                        let mut floating = expr.clone();
                        floating["match"]["right"] = json!(n as f64);
                        assert!(check_l4(&floating, n).is_err());
                        found += 1;
                    }
                }
            }
        }
        assert_eq!(found, 2);
    }

    #[test]
    fn checks_netlink_endianness_and_register() {
        let text = "[ socket load cgroupv2 => reg 1 ]\n[ cmp eq reg 1 0x78563412 0x00000000 ]";
        assert!(selectors(text, &json!("little"), 0x12345678, 1).is_ok());
        assert!(selectors(text, &json!("little"), 0x78563412, 1).is_err());
        assert!(
            selectors(
                &text.replace("eq reg 1", "eq reg 2"),
                &json!("little"),
                0x12345678,
                1
            )
            .is_err()
        );
    }
}

#[cfg(test)]
mod lifecycle_tests;
