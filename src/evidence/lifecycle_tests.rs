use super::*;

const PARENT: u64 = 0x1234;
const OTHER: u64 = 0x1235;
const BOOT: &str = "11111111-1111-4111-8111-111111111111";

fn process_fixture(a: &mut Value, pid: usize, cgroup: &str, unit_cgroup: &str) {
    let identity =
        json!({"pid":pid,"start_ticks":100,"uid":19101,"caps":0,"no_new_privs":1,"cgroup":cgroup});
    a["ready"] = identity.clone();
    a["observed"] = identity.clone();
    a["sent"]["identity"] = identity;
    a["unit"] = json!({"InvocationID":format!("{pid:032x}"),"ActiveState":"active",
        "MainPID":pid.to_string(),"ControlGroup":unit_cgroup});
    a["terminal"] = json!({"ExecMainCode":"1","ExecMainStatus":"0","Result":"success","ActiveState":"active","SubState":"exited"});
    for key in ["sender_gone", "unit_empty", "parent_empty"] {
        a[key] = json!(true);
    }
}

fn netlink(id: u64) -> String {
    format!(
        "[ socket load cgroupv2 => reg 1 ]\n[ cmp eq reg 1 0x{:08x} 0x00000000 ]\n",
        (id as u32).swap_bytes()
    )
}

fn peer(family: u64) -> Value {
    if family == 4 {
        json!([address(family), 50123])
    } else {
        json!([address(family), 50123, 0, 0])
    }
}

fn b_rules(family: u64, proto: &str, selector: &str, count: u64) -> Value {
    let mut doc = json!({"nftables":[
        {"table":{"family":"inet","name":"keeper_b"}},
        {"chain":{"family":"inet","table":"keeper_b","name":"output","type":"filter","hook":"output","prio":0,"policy":"accept"}},
        {"rule":{"family":"inet","table":"keeper_b","chain":"output","comment":"keeper-b-selection","expr":[]}}
    ]});
    doc["nftables"][2]["rule"]["expr"] = json!([
        destination(family),dport(proto,43101),socket(selector),{"counter":{"packets":count,"bytes":count * 42}}
    ]);
    doc
}

fn b_fixture() -> Value {
    let mut phases = Vec::new();
    for kind in KINDS {
        for family in [4, 6] {
            for proto in PROTOCOLS {
                let trial = format!("{kind}-{family}-{proto}");
                let (selector, id) = if kind == "wrong" {
                    ("veilkeepercontrol.slice", OTHER)
                } else {
                    ("veilkeepertrial.slice", PARENT)
                };
                let covered = matches!(kind, "target" | "child" | "restart");
                let mut phase = json!({"kind":kind,"family":family,"protocol":proto,"trial_id":trial,"parent_id":PARENT,
                    "selected_id":id,"port":43101,"byteorder":"little","rule_text":"socket cgroupv2 level 1",
                    "rule_before":b_rules(family,proto,selector,0),"rule_after":b_rules(family,proto,selector,u64::from(covered)),
                    "rule_netlink":netlink(id),"sent":{"trial_id":trial,"returncode":0},
                    "receiver":{"trial_id":trial,"identity":{"uid":0,"cgroup":"/system.slice/fixture.service"},"peer":peer(family)}});
                let unit = if matches!(kind, "target" | "restart") {
                    "same.service"
                } else {
                    "sender.service"
                };
                let under = |s| format!("/veilkeeper{s}.slice/{unit}");
                process_fixture(
                    &mut phase,
                    phases.len() + 100,
                    &under(if kind == "outside" {
                        "control"
                    } else {
                        "trial"
                    }),
                    &under(if matches!(kind, "outside" | "imported" | "moved") {
                        "control"
                    } else {
                        "trial"
                    }),
                );
                phases.push(phase);
            }
        }
    }
    json!({"schema_version":1,"scenario":"keeper-cgroup-b","completed":true,"enforcement_verified":false,
        "enterprise_ready":false,"boot_id":BOOT,"parent_id":PARENT,"other_id":OTHER,"phases":phases,
        "initial_ruleset":{"nftables":[]},"final_ruleset":{"nftables":[]}})
}

fn c_snapshot(family: u64, proto: &str, wrong: bool, counts: [u64; 3]) -> Value {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/c-nft-117-numeric-protocol.json"
    ))
    .unwrap();
    let mut snapshot = fixture["before"].clone();
    let (id, path) = if wrong {
        (OTHER, "veilkeeperccontrol.slice")
    } else {
        (PARENT, "veilkeeperctrial.slice")
    };
    snapshot["netlink"] = json!(netlink(id).repeat(3));
    let rows = snapshot["json"]["nftables"].as_array_mut().unwrap();
    for (i, rule) in rows
        .iter_mut()
        .filter_map(|r| r.get_mut("rule"))
        .enumerate()
    {
        let expr = rule["expr"].as_array_mut().unwrap();
        let offset = if i == 0 {
            expr[0] = destination(family);
            expr[1] = dport(proto, 43101);
            2
        } else {
            1
        };
        expr[offset] = socket(path);
        expr[offset + 1]["counter"] = json!({"packets":counts[i],"bytes":counts[i] * 42});
    }
    snapshot
}

fn c_fixture() -> Value {
    let mut groups = Vec::new();
    let empty = json!({"json":{"nftables":[]}});
    for family in [4, 6] {
        for proto in PROTOCOLS {
            let id = format!("{family}-{proto}");
            let policy = json!({"schema_version":1,"parent_id":PARENT,"family":family,
                "protocol":transport(proto),"allow_port":43101});
            let mut malformed = policy.clone();
            malformed["parent_id"] = json!(true);
            let receivers = json!([
                {"role":"allow","port":43101,"thread_alive":true,"error":null,"inode":30},
                {"role":"deny","port":43102,"thread_alive":true,"error":null,"inode":40}
            ]);
            let mut counts = [0; 3];
            let mut attempts = Vec::new();
            for (index, step) in STEPS.into_iter().enumerate() {
                let trial = format!("{id}-{step}");
                let (role, port) = if step.ends_with("allow") {
                    ("allow", 43101)
                } else {
                    ("deny", 43102)
                };
                let denied = step == "active-deny";
                let start = (index + 1) as u64 * 1_000_000_000;
                let mut a = json!({"trial_id":trial,"family":family,"step":step,"protocol":proto,"byteorder":"little",
                    "destination":role,"port":port,"parent_id":PARENT,"start_ns":start,"end_ns":start+800_000_000,
                    "receiver_before":receivers,"receiver_after":receivers,
                    "sent":{"trial_id":trial,"finished_ns":start+100_000_000,"socket_errno":if denied {13} else {0},
                        "sent_bytes":if denied {0} else {trial.len()},"local":peer(family)},"received":[]});
                let outside = matches!(
                    step,
                    "active-health-before" | "active-health-after" | "active-outside-allow"
                );
                let cgroup = format!(
                    "/veilkeeperc{}.slice/keeper-c-{trial}.service",
                    if outside { "control" } else { "trial" }
                );
                process_fixture(&mut a, index + 100, &cgroup, &cgroup);
                if !denied {
                    a["received"] = json!([{"trial_id":trial,"role":role,"port":port,"peer":peer(family),"received_ns":start+50_000_000}]);
                }
                if step == "wrong-deny" {
                    a["before"] = c_snapshot(family, proto, true, [0; 3]);
                    a["after"] = a["before"].clone();
                } else if step.starts_with("active-") {
                    a["before"] = c_snapshot(family, proto, false, counts);
                    if matches!(step, "active-allow" | "active-after-allow") {
                        counts[0] += 1;
                    }
                    if denied {
                        counts[if proto == "tcp" { 1 } else { 2 }] += 1;
                    }
                    a["after"] = c_snapshot(family, proto, false, counts);
                } else {
                    a["before"] = empty.clone();
                    a["after"] = empty.clone();
                }
                attempts.push(a);
            }
            groups.push(json!({"group_id":id,"family":family,"protocol":proto,"policy":policy,"deny_port":43102,
                "attempts":attempts,"invalid_policy":{"request":malformed,"rejected":true,"validation_code":2,
                "commands_before":0,"commands_after":0},"final":empty}));
        }
    }
    json!({"schema_version":1,"scenario":"keeper-cgroup-c","completed":true,"enforcement_verified":false,
        "enterprise_ready":false,"boot_id":BOOT,"parent_id":PARENT,"other_id":OTHER,"groups":groups,
        "initial":empty,"final":empty,"controller":{"pid":2,"start_ticks":10,"uid":0,"cgroup":"/system.slice/keeper-cgroup-c.service"}})
}

#[test]
fn b_requires_every_phase_and_rejects_modified_selector() {
    let fixture = b_fixture();
    assert_eq!(
        verify("b", &fixture).unwrap()["phases"]
            .as_array()
            .unwrap()
            .len(),
        42
    );
    let mut omitted = fixture.clone();
    omitted["phases"].as_array_mut().unwrap().pop();
    assert!(verify("b", &omitted).is_err());
    let mut changed = fixture;
    changed["phases"][0]["rule_netlink"] = json!(netlink(OTHER));
    assert!(verify("b", &changed).is_err());
}

#[test]
fn c_requires_counter_and_health_corroboration_for_a_timeout() {
    let mut fixture = c_fixture();
    let denied = &mut fixture["groups"][0]["attempts"][4];
    denied["sent"]["socket_errno"] = json!(110);
    let result = verify("c", &fixture).unwrap();
    assert_eq!(result["attempts"], 66);
    assert_eq!(result["runtime_acceptance"], false);
    let mut no_gain = fixture.clone();
    no_gain["groups"][0]["attempts"][4]["after"] =
        no_gain["groups"][0]["attempts"][4]["before"].clone();
    assert!(verify("c", &no_gain).is_err());
    let mut no_health = fixture.clone();
    no_health["groups"][0]["attempts"][5]["received"] = json!([]);
    assert!(verify("c", &no_health).is_err());
    let mut malformed = fixture;
    malformed["groups"][1]["attempts"][0]["sent"]["local"][0] = json!("0.0.0.0");
    assert!(verify("c", &malformed).is_err());
}
