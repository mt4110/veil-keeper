use serde_json::{Value, json};

pub fn inspect() -> Value {
    let mut result = json!({"status":"unsupported_platform","system_changes":false,
        "apply_supported":false,"enforcement_verified":false,"kernel_socket_cgroupv2":"unverified"});
    #[cfg(target_os = "linux")]
    {
        use std::{fs, os::unix::fs::PermissionsExt, path::Path};
        let available = |name: &str| {
            [
                "/run/current-system/sw/bin",
                "/usr/sbin",
                "/usr/bin",
                "/sbin",
                "/bin",
            ]
            .iter()
            .any(|dir| {
                fs::metadata(Path::new(dir).join(name))
                    .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            })
        };
        let kernel = fs::read_to_string("/proc/sys/kernel/osrelease").ok();
        let manager = fs::read_to_string("/proc/1/comm").is_ok_and(|s| s.trim() == "systemd");
        let cgroup = fs::read_to_string("/sys/fs/cgroup/cgroup.controllers").is_ok();
        let nft = available("nft");
        let systemctl = available("systemctl");
        result["kernel_release"] = json!(kernel.as_deref().map(str::trim));
        result["systemd_pid_1"] = json!(manager);
        result["systemctl_present"] = json!(systemctl);
        result["cgroup_v2_readable"] = json!(cgroup);
        result["nft_present"] = json!(nft);
        result["status"] = json!(
            if kernel.is_some() && manager && cgroup && nft && systemctl {
                "candidate_for_diagnosis"
            } else {
                "prerequisites_unconfirmed"
            }
        );
    }
    #[cfg(not(target_os = "linux"))]
    {
        result["reason"] = json!("Linux is required for live preflight");
    }
    result
}
