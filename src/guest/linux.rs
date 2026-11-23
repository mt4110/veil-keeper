use crate::{evidence, io as report_io};
use serde_json::{Value, json};
use socket2::{Domain, SockAddr, Socket, Type};
use std::{
    fs::{self, OpenOptions, Permissions},
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, UdpSocket},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::mpsc::{self, Receiver as Channel},
    thread,
    time::{Duration, Instant},
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const UID: u32 = 19101;
const LIMIT: Duration = Duration::from_secs(8);
static COMMANDS_STARTED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn demand(ok: bool, message: &'static str) -> Result<()> {
    if ok { Ok(()) } else { Err(message.into()) }
}

struct Scenario {
    mode: &'static str,
    parent: &'static str,
    other: &'static str,
    table: &'static str,
}

impl Scenario {
    fn select(mode: &str) -> Result<Self> {
        match mode {
            "b" => Ok(Self {
                mode: "b",
                parent: "veilkeepertrial.slice",
                other: "veilkeepercontrol.slice",
                table: "keeper_b",
            }),
            "c" => Ok(Self {
                mode: "c",
                parent: "veilkeeperctrial.slice",
                other: "veilkeeperccontrol.slice",
                table: "keeper_c",
            }),
            _ => Err("invalid fixture mode".into()),
        }
    }
    fn work(&self) -> PathBuf {
        PathBuf::from(format!("/run/keeper-{}", self.mode))
    }

    fn guard(&self, controller: bool) -> Result<()> {
        demand(
            !controller || unsafe { libc::geteuid() } == 0,
            "guest root required",
        )?;
        demand(
            cfg!(target_endian = "little"),
            "pinned little-endian guest required",
        )?;
        demand(
            fs::read_to_string("/etc/hostname")?.trim() == format!("veil-cgroup-{}", self.mode)
                && fs::read_to_string("/proc/cmdline")?
                    .split_whitespace()
                    .any(|token| token == format!("keeper.cgroup_{}=1", self.mode)),
            "dedicated guest markers required",
        )?;
        let names = fs::read_dir("/sys/class/net")?
            .map(|e| e.map(|e| e.file_name()))
            .collect::<io::Result<Vec<_>>>()?;
        demand(
            names.len() == 1 && names[0] == "lo",
            "loopback-only guest required",
        )?;
        demand(
            fs::read_to_string("/proc/1/comm")?.trim() == "systemd"
                && Path::new("/sys/fs/cgroup/cgroup.controllers").is_file(),
            "systemd cgroup v2 guest required",
        )?;
        if controller {
            for namespace in ["net", "mnt", "user", "pid", "cgroup"] {
                demand(
                    fs::read_link(format!("/proc/self/ns/{namespace}"))?
                        == fs::read_link(format!("/proc/1/ns/{namespace}"))?,
                    "initial guest namespaces required",
                )?;
            }
            let vm = command("systemd-detect-virt", &["--vm"], None)?;
            demand(
                matches!(vm.trim(), "kvm" | "qemu"),
                "QEMU or KVM guest required",
            )?;
        }
        Ok(())
    }

    fn snapshot(&self) -> Result<Value> {
        Ok(json!({
            "json":serde_json::from_str::<Value>(&command("nft", &["-j","-n","list","ruleset"], None)?)?,
            "text":command("nft", &["-n","list","ruleset"], None)?,
            "netlink":command("nft", &["--debug=netlink","-n","list","ruleset"], None)?,
        }))
    }

    fn install(&self, rules: &str) -> Result<Installed<'_>> {
        evidence::empty(&self.snapshot()?["json"])?;
        command("nft", &["-f", "-"], Some(rules))?;
        Ok(Installed {
            scenario: self,
            active: true,
        })
    }
}

fn command(program: &str, args: &[&str], input: Option<&str>) -> Result<String> {
    let path = [
        "/run/current-system/sw/bin",
        "/usr/sbin",
        "/usr/bin",
        "/sbin",
        "/bin",
    ]
    .iter()
    .map(|p| Path::new(p).join(program))
    .find(|p| p.is_file())
    .ok_or("fixture command unavailable")?;
    let mut child = Command::new(path)
        .args(args)
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    COMMANDS_STARTED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let drain = |mut source: Box<dyn Read + Send>| -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        (&mut source)
            .take(4 * 1024 * 1024 + 1)
            .read_to_end(&mut out)?;
        if out.len() > 4 * 1024 * 1024 {
            return Err(io::Error::other("command output too large"));
        }
        Ok(out)
    };
    let output = thread::spawn(move || drain(Box::new(stdout)));
    let errors = thread::spawn(move || drain(Box::new(stderr)));
    if let Some(input) = input
        && let Err(error) = child.stdin.take().unwrap().write_all(input.as_bytes())
    {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error.into());
    }
    let deadline = Instant::now() + Duration::from_secs(12);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("{program} timed out").into());
        }
        thread::sleep(Duration::from_millis(10));
    };
    let mut output = output.join().map_err(|_| "stdout reader failed")??;
    let errors = errors.join().map_err(|_| "stderr reader failed")??;
    if !status.success() {
        return Err(format!(
            "{program} failed with {status}: {}",
            String::from_utf8_lossy(&errors)
        )
        .into());
    }
    if args.contains(&"--debug=netlink") {
        output.extend(errors);
    }
    Ok(String::from_utf8(output)?)
}

struct Installed<'a> {
    scenario: &'a Scenario,
    active: bool,
}
impl Installed<'_> {
    fn remove(&mut self) -> Result<()> {
        command(
            "nft",
            &["delete", "table", "inet", self.scenario.table],
            None,
        )?;
        self.active = false;
        Ok(())
    }
}
impl Drop for Installed<'_> {
    fn drop(&mut self) {
        if self.active
            && let Err(error) = self.remove()
        {
            eprintln!("fixture table cleanup failed: {error}");
        }
    }
}

fn ip(family: u64) -> IpAddr {
    if family == 4 {
        Ipv4Addr::LOCALHOST.into()
    } else {
        Ipv6Addr::LOCALHOST.into()
    }
}
fn endpoint(addr: SocketAddr) -> Value {
    match addr {
        SocketAddr::V4(a) => json!([a.ip().to_string(), a.port()]),
        SocketAddr::V6(a) => json!([a.ip().to_string(), a.port(), a.flowinfo(), a.scope_id()]),
    }
}
fn monotonic() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    assert_eq!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) },
        0
    );
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

fn child_id(pid: u32) -> Result<Value> {
    demand(pid > 1, "sender PID invalid")?;
    let base = PathBuf::from(format!("/proc/{pid}"));
    let status = fs::read_to_string(base.join("status"))?;
    let get = |name| {
        status
            .lines()
            .filter_map(|l| l.split_once(':'))
            .find(|(k, _)| *k == name)
            .map(|(_, v)| v.trim())
            .ok_or("sender status missing")
    };
    let stat = fs::read_to_string(base.join("stat"))?;
    let start_ticks = stat
        .rsplit_once(')')
        .and_then(|(_, fields)| fields.split_whitespace().nth(19))
        .ok_or("sender start time missing")?
        .parse::<u64>()?;
    let cgroup = fs::read_to_string(base.join("cgroup"))?;
    let group = cgroup
        .trim()
        .strip_prefix("0::")
        .ok_or("expected unified cgroup")?;
    Ok(json!({"pid":pid,"start_ticks":start_ticks,"cgroup":group,
        "uid":get("Uid")?.split_whitespace().nth(1).ok_or("sender UID missing")?.parse::<u32>()?,
        "caps":u64::from_str_radix(get("CapEff")?,16)?,"no_new_privs":get("NoNewPrivs")?.parse::<u32>()?}))
}

fn create(path: &Path, v: &Value, mode: u32) -> Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    f.set_permissions(Permissions::from_mode(mode))?;
    serde_json::to_writer(&mut f, v)?;
    Ok(())
}

fn wait_json(path: &Path) -> Result<Value> {
    let deadline = Instant::now() + LIMIT;
    loop {
        if let Ok((value, _)) = report_io::read(path, 64 * 1024) {
            return Ok(value);
        }
        demand(Instant::now() < deadline, "fixture IPC timed out")?;
        thread::sleep(Duration::from_millis(10));
    }
}

struct Unit {
    name: String,
    active: bool,
}
impl Unit {
    fn show(&self, properties: &str) -> Result<Value> {
        let args = format!("--property={properties}");
        let output = command("systemctl", &["show", &self.name, &args], None)?;
        Ok(Value::Object(
            output
                .lines()
                .filter_map(|s| s.split_once('='))
                .map(|(k, v)| (k.into(), json!(v)))
                .collect(),
        ))
    }
    fn stop(&mut self) -> Result<()> {
        command("systemctl", &["stop", &self.name], None)?;
        self.active = false;
        Ok(())
    }
}
impl Drop for Unit {
    fn drop(&mut self) {
        if self.active
            && let Err(error) = self.stop()
        {
            eprintln!("fixture service cleanup failed: {error}");
        }
    }
}

#[derive(Clone, Copy)]
struct Trial<'a> {
    name: &'a str,
    kind: &'a str,
    family: u64,
    proto: &'a str,
    port: u16,
}

impl Trial<'_> {
    fn start(self, s: &Scenario, outside: bool) -> Result<(Unit, PathBuf, Value, Value, Value)> {
        let dir = s.work().join(self.name);
        fs::create_dir(&dir)?;
        fs::set_permissions(&dir, Permissions::from_mode(0o755))?;
        let ipc = dir.join("sender");
        fs::create_dir(&ipc)?;
        use std::os::unix::fs::chown;
        chown(&ipc, Some(UID), Some(UID))?;
        fs::set_permissions(&ipc, Permissions::from_mode(0o700))?;
        let name = if s.mode == "b" && matches!(self.kind, "target" | "restart") {
            "keeper-b-target.service".into()
        } else {
            format!("keeper-{}-{}.service", s.mode, self.name)
        };
        let unit_arg = format!("--unit={name}");
        let slice = format!(
            "--property=Slice={}",
            if outside { s.other } else { s.parent }
        );
        let mut args = vec![
            unit_arg.as_str(),
            "--service-type=exec",
            &slice,
            "--property=NoNewPrivileges=yes",
            "--property=KillMode=control-group",
            "--property=RemainAfterExit=yes",
            "--property=RuntimeMaxSec=30",
        ];
        if !matches!(self.kind, "imported" | "moved") {
            args.extend([
                "--property=User=19101",
                "--property=Group=19101",
                "--property=CapabilityBoundingSet=",
                "--property=AmbientCapabilities=",
            ]);
        } else {
            args.push("--property=CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_DAC_OVERRIDE");
        }
        let exe = std::env::current_exe()?;
        let family = self.family.to_string();
        let port = self.port.to_string();
        args.extend([
            exe.to_str().ok_or("guest binary path must be UTF-8")?,
            "__fixture_sender",
            s.mode,
            self.name,
            self.kind,
            &family,
            self.proto,
            &port,
        ]);
        // Arm the cleanup before launching, including timeout or partial start.
        let mut unit = Unit {
            name,
            active: false,
        };
        demand(
            unit.show("LoadState")?["LoadState"] == "not-found",
            "fixture service name already in use",
        )?;
        unit.active = true;
        command("systemd-run", &args, None)?;
        let ready = wait_json(&ipc.join("ready.json"))?;
        let observed = child_id(
            ready["pid"]
                .as_u64()
                .and_then(|p| p.try_into().ok())
                .ok_or("sender PID missing")?,
        )?;
        let props = unit.show("InvocationID,MainPID,ControlGroup,ActiveState")?;
        demand(ready == observed, "sender identity differed before traffic")?;
        Ok((unit, dir, ready, observed, props))
    }
}

fn empty_group(path: &str) -> Result<bool> {
    demand(
        path.starts_with('/') && !path.contains(".."),
        "invalid cgroup path",
    )?;
    let events = format!("/sys/fs/cgroup{path}/cgroup.events");
    match fs::read_to_string(events) {
        Ok(value) => Ok(value.lines().any(|line| line == "populated 0")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error.into()),
    }
}
fn stop(mut unit: Unit, dir: &Path, props: &Value, pid: u64, parent: &str) -> Result<Value> {
    create(&dir.join("release.json"), &json!({}), 0o644)?;
    let expires = Instant::now() + LIMIT;
    let proc_path = format!("/proc/{pid}");
    let main_path = format!(
        "/proc/{}",
        props["MainPID"].as_str().ok_or("unit main PID")?
    );
    while (Path::new(&proc_path).exists() || Path::new(&main_path).exists())
        && Instant::now() < expires
    {
        thread::sleep(Duration::from_millis(10));
    }
    let sender_gone = !Path::new(&proc_path).exists();
    let terminal = unit.show("ExecMainCode,ExecMainStatus,Result,ActiveState,SubState")?;
    unit.stop()?;
    Ok(json!({"sender_gone":sender_gone,"terminal":terminal,
        "unit_empty":empty_group(props["ControlGroup"].as_str().ok_or("unit cgroup")?)?,
        "parent_empty":empty_group(&format!("/{parent}"))?}))
}

fn fork_and_wait() -> Result<bool> {
    // This is called only in the single-threaded sender process.
    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err(io::Error::last_os_error().into());
    }
    if child == 0 {
        return Ok(false);
    }
    let mut status = 0;
    loop {
        if unsafe { libc::waitpid(child, &mut status, 0) } == child {
            break;
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error.into());
        }
    }
    demand(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "fixture child failed",
    )?;
    Ok(true)
}

pub fn sender(args: &[Option<&str>]) -> std::result::Result<(), String> {
    send(args).map_err(|error| error.to_string())
}

fn send(args: &[Option<&str>]) -> Result<()> {
    let [
        Some(mode),
        Some(name),
        Some(kind),
        Some(family),
        Some(proto),
        Some(port),
    ] = args
    else {
        return Err("invalid fixture sender arguments".into());
    };
    let s = Scenario::select(mode)?;
    let contrast = matches!(*kind, "imported" | "moved");
    s.guard(false)?;
    demand(
        unsafe { libc::geteuid() } == if contrast { 0 } else { UID },
        "fixture sender UID",
    )?;
    demand(
        name.len() <= 80
            && !name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && evidence::PROTOCOLS.contains(proto)
            && (if *mode == "b" {
                evidence::KINDS.contains(kind)
            } else {
                *kind == "normal"
            }),
        "invalid fixture tuple",
    )?;
    let family = family.parse::<u64>()?;
    let port = port.parse::<u16>()?;
    demand(
        matches!(family, 4 | 6) && port > 0,
        "invalid fixture endpoint",
    )?;
    let dir = s.work().join(name);
    let expected_unit = if *mode == "b" && matches!(*kind, "target" | "restart") {
        "keeper-b-target.service".into()
    } else {
        format!("keeper-{mode}-{name}.service")
    };
    let outside = matches!(*kind, "outside" | "imported" | "moved")
        || (*mode == "c"
            && (name.ends_with("active-health-before")
                || name.ends_with("active-health-after")
                || name.ends_with("active-outside-allow")));
    let slice = if outside { s.other } else { s.parent };
    let sender = child_id(std::process::id())?;
    demand(
        sender["cgroup"] == format!("/{slice}/{expected_unit}"),
        "dedicated fixture sender service required",
    )?;
    let work = fs::symlink_metadata(s.work())?;
    demand(
        work.is_dir() && work.uid() == 0 && work.mode() & 0o022 == 0 && dir.join("sender").is_dir(),
        "fixture sender directory missing",
    )?;
    let socket = || {
        Socket::new(
            if family == 4 {
                Domain::IPV4
            } else {
                Domain::IPV6
            },
            if *proto == "tcp" {
                Type::STREAM
            } else {
                Type::DGRAM
            },
            None,
        )
    };
    let precreated = if contrast { Some(socket()?) } else { None };
    if matches!(*kind, "imported" | "child") && fork_and_wait()? {
        return Ok(());
    }
    if contrast {
        let leaf = format!("/sys/fs/cgroup/{}/contrast-{name}", s.parent);
        fs::create_dir(&leaf)?;
        fs::write(
            format!("{leaf}/cgroup.procs"),
            std::process::id().to_string(),
        )?;
        demand(
            unsafe {
                libc::setgroups(0, std::ptr::null()) == 0
                    && libc::setgid(UID) == 0
                    && libc::setuid(UID) == 0
            },
            "sender privilege drop failed",
        )?;
    }
    let identity = child_id(std::process::id())?;
    demand(
        identity["uid"] == UID && identity["caps"] == 0 && identity["no_new_privs"] == 1,
        "fixture sender privileges",
    )?;
    create(&dir.join("sender/ready.json"), &identity, 0o600)?;
    wait_json(&dir.join("go.json"))?;
    let sock = match precreated {
        Some(sock) => sock,
        None => socket()?,
    };
    sock.set_write_timeout(Some(Duration::from_secs(3)))?;
    let dest = SockAddr::from(SocketAddr::new(ip(family), port));
    // The unconnected UDP source must be concrete for strict receiver comparison.
    if *proto != "tcp" {
        sock.bind(&SocketAddr::new(ip(family), 0).into())?;
    }
    let payload = name.as_bytes();
    let result = if *proto == "udp" {
        sock.send_to(payload, &dest)
    } else if *proto == "tcp" {
        sock.connect_timeout(&dest, Duration::from_secs(3))
            .and_then(|()| {
                (&sock).write_all(payload)?;
                sock.shutdown(Shutdown::Write)?;
                Ok(payload.len())
            })
    } else {
        sock.connect(&dest).and_then(|()| sock.send(payload))
    };
    let local = sock
        .local_addr()
        .ok()
        .and_then(|addr| addr.as_socket())
        .map(endpoint);
    drop(sock);
    let (bytes, errno, deadline) = match result {
        Ok(bytes) => (bytes, Some(0), false),
        Err(error)
            if *proto == "tcp"
                && error.kind() == io::ErrorKind::TimedOut
                && error.raw_os_error().is_none() =>
        {
            (0, None, true)
        }
        Err(error) => (
            0,
            Some(
                error
                    .raw_os_error()
                    .ok_or("sender error missing Linux errno")?,
            ),
            false,
        ),
    };
    let sent = json!({"identity":child_id(std::process::id())?,"trial_id":name,"returncode":if errno == Some(0) {0} else {1},
        "socket_errno":errno,"connect_deadline":deadline,"sent_bytes":bytes,"local":local,"finished_ns":monotonic()});
    create(&dir.join("sender/sent.json"), &sent, 0o600)?;
    wait_json(&dir.join("release.json"))?;
    Ok(())
}

struct Listener {
    port: u16,
    inode: u64,
    role: &'static str,
    events: Channel<ResultEvent>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}
type ResultEvent = std::result::Result<Value, String>;

impl Listener {
    fn new(family: u64, proto: &str, role: &'static str) -> Result<Self> {
        use std::os::fd::AsRawFd;
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };
        let addr = SocketAddr::new(ip(family), 0);
        let tcp = if proto == "tcp" {
            Some(TcpListener::bind(addr)?)
        } else {
            None
        };
        let udp = if tcp.is_none() {
            Some(UdpSocket::bind(addr)?)
        } else {
            None
        };
        let (port, fd) = if let Some(sock) = &tcp {
            sock.set_nonblocking(true)?;
            (sock.local_addr()?.port(), sock.as_raw_fd())
        } else {
            let sock = udp.as_ref().unwrap();
            sock.set_nonblocking(true)?;
            (sock.local_addr()?.port(), sock.as_raw_fd())
        };
        let inode = fs::metadata(format!("/proc/self/fd/{fd}"))?.ino();
        let stop = Arc::new(AtomicBool::new(false));
        let cancelled = stop.clone();
        let (tx, events) = mpsc::channel();
        let thread = thread::spawn(move || {
            while !cancelled.load(Ordering::Relaxed) {
                let mut buffer = [0; 128];
                let received = if let Some(sock) = &tcp {
                    sock.accept().and_then(|(stream, peer)| {
                        stream.set_read_timeout(Some(Duration::from_secs(1)))?;
                        let mut payload = Vec::new();
                        stream
                            .take(129)
                            .read_to_end(&mut payload)
                            .map_err(|error| {
                                io::Error::other(format!("fixture receive failed: {error}"))
                            })?;
                        if payload.len() > 128 {
                            return Err(io::Error::other("oversized TCP fixture message"));
                        }
                        buffer[..payload.len()].copy_from_slice(&payload);
                        Ok((payload.len(), peer))
                    })
                } else {
                    udp.as_ref().unwrap().recv_from(&mut buffer)
                };
                match received {
                    Ok((length, peer)) => {
                        let result = std::str::from_utf8(&buffer[..length]).map(|payload| json!({
                            "trial_id":payload,"received_ns":monotonic(),"peer":endpoint(peer),"port":port,"role":role
                        })).map_err(|e| e.to_string());
                        if tx.send(result).is_err() {
                            break;
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(error) => {
                        let _ = tx.send(Err(error.to_string()));
                        break;
                    }
                }
            }
        });
        Ok(Self {
            port,
            inode,
            role,
            events,
            stop,
            thread: Some(thread),
        })
    }
    fn state(&self) -> Value {
        json!({"port":self.port,"inode":self.inode,"role":self.role,
            "thread_alive":self.thread.as_ref().is_some_and(|t| !t.is_finished()),"error":null})
    }
    fn collect(&self) -> Result<Vec<Value>> {
        self.events
            .try_iter()
            .map(|event| event.map_err(Into::into))
            .collect()
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn cgroup_inode(slice: &str) -> Result<u64> {
    Ok(fs::metadata(format!("/sys/fs/cgroup/{slice}"))?.ino())
}

fn recipe(s: &Scenario, family: u64, proto: &str, port: u16, selected: u64) -> String {
    let network = if family == 4 { "ip" } else { "ip6" };
    let address = ip(family);
    let transport = if proto == "tcp" { "tcp" } else { "udp" };
    let table = s.table;
    let selector = format!("socket cgroupv2 level 1 {selected}");
    let mut text = format!(
        "add table inet {table}\nadd chain inet {table} output {{ type filter hook output priority 0; policy accept; }}\n"
    );
    let action = if s.mode == "b" {
        "comment \"keeper-b-selection\""
    } else {
        "accept comment \"keeper-c-allow\""
    };
    text.push_str(&format!("add rule inet {table} output {network} daddr {address} {transport} dport {port} {selector} counter {action}\n"));
    if s.mode == "c" {
        for transport in ["tcp", "udp"] {
            text.push_str(&format!("add rule inet {table} output meta l4proto {transport} {selector} counter drop comment \"keeper-c-deny-{transport}\"\n"));
        }
    }
    text
}

fn c_recipe(s: &Scenario, policy: &Value) -> Result<String> {
    let p = policy
        .as_object()
        .filter(|p| p.len() == 5)
        .ok_or("invalid policy fields")?;
    demand(
        p.get("schema_version").and_then(Value::as_u64) == Some(1),
        "invalid policy version",
    )?;
    let id = policy["parent_id"]
        .as_u64()
        .filter(|&p| p > 0)
        .ok_or("invalid policy cgroup")?;
    let family = policy["family"]
        .as_u64()
        .filter(|&f| matches!(f, 4 | 6))
        .ok_or("invalid policy family")?;
    let protocol = policy["protocol"]
        .as_str()
        .filter(|&p| matches!(p, "tcp" | "udp"))
        .ok_or("invalid policy transport")?;
    let port = policy["allow_port"]
        .as_u64()
        .and_then(|p| u16::try_from(p).ok())
        .filter(|&p| p > 0)
        .ok_or("invalid policy port")?;
    Ok(recipe(s, family, protocol, port, id))
}

fn merge(v: &mut Value, fields: Value) {
    v.as_object_mut()
        .unwrap()
        .extend(fields.as_object().unwrap().clone());
}

fn run_b(s: &Scenario, parent: u64, other: u64, report: &mut Value) -> Result<()> {
    for kind in evidence::KINDS {
        for family in [4, 6] {
            for proto in evidence::PROTOCOLS {
                let name = format!("{kind}-{family}-{proto}");
                let listener = Listener::new(family, proto, "test")?;
                let selected = if kind == "wrong" { other } else { parent };
                let mut installed =
                    s.install(&recipe(s, family, proto, listener.port, selected))?;
                let before = s.snapshot()?;
                let trial = Trial {
                    name: &name,
                    kind,
                    family,
                    proto,
                    port: listener.port,
                };
                let (unit, dir, ready, observed, props) =
                    trial.start(s, matches!(kind, "outside" | "moved" | "imported"))?;
                create(&dir.join("go.json"), &json!({}), 0o644)?;
                let event = listener
                    .events
                    .recv_timeout(LIMIT)?
                    .map_err(io::Error::other)?;
                let sent = wait_json(&dir.join("sender/sent.json"))?;
                let after = s.snapshot()?;
                let terminal = stop(
                    unit,
                    &dir,
                    &props,
                    ready["pid"].as_u64().ok_or("sender PID")?,
                    s.parent,
                )?;
                if matches!(kind, "imported" | "moved") {
                    fs::remove_dir(format!("/sys/fs/cgroup/{}/contrast-{name}", s.parent))?;
                }
                installed.remove()?;
                let mut phase = json!({"kind":kind,"trial_id":name,"family":family,"protocol":proto,
                    "port":listener.port,"parent_id":cgroup_inode(s.parent)?,"selected_id":selected,
                    "byteorder":"little","rule_before":before["json"],"rule_after":after["json"],
                    "rule_text":after["text"],"rule_netlink":after["netlink"],"ready":ready,"observed":observed,
                    "unit":props,"sent":sent,"receiver":{"peer":event["peer"],"trial_id":event["trial_id"],
                    "identity":report["controller"]}});
                merge(&mut phase, terminal);
                report["phases"].as_array_mut().unwrap().push(phase);
                evidence::validate_b_prefix(report, parent, other)?;
            }
        }
    }
    Ok(())
}

fn run_c(s: &Scenario, parent: u64, other: u64, report: &mut Value) -> Result<()> {
    for family in [4, 6] {
        for proto in evidence::PROTOCOLS {
            let id = format!("{family}-{proto}");
            let allow = Listener::new(family, proto, "allow")?;
            let deny = Listener::new(family, proto, "deny")?;
            let policy = json!({"schema_version":1,"parent_id":parent,"family":family,
                "protocol":if proto == "tcp" {"tcp"} else {"udp"},"allow_port":allow.port});
            let mut invalid = policy.clone();
            invalid["parent_id"] = json!(true);
            use std::sync::atomic::Ordering;
            let commands_before = COMMANDS_STARTED.load(Ordering::Relaxed);
            demand(c_recipe(s, &invalid).is_err(), "invalid policy accepted")?;
            let commands_after = COMMANDS_STARTED.load(Ordering::Relaxed);
            demand(
                commands_before == commands_after,
                "invalid policy launched a command",
            )?;
            let mut wrong = policy.clone();
            wrong["parent_id"] = json!(other);
            let mut installed = None;
            let groups = report["groups"].as_array_mut().unwrap();
            groups.push(json!({"group_id":id,"family":family,"protocol":proto,"deny_port":deny.port,
                "policy":policy,"invalid_policy":{"request":invalid,"rejected":true,"validation_code":2,
                "commands_before":commands_before,"commands_after":commands_after},"attempts":[]}));
            let group = groups.last_mut().unwrap();
            for step in evidence::STEPS {
                match step {
                    "active-allow" => installed = Some(s.install(&c_recipe(s, &policy)?)?),
                    "removed-allow" => installed.take().ok_or("active table missing")?.remove()?,
                    "wrong-deny" => installed = Some(s.install(&c_recipe(s, &wrong)?)?),
                    _ => {}
                }
                let outside = matches!(
                    step,
                    "active-health-before" | "active-health-after" | "active-outside-allow"
                );
                let receiver = if step.ends_with("allow") {
                    &allow
                } else {
                    &deny
                };
                let name = format!("{id}-{step}");
                let trial = Trial {
                    name: &name,
                    kind: "normal",
                    family,
                    proto,
                    port: receiver.port,
                };
                let (unit, dir, ready, observed, props) = trial.start(s, outside)?;
                let before = s.snapshot()?;
                let receiver_before = json!([allow.state(), deny.state()]);
                let start = monotonic();
                create(&dir.join("go.json"), &json!({}), 0o644)?;
                let sent = wait_json(&dir.join("sender/sent.json"))?;
                thread::sleep(Duration::from_millis(750));
                let end = monotonic();
                let mut events = allow.collect()?;
                events.extend(deny.collect()?);
                let receiver_after = json!([allow.state(), deny.state()]);
                let after = s.snapshot()?;
                let terminal = stop(
                    unit,
                    &dir,
                    &props,
                    ready["pid"].as_u64().ok_or("sender PID")?,
                    s.parent,
                )?;
                let mut attempt = json!({"trial_id":name,"step":step,"family":family,"protocol":proto,"destination":receiver.role,
                    "port":receiver.port,"parent_id":cgroup_inode(s.parent)?,"byteorder":"little","ready":ready,"observed":observed,
                    "sent":sent,"unit":props,"before":before,"after":after,"receiver_before":receiver_before,
                    "receiver_after":receiver_after,"received":events,"start_ns":start,"end_ns":end});
                merge(&mut attempt, terminal);
                group["attempts"].as_array_mut().unwrap().push(attempt);
                evidence::validate_c_prefix(group, family, proto, parent, other)?;
            }
            installed
                .take()
                .ok_or("wrong-selector table missing")?
                .remove()?;
            group["final"] = s.snapshot()?;
            evidence::validate_c_group(group, family, proto, parent, other)?;
        }
    }
    Ok(())
}

fn verify(mode: &str) -> Result<Value> {
    let s = Scenario::select(mode)?;
    s.guard(true)?;
    let controller = child_id(std::process::id())?;
    demand(
        controller["cgroup"] == format!("/system.slice/keeper-cgroup-{mode}.service"),
        "dedicated systemd controller service required",
    )?;
    let initial = s.snapshot()?;
    evidence::empty(&initial["json"])?;
    let work = s.work();
    fs::create_dir(&work)?;
    fs::set_permissions(&work, Permissions::from_mode(0o755))?;
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let mut report = json!({"schema_version":1,"scenario":format!("keeper-cgroup-{mode}"),
        "boot_id":boot.trim(),"controller":controller,"completed":false,"enforcement_verified":false,"enterprise_ready":false});
    if mode == "b" {
        report["initial_ruleset"] = initial["json"].clone();
        report["phases"] = json!([]);
    } else {
        report["initial"] = initial;
        report["groups"] = json!([]);
    }
    let result = (|| -> Result<Value> {
        command("systemctl", &["start", s.parent, s.other], None)?;
        let parent = cgroup_inode(s.parent)?;
        let other = cgroup_inode(s.other)?;
        report["parent_id"] = json!(parent);
        report["other_id"] = json!(other);
        demand(
            parent != other && parent > 0 && other > 0,
            "invalid cgroup identity",
        )?;
        if mode == "b" {
            run_b(&s, parent, other, &mut report)?;
        } else {
            run_c(&s, parent, other, &mut report)?;
        }
        let final_snapshot = s.snapshot()?;
        if mode == "b" {
            report["final_ruleset"] = final_snapshot["json"].clone();
        } else {
            report["final"] = final_snapshot;
        }
        report["completed"] = json!(true);
        Ok(evidence::verify(mode, &report)?)
    })();
    if let Err(error) = &result {
        report["completed"] = json!(false);
        report["failure_reason"] = json!(error.to_string());
        match s.snapshot() {
            Ok(snapshot) => report["failure_final_snapshot"] = snapshot,
            Err(error) => report["failure_final_snapshot_error"] = json!(error.to_string()),
        }
    }
    report_io::save(&work.join("report.json"), &report)?;
    result
}

pub fn run(mode: &str) -> std::result::Result<Value, String> {
    verify(mode).map_err(|e| e.to_string())
}
