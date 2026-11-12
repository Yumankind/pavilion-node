//! One job, one fresh sandbox (docs/DESIGN.md), on a host-only network made for that job, so the sandbox reaches
//! this machine's broker and nothing beyond it. Every sandbox is labelled `pavilion.job`, so a node that restarts can
//! find and stop the ones it started.
//!   macOS: Apple `container` (a small Linux VM per job).
//!   Linux: Podman with krun (a VM per job, needs /dev/kvm) or gVisor `runsc` (a user-space kernel). Plain runc/crun is
//!          refused for jobs from the pavilion.
use crate::broker::{parse_subnet, Broker, Grant};
use anyhow::{anyhow, Context, Result};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::process::Command;

pub struct JobSpec {
    pub job: String,
    pub project: String,
    pub image: String,
    pub cmd: String,
    pub cpus: u32,
    pub memory_mib: u64,
    pub timeout_s: u64,
    pub grants: HashMap<String, Grant>,
    /// Keep the sandbox for this key's next job (the same task's steps on this machine): docs/DESIGN.md, "Warm sandboxes".
    pub warm: Option<Warm>,
}

pub struct Warm { pub key: String, pub keep_s: u64 }

/// A sandbox kept running between the steps of one task. Never shared across projects: the key and the project must match.
struct WarmBox { name: String, project: String, image: String, gw: String, sub: (u32, u32), memory_mib: u64, last: std::time::Instant, keep: Duration, busy: bool }
fn warm_boxes() -> &'static tokio::sync::Mutex<HashMap<String, WarmBox>> {
    static W: std::sync::OnceLock<tokio::sync::Mutex<HashMap<String, WarmBox>>> = std::sync::OnceLock::new();
    W.get_or_init(Default::default)
}
/// Memory held by warm sandboxes that aren't running a job right now (counted by the guard's admission).
pub async fn warm_idle_memory_mib() -> u64 { warm_boxes().lock().await.values().filter(|b| !b.busy).map(|b| b.memory_mib).sum() }
/// Removes warm sandboxes idle past their time, or every idle one when `all` (the guard needs memory back).
pub async fn reap_warm(all: bool) -> usize {
    let Ok(rt) = detect() else { return 0 };
    let gone: Vec<String> = {
        let mut m = warm_boxes().lock().await;
        let keys: Vec<String> = m.iter().filter(|(_, b)| !b.busy && (all || b.last.elapsed() > b.keep)).map(|(k, _)| k.clone()).collect();
        keys.iter().filter_map(|k| m.remove(k).map(|b| b.name)).collect()
    };
    for n in &gone { remove(&rt, n).await; }
    gone.len()
}

pub struct Outcome { pub exit_code: i32, pub output: String, pub note: String }

#[derive(Clone, Debug, PartialEq)]
pub enum Runtime { Apple, Podman { oci: &'static str } }

impl Runtime {
    fn cli(&self) -> &'static str { match self { Runtime::Apple => "container", Runtime::Podman { .. } => "podman" } }
    pub fn describe(&self) -> String { match self { Runtime::Apple => "apple-container (VM)".into(), Runtime::Podman { oci } => format!("podman + {oci}") } }
}

fn on_path(bin: &str) -> bool {
    std::env::var("PATH").unwrap_or_default().split(':').any(|d| std::path::Path::new(d).join(bin).exists())
        || ["/usr/bin", "/usr/local/bin", "/usr/libexec/podman"].iter().any(|d| std::path::Path::new(d).join(bin).exists())
}

/// The strongest sandbox this machine has, or why there's none. Never falls back to running on the host.
pub fn detect() -> Result<Runtime> {
    if cfg!(target_os = "macos") { return if on_path("container") { Ok(Runtime::Apple) } else { Err(anyhow!("Apple container isn't installed (brew install container)")) }; }
    if !on_path("podman") { return Err(anyhow!("Podman isn't installed")); }
    if std::path::Path::new("/dev/kvm").exists() && on_path("krun") { return Ok(Runtime::Podman { oci: "krun" }); }
    if on_path("runsc") { return Ok(Runtime::Podman { oci: "runsc" }); }
    Err(anyhow!("no strong sandbox here: install krun (with /dev/kvm) or gVisor's runsc. Plain containers are refused for pavilion jobs."))
}

async fn cli(rt: &Runtime, args: &[&str]) -> Result<String> {
    let out = Command::new(rt.cli()).args(args).output().await.with_context(|| format!("running `{}`", rt.cli()))?;
    if !out.status.success() { return Err(anyhow!("{} {}: {}", rt.cli(), args.join(" "), String::from_utf8_lossy(&out.stderr).trim())); }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

async fn json(rt: &Runtime, args: &[&str]) -> Vec<Value> {
    cli(rt, args).await.ok().and_then(|s| serde_json::from_str::<Value>(&s).ok()).and_then(|v| v.as_array().cloned()).unwrap_or_default()
}

async fn remove(rt: &Runtime, name: &str) {
    match rt {
        Runtime::Apple => { let _ = cli(rt, &["stop", name]).await; let _ = cli(rt, &["delete", "--force", name]).await; let _ = cli(rt, &["network", "delete", name]).await; }
        Runtime::Podman { .. } => { let _ = cli(rt, &["rm", "--force", "--time", "2", name]).await; let _ = cli(rt, &["network", "rm", "--force", name]).await; }
    }
}

/// Sandboxes the node started earlier and no longer knows about (it crashed or restarted): stop them.
pub async fn sweep() -> Vec<String> {
    let Ok(rt) = detect() else { return vec![] };
    let mut names = vec![];
    match rt {
        Runtime::Apple => for c in json(&rt, &["list", "--all", "--format", "json"]).await {
            if c["configuration"]["labels"].get("pavilion.job").is_some() { if let Some(id) = c["configuration"]["id"].as_str() { names.push(id.to_string()); } }
        },
        Runtime::Podman { .. } => for c in json(&rt, &["ps", "--all", "--filter", "label=pavilion.job", "--format", "json"]).await {
            if let Some(n) = c["Names"][0].as_str() { names.push(n.to_string()); }
        },
    }
    for n in &names { remove(&rt, n).await; }
    names
}

pub async fn running_memory_mib() -> u64 {
    let Ok(rt) = detect() else { return 0 };
    if rt != Runtime::Apple { return 0; } // Podman: the node's own record of running jobs is used instead.
    json(&rt, &["list", "--format", "json"]).await.iter()
        .filter(|c| c["configuration"]["labels"].get("pavilion.job").is_some())
        .map(|c| c["configuration"]["resources"]["memoryInBytes"].as_u64().unwrap_or(0) >> 20).sum()
}

pub async fn stop(job: &str) {
    let Ok(rt) = detect() else { return };
    let name = format!("pav-{job}");
    match rt { Runtime::Apple => { let _ = cli(&rt, &["stop", &name]).await; } Runtime::Podman { .. } => { let _ = cli(&rt, &["stop", "--time", "2", &name]).await; } }
}

/// The job network's gateway (where the broker answers) and subnet.
fn gateway_and_subnet(rt: &Runtime, inspect: &Value) -> (String, String) {
    match rt {
        Runtime::Apple => (inspect[0]["status"]["ipv4Gateway"].as_str().unwrap_or_default().into(), inspect[0]["status"]["ipv4Subnet"].as_str().unwrap_or_default().into()),
        Runtime::Podman { .. } => (inspect[0]["subnets"][0]["gateway"].as_str().unwrap_or_default().into(), inspect[0]["subnets"][0]["subnet"].as_str().unwrap_or_default().into()),
    }
}

/// A host-only network for one sandbox, in 10.89.0.0/16, so the host's packet filter can let sandboxes reach the brokers
/// and nothing else (pf/pavilion.conf on macOS). Returns its gateway (where the broker answers) and subnet.
async fn make_network(rt: &Runtime, name: &str, label: &str) -> Result<(String, (u32, u32))> {
    let used: Vec<String> = match rt {
        Runtime::Apple => json(&rt, &["network", "list", "--format", "json"]).await.iter().filter_map(|n| n["status"]["ipv4Subnet"].as_str().map(String::from)).collect(),
        Runtime::Podman { .. } => json(&rt, &["network", "ls", "--format", "json"]).await.iter().filter_map(|n| n["subnets"][0]["subnet"].as_str().map(String::from)).collect(),
    };
    let subnet_arg = (0..50).map(|_| format!("10.89.{}.0/24", 1 + rand::random::<u8>() % 250)).find(|c| !used.contains(c))
        .ok_or_else(|| anyhow!("no free job subnet in 10.89.0.0/16"))?;
    cli(rt, &["network", "create", "--internal", "--subnet", &subnet_arg, "--label", label, name]).await?;
    let inspect: Value = serde_json::from_str(&cli(rt, &["network", "inspect", name]).await?)?;
    let (gw, subnet) = gateway_and_subnet(rt, &inspect);
    let Some(sub) = parse_subnet(&subnet) else { remove(rt, name).await; return Err(anyhow!("the job network has no IPv4 subnet")); };
    if gw.is_empty() { remove(rt, name).await; return Err(anyhow!("the job network has no gateway for the broker")); }
    Ok((gw, sub))
}

/// The flags every sandbox gets: fixed memory and CPUs, no host folders, no DNS; on Linux no capabilities either.
fn sandbox_flags(rt: &Runtime, name: &str, spec: &JobSpec) -> Vec<String> {
    let cpus = spec.cpus.to_string();
    match rt {
        Runtime::Apple => ["--name", name, "--network", name, "--no-dns", "--arch", "arm64", "-m", &format!("{}M", spec.memory_mib), "-c", &cpus].iter().map(|s| s.to_string()).collect(),
        Runtime::Podman { oci } => ["--name", name, "--network", name, "--dns", "none", "--runtime", oci, "--memory", &format!("{}m", spec.memory_mib), "--cpus", &cpus,
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "512"].iter().map(|s| s.to_string()).collect(),
    }
}

async fn finish(child: impl std::future::Future<Output = std::io::Result<std::process::Output>>, timeout_s: u64, note: String) -> (i32, String, String) {
    match tokio::time::timeout(Duration::from_secs(timeout_s), child).await {
        Ok(Ok(out)) => {
            let mut s = String::from_utf8_lossy(&out.stdout).to_string();
            let e = String::from_utf8_lossy(&out.stderr);
            if !e.trim().is_empty() { s.push_str("\n[stderr]\n"); s.push_str(&e); }
            (out.status.code().unwrap_or(-1), s, note)
        }
        Ok(Err(e)) => (-1, String::new(), format!("couldn't start the sandbox: {e}")),
        Err(_) => (-1, String::new(), format!("stopped after the {timeout_s} s time limit")),
    }
}
fn tail(s: String) -> String { s.chars().rev().take(16_000).collect::<String>().chars().rev().collect() }

pub async fn run(spec: JobSpec, gate: &str, pavilion: &str, key: ed25519_dalek::SigningKey) -> Result<Outcome> {
    if spec.warm.is_some() { return run_warm(spec, gate, pavilion, key).await; }
    let rt = detect()?;
    let name = format!("pav-{}", spec.job);
    // 1. A host-only network for this job alone.
    let label = format!("pavilion.job={}", spec.job);
    let (gw, sub) = make_network(&rt, &name, &label).await?;

    // 2. The broker, answering only this subnet.
    let broker = Arc::new(Broker { gate: gate.into(), pavilion: pavilion.into(), key, grants: spec.grants.clone(), subnet: sub,
        http: reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build()? });
    let (port, broker_task) = broker.serve().await?;

    // 3. The sandbox, with only the broker's address.
    let broker_url = format!("PAVILION_BROKER=http://{gw}:{port}");
    let (proj_l, job_env) = (format!("pavilion.project={}", spec.project), format!("PAVILION_JOB={}", spec.job));
    let mut args: Vec<String> = vec!["run".into()];
    if rt == Runtime::Apple { args.extend(["--progress".into(), "none".into()]); }
    args.extend(sandbox_flags(&rt, &name, &spec));
    for a in ["--label", &label, "--label", &proj_l, "-e", &broker_url, "-e", &job_env, &spec.image, "sh", "-c", &spec.cmd] { args.push(a.to_string()); }
    let (exit_code, output, note) = finish(Command::new(rt.cli()).args(&args).output(), spec.timeout_s, format!("sandbox: {}", rt.describe())).await;
    // 4. Nothing is kept: sandbox, disk and network go; the next job (or project) starts from scratch.
    broker_task.abort();
    remove(&rt, &name).await;
    Ok(Outcome { exit_code, output: tail(output), note })
}

/// The same task's steps on this machine run in one sandbox kept warm between them (caches and build output stay).
/// Each job still gets its own broker with only its own grants; the sandbox goes after `keep_s` idle seconds.
async fn run_warm(spec: JobSpec, gate: &str, pavilion: &str, key: ed25519_dalek::SigningKey) -> Result<Outcome> {
    let rt = detect()?;
    let w = spec.warm.as_ref().unwrap();
    let (name, gw, sub, reused) = {
        let mut m = warm_boxes().lock().await;
        match m.get_mut(&w.key) {
            Some(b) if b.project == spec.project && b.image == spec.image && !b.busy => { b.busy = true; (b.name.clone(), b.gw.clone(), b.sub, true) }
            Some(_) => return Err(anyhow!("the warm sandbox for this task is busy or belongs to something else")),
            None => {
                let name = format!("pav-w{}", &spec.job.trim_start_matches("job_"));
                let label = format!("pavilion.job=warm-{}", spec.job);
                let (gw, sub) = make_network(&rt, &name, &label).await?;
                let mut args: Vec<String> = vec!["run".into(), "-d".into()];
                if rt == Runtime::Apple { args.extend(["--progress".into(), "none".into()]); }
                args.extend(sandbox_flags(&rt, &name, &spec));
                for a in ["--label", &label, "--label", &format!("pavilion.project={}", spec.project), &spec.image, "sleep", "86400"] { args.push(a.to_string()); }
                if let Err(e) = cli(&rt, &args.iter().map(|s| s.as_str()).collect::<Vec<_>>()).await { remove(&rt, &name).await; return Err(e); }
                m.insert(w.key.clone(), WarmBox { name: name.clone(), project: spec.project.clone(), image: spec.image.clone(), gw: gw.clone(), sub,
                    memory_mib: spec.memory_mib, last: std::time::Instant::now(), keep: Duration::from_secs(w.keep_s.clamp(30, 3600)), busy: true });
                (name, gw, sub, false)
            }
        }
    };
    let broker = Arc::new(Broker { gate: gate.into(), pavilion: pavilion.into(), key, grants: spec.grants.clone(), subnet: sub,
        http: reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build()? });
    let (port, broker_task) = broker.serve().await?;
    let (broker_url, job_env) = (format!("PAVILION_BROKER=http://{gw}:{port}"), format!("PAVILION_JOB={}", spec.job));
    let args = ["exec", "-e", &broker_url, "-e", &job_env, &name, "sh", "-c", &spec.cmd];
    let (exit_code, output, note) = finish(Command::new(rt.cli()).args(args).output(), spec.timeout_s,
        format!("sandbox: {} · warm, {}", rt.describe(), if reused { "reused from this task's last step" } else { "new" })).await;
    broker_task.abort();
    {
        let mut m = warm_boxes().lock().await;
        // A step that ran out of time may have left the sandbox in a bad state: don't reuse it.
        if note.starts_with("stopped after") { if let Some(b) = m.remove(&w.key) { remove(&rt, &b.name).await; } }
        else if let Some(b) = m.get_mut(&w.key) { b.busy = false; b.last = std::time::Instant::now(); }
    }
    Ok(Outcome { exit_code, output: tail(output), note })
}

/* ---------- can a sandbox reach this machine's own services? (docs/DESIGN.md) ---------- */

/// Ports often open on a Mac or a Linux box (SSH, Kerberos, file sharing, Screen Sharing, AirPlay, dev servers, databases,
/// Ollama, rapportd), tried by the probe as well as whatever netstat shows.
const COMMON_PORTS: &[u16] = &[22, 80, 88, 443, 445, 548, 3000, 3306, 5000, 5173, 5432, 5900, 6379, 7000, 8000, 8080, 8443, 8812, 8820, 11434, 49152];

/// TCP ports this machine listens on beyond loopback (any user's; netstat/ss need no root).
pub fn exposed_ports() -> Vec<u16> {
    let mut ports = std::collections::BTreeSet::new();
    let out = if cfg!(target_os = "macos") { // netstat prints nothing when this process's open-file limit is very high (seen here: 1048576), so lower it for netstat.
        std::process::Command::new("/bin/sh").args(["-c", "ulimit -n 10240; /usr/sbin/netstat -an"]).stdin(std::process::Stdio::null()).output() }
              else { std::process::Command::new("ss").args(["-ltnH"]).output() };
    let Ok(out) = out else { return vec![] };
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        let local = if cfg!(target_os = "macos") { if !line.contains("LISTEN") || !line.starts_with("tcp") { continue } f.get(3).copied() } else { f.get(3).copied() };
        let Some(local) = local else { continue };
        let (addr, port) = match local.rsplit_once(if cfg!(target_os = "macos") { '.' } else { ':' }) { Some(x) => x, None => continue };
        if addr.starts_with("127.") || addr == "::1" || addr.starts_with("[::1]") || addr.starts_with("fe80") { continue; }
        if (47100..=47199).contains(&port.parse::<u16>().unwrap_or(0)) { continue; } // our own brokers
        if let Ok(p) = port.parse::<u16>() { ports.insert(p); }
    }
    ports.into_iter().collect()
}

/// This machine's own addresses beyond loopback (the LAN address, say), IPv4.
fn host_ipv4s() -> Vec<String> {
    let Ok(out) = std::process::Command::new("ifconfig").output() else { return vec![] };
    String::from_utf8_lossy(&out.stdout).lines().filter_map(|l| {
        let l = l.trim(); let ip = l.strip_prefix("inet ")?.split_whitespace().next()?;
        if ip.starts_with("127.") || ip.starts_with("10.89.") { None } else { Some(ip.to_string()) }
    }).collect()
}

/// Starts a throwaway sandbox on a job network and tries every exposed port, on the job gateway and on this machine's
/// other addresses. Returns what it could reach (empty is the only safe answer).
pub async fn probe_exposure() -> Result<Vec<String>> {
    let rt = detect()?;
    // A canary: a port this node opens on all addresses, outside the broker range. If a sandbox can reach it, the
    // firewall rule isn't in place, whatever else is listening. (Listing other programs' sockets isn't reliable:
    // some processes see none of them.)
    let canary = std::net::TcpListener::bind(("0.0.0.0", 0))?;
    let canary_port = canary.local_addr()?.port();
    let mut ports: Vec<u16> = exposed_ports();
    for p in COMMON_PORTS { if !ports.contains(p) { ports.push(*p); } }
    ports.push(canary_port);
    let name = format!("pav-probe-{}", rand::random::<u32>());
    let subnet = format!("10.89.{}.0/24", 251 + rand::random::<u8>() % 4);
    cli(&rt, &["network", "create", "--internal", "--subnet", &subnet, "--label", "pavilion.job=probe", &name]).await?;
    let inspect: Value = serde_json::from_str(&cli(&rt, &["network", "inspect", &name]).await?)?;
    let (gw, _) = gateway_and_subnet(&rt, &inspect);
    let mut targets = vec![gw.clone()]; targets.extend(host_ipv4s());
    // All at once: with the firewall in place every attempt waits out its timeout, so one by one would take minutes.
    let script = format!("for h in {}; do for p in {}; do (timeout 2 nc -w 1 $h $p </dev/null >/dev/null 2>&1 && echo OPEN $h:$p) & done; done; wait; true",
        targets.join(" "), ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(" "));
    let mut args: Vec<String> = match rt {
        Runtime::Apple => ["run", "--progress", "none", "--name", &name, "--network", &name, "--no-dns", "--arch", "arm64", "-m", "256M", "-c", "1"].iter().map(|s| s.to_string()).collect(),
        Runtime::Podman { oci } => ["run", "--name", &name, "--network", &name, "--dns", "none", "--runtime", oci, "--memory", "256m", "--cap-drop", "ALL"].iter().map(|s| s.to_string()).collect(),
    };
    for a in ["--label", "pavilion.job=probe", "docker.io/library/alpine:3.22", "sh", "-c", &script] { args.push(a.into()); }
    let out = tokio::time::timeout(Duration::from_secs(120), Command::new(rt.cli()).args(&args).output()).await;
    remove(&rt, &name).await;
    let out = out.map_err(|_| anyhow!("the exposure probe timed out"))??;
    drop(canary);
    Ok(String::from_utf8_lossy(&out.stdout).lines().filter_map(|l| l.strip_prefix("OPEN ")).map(|hp| {
        if hp.ends_with(&format!(":{canary_port}")) { format!("{hp} (the node's canary: the firewall rule isn't loaded)") } else { hp.to_string() }
    }).collect())
}
