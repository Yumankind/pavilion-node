//! What this machine has (docs/DESIGN.md). A claim, used to pick machines, never to trust them.
//! No serial numbers, MAC addresses or user names. `pavilion-node inventory` prints exactly what would be sent.
use serde_json::{json, Value};
use std::process::Command;
use std::time::Duration;

fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(cmd).args(args).output().ok()?;
    if !out.status.success() { return None; }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

fn first_line(s: Option<String>) -> Option<String> { s.map(|s| s.lines().next().unwrap_or("").trim().to_string()) }

#[cfg(target_os = "macos")]
fn sysctl_str(name: &str) -> Option<String> {
    let c = std::ffi::CString::new(name).ok()?;
    let mut len = 0usize;
    unsafe { libc::sysctlbyname(c.as_ptr(), std::ptr::null_mut(), &mut len, std::ptr::null_mut(), 0) };
    if len == 0 { return None; }
    let mut buf = vec![0u8; len];
    unsafe { libc::sysctlbyname(c.as_ptr(), buf.as_mut_ptr() as *mut libc::c_void, &mut len, std::ptr::null_mut(), 0) };
    Some(String::from_utf8_lossy(&buf[..len.saturating_sub(1)]).to_string())
}

fn os() -> Value {
    #[cfg(target_os = "macos")]
    {
        return json!({ "family": "macos", "name": "macOS", "version": run("sw_vers", &["-productVersion"]), "build": run("sw_vers", &["-buildVersion"]),
            "kernel": run("uname", &["-r"]), "arch": std::env::consts::ARCH });
    }
    #[cfg(target_os = "linux")]
    {
        let rel = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
        let get = |k: &str| rel.lines().find(|l| l.starts_with(&format!("{k}="))).map(|l| l[k.len() + 1..].trim_matches('"').to_string());
        return json!({ "family": "linux", "name": get("NAME"), "id": get("ID"), "version": get("VERSION_ID"), "kernel": run("uname", &["-r"]), "arch": std::env::consts::ARCH });
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    return json!({ "family": std::env::consts::OS, "arch": std::env::consts::ARCH });
}

fn cpu() -> Value {
    #[cfg(target_os = "macos")]
    {
        return json!({ "model": sysctl_str("machdep.cpu.brand_string"), "cores": std::thread::available_parallelism().map(|n| n.get()).unwrap_or(0),
            "performance_cores": run("sysctl", &["-n", "hw.perflevel0.physicalcpu"]).and_then(|s| s.parse::<u32>().ok()),
            "efficiency_cores": run("sysctl", &["-n", "hw.perflevel1.physicalcpu"]).and_then(|s| s.parse::<u32>().ok()) });
    }
    #[allow(unreachable_code)]
    {
        let ci = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
        let model = ci.lines().find(|l| l.starts_with("model name")).and_then(|l| l.split(':').nth(1)).map(|s| s.trim().to_string());
        json!({ "model": model, "cores": std::thread::available_parallelism().map(|n| n.get()).unwrap_or(0) })
    }
}

fn gpus() -> Value {
    let mut out = vec![];
    #[cfg(target_os = "macos")]
    if let Some(j) = run("system_profiler", &["SPDisplaysDataType", "-json"]).and_then(|s| serde_json::from_str::<Value>(&s).ok()) {
        for g in j["SPDisplaysDataType"].as_array().cloned().unwrap_or_default() {
            out.push(json!({ "vendor": g["spdisplays_vendor"].as_str().map(|v| v.replace("sppci_vendor_", "")), "model": g["sppci_model"], "cores": g["sppci_cores"],
                "metal": g["spdisplays_mtlgpufamilysupport"], "memory": "unified (shares RAM)", "api": "metal", "in_sandbox": false }));
        }
    }
    if let Some(s) = run("nvidia-smi", &["--query-gpu=name,memory.total,driver_version", "--format=csv,noheader,nounits"]) {
        for l in s.lines() {
            let f: Vec<&str> = l.split(',').map(|x| x.trim()).collect();
            out.push(json!({ "vendor": "nvidia", "model": f.first(), "vram_mib": f.get(1).and_then(|v| v.parse::<u64>().ok()), "driver": f.get(2), "api": "cuda", "in_sandbox": false }));
        }
    }
    if let Some(s) = run("rocm-smi", &["--showproductname"]) { out.push(json!({ "vendor": "amd", "detail": s.lines().take(5).collect::<Vec<_>>().join(" / "), "api": "rocm" })); }
    Value::Array(out)
}

fn sandboxes() -> Value {
    let mut v = vec![];
    if let Some(s) = first_line(run("container", &["--version"])) { v.push(json!({ "runtime": "apple-container", "version": s, "isolation": "vm" })); }
    if let Some(s) = first_line(run("podman", &["--version"])) {
        v.push(json!({ "runtime": "podman", "version": s, "kvm": std::path::Path::new("/dev/kvm").exists(), "krun": run("which", &["krun"]).is_some(), "gvisor": run("which", &["runsc"]).is_some() }));
    }
    Value::Array(v)
}

/// Tools the pavilion cares about, with versions (for picking machines and for CVE matching, docs/DESIGN.md).
fn tools() -> Value {
    let mut v = serde_json::Map::new();
    for (name, args) in [("claude", vec!["--version"]), ("codex", vec!["--version"]), ("gemini", vec!["--version"]), ("ollama", vec!["--version"]),
        ("ffmpeg", vec!["-version"]), ("git", vec!["--version"]), ("node", vec!["--version"]), ("python3", vec!["--version"]), ("docker", vec!["--version"]),
        ("brew", vec!["--version"]), ("comfy", vec!["--version"])] {
        if let Some(s) = first_line(run(name, &args)) { v.insert(name.into(), Value::String(s.chars().take(120).collect())); }
    }
    Value::Object(v)
}

async fn local_models() -> Value {
    let c = reqwest::Client::builder().timeout(Duration::from_millis(800)).build().unwrap();
    let mut v = vec![];
    if let Ok(r) = c.get("http://127.0.0.1:11434/api/tags").send().await {
        if let Ok(j) = r.json::<Value>().await {
            for m in j["models"].as_array().cloned().unwrap_or_default() { v.push(json!({ "runner": "ollama", "name": m["name"], "size": m["size"] })); }
        }
    }
    if let Ok(r) = c.get("http://127.0.0.1:1234/v1/models").send().await {
        if let Ok(j) = r.json::<Value>().await {
            for m in j["data"].as_array().cloned().unwrap_or_default() { v.push(json!({ "runner": "lm-studio", "name": m["id"] })); }
        }
    }
    Value::Array(v)
}

fn capabilities(gpus: &Value, tools: &Value, models: &Value, sandboxes: &Value) -> Vec<String> {
    let mut c = vec![];
    for sb in sandboxes.as_array().cloned().unwrap_or_default() {
        if sb["isolation"] == "vm" || (sb["kvm"] == true && sb["krun"] == true) { c.push("sandbox:vm".into()); }
        else if sb["gvisor"] == true { c.push("sandbox:gvisor".into()); }
    }
    for g in gpus.as_array().cloned().unwrap_or_default() { if let Some(api) = g["api"].as_str() { c.push(format!("gpu:{api}-host")); } }
    if models.as_array().map_or(false, |a| !a.is_empty()) { c.push("llm:local".into()); }
    if tools.get("claude").is_some() { c.push("agent:claude-code".into()); }
    if tools.get("codex").is_some() { c.push("agent:codex".into()); }
    if tools.get("ffmpeg").is_some() { c.push("media:ffmpeg".into()); }
    c.sort(); c.dedup(); c
}

pub async fn collect() -> Value {
    let s = crate::guard::sample();
    let limits = crate::guard::Limits::defaults(&s);
    let (g, t, sb) = (gpus(), tools(), sandboxes());
    let m = local_models().await;
    json!({
        "os": os(), "cpu": cpu(),
        "memory_mib": s.mem_total_mib,
        "disk": { "free_mib": s.disk_free_mib, "total_mib": s.disk_total_mib },
        "gpus": g, "sandboxes": sb, "tools": t, "local_models": m,
        "capabilities": capabilities(&g, &t, &m, &sb),
        "slots": { "vm_budget_mib": limits.vm_budget_mib(&s), "small_1gib": crate::guard::slots(&s, &limits, 1024), "large_3gib": crate::guard::slots(&s, &limits, 3072),
                   "small_now": crate::guard::slots_now(&s, &limits, 1024, 0), "large_now": crate::guard::slots_now(&s, &limits, 3072, 0), "vm_storage": s.storage,
                   "owner_reserve_mib": limits.owner_reserve_mib, "disk_floor_mib": limits.disk_floor_mib },
        "node": env!("CARGO_PKG_VERSION"),
    })
}
