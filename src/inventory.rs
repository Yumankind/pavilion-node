//! What this machine has (docs/MACHINES.md §4). A claim, used to pick machines, never to trust them.
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
    if let Some(s) = run("nvidia-smi", &["--query-gpu=name,memory.total,driver_version,memory.free", "--format=csv,noheader,nounits"]) {
        for l in s.lines() {
            let f: Vec<&str> = l.split(',').map(|x| x.trim()).collect();
            out.push(json!({ "vendor": "nvidia", "model": f.first(), "vram_mib": f.get(1).and_then(|v| v.parse::<u64>().ok()), "driver": f.get(2),
                "vram_free_mib": f.get(3).and_then(|v| v.parse::<u64>().ok()), "api": "cuda", "in_sandbox": false }));
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
    // Windows: rootless Podman in the node's WSL distro (sandbox/wsl.rs).
    #[cfg(windows)]
    v.push(crate::sandbox::wsl::inventory());
    Value::Array(v)
}

/// Xcode and its simulator runtimes (docs/WORK-ROUTING.md §4): what an iOS build or test needs. macOS only; read with
/// `xcodebuild -version` and `xcrun simctl list runtimes -j`, never by opening Xcode. Null without Xcode.
fn xcode() -> Value {
    #[cfg(target_os = "macos")]
    {
        let Some(v) = run("xcodebuild", &["-version"]) else { return Value::Null };
        let version = v.lines().find_map(|l| l.strip_prefix("Xcode ")).map(|s| s.trim().to_string());
        let build = v.lines().find_map(|l| l.strip_prefix("Build version ")).map(|s| s.trim().to_string());
        let rts = run("xcrun", &["simctl", "list", "runtimes", "-j"]).and_then(|s| serde_json::from_str::<Value>(&s).ok()).map(|j| simulator_runtimes(&j)).unwrap_or_default();
        return json!({ "version": version, "build": build, "runtimes": rts });
    }
    #[allow(unreachable_code)]
    Value::Null
}
/// `simctl list runtimes -j` trimmed to platform, version and whether it is usable.
fn simulator_runtimes(j: &Value) -> Vec<Value> {
    j["runtimes"].as_array().cloned().unwrap_or_default().iter().take(20).map(|r| json!({
        "platform": r["platform"].as_str().or_else(|| r["name"].as_str().and_then(|n| n.split(' ').next())), "version": r["version"], "available": r["isAvailable"].as_bool().unwrap_or(true) })).collect()
}

/// On mains or battery, the charge, and the thermal state (docs/WORK-ROUTING.md §4). The guard samples none of these
/// every 2 seconds; they go in the full record, sent every 15 minutes.
fn power() -> Value {
    #[cfg(target_os = "macos")]
    {
        let b = run("pmset", &["-g", "batt"]).unwrap_or_default();
        let source = if b.contains("'AC Power'") { Some("mains") } else if b.contains("'Battery Power'") { Some("battery") } else { None };
        let pct = b.split_whitespace().find_map(|w| w.strip_suffix("%;").and_then(|p| p.parse::<u32>().ok()));
        let t = run("pmset", &["-g", "therm"]).unwrap_or_default();
        // "Thermal warning level set to N." only while one is in force; otherwise "No thermal warning level has been recorded".
        let thermal = if t.is_empty() { None } else if t.contains("warning level set to") { Some("warning") } else { Some("nominal") };
        return json!({ "source": source, "battery_pct": pct, "thermal": thermal });
    }
    #[cfg(target_os = "linux")]
    {
        let dir = std::fs::read_dir("/sys/class/power_supply").map(|d| d.filter_map(|e| e.ok()).map(|e| e.path()).collect::<Vec<_>>()).unwrap_or_default();
        let read = |p: &std::path::Path, f: &str| std::fs::read_to_string(p.join(f)).ok().map(|s| s.trim().to_string());
        let bat = dir.iter().find(|p| read(p, "type").as_deref() == Some("Battery"));
        let mains = dir.iter().find(|p| read(p, "type").as_deref() == Some("Mains")).and_then(|p| read(p, "online")).map(|o| o == "1");
        let source = match (bat, mains) { (None, _) => Some("mains"), (_, Some(true)) => Some("mains"), (_, Some(false)) => Some("battery"), _ => None };
        return json!({ "source": source, "battery_pct": bat.and_then(|p| read(p, "capacity")).and_then(|c| c.parse::<u32>().ok()), "thermal": Value::Null });
    }
    #[allow(unreachable_code)]
    { json!({ "source": Value::Null, "battery_pct": Value::Null, "thermal": Value::Null }) }
}

/// Tools the pavilion cares about, with versions (for picking machines and for CVE matching, docs/MACHINES.md §4b).
fn tools() -> Value {
    let mut v = serde_json::Map::new();
    for (name, args) in [("claude", vec!["--version"]), ("codex", vec!["--version"]), ("gemini", vec!["--version"]), ("ollama", vec!["--version"]),
        ("ffmpeg", vec!["-version"]), ("git", vec!["--version"]), ("node", vec!["--version"]), ("python3", vec!["--version"]), ("docker", vec!["--version"]),
        ("brew", vec!["--version"]), ("comfy", vec!["--version"])] {
        if let Some(s) = first_line(run(name, &args)) { v.insert(name.into(), Value::String(s.chars().take(120).collect())); }
    }
    Value::Object(v)
}

/// The local model runtimes' own answers, read on loopback only and trimmed to what the pavilion parses
/// (`parseLocalModels` in gate/src/model-providers/machine.ts): Ollama's `/api/tags`, `/api/show` per model
/// (capabilities and context length; never its template, licence or tokenizer) and `/api/ps` (what is loaded now), and
/// LM Studio's `/api/v1/models`, or `/api/v0/models` from an older LM Studio. Nothing pulls, loads or changes a model.
pub async fn model_runtimes(b: &crate::relay::Bases) -> Value {
    let c = reqwest::Client::builder().no_proxy().timeout(Duration::from_millis(1500)).build().unwrap_or_default();
    async fn get(c: &reqwest::Client, u: String) -> Option<Value> { c.get(u).send().await.ok()?.error_for_status().ok()?.json::<Value>().await.ok() }
    let mut out = json!({});
    if let Some(tags) = get(&c, format!("{}/api/tags", b.ollama)).await {
        let list: Vec<Value> = tags["models"].as_array().cloned().unwrap_or_default().into_iter().take(MAX_LOCAL_MODELS).collect();
        let mut show = serde_json::Map::new();
        for m in &list {
            let Some(name) = m["name"].as_str().or(m["model"].as_str()) else { continue };
            let r = async { c.post(format!("{}/api/show", b.ollama)).json(&json!({ "model": name })).send().await.ok()?.error_for_status().ok()?.json::<Value>().await.ok() }.await;
            if let Some(s) = r {
                let info: serde_json::Map<String, Value> = s["model_info"].as_object().map(|o| o.iter().filter(|(k, _)| k.ends_with(".context_length") || *k == "general.architecture").map(|(k, v)| (k.clone(), v.clone())).collect()).unwrap_or_default();
                show.insert(name.to_string(), json!({ "capabilities": s["capabilities"], "details": s["details"], "model_info": info }));
            }
        }
        let tags: Vec<Value> = list.iter().map(|m| json!({ "name": m["name"], "model": m["model"], "size": m["size"], "details": m["details"] })).collect();
        let ps: Vec<Value> = get(&c, format!("{}/api/ps", b.ollama)).await.and_then(|p| p["models"].as_array().cloned()).unwrap_or_default().into_iter()
            .map(|m| json!({ "name": m["name"], "model": m["model"], "size_vram": m["size_vram"], "context_length": m["context_length"], "expires_at": m["expires_at"] })).collect();
        out["ollama"] = json!({ "tags": { "models": tags }, "show": show, "ps": { "models": ps } });
    }
    let v1 = get(&c, format!("{}/api/v1/models", b.lmstudio)).await.filter(|j| j["models"].is_array() || j["data"].is_array());
    if let Some(mut v1) = v1 {
        for k in ["models", "data"] { if let Some(a) = v1[k].as_array_mut() { a.truncate(MAX_LOCAL_MODELS); } }
        out["lmstudio"] = json!({ "v1": v1 });
    } else if let Some(mut v0) = get(&c, format!("{}/api/v0/models", b.lmstudio)).await {
        if let Some(a) = v0["data"].as_array_mut() { a.truncate(MAX_LOCAL_MODELS); }
        out["lmstudio"] = json!({ "v0": v0 });
    }
    out
}
/// The pavilion's inventory has room for this many models per runtime (gate `cleanInventory` keeps 128 KB in all).
pub const MAX_LOCAL_MODELS: usize = 30;

/// The older short list (runner and name), derived from the runtimes' answers: `llm:local` and the console read it.
fn local_models(r: &Value) -> Value {
    let mut v = vec![];
    for m in r["ollama"]["tags"]["models"].as_array().cloned().unwrap_or_default() { v.push(json!({ "runner": "ollama", "name": m["name"], "size": m["size"] })); }
    let lm = &r["lmstudio"];
    let list = lm["v1"]["models"].as_array().or(lm["v1"]["data"].as_array()).or(lm["v0"]["data"].as_array()).cloned().unwrap_or_default();
    for m in list { if m["type"] == "llm" || m["type"] == "vlm" { v.push(json!({ "runner": "lm-studio", "name": m["key"].as_str().or(m["id"].as_str()) })); } }
    Value::Array(v)
}

/// `agent-jobs` (agent.rs): this node runs agent jobs on task branches, because it has a strong sandbox and the worker
/// image is already here; `agent-jobs:<harness>` for each CLI that image has (`claude-code`, `codex`, `gemini-cli`). The
/// Gate sends agent work only to machines that report it, and Codex or Gemini work only where that CLI is.
fn capabilities(gpus: &Value, tools: &Value, models: &Value, sandboxes: &Value, agent_harnesses: &[&str]) -> Vec<String> {
    let agent_jobs = !agent_harnesses.is_empty();
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
    if agent_jobs { c.push("agent-jobs".into()); }
    for h in agent_harnesses { c.push(format!("agent-jobs:{h}")); }
    c.sort(); c.dedup(); c
}

pub async fn collect() -> Value {
    let s = crate::guard::sample();
    let limits = crate::guard::Limits::defaults(&s);
    let (g, t, sb) = (gpus(), tools(), sandboxes());
    let cfg = crate::state::config();
    let runtimes = model_runtimes(&crate::relay::Bases::from_config(&cfg)).await;
    let m = local_models(&runtimes);
    let relay = crate::relay::settings_from(&cfg);
    let agent = crate::agent::resolved().await;
    let harnesses: Vec<&str> = agent.as_ref().map(|(_, h)| h.clone()).unwrap_or_default();
    json!({
        "os": os(), "cpu": cpu(),
        "memory_mib": s.mem_total_mib,
        "disk": { "free_mib": s.disk_free_mib, "total_mib": s.disk_total_mib },
        "gpus": g, "sandboxes": sb, "tools": t, "local_models": m,
        // Programs the owner offers to CLI connectors, each in its sandbox image (cli.rs, docs/CONNECTORS.md §8b).
        "cli_tools": crate::cli::inventory(),
        // The model relay (relay.rs): the runtimes' raw answers, and what the owner allows on this machine.
        "model_runtimes": runtimes,
        "model_relay": { "on": relay.on, "slots": relay.slots, "offered": relay.only },
        "capabilities": capabilities(&g, &t, &m, &sb, &harnesses),
        "agent_image": agent.as_ref().map(|(i, _)| json!(i)).unwrap_or(Value::Null),
        "slots": { "vm_budget_mib": limits.vm_budget_mib(&s), "small_1gib": crate::guard::slots(&s, &limits, 1024), "large_3gib": crate::guard::slots(&s, &limits, 3072),
                   "small_now": crate::guard::slots_now(&s, &limits, 1024, 0), "large_now": crate::guard::slots_now(&s, &limits, 3072, 0), "vm_storage": s.storage,
                   "owner_reserve_mib": limits.owner_reserve_mib, "disk_floor_mib": limits.disk_floor_mib },
        "platform": crate::media::catalog::platform(),
        "media_models": crate::media::catalog::report(&crate::media::catalog::catalog()),
        "model_storage": crate::media::catalog::storage_report(&crate::media::catalog::storage()),
        "media_loaded_model": crate::media::loaded_model(),
        // The capability record's new fields (docs/WORK-ROUTING.md §4): simulators for iOS work, and the power state.
        "xcode": xcode(), "power": power(),
        // This machine's own account slots (accounts.rs, WORK-ROUTING §9): labels and states only, never a credential.
        "accounts": crate::accounts::current(),
        // This node sends live lines (live.rs): until this connection's first one, the router places nothing here.
        "live_lines": 1,
        "node": env!("CARGO_PKG_VERSION"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    /// `agent-jobs` only when the node said the image is here (and the runtime works); never from tools alone.
    #[test]
    fn agent_jobs_only_with_the_image() {
        let sb = json!([{ "runtime": "apple-container", "version": "1.5.0", "isolation": "vm" }]);
        let tools = json!({ "claude": "2.1.310 (Claude Code)", "git": "git version 2.50" });
        let without = capabilities(&json!([]), &tools, &json!([]), &sb, &[]);
        assert!(!without.contains(&"agent-jobs".to_string()) && without.contains(&"agent:claude-code".to_string()), "{without:?}");
        let with = capabilities(&json!([]), &json!({}), &json!([]), &sb, &["claude-code"]);
        assert!(with.contains(&"agent-jobs".to_string()) && with.contains(&"sandbox:vm".to_string()) && with.contains(&"agent-jobs:claude-code".to_string()), "{with:?}");
        assert!(!with.contains(&"agent-jobs:codex".to_string()), "an image without Codex says so");
        let all = capabilities(&json!([]), &json!({}), &json!([]), &sb, &["claude-code", "codex", "gemini-cli"]);
        assert!(all.contains(&"agent-jobs:codex".to_string()) && all.contains(&"agent-jobs:gemini-cli".to_string()), "{all:?}");
    }

    /// The simulators an iOS job needs, as `simctl` lists them: platform, version, usable or not.
    #[test]
    fn simulator_runtimes_are_trimmed() {
        let j = json!({ "runtimes": [
            { "name": "iOS 26.0", "platform": "iOS", "version": "26.0", "isAvailable": true, "bundlePath": "/Library/…", "identifier": "com.apple.CoreSimulator.SimRuntime.iOS-26-0" },
            { "name": "watchOS 11.4", "version": "11.4", "isAvailable": false } ] });
        assert_eq!(simulator_runtimes(&j), vec![json!({ "platform": "iOS", "version": "26.0", "available": true }), json!({ "platform": "watchOS", "version": "11.4", "available": false })]);
        assert!(simulator_runtimes(&json!({})).is_empty());
    }

    /// Ollama's list, capabilities and what is loaded; LM Studio's newer list, or its older one when the newer is
    /// missing. Raw, as the Gate parses them, without the model files, templates or tokenizers `/api/show` also sends.
    #[tokio::test]
    async fn model_runtimes_from_a_stand_in() {
        use crate::relay::{standin, Bases};
        let (_o, ollama) = standin::start("ollama").await;
        let (_l1, v1) = standin::start("lmstudio-v1").await;
        let (_l0, v0) = standin::start("lmstudio-v0").await;
        let r = model_runtimes(&Bases { ollama: ollama.clone(), lmstudio: v1 }).await;
        assert_eq!(r["ollama"]["tags"]["models"].as_array().unwrap().len(), 3);
        assert_eq!(r["ollama"]["show"]["qwen3:8b"]["capabilities"], json!(["completion", "tools", "thinking"]));
        assert_eq!(r["ollama"]["show"]["qwen3:8b"]["model_info"], json!({ "general.architecture": "qwen3", "qwen3.context_length": 40960 }));
        assert_eq!(r["ollama"]["show"]["llava:7b"]["capabilities"], json!(["completion", "vision"]));
        assert_eq!(r["ollama"]["ps"]["models"][0]["name"], "qwen3:8b");
        let text = r.to_string();
        assert!(!text.contains("tokenizer") && !text.contains("modelfile") && !text.contains("license") && text.len() < 4000, "{}", text.len());
        assert_eq!(r["lmstudio"]["v1"]["models"][0]["capabilities"]["trained_for_tool_use"], true);
        let names: Vec<String> = local_models(&r).as_array().unwrap().iter().map(|m| format!("{}:{}", m["runner"].as_str().unwrap(), m["name"].as_str().unwrap())).collect();
        assert_eq!(names, vec!["ollama:qwen3:8b", "ollama:llava:7b", "ollama:nomic-embed-text:latest", "lm-studio:qwen/qwen3-vl-8b"]);
        let r = model_runtimes(&Bases { ollama: "http://127.0.0.1:9".into(), lmstudio: v0 }).await;
        assert!(r["ollama"].is_null() && r["lmstudio"]["v1"].is_null() && r["lmstudio"]["v0"]["data"][0]["type"] == "vlm", "{r}");
        // What the relay checks a call against: the same lists, read now.
        let ids = crate::relay::local_ids(&Bases { ollama, lmstudio: "http://127.0.0.1:9".into() }).await;
        assert_eq!(ids, vec!["ollama:qwen3:8b", "ollama:llava:7b", "ollama:nomic-embed-text:latest"]);
    }
}
