//! The media runner (docs/MEDIA.md, step 2): takes media jobs from the pavilion, one at a time (one GPU), and runs them
//! on this machine's own models.
//!
//!   1. Ask: signed `POST /node/media/next` every few seconds while idle and the guard is below red.
//!   2. Check: the model is in the catalog and available here, the task is one of its tasks, the inputs fit its schema,
//!      its references, its sizes; the boot disk has room and memory has headroom.
//!   3. Inputs: each file the job names is fetched into the job's own folder and re-encoded in a VM (vm.rs); without a
//!      VM, jobs with files are refused.
//!   4. Run: the runner's argv (adapters.rs) in its own process group, in the job folder, with a short environment that
//!      can't download anything; progress goes to `/progress`, whose answer says whether to stop.
//!   5. Outputs: typed from their bytes, a provenance note added, uploaded with a JSON sidecar, then `/done`.
pub mod adapters;
pub mod catalog;
pub mod provenance;
pub mod resident;
pub mod schema;
pub mod store;
pub mod vm;

use crate::guard::{self, Level};
use crate::signing::signed_headers;
use adapters::{Adapter, Input, Plan};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
use vm::Kind;

/// The tasks the Gate knows (gate/src/media.ts TASKS).
#[cfg(test)]
pub const TASKS: &[&str] = &["image.generate", "image.edit", "video.generate", "video.from_image", "music.generate", "audio.generate", "speech", "speech.clone", "speech.transcribe", "upscale"];
const POLL: Duration = Duration::from_secs(3);
const MAX_OUTPUTS: usize = 16;
const MAX_OUTPUT_BYTES: u64 = 50 * 1024 * 1024;
/// How long a job waits for memory to free up before it fails.
const MEMORY_WAIT: Duration = Duration::from_secs(300);

/// What kind of file a reference role is.
pub fn role_kind(role: &str) -> Option<Kind> {
    match role {
        "subject" | "style" | "mask" | "first_frame" | "last_frame" | "keyframe" => Some(Kind::Image),
        "voice" | "melody" | "source_audio" => Some(Kind::Audio),
        "source_video" => Some(Kind::Video),
        _ => None,
    }
}

/* ---------- shared with the link: the guard's level, the running process ---------- */

static LEVEL: AtomicU8 = AtomicU8::new(0);
static PGID: AtomicI32 = AtomicI32::new(0);
/// The model of the last job (MLX runners exit after each job; the OS keeps its files warm).
static LOADED: Mutex<Option<String>> = Mutex::new(None);
pub fn loaded_model() -> Option<String> { LOADED.lock().unwrap().clone() }
fn level_of(n: u8) -> Level { match n { 0 => Level::Green, 1 => Level::Amber, 2 => Level::Red, _ => Level::Critical } }
/// The link's guard tells the runner its level (it has the swap history).
pub fn set_level(l: Level) { LEVEL.store(l as u8, Ordering::Relaxed); }
/// The worse of the link's level and a fresh sample (the runner keeps going while the link reconnects).
pub(crate) fn level_now() -> (Level, String) {
    let s = guard::sample();
    let (own, why) = guard::level(&s, &guard::Limits::defaults(&s), 0.0);
    let shared = level_of(LEVEL.load(Ordering::Relaxed));
    if shared > own { (shared, "the guard's last reading".into()) } else { (own, why) }
}
/// Stops the running media job's processes (the node is stopping).
pub fn kill_running() { kill_group_hard(PGID.load(Ordering::Relaxed)); resident::kill_now(); }

/// Whether what the inventory says about media changed since the last call (availability, verification, the loaded
/// model): the link sends the inventory again when it did.
pub fn inventory_changed() -> bool {
    use std::hash::{Hash, Hasher};
    static LAST: Mutex<Option<u64>> = Mutex::new(None);
    let mut h = std::collections::hash_map::DefaultHasher::new();
    catalog::report(&catalog::catalog()).to_string().hash(&mut h);
    loaded_model().hash(&mut h);
    let fp = h.finish();
    let mut last = LAST.lock().unwrap();
    let changed = last.map_or(false, |l| l != fp);
    *last = Some(fp);
    changed
}

fn busy_file() -> PathBuf { crate::state::dir().join("media").join("busy") }
/// Whether a media job is running (in this or another node process on this machine).
pub fn busy() -> bool {
    std::fs::read_to_string(busy_file()).ok().and_then(|s| s.trim().parse::<i32>().ok()).map_or(false, |pid| pid > 0 && crate::platform::pid_alive(pid))
}
struct BusyGuard;
impl BusyGuard { fn take() -> BusyGuard { let _ = std::fs::create_dir_all(busy_file().parent().unwrap()); let _ = std::fs::write(busy_file(), std::process::id().to_string()); BusyGuard } }
impl Drop for BusyGuard { fn drop(&mut self) { let _ = std::fs::remove_file(busy_file()); } }

/// Error text for the pavilion: no home folder (and so no user name) in it.
fn clean(s: &str) -> String { let h = catalog::home().to_string_lossy().to_string(); let s = if h.len() > 1 { s.replace(&h, "~") } else { s.to_string() }; s.chars().take(480).collect() }

/* ---------- talking to the Gate (signed like every machine request) ---------- */

struct Gate { http: reqwest::Client, base: String, host: String, pav: String, key: ed25519_dalek::SigningKey }

impl Gate {
    fn new() -> anyhow::Result<Gate> {
        let st = crate::state::load()?;
        let url = reqwest::Url::parse(&st.gate)?;
        let host = url.host_str().unwrap_or_default().to_string() + &url.port().map(|p| format!(":{p}")).unwrap_or_default();
        Ok(Gate { http: reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).timeout(Duration::from_secs(120)).build()?,
            base: st.gate.trim_end_matches('/').to_string(), host, pav: st.pavilion, key: crate::state::key()? })
    }
    fn path(&self, p: &str) -> String { format!("/p/{}/node/media{p}", self.pav) }
    async fn send(&self, method: &str, path: &str, ctype: &str, body: Vec<u8>) -> Result<reqwest::Response, String> {
        let mut rb = self.http.request(method.parse().unwrap(), format!("{}{path}", self.base));
        for (k, v) in signed_headers(&self.key, &self.host, method, path, &body) { rb = rb.header(k, v); }
        if !body.is_empty() { rb = rb.header("content-type", ctype).body(body); }
        rb.send().await.map_err(|e| format!("the Gate: {e}"))
    }
    async fn post(&self, p: &str, body: &Value) -> Result<Value, String> {
        let r = self.send("POST", &self.path(p), "application/json", serde_json::to_vec(body).unwrap()).await?;
        let status = r.status();
        let v: Value = r.json().await.unwrap_or(json!({}));
        if !status.is_success() || v.get("error").is_some() { return Err(v["error"].as_str().unwrap_or(status.as_str()).to_string()); }
        Ok(v)
    }
    /// Fetches one input into `dest`, at most `cap` bytes. Returns its media type.
    async fn fetch(&self, job: &str, asset: &str, dest: &Path, cap: u64) -> Result<String, String> {
        use futures_util::StreamExt;
        let r = self.send("GET", &self.path(&format!("/jobs/{job}/inputs/{asset}")), "", vec![]).await?;
        if !r.status().is_success() { return Err(format!("the Gate didn't give {asset}: {}", r.status())); }
        let ctype = r.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("").to_lowercase();
        if r.content_length().map_or(false, |l| l > cap) { return Err(format!("{asset} is over {} MB", cap >> 20)); }
        let mut f = std::fs::File::create(dest).map_err(|e| e.to_string())?;
        let (mut n, mut s) = (0u64, r.bytes_stream());
        while let Some(chunk) = s.next().await {
            let c = chunk.map_err(|e| format!("reading {asset}: {e}"))?;
            n += c.len() as u64;
            if n > cap { return Err(format!("{asset} is over {} MB", cap >> 20)); }
            std::io::Write::write_all(&mut f, &c).map_err(|e| e.to_string())?;
        }
        Ok(ctype)
    }
    async fn upload(&self, job: &str, name: &str, ctype: &str, bytes: Vec<u8>) -> Result<String, String> {
        let r = self.send("PUT", &format!("{}?name={name}", self.path(&format!("/jobs/{job}/outputs"))), ctype, bytes).await?;
        let status = r.status();
        let v: Value = r.json().await.unwrap_or(json!({}));
        if !status.is_success() || v.get("error").is_some() { return Err(format!("uploading {name}: {}", v["error"].as_str().unwrap_or(status.as_str()))); }
        Ok(v["asset"].as_str().unwrap_or("").to_string())
    }
}

/* ---------- progress and stopping, shared by the runner and the reporter ---------- */

#[derive(Default)]
pub struct Ctl {
    cancel: AtomicBool,
    /// Why it was stopped, when not by a person (the guard, the drive, the clock).
    why: Mutex<Option<String>>,
    prog: Mutex<(u64, u64, String)>,
    /// Stop the run when the guard reaches critical (always, except in tests).
    guard: bool,
    /// Stopped for a passing reason (the guard): the job goes back to the queue rather than failing.
    requeue: AtomicBool,
    /// The most memory the runner's processes used together (MiB), sampled while it runs.
    peak_mib: std::sync::atomic::AtomicU64,
}
impl Ctl {
    fn guarded() -> Ctl { Ctl { guard: true, ..Default::default() } }
    fn stage(&self, s: &str) { let mut p = self.prog.lock().unwrap(); *p = (0, 0, s.to_string()); }
    fn stop(&self, why: Option<String>) { if let Some(w) = why { self.why.lock().unwrap().get_or_insert(w); } self.cancel.store(true, Ordering::Relaxed); }
    fn stopped(&self) -> bool { self.cancel.load(Ordering::Relaxed) }
    fn give_back(&self, why: String) { self.requeue.store(true, Ordering::Relaxed); self.stop(Some(why)); }
}

pub enum Stop { Canceled, Failed(String), Requeue(String) }
impl Stop {
    fn from(ctl: &Ctl) -> Stop {
        match ctl.why.lock().unwrap().clone() {
            Some(w) if ctl.requeue.load(Ordering::Relaxed) => Stop::Requeue(w),
            Some(w) => Stop::Failed(w),
            None => Stop::Canceled,
        }
    }
}

/// Checks, while a runner works, whether it must stop: the guard at critical (the job goes back to the queue), its
/// time is up, or the drive with its weights went away. True when it must stop now.
fn watch(ctl: &Ctl, p: &Plan, deadline: Instant) -> bool {
    if ctl.stopped() { return true; }
    if ctl.guard { let (lvl, why) = level_now(); if lvl == Level::Critical { ctl.give_back(format!("stopped by the resource guard on its machine ({why})")); } }
    if Instant::now() > deadline { ctl.stop(Some("stopped at its time limit".into())); }
    if p.weights.as_ref().map_or(false, |w| !w.exists()) { ctl.stop(Some("the drive with the model's weights went away".into())); }
    ctl.stopped()
}

/// Reports progress every 2 s (and at once when the stage changes); the answer may say stop.
async fn reporter(gate: Arc<Gate>, job: String, ctl: Arc<Ctl>) {
    let mut last: Option<(u64, u64, String)> = None;
    let mut sent_at = Instant::now().checked_sub(Duration::from_secs(60)).unwrap_or_else(Instant::now);
    loop {
        let p = ctl.prog.lock().unwrap().clone();
        if last.as_ref() != Some(&p) || sent_at.elapsed() > Duration::from_secs(10) {
            let mut body = json!({ "stage": p.2 });
            if p.1 > 0 { body["step"] = json!(p.0); body["total"] = json!(p.1); }
            match gate.post(&format!("/jobs/{job}/progress"), &json!({ "progress": body })).await {
                Ok(v) if v["cancel"] == true => { eprintln!("media: {job} cancelled"); ctl.stop(None); }
                Err(e) if e.starts_with("the job is") || e == "not your job" => { ctl.stop(Some(format!("the pavilion closed the job ({e})"))); }
                _ => {}
            }
            last = Some(p); sent_at = Instant::now();
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/* ---------- machine checks before a model run ---------- */

/// (available GB, total GB, swap used GB) from vm_stat and sysctl.
/// (available GB, total GB, swap used GB, under pressure now) from vm_stat and sysctl.
fn memory() -> Option<(f64, f64, f64, bool)> {
    let out = String::from_utf8_lossy(&std::process::Command::new("vm_stat").output().ok()?.stdout).to_string();
    let page = out.lines().next().and_then(|l| l.split("page size of ").nth(1)).and_then(|s| s.split_whitespace().next()).and_then(|s| s.parse::<f64>().ok()).unwrap_or(16384.0);
    let pages = |k: &str| out.lines().find(|l| l.starts_with(k)).and_then(|l| l.split(':').nth(1)).and_then(|v| v.trim().trim_end_matches('.').parse::<f64>().ok()).unwrap_or(0.0);
    let counted = (pages("Pages free") + pages("Pages inactive") + pages("Pages speculative")) * page / (1u64 << 30) as f64;
    let s = guard::sample();
    let total = s.mem_total_mib as f64 / 1024.0;
    // free + inactive + speculative misses file cache macOS gives back at once (measured here: 4.8 GB by vm_stat while the
    // kernel said 61% free), so the kernel's own free level counts too.
    let kernel = total * s.mem_free_pct as f64 / 100.0;
    Some((counted.max(kernel), total, s.swap_used_mib as f64 / 1024.0, s.pressure >= 2))
}
/// macOS keeps this much for itself.
const OS_RESERVE_GB: f64 = 4.0;
/// Room for a model of `need_gb`: headroom after the OS reserve covers it, and three times over when the machine has
/// swapped heavily and is under memory pressure now. (macOS never gives swap back, so swap alone, with the kernel
/// reporting plenty free, would refuse mid-size models until a reboot.)
pub fn headroom_ok(avail_gb: f64, total_gb: f64, swap_gb: f64, pressure: bool, need_gb: f64) -> Result<(), String> {
    let headroom = avail_gb - OS_RESERVE_GB;
    let swap_heavy = swap_gb > total_gb / 8.0 && pressure;
    if headroom < need_gb || (swap_heavy && headroom < need_gb * 3.0) {
        return Err(format!("not enough free memory: {avail_gb:.1} GB of {total_gb:.0} GB is available{}, and this model needs about {need_gb:.1} GB plus {OS_RESERVE_GB:.0} GB for macOS",
            if swap_gb >= 0.1 { format!(" and {swap_gb:.1} GB is already swapped to disk") } else { String::new() }));
    }
    Ok(())
}
/// The boot disk needs 8 GB free for macOS to swap while a model is in memory.
pub fn boot_disk_ok(free_mb: u64) -> Result<(), String> {
    if free_mb < store::BOOT_FLOOR_MB {
        let need = (store::BOOT_FLOOR_MB - free_mb) as f64 / 1024.0;
        return Err(format!("the boot disk has {:.1} GB free; running a model needs at least 8 GB free there so macOS can swap while the model is in memory. \
            Free {:.1} GB more on the boot disk. Keeping models on another drive doesn't change this: swap always lives on the boot disk", free_mb as f64 / 1024.0, need.max(0.1)));
    }
    Ok(())
}
fn boot_free_mb() -> u64 { let d = catalog::disk(Path::new("/System/Volumes/Data")); if d.1 > 0 { d.0 } else { catalog::disk(Path::new("/")).0 } }

/// Models held by Ollama give their memory back first (one generation on the machine at a time).
async fn evict_resident() {
    let c = reqwest::Client::builder().timeout(Duration::from_secs(3)).build().unwrap();
    let Ok(r) = c.get("http://127.0.0.1:11434/api/ps").send().await else { return };
    let Ok(v) = r.json::<Value>().await else { return };
    for m in v["models"].as_array().cloned().unwrap_or_default() {
        if let Some(name) = m["name"].as_str() {
            eprintln!("media: asking Ollama to unload {name}");
            let _ = c.post("http://127.0.0.1:11434/api/generate").json(&json!({ "model": name, "keep_alive": 0 })).send().await;
        }
    }
}

/* ---------- running a plan ---------- */

/// The runner's environment: nothing inherited but the basics, and Hugging Face told never to go online.
fn runner_env(p: &Plan, hub: Option<&Path>) -> Vec<(String, String)> {
    let mut dirs: Vec<String> = p.bins.values().filter_map(|b| b.parent().map(|d| d.to_string_lossy().to_string())).collect();
    dirs.sort(); dirs.dedup();
    dirs.extend(["/usr/bin", "/bin", "/usr/sbin", "/sbin"].iter().map(|s| s.to_string()));
    let tmp = p.work.join("tmp");
    let _ = std::fs::create_dir_all(&tmp);
    let mut env = vec![("PATH".into(), dirs.join(":")), ("HOME".into(), catalog::home().to_string_lossy().to_string()), ("TMPDIR".into(), tmp.to_string_lossy().to_string()),
        ("LANG".into(), "en_US.UTF-8".into()), ("HF_HUB_OFFLINE".into(), "1".into()), ("TRANSFORMERS_OFFLINE".into(), "1".into()), ("HF_DATASETS_OFFLINE".into(), "1".into()),
        ("HF_HUB_DISABLE_TELEMETRY".into(), "1".into()), ("DO_NOT_TRACK".into(), "1".into()), ("PYTHONNOUSERSITE".into(), "1".into()), ("PYTHONDONTWRITEBYTECODE".into(), "1".into()),
        ("TQDM_MININTERVAL".into(), "0.5".into())];
    // uv projects (LTX, ACE-Step) run from their own environment and cache, offline.
    if let Some(root) = catalog::storage().chosen { let c = root.join("uv-cache"); if c.is_dir() { env.push(("UV_CACHE_DIR".into(), c.to_string_lossy().to_string())); } }
    env.push(("UV_OFFLINE".into(), "1".into()));
    if let Some(h) = hub {
        env.push(("HF_HUB_CACHE".into(), h.to_string_lossy().to_string()));
        if let Some(home) = h.parent() { env.push(("HF_HOME".into(), home.to_string_lossy().to_string())); }
    }
    env
}

/// Memory a process group uses now (MiB): the sum of its processes' footprints, which counts what MLX keeps on the GPU.
#[cfg(target_os = "macos")]
pub fn group_footprint_mib(pgid: i32) -> u64 {
    if pgid <= 1 { return 0; }
    let mut pids = vec![0i32; 256];
    let n = unsafe { libc::proc_listpgrppids(pgid, pids.as_mut_ptr() as *mut libc::c_void, (pids.len() * 4) as libc::c_int) };
    if n <= 0 { return 0; }
    // The buffer starts zeroed; what the call filled in are the non-zero entries (it returns a count, not bytes).
    pids.iter().filter(|p| **p > 0).map(|&pid| {
        let mut ri: libc::rusage_info_v4 = unsafe { std::mem::zeroed() };
        let ok = unsafe { libc::proc_pid_rusage(pid, libc::RUSAGE_INFO_V4, &mut ri as *mut _ as *mut libc::rusage_info_t) } == 0;
        if ok { ri.ri_phys_footprint >> 20 } else { 0 }
    }).sum()
}
#[cfg(not(target_os = "macos"))]
pub fn group_footprint_mib(_pgid: i32) -> u64 { 0 }
fn note_peak(ctl: &Ctl, pgid: i32) { ctl.peak_mib.fetch_max(group_footprint_mib(pgid), Ordering::Relaxed); }

// Never with 0 or 1: kill(-0) would hit the node's own group. (On Windows: the runner's group in the WSL distro.)
fn kill_group(pid: i32) { crate::platform::kill_runner(pid, false) }
fn kill_group_hard(pid: i32) { crate::platform::kill_runner(pid, true) }

/// Lines of a child's output, split on newlines and carriage returns (tqdm redraws with \r).
fn lines_of(mut r: impl tokio::io::AsyncRead + Unpin + Send + 'static, tx: tokio::sync::mpsc::UnboundedSender<String>) {
    tokio::spawn(async move {
        let (mut buf, mut cur) = (vec![0u8; 8192], Vec::new());
        loop {
            let n = match r.read(&mut buf).await { Ok(0) | Err(_) => break, Ok(n) => n };
            for &b in &buf[..n] {
                if b == b'\n' || b == b'\r' { if !cur.is_empty() { let _ = tx.send(String::from_utf8_lossy(&cur).to_string()); cur.clear(); } }
                else if cur.len() < 4096 { cur.push(b); }
            }
        }
        if !cur.is_empty() { let _ = tx.send(String::from_utf8_lossy(&cur).to_string()); }
    });
}

/// Runs a plan's steps one after another. Stops when told (cancel, the guard at critical, the model's drive gone, time).
pub async fn run_plan(a: &dyn Adapter, p: &Plan, hub: Option<&Path>, timeout: Duration, ctl: &Ctl) -> Result<Option<Value>, Stop> {
    let deadline = Instant::now() + timeout;
    if let Some(run) = a.custom(p, ctl, deadline) { return run.await; }
    let steps = a.steps(p).map_err(Stop::Failed)?;
    let env = runner_env(p, hub);
    let n = steps.len() as u64;
    let mut last_err = String::new();
    for (i, argv) in steps.iter().enumerate() {
        let mut c = std::process::Command::new(&argv[0]);
        c.args(&argv[1..]).current_dir(&p.work).env_clear().envs(env.iter().cloned());
        // Its own process group; on Windows, the same in the WSL distro (platform/mod.rs).
        let mut cmd = tokio::process::Command::from(crate::platform::runner_cmd(c));
        cmd.stdin(std::process::Stdio::null()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).kill_on_drop(true);
        let mut child = cmd.spawn().map_err(|e| Stop::Failed(format!("couldn't start {}: {e}", Path::new(&argv[0]).file_name().unwrap_or_default().to_string_lossy())))?;
        let pid = child.id().unwrap_or(0) as i32;
        PGID.store(pid, Ordering::Relaxed);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        lines_of(child.stdout.take().unwrap(), tx.clone());
        lines_of(child.stderr.take().unwrap(), tx);
        let mut tail: std::collections::VecDeque<String> = Default::default();
        let mut tick = tokio::time::interval(Duration::from_millis(250));
        let mut why_stop: Option<String> = None;
        let status = loop {
            tokio::select! {
                Some(line) = rx.recv() => {
                    if let Some((d, t)) = a.progress(&line, p) { *ctl.prog.lock().unwrap() = (i as u64 * t + d, n * t, if n > 1 { format!("running {}/{}", i + 1, n) } else { "running".into() }); }
                    else if !line.trim().is_empty() { tail.push_back(line); if tail.len() > 20 { tail.pop_front(); } }
                }
                s = child.wait() => break s.ok(),
                _ = tick.tick() => {
                    note_peak(ctl, pid);
                    if why_stop.is_none() {
                        if Instant::now() > deadline { ctl.stop(Some(format!("stopped after the {} s time limit", timeout.as_secs()))); }
                        if watch(ctl, p, deadline) { why_stop = Some(String::new()); kill_group(pid); tokio::spawn(async move { tokio::time::sleep(Duration::from_secs(3)).await; kill_group_hard(pid); }); }
                    }
                }
            }
        };
        PGID.store(0, Ordering::Relaxed);
        kill_group_hard(pid); // anything it left behind in its group
        if why_stop.is_some() { return Err(Stop::from(ctl)); }
        let code = status.and_then(|s| s.code()).unwrap_or(-1);
        let last = tail.iter().rev().find(|l| l.to_lowercase().contains("error")).or(tail.back()).cloned().unwrap_or_default();
        last_err = tail.iter().rev().find(|l| l.to_lowercase().contains("error")).cloned().unwrap_or_default();
        if code != 0 {
            return Err(Stop::Failed(clean(&format!("the runner stopped with code {code}{}", if last.is_empty() { String::new() } else { format!(": {}", last.trim()) }))));
        }
    }
    // Some runners exit 0 after an error: what they said goes with the failure.
    a.finish(p).map_err(|e| Stop::Failed(clean(&if last_err.is_empty() { e } else { format!("{e} ({})", last_err.trim()) })))
}

/* ---------- one job ---------- */

fn explain_missing(e: &catalog::Entry, ram: u64) -> String {
    let id = &e.m.id;
    match e.missing {
        Some("platform") => { let p = catalog::platform(); format!("{id} has no version for this kind of machine ({} {} {})", p.os, p.arch, p.accel) }
        Some("runner") => format!("{id} can't run on this machine: its runner ({}) isn't installed. The owner can add it: pavilion-node models add {id}", e.m.runner),
        Some("weights") => format!("{id} isn't installed on this machine (its weights aren't on disk). The owner can add it: pavilion-node models add {id}"),
        Some("storage") => format!("{id} is on a drive that isn't connected to this machine"),
        Some("memory") => format!("{id} needs a machine with {} GB of memory; this one has {ram} GB", e.m.min_ram_gb),
        Some("unverified") => format!("{id} hasn't been checked on this machine yet. The owner can: pavilion-node models verify {id}"),
        _ => format!("{id} isn't available here"),
    }
}

/// Everything about a job that can be checked before touching a file: model, task, inputs, references, size.
pub fn check_job(e: &catalog::Entry, task: &str, inputs: &Value, ram: u64) -> Result<Option<catalog::WxH>, String> {
    if !e.available() { return Err(explain_missing(e, ram)); }
    if !e.m.tasks.iter().any(|t| t == task) { return Err(format!("{} does {}, not {task}", e.m.id, e.m.tasks.join(", "))); }
    // As the Gate does: the schema is for everything but `references`, which the manifest's own limits check.
    let mut rest = inputs.clone();
    if let Some(o) = rest.as_object_mut() { o.remove("references"); }
    schema::check(&e.m.input_schema, &rest, "inputs")?;
    let refs = inputs["references"].as_array().cloned().unwrap_or_default();
    for (role, lim) in &e.m.references {
        let n = refs.iter().filter(|r| r["role"] == role.as_str()).count();
        if n > lim.max as usize { return Err(format!("{} takes at most {} {role} reference(s); this job has {n}", e.m.id, lim.max)); }
    }
    for r in &refs {
        let role = r["role"].as_str().unwrap_or("");
        if !e.m.references.contains_key(role) { return Err(format!("{} takes no {role} reference", e.m.id)); }
        if !r["asset"].as_str().map_or(false, |a| a.starts_with("ast_") && a.len() == 28 && a[4..].chars().all(|c| c.is_ascii_hexdigit())) { return Err("a reference names an asset (ast_…)".into()); }
    }
    match &e.m.sizes { Some(s) => s.pick(inputs["size"].as_str()).map(Some), None => Ok(None) }
}

async fn run_job(gate: &Arc<Gate>, job: &Value, ctl: &Arc<Ctl>, dir: &Path) -> Result<(Option<Value>, Vec<String>), Stop> {
    let (id, model, task) = (job["id"].as_str().unwrap_or(""), job["model"].as_str().unwrap_or(""), job["task"].as_str().unwrap_or(""));
    let inputs = job["inputs"].clone();
    let ram = catalog::ram_gb();
    let e = catalog::catalog().into_iter().find(|e| e.m.id == model).ok_or_else(|| Stop::Failed(format!("this machine has no model called {model}")))?;
    let size = check_job(&e, task, &inputs, ram).map_err(Stop::Failed)?;
    let adapter = adapters::get(&e.m.runner).ok_or_else(|| Stop::Failed("no runner".into()))?;

    // A real model: room on the boot disk to swap, memory to load it, nothing else holding the GPU.
    if e.m.runtime != "ffmpeg" {
        // Not the job's fault: it goes back to the queue (at most twice) until the owner frees space.
        boot_disk_ok(boot_free_mb()).map_err(Stop::Requeue)?;
        // One generation at a time: a server kept for another model gives its memory back first.
        if resident::current().await.is_some() && resident::current().await != adapter.resident() { resident::evict().await; }
        evict_resident().await;
        let since = Instant::now();
        loop {
            match memory().map(|(a, t, s, p)| headroom_ok(a, t, s, p, e.m.memory_gb)) {
                None | Some(Ok(())) => break,
                Some(Err(why)) if since.elapsed() > MEMORY_WAIT => return Err(Stop::Requeue(why)),
                Some(Err(_)) => { ctl.stage("waiting for memory"); tokio::time::sleep(Duration::from_secs(5)).await; if ctl.stopped() { return Err(Stop::from(ctl)); } }
            }
        }
    }

    // Inputs: fetched into this job's folder, re-encoded in a VM; only the re-encoded files go further.
    let refs = inputs["references"].as_array().cloned().unwrap_or_default();
    let mut ready_refs = vec![];
    if !refs.is_empty() {
        ctl.stage("re-encoding inputs");
        vm::ready().await.map_err(|e| Stop::Failed(format!("this machine can't re-encode input files in a VM ({e}), so it takes no jobs with files")))?;
        let (raw, clean_dir) = (dir.join("in"), dir.join("refs"));
        for d in [&raw, &clean_dir] { std::fs::create_dir_all(d).map_err(|e| Stop::Failed(e.to_string()))?; }
        for (i, r) in refs.iter().enumerate() {
            if ctl.stopped() { return Err(Stop::from(ctl)); }
            let (asset, role) = (r["asset"].as_str().unwrap_or(""), r["role"].as_str().unwrap_or(""));
            let ctype = gate.fetch(id, asset, &raw.join(i.to_string()), vm::MAX_INPUT_BYTES).await.map_err(Stop::Failed)?;
            let want = role_kind(role).ok_or_else(|| Stop::Failed(format!("unknown role {role}")))?;
            if Kind::of_media_type(&ctype) != Some(want) { return Err(Stop::Failed(format!("the {role} reference must be {}; {asset} is {ctype}", match want { Kind::Image => "an image", Kind::Audio => "audio", Kind::Video => "a video" }))); }
            let (path, seconds) = vm::reencode(id, &raw, &clean_dir, i, want, role == "mask").await.map_err(Stop::Failed)?;
            ready_refs.push(Input { role: role.into(), path, seconds, transcript: r["transcript"].as_str().map(|t| t.chars().take(4000).collect()) });
        }
        let _ = std::fs::remove_dir_all(&raw); // the raw files are never read on the host
    }

    let out = dir.join("out");
    std::fs::create_dir_all(&out).map_err(|e| Stop::Failed(e.to_string()))?;
    let mut plan = plan_for(&e, task, inputs.clone(), ready_refs, dir, &out, size);
    adapter.prepare(&mut plan).map_err(Stop::Failed)?;
    let left = job["expires_at"].as_u64().map(|x| x.saturating_sub(now_ms()) / 1000).unwrap_or(u64::MAX);
    let timeout = Duration::from_secs(adapter.timeout_s(&plan, e.m.timeout_s).min(left).max(10));
    ctl.stage(if e.m.runtime == "ffmpeg" { "running" } else { "loading the model" });
    let result = run_plan(adapter, &plan, e.hub.as_deref(), timeout, ctl).await?;

    // Outputs: typed by their bytes, noted, uploaded with a sidecar.
    ctl.stage("uploading");
    let mut files = adapters::files(&out);
    files.sort();
    if files.is_empty() { return Err(Stop::Failed("the runner made no files".into())); }
    if files.len() > MAX_OUTPUTS { return Err(Stop::Failed(format!("the runner made {} files; at most {MAX_OUTPUTS}", files.len()))); }
    let at = provenance::now_iso();
    let note = provenance::note(model, id, &gate.pav, &at);
    let mut assets = vec![];
    for f in files {
        if ctl.stopped() { return Err(Stop::from(ctl)); }
        if std::fs::metadata(&f).map(|m| m.len()).unwrap_or(0) > MAX_OUTPUT_BYTES { return Err(Stop::Failed("an output is over 50 MB".into())); }
        let bytes = std::fs::read(&f).map_err(|e| Stop::Failed(e.to_string()))?;
        let Some((ext, ctype)) = provenance::sniff(&bytes) else { return Err(Stop::Failed("the runner made a file of an unknown type".into())) };
        let stem: String = f.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default().chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_').take(60).collect();
        let stem = if stem.is_empty() { "output".to_string() } else { stem };
        let bytes = if ext == "json" {
            // Our own JSON (a transcript) carries the note as a field.
            let mut v: Value = serde_json::from_slice(&bytes).unwrap_or(json!({}));
            if let Some(o) = v.as_object_mut() { o.insert("provenance".into(), note.clone()); }
            serde_json::to_vec_pretty(&v).unwrap()
        } else { provenance::embed(bytes, ext, &note) };
        assets.push(gate.upload(id, &format!("{stem}.{ext}"), ctype, bytes).await.map_err(Stop::Failed)?);
        let kind = ctype.split('/').next().unwrap_or("file");
        let side = provenance::sidecar(kind, model, task, &inputs, &at, &gate.pav, id, ctype);
        gate.upload(id, &format!("{stem}.{ext}.provenance.json"), "application/json", serde_json::to_vec_pretty(&side).unwrap()).await.map_err(Stop::Failed)?;
    }
    Ok((result, assets))
}

/// A plan for an entry of the catalog: its programs, weights and the repos it loads.
fn plan_for(e: &catalog::Entry, task: &str, inputs: Value, refs: Vec<Input>, work: &Path, out: &Path, size: Option<catalog::WxH>) -> Plan {
    let w = e.m.weights.as_ref();
    Plan { task: task.into(), inputs, refs, work: work.to_path_buf(), out: out.to_path_buf(), bins: e.bins.clone(), weights: e.weights.clone(),
        repo: w.map(|w| w.hf.clone()), also: w.map(|w| w.also.clone()).unwrap_or_default(), weights_file: w.and_then(|w| w.file.as_ref()).and_then(|f| e.weights.as_ref().map(|s| s.join(f))),
        base_model: w.and_then(|w| w.base_model.clone()), size, chunks: vec![] }
}

fn now_ms() -> u64 { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64 }

fn job_dir(id: &str) -> PathBuf { crate::platform::media_dir().join("jobs").join(id) }

async fn handle(gate: Arc<Gate>, job: Value) {
    let id = job["id"].as_str().unwrap_or("").to_string();
    if !(id.starts_with("mj_") && id.len() <= 27 && id[3..].chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())) { eprintln!("media: a job with a bad id; ignored"); return; }
    eprintln!("media: {id} · {} · {}", job["task"].as_str().unwrap_or(""), job["model"].as_str().unwrap_or(""));
    let _busy = BusyGuard::take();
    let dir = job_dir(&id);
    let _ = std::fs::remove_dir_all(&dir);
    if let Err(e) = std::fs::create_dir_all(&dir) { let _ = gate.post(&format!("/jobs/{id}/done"), &json!({ "ok": false, "error": format!("making the job folder: {e}") })).await; return; }
    #[cfg(unix)]
    { use std::os::unix::fs::PermissionsExt; let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)); }
    let ctl = Arc::new(Ctl::guarded());
    ctl.stage("preparing");
    let rep = tokio::spawn(reporter(gate.clone(), id.clone(), ctl.clone()));
    let started = Instant::now();
    let r = run_job(&gate, &job, &ctl, &dir).await;
    rep.abort();
    let peak = ctl.peak_mib.load(Ordering::Relaxed);
    let body = match &r {
        Ok((result, assets)) => {
            let secs = (started.elapsed().as_secs_f64() * 10.0).round() / 10.0;
            eprintln!("media: {id} succeeded in {secs} s, {} file(s), peak {peak} MiB", assets.len());
            let mut res = result.clone().filter(|r| r.is_object()).unwrap_or(json!({}));
            res["seconds"] = json!(secs);
            if peak > 0 { res["peak_memory_mib"] = json!(peak); }
            json!({ "ok": true, "result": res })
        }
        Err(Stop::Canceled) => { eprintln!("media: {id} stopped (cancelled)"); json!({ "canceled": true }) }
        Err(Stop::Failed(e)) => { eprintln!("media: {id} failed: {e}"); json!({ "ok": false, "error": clean(e) }) }
        Err(Stop::Requeue(why)) => { eprintln!("media: {id} given back to the queue: {why}"); json!({ "requeue": true, "why": clean(why) }) }
    };
    if let Err(e) = gate.post(&format!("/jobs/{id}/done"), &body).await { eprintln!("media: reporting {id}: {e}"); }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Takes media jobs while the node runs, one at a time.
pub async fn run_loop() {
    // Job folders left by a node that stopped mid-job.
    let _ = std::fs::remove_dir_all(crate::platform::media_dir().join("jobs"));
    let mut quiet_until = Instant::now();
    let mut refused: Option<String> = None; // why the ceiling refuses media jobs, said once each time it changes
    loop {
        tokio::time::sleep(POLL).await;
        resident::reap_idle(catalog::ram_gb()).await;
        if level_now().0 >= Level::Red || Instant::now() < quiet_until { continue; }
        // The local ceiling's `jobs:` section (ceiling.rs): no asking for media work while it refuses media jobs.
        let why = crate::ceiling::load_jobs().and_then(|j| j.allows_kind("media")).err();
        if why != refused { if let Some(w) = &why { eprintln!("media: not asking for work: {w}"); } else { eprintln!("media: the ceiling allows media jobs again"); } refused = why; }
        if refused.is_some() { continue; }
        let Ok(gate) = Gate::new() else { continue };
        let _ = store::ensure_attached();
        let job = match gate.post("/next", &json!({ "loaded_model": loaded_model() })).await {
            Ok(v) => v["job"].clone(),
            Err(e) => { eprintln!("media: asking for work: {e}"); quiet_until = Instant::now() + Duration::from_secs(30); continue; }
        };
        if !job.is_object() { continue; }
        *LOADED.lock().unwrap() = job["model"].as_str().map(String::from);
        handle(Arc::new(gate), job).await;
    }
}

/* ---------- `pavilion-node models verify <id>` ---------- */

/// A tiny real generation on this machine; when it works, the model is marked verified (and so available to jobs).
pub async fn verify(id: &str) -> anyhow::Result<()> {
    let _ = store::ensure_attached();
    let st = catalog::storage();
    let ram = catalog::ram_gb();
    let m = catalog::manifests().into_iter().find(|m| m.id == id).ok_or_else(|| anyhow::anyhow!("no model {id} in the catalog"))?;
    let e = catalog::entry(m, &st, ram, false);
    if !e.available() { anyhow::bail!("{}", explain_missing(&e, ram)); }
    let a = adapters::get(&e.m.runner).unwrap();
    if e.m.runtime != "ffmpeg" {
        boot_disk_ok(boot_free_mb()).map_err(|e| anyhow::anyhow!(e))?;
        if let Some((av, t, s, p)) = memory() { headroom_ok(av, t, s, p, e.m.memory_gb).map_err(|e| anyhow::anyhow!(e))?; }
        evict_resident().await;
    }
    let dir = crate::platform::media_dir().join(format!("verify-{id}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("out"))?;
    let _busy = BusyGuard::take();
    let task = e.m.tasks[0].clone();
    let phrase = "Hello from the pavilion.";
    let mut inputs = match task.as_str() {
        "image.generate" | "image.edit" => json!({ "prompt": "a red apple on a wooden table", "size": "256x256", "seed": 1 }),
        "speech" | "audio.generate" => json!({ "prompt": phrase, "duration_s": 1 }),
        "music.generate" => json!({ "prompt": "calm solo piano, slow", "duration_s": 10, "seed": 1 }),
        "video.generate" | "video.from_image" => json!({ "prompt": "waves rolling onto a beach at sunset", "duration_s": 1, "seed": 1 }),
        "speech.clone" => json!({ "prompt": "This is a short test of a cloned voice." }),
        _ => json!({}),
    };
    if task.starts_with("image") && e.m.sizes.as_ref().map_or(false, |s| s.min_side > 256) { inputs["size"] = json!(null); }
    let mut refs = vec![];
    let mut expect_words = false;
    // Only tasks that need a recording get one: a transcription its source, a clone its voice.
    let audio_role = match task.as_str() { "speech.transcribe" => Some("source_audio"), "speech.clone" => Some("voice"), _ => None };
    if let Some(role) = audio_role {
        // A recording: the phrase spoken by Kokoro when it's here, else a tone. Whisper should hear the phrase back.
        let src = dir.join("refs");
        std::fs::create_dir_all(&src)?;
        let speech = catalog::entry(catalog::manifests().into_iter().find(|m| m.id == "kokoro-82m").unwrap(), &st, ram, false);
        let raw = dir.join("speech-raw");
        std::fs::create_dir_all(&raw)?;
        let made = if speech.available() {
            let p = plan_for(&speech, "speech", json!({ "prompt": phrase }), vec![], &dir, &raw, None);
            run_plan(adapters::get(&speech.m.runner).unwrap(), &p, speech.hub.as_deref(), Duration::from_secs(300), &Ctl::guarded()).await.is_ok()
        } else { false };
        if role == "voice" && !made { anyhow::bail!("checking a voice clone needs Kokoro on this machine (for the sample voice)"); }
        let ff = catalog::program("ffmpeg").ok_or_else(|| anyhow::anyhow!("ffmpeg isn't installed"))?;
        let mut cmd = std::process::Command::new(ff);
        cmd.args(["-hide_banner", "-loglevel", "error", "-nostdin", "-y"]);
        if made { cmd.arg("-i").arg(raw.join("speech.wav")); expect_words = role == "source_audio"; } else { cmd.args(["-f", "lavfi", "-i", "sine=frequency=440:duration=2"]); }
        cmd.args(["-ar", "24000", "-ac", "1", "-c:a", "pcm_s16le"]).arg(src.join("0.wav"));
        if !crate::platform::linux_cmd(cmd).status()?.success() { anyhow::bail!("couldn't make the test recording"); }
        refs.push(Input { role: role.into(), path: src.join("0.wav"), transcript: (role == "voice").then(|| phrase.to_string()), seconds: vm::check_wav(&src.join("0.wav"), 60.0).ok().map(|w| w.seconds) });
        inputs["references"] = json!([{ "asset": "ast_000000000000000000000000", "role": role }]);
    }
    if e.m.references.contains_key("subject") && task == "upscale" {
        // Something to upscale: a 256x256 test pattern.
        let src = dir.join("refs");
        std::fs::create_dir_all(&src)?;
        let ff = catalog::program("ffmpeg").ok_or_else(|| anyhow::anyhow!("ffmpeg isn't installed"))?;
        let mut cmd = std::process::Command::new(ff);
        cmd.args(["-hide_banner", "-loglevel", "error", "-nostdin", "-y", "-f", "lavfi", "-i", "testsrc2=size=256x256", "-frames:v", "1"]).arg(src.join("0.png"));
        if !crate::platform::linux_cmd(cmd).status()?.success() { anyhow::bail!("couldn't make the test image"); }
        refs.push(Input { role: "subject".into(), path: src.join("0.png"), transcript: None, seconds: None });
        inputs["params"] = json!({ "shortest_side": 512 });
    }
    let size = e.m.sizes.as_ref().map(|s| s.pick(inputs["size"].as_str())).transpose().map_err(|e| anyhow::anyhow!(e))?;
    let mut p = plan_for(&e, &task, inputs, refs, &dir, &dir.join("out"), size);
    a.prepare(&mut p).map_err(|e| anyhow::anyhow!(e))?;
    eprintln!("verifying {id}: {task}…");
    let t0 = Instant::now();
    let ctl = Ctl::guarded();
    let r = run_plan(a, &p, e.hub.as_deref(), Duration::from_secs(a.timeout_s(&p, e.m.timeout_s).min(1200)), &ctl).await;
    let secs = t0.elapsed().as_secs_f64();
    if a.resident().is_some() { resident::evict().await; }
    let result = match r { Ok(r) => r, Err(Stop::Canceled) => anyhow::bail!("stopped"), Err(Stop::Failed(e)) | Err(Stop::Requeue(e)) => anyhow::bail!("{id} didn't work here: {e}") };
    let files = adapters::files(&p.out);
    if files.is_empty() { anyhow::bail!("{id} made nothing"); }
    for f in &files { if provenance::sniff(&std::fs::read(f)?).is_none() { anyhow::bail!("{id} made a file of an unknown type"); } }
    if expect_words {
        let text = result.as_ref().and_then(|r| r["text"].as_str()).unwrap_or("").to_lowercase();
        if !text.contains("hello") { anyhow::bail!("{id} transcribed the test phrase as {text:?}"); }
    }
    if e.m.runtime != "ffmpeg" {
        let marker = catalog::verified_marker(id);
        std::fs::create_dir_all(marker.parent().unwrap())?;
        let rev = e.weights.as_ref().and_then(|s| s.file_name()).map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "none".into());
        std::fs::write(&marker, serde_json::to_vec_pretty(&json!({ "revision": rev, "at": provenance::now_iso(), "seconds": (secs * 10.0).round() / 10.0, "task": task }))?)?;
    }
    println!("{id} works on this machine: {} file(s) in {secs:.1} s, peak {} MiB{}", files.len(), ctl.peak_mib.load(Ordering::Relaxed), result.and_then(|r| r["text"].as_str().map(|t| format!(" · heard: {t}"))).unwrap_or_default());
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn memory_headroom() {
        assert!(headroom_ok(12.0, 16.0, 0.0, false, 6.0).is_ok());
        assert!(headroom_ok(9.0, 16.0, 0.0, false, 6.0).unwrap_err().starts_with("not enough free memory: 9.0 GB of 16 GB"));
        // Swap left over from earlier, no pressure now: the plain check.
        assert!(headroom_ok(13.0, 16.0, 3.2, false, 3.0).is_ok());
        // Swapped heavily already (over an eighth of RAM): needs three times the headroom.
        assert!(headroom_ok(12.0, 16.0, 3.0, true, 6.0).unwrap_err().contains("3.0 GB is already swapped"));
        assert!(headroom_ok(12.0, 16.0, 3.0, true, 2.0).is_ok());
        assert!(boot_disk_ok(13 * 1024).is_ok());
        let e = boot_disk_ok(7_680).unwrap_err();
        assert!(e.contains("7.5 GB free") && e.contains("Free 0.5 GB more") && e.contains("swap always lives on the boot disk"), "{e}");
    }

    fn entry(id: &str) -> catalog::Entry {
        let m = catalog::manifests().into_iter().find(|m| m.id == id).unwrap();
        catalog::Entry { m, missing: None, bins: Default::default(), weights: None, hub: None }
    }

    #[test]
    fn jobs_are_checked_against_the_manifest() {
        let e = entry("test-pattern");
        assert_eq!(check_job(&e, "image.generate", &json!({ "prompt": "x", "size": "256x256" }), 16).unwrap(), Some(catalog::WxH { width: 256, height: 256 }));
        assert!(check_job(&e, "speech", &json!({}), 16).unwrap_err().contains("not speech"));
        assert!(check_job(&e, "image.generate", &json!({ "size": "1000x1000" }), 16).unwrap_err().contains("nearest is 1008x1008"));
        assert!(check_job(&e, "image.generate", &json!({ "fps": 3 }), 16).unwrap_err().contains("doesn't take it"));
        let two = json!({ "references": [{ "asset": "ast_aaaaaaaaaaaaaaaaaaaaaaaa", "role": "subject" }, { "asset": "ast_bbbbbbbbbbbbbbbbbbbbbbbb", "role": "subject" }] });
        assert!(check_job(&e, "image.edit", &two, 16).unwrap_err().contains("at most 1 subject"));
        let style = json!({ "references": [{ "asset": "ast_aaaaaaaaaaaaaaaaaaaaaaaa", "role": "style" }] });
        assert!(check_job(&e, "image.edit", &style, 16).unwrap_err().contains("no style reference"));
        let mut gone = entry("flux2-klein-4b");
        gone.missing = Some("weights");
        assert!(check_job(&gone, "image.generate", &json!({ "prompt": "x" }), 16).unwrap_err().contains("pavilion-node models add flux2-klein-4b"));
        gone.missing = Some("unverified");
        assert!(check_job(&gone, "image.generate", &json!({ "prompt": "x" }), 16).unwrap_err().contains("models verify"));
        let k = entry("flux2-klein-4b");
        assert!(check_job(&k, "image.generate", &json!({}), 16).unwrap_err().contains("prompt: required"));
        assert!(check_job(&k, "image.generate", &json!({ "prompt": "x", "negative_prompt": "y" }), 16).unwrap_err().contains("doesn't take it"));
    }

    #[test]
    fn roles_have_kinds() {
        assert_eq!(role_kind("subject"), Some(Kind::Image));
        assert_eq!(role_kind("source_audio"), Some(Kind::Audio));
        assert_eq!(role_kind("source_video"), Some(Kind::Video));
        assert_eq!(role_kind("../x"), None);
    }

    #[test]
    fn errors_carry_no_home_folder() {
        let h = catalog::home().to_string_lossy().to_string();
        assert!(!clean(&format!("{h}/Library/x failed")).contains(&h));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_process_groups_memory_is_measured() {
        use std::os::unix::process::CommandExt;
        // A child that holds 64 MiB in its own group.
        let mut c = std::process::Command::new("/usr/bin/python3").args(["-c", "b = bytearray(64 << 20); import time; time.sleep(5)"]).process_group(0).spawn().unwrap();
        std::thread::sleep(Duration::from_millis(1500));
        let mib = group_footprint_mib(c.id() as i32);
        let _ = c.kill(); let _ = c.wait();
        assert!(mib >= 60, "{mib} MiB");
    }

    #[tokio::test]
    async fn a_runner_is_stopped_with_its_whole_process_group() {
        // A "runner" that starts a child and sleeps: cancelling must stop both.
        struct Sleeper;
        impl Adapter for Sleeper {
            fn programs(&self) -> &'static [&'static str] { &[] }
            fn steps(&self, p: &Plan) -> Result<Vec<Vec<String>>, String> {
                Ok(vec![vec!["/bin/sh".into(), "-c".into(), format!("sleep 30 & echo $! > {}/child; echo ' 50%|##   | 1/2 [00:01<00:01]'; wait", p.work.display())]])
            }
        }
        let work = std::env::temp_dir().join(format!("pavilion-run-{}", rand::random::<u32>()));
        std::fs::create_dir_all(&work).unwrap();
        let p = Plan { task: "t".into(), inputs: json!({}), refs: vec![], work: work.clone(), out: work.clone(), bins: Default::default(),
            weights: None, repo: None, also: vec![], weights_file: None, base_model: None, size: None, chunks: vec![] };
        let ctl = Arc::new(Ctl::default());
        let c2 = ctl.clone();
        tokio::spawn(async move { tokio::time::sleep(Duration::from_millis(800)).await; c2.stop(None); });
        let t0 = Instant::now();
        let r = run_plan(&Sleeper, &p, None, Duration::from_secs(20), &ctl).await;
        assert!(matches!(r, Err(Stop::Canceled)));
        assert!(t0.elapsed() < Duration::from_secs(5));
        assert_eq!(ctl.prog.lock().unwrap().0, 1, "progress was read");
        tokio::time::sleep(Duration::from_millis(300)).await;
        let child: i32 = std::fs::read_to_string(work.join("child")).unwrap().trim().parse().unwrap();
        assert_ne!(unsafe { libc::kill(child, 0) }, 0, "the runner's child is gone too");
        // And the time limit stops it the same way, as a failure.
        let ctl = Ctl::default();
        match run_plan(&Sleeper, &p, None, Duration::from_millis(600), &ctl).await { Err(Stop::Failed(e)) => assert!(e.contains("time limit"), "{e}"), _ => panic!("expected a failure") }
    }
}
