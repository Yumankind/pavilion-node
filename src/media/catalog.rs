//! The model catalog (docs/MEDIA.md §5): manifests shipped in the binary, and which of them this machine can run now.
//! A model is available only when its runner's programs are installed and its weights are already on disk. Nothing here
//! ever downloads: a missing model is reported, never fetched (`pavilion-node models add` is the owner's way).
use super::adapters;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

const MANIFESTS: &[&str] = &[
    include_str!("../../models/test-pattern.json"),
    include_str!("../../models/test-tone.json"),
    include_str!("../../models/test-transcribe.json"),
    include_str!("../../models/flux2-klein-4b.json"),
    include_str!("../../models/z-image-turbo.json"),
    include_str!("../../models/seedvr2-3b.json"),
    include_str!("../../models/kokoro-82m.json"),
    include_str!("../../models/qwen3-tts-0.6b-base.json"),
    include_str!("../../models/stable-audio-3-small-music.json"),
    include_str!("../../models/stable-audio-3-small-sfx.json"),
    include_str!("../../models/ace-step-1.5.json"),
    include_str!("../../models/whisper-large-v3-turbo.json"),
    include_str!("../../models/whisper-small.json"),
    include_str!("../../models/parakeet-tdt-0.6b-v3.json"),
    include_str!("../../models/ltx-2.3-distilled-q4.json"),
    include_str!("../../models/wan2.2-ti2v-5b.json"),
];

/// A model as shipped: what it is (the same everywhere), and how it runs on each kind of machine.
#[derive(Deserialize, Clone, Debug)]
struct ModelFile {
    id: String,
    tasks: Vec<String>,
    input_schema: Value,
    #[serde(default)]
    references: BTreeMap<String, RefLimit>,
    license: String,
    commercial: bool,
    #[serde(default)]
    gated: bool,
    #[serde(default)]
    negative_prompt: bool,
    #[serde(default)]
    sizes: Option<Sizes>,
    variants: Vec<Variant>,
}

/// How a model runs on one kind of machine: the first variant whose platform matches is used.
#[derive(Deserialize, Clone, Debug)]
pub struct Variant {
    pub platform: PlatformReq,
    pub runner: String,
    /// mlx | comfy | python | ollama | ffmpeg | cpp
    pub runtime: String,
    pub backends: Vec<String>,
    /// Memory it takes while running (unified memory on a Mac, else RAM; VRAM is in the platform).
    pub memory_gb: f64,
    /// Installed memory it needs, compared with the machine's rounded RAM (a "16 GB" Mac reports about 15.6).
    #[serde(default)]
    pub min_ram_gb: u64,
    /// Weights on disk.
    #[serde(default)]
    pub size_gb: f64,
    #[serde(default = "default_timeout")]
    pub timeout_s: u64,
    #[serde(default)]
    pub speed: Option<Value>,
    /// Where the weights come from; none for the test models, which need nothing but ffmpeg.
    #[serde(default)]
    pub weights: Option<Weights>,
    /// How the owner installs it here: a closed list of steps, never a shell line (`pavilion-node models add`).
    #[serde(default)]
    pub install: Vec<Value>,
    /// Where this variant was seen working; null when it hasn't been run on such hardware yet.
    #[serde(default)]
    pub verified_on: Option<String>,
}
fn default_timeout() -> u64 { 1800 }

#[derive(Deserialize, serde::Serialize, Clone, Debug, PartialEq)]
pub struct PlatformReq {
    /// macos | linux | windows | any
    pub os: String,
    /// arm64 | x86_64 | any
    pub arch: String,
    /// mlx | mps | cuda | rocm | cpu | any
    pub accel: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_vram_gb: Option<f64>,
}

/// What this machine is, for picking variants.
#[derive(serde::Serialize, Clone, Debug, PartialEq)]
pub struct Platform { pub os: String, pub arch: String, pub accel: String, pub vram_gb: Option<f64> }

impl PlatformReq {
    /// A variant fits when its OS and architecture match and the machine has its accelerator. A CPU variant is only
    /// shipped for models that are practical on a CPU, so it never stands in for a GPU model.
    pub fn matches(&self, p: &Platform) -> bool {
        let any = |x: &str, y: &str| x == "any" || x == y;
        let accel = match self.accel.as_str() {
            "any" | "cpu" => true,
            "mlx" | "mps" => p.accel == "mlx",
            "cuda" => p.accel == "cuda" && self.min_vram_gb.map_or(true, |v| p.vram_gb.unwrap_or(0.0) >= v),
            "rocm" => p.accel == "rocm",
            _ => false,
        };
        any(&self.os, &p.os) && any(&self.arch, &p.arch) && accel
    }
}

/// This machine: macOS on Apple Silicon runs MLX; Linux with nvidia-smi runs CUDA (with its largest GPU's memory).
/// Windows runs the Linux variants in its WSL distro, CUDA through WSL's GPU passthrough. Checked once per process.
pub fn platform() -> Platform { static P: std::sync::OnceLock<Platform> = std::sync::OnceLock::new(); P.get_or_init(detect_platform).clone() }
#[cfg_attr(windows, allow(unreachable_code, unused_variables))]
fn detect_platform() -> Platform {
    let os = std::env::consts::OS.to_string();
    let arch = match std::env::consts::ARCH { "aarch64" => "arm64", a => a }.to_string();
    #[cfg(windows)]
    { let (accel, vram_gb) = crate::sandbox::wsl::media_accel(); return Platform { os: "linux".into(), arch, accel, vram_gb }; }
    let (accel, vram) = if os == "macos" && arch == "arm64" { ("mlx".to_string(), None) } else {
        let nv = std::process::Command::new("nvidia-smi").args(["--query-gpu=memory.total", "--format=csv,noheader,nounits"]).output().ok()
            .filter(|o| o.status.success()).map(|o| String::from_utf8_lossy(&o.stdout).lines().filter_map(|l| l.trim().parse::<f64>().ok()).fold(0.0, f64::max));
        match nv {
            Some(mib) if mib > 0.0 => ("cuda".to_string(), Some((mib / 1024.0 * 10.0).round() / 10.0)),
            _ if std::process::Command::new("rocm-smi").output().map(|o| o.status.success()).unwrap_or(false) => ("rocm".to_string(), None),
            _ => ("cpu".to_string(), None),
        }
    };
    Platform { os, arch, accel, vram_gb: vram }
}

/// A model resolved for one machine: the model's fields and its matching variant's. With no variant for the machine,
/// `unsupported` is set and the variant fields are empty.
#[derive(Clone, Debug)]
pub struct Manifest {
    pub id: String,
    pub tasks: Vec<String>,
    pub input_schema: Value,
    pub references: BTreeMap<String, RefLimit>,
    pub license: String,
    pub commercial: bool,
    pub gated: bool,
    pub negative_prompt: bool,
    pub sizes: Option<Sizes>,
    pub runner: String,
    pub runtime: String,
    pub backends: Vec<String>,
    pub memory_gb: f64,
    pub min_ram_gb: u64,
    pub size_gb: f64,
    pub timeout_s: u64,
    pub speed: Option<Value>,
    pub weights: Option<Weights>,
    pub install: Vec<Value>,
    pub verified_on: Option<String>,
    pub platform: Option<PlatformReq>,
    /// No variant of this model runs on this kind of machine.
    pub unsupported: bool,
}

fn resolve(f: ModelFile, p: &Platform) -> Manifest {
    // Native Windows variants don't exist: a Windows node reports itself as linux (its WSL distro), see detect_platform.
    let v = if p.os == "windows" { None } else { f.variants.iter().find(|v| v.platform.matches(p)).cloned() };
    let unsupported = v.is_none();
    let v = v.unwrap_or(Variant { platform: PlatformReq { os: String::new(), arch: String::new(), accel: String::new(), min_vram_gb: None }, runner: String::new(), runtime: String::new(),
        backends: vec![], memory_gb: 0.0, min_ram_gb: 0, size_gb: 0.0, timeout_s: default_timeout(), speed: None, weights: None, install: vec![], verified_on: None });
    Manifest { id: f.id, tasks: f.tasks, input_schema: f.input_schema, references: f.references, license: f.license, commercial: f.commercial, gated: f.gated,
        negative_prompt: f.negative_prompt, sizes: f.sizes, runner: v.runner, runtime: v.runtime, backends: v.backends, memory_gb: v.memory_gb, min_ram_gb: v.min_ram_gb,
        size_gb: v.size_gb, timeout_s: v.timeout_s, speed: v.speed, weights: v.weights, install: v.install, verified_on: v.verified_on,
        platform: if unsupported { None } else { Some(v.platform) }, unsupported }
}

fn files() -> Vec<ModelFile> { MANIFESTS.iter().map(|s| serde_json::from_str::<ModelFile>(s).expect("a shipped manifest is valid")).collect() }
/// The catalog resolved for a kind of machine.
pub fn manifests_for(p: &Platform) -> Vec<Manifest> { files().into_iter().map(|f| resolve(f, p)).collect() }
/// The catalog resolved for this machine.
pub fn manifests() -> Vec<Manifest> { manifests_for(&platform()) }

#[derive(Deserialize, serde::Serialize, Clone, Debug)]
pub struct RefLimit { pub max: u32 }

#[derive(Deserialize, Clone, Debug)]
pub struct Weights {
    /// A Hugging Face repo, `org/name`.
    pub hf: String,
    /// The commit we checked; `models add` fetches exactly this.
    #[serde(default)]
    pub revision: Option<String>,
    /// For runners that load a third-party repo on top of a built-in model (mflux `--base-model`).
    #[serde(default)]
    pub base_model: Option<String>,
    /// Other repos it loads, which must be there too (LTX's text encoder).
    #[serde(default)]
    pub also: Vec<String>,
    /// A file in the repo the runner is given (whisper.cpp's ggml model).
    #[serde(default)]
    pub file: Option<String>,
}

#[derive(Deserialize, serde::Serialize, Clone, Debug)]
pub struct Sizes { pub block: u32, pub min_side: u32, pub max_side: u32, pub max_pixels: u64, pub default: WxH }
#[derive(Deserialize, serde::Serialize, Clone, Copy, Debug, PartialEq)]
pub struct WxH { pub width: u32, pub height: u32 }

impl Sizes {
    /// The size to use for `asked` ("1024x768"), or why not, naming the nearest legal size.
    pub fn pick(&self, asked: Option<&str>) -> Result<WxH, String> {
        let Some(a) = asked else { return Ok(self.default) };
        let (w, h) = a.split_once('x').and_then(|(w, h)| Some((w.parse::<u32>().ok()?, h.parse::<u32>().ok()?))).ok_or_else(|| format!("size is WIDTHxHEIGHT, like {}x{}", self.default.width, self.default.height))?;
        let legal = |w: u32, h: u32| w % self.block == 0 && h % self.block == 0 && w.min(h) >= self.min_side && w.max(h) <= self.max_side && (w as u64) * (h as u64) <= self.max_pixels;
        if legal(w, h) { return Ok(WxH { width: w, height: h }); }
        let n = self.nearest(w, h);
        Err(format!("size {w}x{h} isn't possible for this model (sides {}–{} in steps of {}, at most {} pixels); the nearest is {}x{}",
            self.min_side, self.max_side, self.block, self.max_pixels, n.width, n.height))
    }
    pub fn nearest(&self, w: u32, h: u32) -> WxH {
        let b = self.block.max(1);
        let snap = |x: f64| (((x / b as f64).round() as u32) * b).clamp(self.min_side.div_ceil(b) * b, self.max_side / b * b);
        let (mut w2, mut h2) = (snap(w.max(1) as f64), snap(h.max(1) as f64));
        if (w2 as u64) * (h2 as u64) > self.max_pixels {
            let k = (self.max_pixels as f64 / (w2 as f64 * h2 as f64)).sqrt();
            let down = |x: u32| (((x as f64 * k) / b as f64).floor() as u32 * b).max(self.min_side.div_ceil(b) * b);
            w2 = down(w2); h2 = down(h2);
        }
        WxH { width: w2, height: h2 }
    }
}

/* ---------- where models live ---------- */

/// The home folder runners see; on Windows, the WSL distro user's (as \\wsl.localhost\pavilion\home\pavilion).
#[cfg_attr(windows, allow(unreachable_code))]
pub fn home() -> PathBuf {
    #[cfg(windows)]
    return crate::sandbox::wsl::unc(crate::sandbox::wsl::HOME);
    PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into()))
}

/// Hugging Face's own cache: $HF_HUB_CACHE, $HF_HOME/hub, or ~/.cache/huggingface/hub.
pub fn default_hub() -> PathBuf {
    // Windows: the HF variables, if set, are Windows paths; the cache lives in the distro.
    if cfg!(windows) { return home().join(".cache").join("huggingface").join("hub"); }
    if let Ok(d) = std::env::var("HF_HUB_CACHE") { if !d.is_empty() { return PathBuf::from(d); } }
    if let Ok(d) = std::env::var("HF_HOME") { if !d.is_empty() { return PathBuf::from(d).join("hub"); } }
    home().join(".cache/huggingface/hub")
}

/// Where this node keeps models: `model_storage` in config.json (a folder, an external drive say), else HF's cache.
pub struct Storage {
    /// The folder the owner chose, if any (for a disk image, where it's mounted).
    pub chosen: Option<PathBuf>,
    /// An APFS sparse bundle holding the models, for drives that can't (exFAT has no symlinks, which HF's cache needs).
    pub image: Option<PathBuf>,
    /// The Hugging Face cache inside it (or the default one).
    pub hub: PathBuf,
    /// The chosen folder isn't there (the drive is unplugged, the image isn't attached).
    pub missing: bool,
}
/// `model_storage` in config.json: a folder, or `{ "image": "….sparsebundle", "mount": "/Volumes/…" }`.
pub fn storage_from(c: &Value) -> Storage {
    let (mount, image) = match &c["model_storage"] {
        Value::String(p) if !p.is_empty() => (Some(PathBuf::from(p)), None),
        Value::Object(o) => (o.get("mount").and_then(|m| m.as_str()).filter(|m| !m.is_empty()).map(PathBuf::from), o.get("image").and_then(|m| m.as_str()).map(PathBuf::from)),
        _ => (None, None),
    };
    match mount {
        Some(p) => Storage { hub: hub_in(&p), missing: !p.is_dir(), chosen: Some(p), image },
        None => Storage { chosen: None, image: None, hub: default_hub(), missing: false },
    }
}
pub fn storage() -> Storage { storage_from(&crate::state::config()) }
/// The HF cache layout inside a chosen folder.
pub fn hub_in(folder: &Path) -> PathBuf { folder.join("huggingface").join("hub") }

/// Where to look for weights: the chosen folder first, then HF's default cache (read only, never written by jobs).
pub fn hubs(s: &Storage) -> Vec<PathBuf> {
    let mut v = vec![];
    if !s.missing { v.push(s.hub.clone()); }
    let d = default_hub();
    if !v.contains(&d) { v.push(d); }
    v
}

/// Where runners that are projects rather than tools live (LTX's uv project, ACE-Step): `runners` in model storage.
pub fn runners_dir() -> Option<PathBuf> { storage().chosen.map(|c| c.join("runners")) }

/// Paths shown to the pavilion with the home folder as `~` (no user names leave the machine).
pub fn shown(p: &Path) -> String {
    let h = home();
    match p.strip_prefix(&h) { Ok(rest) if h.as_os_str().len() > 1 => format!("~/{}", rest.display()), _ => p.display().to_string() }
}

pub fn repo_dir(hub: &Path, repo: &str) -> PathBuf { hub.join(format!("models--{}", repo.replace('/', "--"))) }

/// The snapshot folder of `repo` in `hub` when every file in it is really there (symlinks followed: the HF cache links
/// snapshot files to blobs, and newer versions link blobs again into a shared store), at least one is a weights file,
/// and nothing is still downloading.
pub fn snapshot(hub: &Path, repo: &str, revision: Option<&str>) -> Option<PathBuf> {
    let dir = repo_dir(hub, repo);
    let main = std::fs::read_to_string(dir.join("refs/main")).ok().map(|s| s.trim().to_string());
    let revs: Vec<String> = revision.map(String::from).into_iter().chain(main).collect();
    if std::fs::read_dir(dir.join("blobs")).map(|r| r.flatten().any(|e| e.file_name().to_string_lossy().ends_with(".incomplete"))).unwrap_or(false) { return None; }
    revs.iter().filter(|r| !r.is_empty() && !r.contains('/') && !r.contains("..")).map(|r| dir.join("snapshots").join(r)).find(|s| complete(s))
}

fn complete(snap: &Path) -> bool {
    let mut weights = false;
    let mut stack = vec![snap.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { return false };
        for e in rd.flatten() {
            let p = e.path();
            let Ok(md) = std::fs::metadata(&p) else { return false }; // a link to nothing: not all there
            if md.is_dir() { stack.push(p); continue; }
            let ext = p.extension().and_then(|x| x.to_str()).unwrap_or("");
            if ["safetensors", "npz", "gguf", "bin", "pt"].contains(&ext) && md.len() > 0 { weights = true; }
        }
    }
    weights
}

/* ---------- programs ---------- */

/// A program by name: on PATH, or where uv, Homebrew and pip put tools (a service's PATH is often short).
#[cfg_attr(windows, allow(unreachable_code))]
pub fn program(name: &str) -> Option<PathBuf> {
    // Windows: programs in the WSL distro, as Windows reaches them (a uv tool's entry there is a link).
    #[cfg(windows)]
    return ["/home/pavilion/.local/bin", "/usr/local/bin", "/usr/bin", "/bin"].iter().map(|d| crate::sandbox::wsl::unc(d).join(name))
        .find(|p| p.is_file() || std::fs::symlink_metadata(p).map(|m| m.file_type().is_symlink()).unwrap_or(false));
    let mut dirs: Vec<PathBuf> = std::env::var("PATH").unwrap_or_default().split(':').filter(|d| !d.is_empty()).map(PathBuf::from).collect();
    dirs.extend([home().join(".local/bin"), PathBuf::from("/opt/homebrew/bin"), PathBuf::from("/usr/local/bin"), PathBuf::from("/usr/bin")]);
    dirs.into_iter().map(|d| d.join(name)).find(|p| is_exec(p))
}
#[cfg(windows)]
pub fn is_exec(p: &Path) -> bool { p.is_file() }
#[cfg(unix)]
pub fn is_exec(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0).unwrap_or(false)
}

/* ---------- the catalog ---------- */

pub struct Entry {
    pub m: Manifest,
    /// None when available; else "platform", "runner", "memory", "storage", "weights" or "unverified".
    pub missing: Option<&'static str>,
    pub bins: HashMap<String, PathBuf>,
    /// The snapshot folder of the weights, and the HF cache it's in.
    pub weights: Option<PathBuf>,
    pub hub: Option<PathBuf>,
}
impl Entry { pub fn available(&self) -> bool { self.missing.is_none() } }

/// This machine's memory in whole GB, as people say it (15.6 GiB reported → 16).
pub fn ram_gb() -> u64 { let s = crate::guard::sample(); ((s.mem_total_mib as f64) / 1024.0).round() as u64 }

/// Where the marker saying a model made something real on this machine lives.
pub fn verified_marker(id: &str) -> PathBuf { crate::state::dir().join("models").join(format!(".verified-{id}")) }
/// Whether `models verify` passed for these weights (the same snapshot: a new revision has to be verified again).
pub fn verified(id: &str, snapshot: &Path) -> bool {
    let rev = snapshot.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "none".into());
    std::fs::read(verified_marker(id)).ok().and_then(|b| serde_json::from_slice::<Value>(&b).ok()).map_or(false, |v| v["revision"] == rev.as_str())
}

pub fn entry(m: Manifest, st: &Storage, ram_gb: u64, need_verified: bool) -> Entry {
    let mut bins = HashMap::new();
    let mut missing = None;
    if m.unsupported { return Entry { m, missing: Some("platform"), bins, weights: None, hub: None }; }
    match adapters::get(&m.runner) {
        None => missing = Some("runner"),
        Some(a) => {
            for p in a.programs() { match program(p) { Some(b) => { bins.insert(p.to_string(), b); } None => missing = Some("runner") } }
            if missing.is_none() && !a.ready(&bins) { missing = Some("runner"); }
        }
    }
    if missing.is_none() && m.min_ram_gb > ram_gb { missing = Some("memory"); }
    let (mut weights, mut hub) = (None, None);
    if let Some(w) = &m.weights {
        match hubs(st).into_iter().find_map(|h| snapshot(&h, &w.hf, w.revision.as_deref()).map(|s| (s, h))) {
            Some((s, h)) => {
                let others = w.also.iter().all(|r| hubs(st).iter().any(|h| snapshot(h, r, None).is_some()));
                let file = w.file.as_ref().map_or(true, |f| !f.contains("..") && s.join(f).is_file());
                if missing.is_none() && (!others || !file) { missing = Some("weights"); }
                if missing.is_none() && need_verified && !verified(&m.id, &s) { missing = Some("unverified"); }
                weights = Some(s); hub = Some(h);
            }
            None => if missing.is_none() { missing = Some(if st.missing { "storage" } else { "weights" }) },
        }
    } else if missing.is_none() && need_verified && m.runtime != "ffmpeg" && !verified(&m.id, Path::new("")) {
        // A real model whose files its runner keeps (ACE-Step, sa3) is checked by a run too.
        missing = Some("unverified");
    }
    Entry { m, missing, bins, weights, hub }
}

pub fn catalog() -> Vec<Entry> { let (st, ram) = (storage(), ram_gb()); manifests().into_iter().map(|m| entry(m, &st, ram, true)).collect() }

/// What the inventory reports as `media_models` (the Gate places jobs with it).
pub fn report(entries: &[Entry]) -> Value {
    Value::Array(entries.iter().map(|e| json!({
        "id": e.m.id, "tasks": e.m.tasks, "runner": e.m.runner, "backends": e.m.backends, "memory_gb": e.m.memory_gb,
        "input_schema": e.m.input_schema, "references": e.m.references, "license": e.m.license, "commercial": e.m.commercial,
        "available": e.available(), "missing": e.missing,
        "runtime": e.m.runtime, "size_gb": e.m.size_gb, "min_ram_gb": e.m.min_ram_gb, "sizes": e.m.sizes, "negative_prompt": e.m.negative_prompt,
        "timeout_s": e.m.timeout_s, "speed": e.m.speed, "gated": e.m.gated, "platform": e.m.platform, "verified_on": e.m.verified_on,
        // Checked by a real run here (`models verify`); models without weights need no check.
        "verified": e.weights.as_ref().map_or(e.m.runtime == "ffmpeg" || (!e.m.unsupported && verified(&e.m.id, Path::new(""))), |s| verified(&e.m.id, s)),
    })).collect())
}

/// `model_storage` in the inventory.
pub fn storage_report(st: &Storage) -> Value {
    let p = st.chosen.clone().unwrap_or_else(|| st.hub.clone());
    let probe = if st.missing { p.clone() } else { nearest_existing(&p) };
    let (free, total) = if st.missing { (0, 0) } else { disk(&probe) };
    json!({ "path": shown(&p), "free_mib": free, "total_mib": total, "missing": st.missing })
}
fn nearest_existing(p: &Path) -> PathBuf { p.ancestors().find(|a| a.exists()).map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("/")) }

/// Free and total MiB of the volume holding `p`.
#[cfg(windows)]
pub fn disk(p: &Path) -> (u64, u64) { crate::platform::disk(p) }
#[cfg(unix)]
pub fn disk(p: &Path) -> (u64, u64) {
    let Ok(c) = std::ffi::CString::new(p.as_os_str().to_string_lossy().as_bytes()) else { return (0, 0) };
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 { return (0, 0); }
    let f = st.f_frsize as u64;
    ((st.f_bavail as u64 * f) >> 20, (st.f_blocks as u64 * f) >> 20)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn every_shipped_manifest_parses_and_is_consistent() {
        let ms = manifests_for(&Platform { os: "macos".into(), arch: "arm64".into(), accel: "mlx".into(), vram_gb: None });
        assert!(ms.len() >= 16);
        let mut ids: Vec<&str> = ms.iter().map(|m| m.id.as_str()).collect();
        ids.sort(); ids.dedup();
        assert_eq!(ids.len(), ms.len(), "ids are unique");
        // Every variant of every model, whatever machine it's for.
        for f in files() {
            assert!(!f.variants.is_empty(), "{}", f.id);
            for v in &f.variants {
                assert!(adapters::get(&v.runner).is_some(), "{}: {} has a runner adapter", f.id, v.runner);
                assert!(["mlx", "comfy", "python", "ollama", "ffmpeg", "cpp"].contains(&v.runtime.as_str()), "{}", f.id);
                assert!(["macos", "linux", "any"].contains(&v.platform.os.as_str()) && ["mlx", "mps", "cuda", "rocm", "cpu", "any"].contains(&v.platform.accel.as_str()), "{}", f.id);
                for st in &v.install { assert!(super::super::store::check_step(st).is_ok(), "{}: {st}", f.id); }
                if let Some(w) = &v.weights { assert!(w.hf.contains('/'), "{}", f.id); }
                if v.runtime != "ffmpeg" { assert!(v.size_gb > 0.0 && !v.install.is_empty(), "{}", f.id); }
            }
        }
        for m in ms.iter().filter(|m| !m.unsupported) {
            assert!(adapters::get(&m.runner).is_some(), "{} has a runner adapter", m.id);
            assert_eq!(m.input_schema["type"], "object", "{}", m.id);
            for r in m.references.keys() { assert!(super::super::role_kind(r).is_some(), "{}: role {r}", m.id); }
            for t in &m.tasks { assert!(super::super::TASKS.contains(&t.as_str()), "{}: task {t}", m.id); }

        }
        let report = report(&ms.into_iter().map(|m| Entry { m, missing: Some("weights"), bins: HashMap::new(), weights: None, hub: None }).collect::<Vec<_>>());
        let keys: Vec<String> = report[0].as_object().unwrap().keys().cloned().collect();
        assert!(keys.len() >= 11);
        for k in ["id", "tasks", "runner", "backends", "memory_gb", "input_schema", "references", "license", "commercial", "available", "missing"] { assert!(keys.contains(&k.to_string()), "{k}"); }
        // The Gate keeps up to 128 KB of inventory; the catalog takes a small part of it.
        assert!(report.to_string().len() < 40_000, "{}", report.to_string().len());
    }

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("pavilion-catalog-{name}-{}", rand::random::<u32>()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn weights_count_only_when_every_linked_file_is_there() {
        let hub = tmp("hub");
        let repo = repo_dir(&hub, "org/model");
        let snap = repo.join("snapshots/abc");
        std::fs::create_dir_all(snap.join("sub")).unwrap();
        std::fs::create_dir_all(repo.join("refs")).unwrap();
        std::fs::write(repo.join("refs/main"), "abc").unwrap();
        // Like the HF cache with its shared store: snapshot → blobs/<hash> → ../../blobs/78/<sha>
        std::fs::create_dir_all(repo.join("blobs")).unwrap();
        std::fs::create_dir_all(hub.join("blobs/78")).unwrap();
        std::fs::write(hub.join("blobs/78/sha"), b"weights").unwrap();
        symlink("../../blobs/78/sha", repo.join("blobs/h1")).unwrap();
        symlink("../../../blobs/h1", snap.join("sub/model.safetensors")).unwrap();
        std::fs::write(snap.join("config.json"), b"{}").unwrap();
        assert_eq!(snapshot(&hub, "org/model", None), Some(snap.clone()));
        assert_eq!(snapshot(&hub, "org/model", Some("abc")), Some(snap.clone()));
        assert_eq!(snapshot(&hub, "org/other", None), None);
        // The shared store went away (another drive, a cleanup): not available.
        std::fs::remove_file(hub.join("blobs/78/sha")).unwrap();
        assert_eq!(snapshot(&hub, "org/model", None), None);
        std::fs::write(hub.join("blobs/78/sha"), b"weights").unwrap();
        // Still downloading: not available.
        std::fs::write(repo.join("blobs/h2.incomplete"), b"").unwrap();
        assert_eq!(snapshot(&hub, "org/model", None), None);
        std::fs::remove_file(repo.join("blobs/h2.incomplete")).unwrap();
        // Only a config, no weights file: not available.
        std::fs::remove_file(snap.join("sub/model.safetensors")).unwrap();
        assert_eq!(snapshot(&hub, "org/model", None), None);
        let _ = std::fs::remove_dir_all(&hub);
    }

    #[test]
    fn an_unplugged_model_drive_reports_storage_not_a_crash() {
        let gone = PathBuf::from("/Volumes/pavilion-test-drive-that-is-not-there");
        let st = storage_from(&json!({ "model_storage": { "image": "/Volumes/gone/pavilion-models.sparsebundle", "mount": gone.to_string_lossy() } }));
        assert!(st.missing && st.image.is_some());
        let m = manifests().into_iter().find(|m| m.id == "flux2-klein-4b").unwrap();
        let mut m2 = m.clone();
        // On a platform the model has no variant for (it is Apple-only), there are no weights to point anywhere, and
        // `platform` is the honest answer; the GitHub runner is Linux.
        if let Some(w) = m2.weights.as_mut() { w.hf = "pavilion-test/never-downloaded".into(); }
        let e = entry(m2, &st, 16, true);
        assert!(!e.available());
        assert!(e.missing == Some("storage") || e.missing == Some("runner") || e.missing == Some("platform"), "{:?}", e.missing);
        assert_eq!(storage_report(&st)["missing"], true);
        // Test models need no weights: only ffmpeg.
        let t = entry(manifests().into_iter().find(|m| m.id == "test-pattern").unwrap(), &st, 16, true);
        assert!(t.missing.is_none() || t.missing == Some("runner"));
    }

    #[test]
    fn sizes_are_checked_and_the_nearest_legal_one_is_named() {
        let s = Sizes { block: 16, min_side: 256, max_side: 1536, max_pixels: 2_097_152, default: WxH { width: 1024, height: 1024 } };
        assert_eq!(s.pick(None).unwrap(), WxH { width: 1024, height: 1024 });
        assert_eq!(s.pick(Some("512x768")).unwrap(), WxH { width: 512, height: 768 });
        assert!(s.pick(Some("1000x1000")).unwrap_err().ends_with("the nearest is 1008x1008"));
        assert!(s.pick(Some("100x100")).unwrap_err().ends_with("the nearest is 256x256"));
        // Both sides legal, too many pixels: scaled down, still in steps of 16.
        let n = s.nearest(1536, 1536);
        assert!(n.width % 16 == 0 && (n.width as u64 * n.height as u64) <= 2_097_152 && n.width >= 1400, "{n:?}");
        assert!(s.pick(Some("1024")).is_err());
        assert!(s.pick(Some("99999999999x1")).is_err());
    }

    #[test]
    fn real_models_need_memory_and_a_verified_run() {
        let st = storage_from(&json!({}));
        assert_eq!(st.hub, default_hub());
        let folder = storage_from(&json!({ "model_storage": "/tmp" }));
        assert_eq!(folder.hub, PathBuf::from("/tmp/huggingface/hub"));
        assert!(!folder.missing);
        let m = manifests().into_iter().find(|m| m.id == "flux2-klein-4b").unwrap();
        let e = entry(m.clone(), &st, 8, true);
        // `platform` where the model has no variant for this machine (Linux, the GitHub runner): checked before memory.
        assert!(e.missing == Some("memory") || e.missing == Some("runner") || e.missing == Some("platform"), "{:?}", e.missing);
        let e = entry(m.clone(), &st, 16, true);
        if let Some(s) = &e.weights { if !verified(&m.id, s) && e.missing != Some("runner") && e.missing != Some("platform") { assert_eq!(e.missing, Some("unverified")); } }
        // `models verify` itself looks past the marker.
        let e = entry(m, &st, 16, false);
        assert_ne!(e.missing, Some("unverified"));
    }

    fn pf(os: &str, arch: &str, accel: &str, vram: Option<f64>) -> Platform { Platform { os: os.into(), arch: arch.into(), accel: accel.into(), vram_gb: vram } }
    fn pick(p: &Platform) -> HashMap<String, String> {
        manifests_for(p).into_iter().map(|m| (m.id.clone(), if m.unsupported { "-".to_string() } else { m.runner.clone() })).collect()
    }

    #[test]
    fn variants_are_picked_per_platform() {
        let mac = pick(&pf("macos", "arm64", "mlx", None));
        assert_eq!(mac["flux2-klein-4b"], "mflux:flux2");
        assert_eq!(mac["whisper-large-v3-turbo"], "mlx-whisper");
        assert_eq!(mac["ltx-2.3-distilled-q4"], "ltx-2-mlx");
        assert_eq!(mac["wan2.2-ti2v-5b"], "-", "Wan has no Mac variant");
        assert_eq!(mac["test-pattern"], "ffmpeg:test-pattern");
        let cuda = pick(&pf("linux", "x86_64", "cuda", Some(24.0)));
        assert_eq!(cuda["whisper-large-v3-turbo"], "whisper.cpp");
        assert_eq!(cuda["whisper-small"], "whisper.cpp");
        assert_eq!(cuda["wan2.2-ti2v-5b"], "wan2.2");
        assert_eq!(cuda["flux2-klein-4b"], "-", "no CUDA variant yet: reported, never run on the CPU");
        assert_eq!(cuda["kokoro-82m"], "-");
        assert_eq!(cuda["ace-step-1.5"], "acestep-api");
        assert_eq!(cuda["test-tone"], "ffmpeg:test-tone");
        // A smaller GPU: Wan needs 24 GB.
        assert_eq!(pick(&pf("linux", "x86_64", "cuda", Some(12.0)))["wan2.2-ti2v-5b"], "-");
        // CPU only: whisper-small through whisper.cpp; large models and video don't fall back to the CPU.
        let cpu = pick(&pf("linux", "x86_64", "cpu", None));
        assert_eq!(cpu["whisper-small"], "whisper.cpp");
        let cpu_m = manifests_for(&pf("linux", "x86_64", "cpu", None));
        assert_eq!(cpu_m.iter().find(|m| m.id == "whisper-small").unwrap().backends, vec!["cpu"]);
        assert_eq!(cpu["whisper-large-v3-turbo"], "-");
        assert_eq!(cpu["wan2.2-ti2v-5b"], "-");
        assert_eq!(cpu["flux2-klein-4b"], "-");
        // An Intel Mac has no MLX.
        assert_eq!(pick(&pf("macos", "x86_64", "cpu", None))["flux2-klein-4b"], "-");
        // Windows: nothing yet, test models included.
        let win = manifests_for(&pf("windows", "x86_64", "cuda", Some(24.0)));
        assert!(win.iter().all(|m| m.unsupported));
        let st = storage_from(&json!({}));
        assert!(win.into_iter().all(|m| entry(m, &st, 32, true).missing == Some("platform")));
    }

    #[test]
    fn variants_say_where_they_were_seen_working() {
        for m in manifests_for(&pf("linux", "x86_64", "cuda", Some(80.0))).into_iter().filter(|m| !m.unsupported && m.runtime != "ffmpeg") {
            assert!(m.verified_on.is_none(), "{}: no NVIDIA box has run it yet", m.id);
        }
        let mac = manifests_for(&pf("macos", "arm64", "mlx", None));
        assert!(mac.iter().find(|m| m.id == "flux2-klein-4b").unwrap().verified_on.as_deref().unwrap().contains("M4"));
    }

    #[test]
    fn home_is_never_shown() {
        let h = home();
        assert_eq!(shown(&h.join(".cache/huggingface/hub")), "~/.cache/huggingface/hub");
        assert_eq!(shown(Path::new("/Volumes/SSD/models")), "/Volumes/SSD/models");
    }
}
