//! The resource guard (docs/MACHINES.md §5b): the node gives up jobs before the host gives up.
//! Samples memory pressure, swap and free disk every 2 s, decides a level, and admits a job only if it fits.
use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Level { Green, Amber, Red, Critical }

#[derive(Clone, Debug, Default, Serialize)]
pub struct Sample {
    pub at_ms: u64,
    pub mem_total_mib: u64,
    /// Free memory as macOS / Linux sees it, in percent.
    pub mem_free_pct: u32,
    /// 1 normal, 2 warn, 4 critical (macOS kern.memorystatus_vm_pressure_level; Linux mapped from PSI; Windows from the
    /// memory load and commit charge).
    pub pressure: u32,
    pub swap_total_mib: u64,
    pub swap_used_mib: u64,
    pub disk_free_mib: u64,
    pub disk_total_mib: u64,
    /// Where VM images and disks live (an external drive, say). Missing means unplugged or unmounted.
    pub storage: String,
    pub storage_missing: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct Limits {
    /// Memory the owner keeps for themselves (MiB). Default: max(25% of RAM, 4 GiB).
    pub owner_reserve_mib: u64,
    /// Memory kept for the OS (MiB).
    pub os_reserve_mib: u64,
    /// Free disk the node never goes below (MiB). Default: max(10 GiB, 5% of the volume).
    pub disk_floor_mib: u64,
    /// When swap counts as a risk: the owner's numbers for this machine (config.json `guard`), else the defaults.
    pub swap: SwapRule,
}

/// How full and how fast-growing swap may be before the guard acts (config.json `guard`, docs/MACHINES.md §5b).
///
/// 21 Nov 2026: a fixed "Red above 75% of the swap total" held a job ~15 minutes on a Mac with 46% memory free and swap
/// 84% used but not growing. macOS leaves swapped pages where they are and adds swap files as it needs them, so the
/// share of the swap total in use says little alone; the risk is swap nearly full *with* memory pressure, or swap
/// growing fast.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct SwapRule {
    /// Swap this full (% of the swap total) is high: Amber while it is steady and memory pressure is normal.
    pub swap_high_pct: u32,
    /// Swap this full is nearly full: Red when memory pressure is up or swap is still growing.
    pub swap_full_pct: u32,
    /// Swap growing this fast (MiB a minute) is Amber on its own, and Red when swap is nearly full.
    pub swap_growth_mib_per_min: u32,
    /// Swap growing this fast while it is high is Red.
    pub swap_fast_mib_per_min: u32,
    /// The keys config.json set (the others are defaults).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub from_config: Vec<String>,
    /// What in config.json was set aside, in words.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub problems: Vec<String>,
}

impl Default for SwapRule {
    fn default() -> SwapRule { SwapRule { swap_high_pct: 75, swap_full_pct: 90, swap_growth_mib_per_min: 200, swap_fast_mib_per_min: 1000, from_config: vec![], problems: vec![] } }
}

impl SwapRule {
    /// The `guard` object of config.json. A missing key keeps its default; one out of range is set aside and said in
    /// `problems` (never read as zero, which would make every sample Red).
    pub fn from_config(cfg: &serde_json::Value) -> SwapRule {
        let mut r = SwapRule::default();
        let g = &cfg["guard"];
        if g.is_null() { return r; }
        if !g.is_object() { r.problems.push("\"guard\" in config.json isn't an object; using the defaults".into()); return r; }
        let mut vals = [r.swap_high_pct, r.swap_full_pct, r.swap_growth_mib_per_min, r.swap_fast_mib_per_min];
        for (i, (key, hi)) in [("swap_high_pct", 100u64), ("swap_full_pct", 100), ("swap_growth_mib_per_min", 1_000_000), ("swap_fast_mib_per_min", 1_000_000)].into_iter().enumerate() {
            if g[key].is_null() { continue; }
            match g[key].as_u64().filter(|n| (1..=hi).contains(n)) {
                Some(n) => { vals[i] = n as u32; r.from_config.push(key.to_string()); }
                None => r.problems.push(format!("guard.{key} must be a whole number from 1 to {hi}; using {}", vals[i])),
            }
        }
        let [high, mut full, growth, mut fast] = vals;
        if full < high { r.problems.push(format!("guard.swap_full_pct ({full}) is below guard.swap_high_pct ({high}); using {high} for both")); full = high; }
        if fast < growth { r.problems.push(format!("guard.swap_fast_mib_per_min ({fast}) is below guard.swap_growth_mib_per_min ({growth}); using {growth} for both")); fast = growth; }
        (r.swap_high_pct, r.swap_full_pct, r.swap_growth_mib_per_min, r.swap_fast_mib_per_min) = (high, full, growth, fast);
        r
    }
    /// This machine's rule: config.json's `guard`, else the defaults.
    pub fn configured() -> SwapRule { SwapRule::from_config(&crate::state::config()) }
    /// What `pavilion-node status` shows.
    pub fn describe(&self) -> String {
        let mut t = format!("Guard: swap is high at {}% (amber while steady) and nearly full at {}% (red with memory pressure or growth); \
growing {} MiB/min is amber, {} MiB/min while high is red", self.swap_high_pct, self.swap_full_pct, self.swap_growth_mib_per_min, self.swap_fast_mib_per_min);
        t.push_str(&if self.from_config.is_empty() { " (the defaults; set them under \"guard\" in config.json)".to_string() } else { format!(" (config.json sets {})", self.from_config.join(", ")) });
        for p in &self.problems { t.push_str(&format!("\n  NOT USED: {p}")); }
        t
    }
}

impl Limits {
    pub fn defaults(s: &Sample) -> Limits {
        Limits {
            owner_reserve_mib: (s.mem_total_mib / 4).max(4096),
            os_reserve_mib: 2048,
            disk_floor_mib: (s.disk_total_mib / 20).max(10 * 1024),
            swap: SwapRule::default(),
        }
    }
    /// The defaults with this machine's swap rule from config.json: what the running guard and `pavilion-node guard` use.
    pub fn configured(s: &Sample) -> Limits { Limits { swap: SwapRule::configured(), ..Limits::defaults(s) } }
    /// Memory all running VMs together may have: never more than this (no overcommit).
    pub fn vm_budget_mib(&self, s: &Sample) -> u64 { s.mem_total_mib.saturating_sub(self.owner_reserve_mib + self.os_reserve_mib) }
}

/// What the owner can do, after the reason. The console shows the reason next to the machine's level, and the Gate
/// keeps 200 characters of it.
const CLOSE_APPS: &str = "Close apps you aren't using";

/// The level for this sample, and why, in words the console shows. `swap_growth_mib_per_min` comes from the previous
/// samples (Watch).
pub fn level(s: &Sample, l: &Limits, swap_growth_mib_per_min: f64) -> (Level, String) {
    let swap_pct = if s.swap_total_mib > 0 { (s.swap_used_mib * 100 / s.swap_total_mib) as u32 } else { 0 };
    let (r, growth) = (&l.swap, swap_growth_mib_per_min);
    let (growing, pressured) = (growth >= r.swap_growth_mib_per_min as f64, s.pressure >= 2);
    if s.storage_missing { return (Level::Critical, format!("VM storage {} isn't mounted: every job is stopped. Plug the drive in, or pick another folder with `pavilion-node storage`", s.storage)); }
    if s.mem_free_pct < 5 { return (Level::Critical, format!("free memory {}%: every job is stopped. {CLOSE_APPS}", s.mem_free_pct)); }
    if s.disk_free_mib < 3 * 1024 { return (Level::Critical, format!("free disk {} MiB: every job is stopped. Free some space on {}", s.disk_free_mib, s.storage)); }
    if s.pressure >= 4 { return (Level::Red, format!("memory pressure critical: jobs are being stopped. {CLOSE_APPS}")); }
    if s.mem_free_pct < 10 { return (Level::Red, format!("free memory {}%: jobs are being stopped. {CLOSE_APPS}", s.mem_free_pct)); }
    if swap_pct >= r.swap_full_pct && pressured { return (Level::Red, format!("swap {swap_pct}% full and memory pressure is up: jobs are being stopped. {CLOSE_APPS}")); }
    if swap_pct >= r.swap_full_pct && growing { return (Level::Red, format!("swap {swap_pct}% full and growing {growth:.0} MiB/min: jobs are being stopped. {CLOSE_APPS}")); }
    if swap_pct >= r.swap_high_pct && growth >= r.swap_fast_mib_per_min as f64 { return (Level::Red, format!("swap {swap_pct}% full and growing fast, {growth:.0} MiB/min: jobs are being stopped. {CLOSE_APPS}")); }
    if s.disk_free_mib < l.disk_floor_mib { return (Level::Red, format!("free disk {} MiB, under the floor of {} MiB: jobs are being stopped. Free some space on {}", s.disk_free_mib, l.disk_floor_mib, s.storage)); }
    if pressured { return (Level::Amber, format!("memory pressure warn: new jobs wait until it eases. {CLOSE_APPS} to start them sooner")); }
    if swap_pct >= r.swap_high_pct { return (Level::Amber, format!("swap {swap_pct}% full but steady, memory pressure normal: new jobs wait. {CLOSE_APPS}, or raise guard.swap_high_pct in config.json")); }
    if growing { return (Level::Amber, format!("swap growing {growth:.0} MiB/min: new jobs wait until it settles. {CLOSE_APPS}")); }
    if s.disk_free_mib < l.disk_floor_mib + 5 * 1024 { return (Level::Amber, format!("free disk {} MiB, near the floor: new jobs wait. Free some space on {}", s.disk_free_mib, s.storage)); }
    (Level::Green, "ok".into())
}

/// Whether a new job fits: level green, its memory within the VM budget next to what's running, its disk above the floor.
pub fn admit(s: &Sample, l: &Limits, lvl: Level, running_mib: u64, job_mem_mib: u64, job_disk_mib: u64) -> Result<(), String> {
    if lvl != Level::Green { return Err(format!("this machine is at {lvl:?}; it takes no new jobs until it's green")); }
    let budget = l.vm_budget_mib(s);
    if running_mib + job_mem_mib > budget { return Err(format!("no memory: {running_mib} MiB running + {job_mem_mib} MiB asked > {budget} MiB budget")); }
    if s.disk_free_mib < l.disk_floor_mib + job_disk_mib { return Err(format!("no disk: {} MiB free, the floor is {} MiB and the job needs {job_disk_mib} MiB", s.disk_free_mib, l.disk_floor_mib)); }
    Ok(())
}

/// How many jobs of a size fit at once on an empty machine: the slots (docs/PROJECTS.md §5).
pub fn slots(s: &Sample, l: &Limits, job_mem_mib: u64) -> u64 { if job_mem_mib == 0 { 0 } else { l.vm_budget_mib(s) / job_mem_mib } }

/// macOS starts warning about memory pressure around this much free memory (measured on an M4, 2026-11-12: warn at 41%).
pub const WARN_FREE_PCT: u32 = 45;
/// Slots right now, with what the owner is running: full-size VMs that fit before memory pressure starts, never more
/// than the budget allows. Conservative: it assumes each VM uses all its memory.
pub fn slots_now(s: &Sample, l: &Limits, job_mem_mib: u64, running: u64) -> u64 {
    if job_mem_mib == 0 { return 0; }
    let headroom = s.mem_total_mib * s.mem_free_pct.saturating_sub(WARN_FREE_PCT) as u64 / 100;
    (running + headroom / job_mem_mib).min(slots(s, l, job_mem_mib))
}

/// Where VM data lives: `vm_storage` in the node's config.json, else the system data volume.
#[cfg_attr(windows, allow(unreachable_code))]
pub fn storage_path() -> String {
    let cfg = crate::state::dir().join("config.json");
    if let Some(p) = std::fs::read(&cfg).ok().and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok()).and_then(|v| v["vm_storage"].as_str().map(String::from)) { return p; }
    #[cfg(windows)]
    return crate::platform::windows::default_vm_storage();
    if cfg!(target_os = "macos") { "/System/Volumes/Data".into() } else { "/".into() }
}

/* ---------- sampling ---------- */

fn now_ms() -> u64 { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64 }

fn disk(path: &str) -> (u64, u64) { crate::platform::disk(std::path::Path::new(path)) }

#[cfg(target_os = "macos")]
fn sysctl<T: Copy + Default>(name: &str) -> T {
    let c = std::ffi::CString::new(name).unwrap();
    let mut v = T::default();
    let mut len = std::mem::size_of::<T>();
    unsafe { libc::sysctlbyname(c.as_ptr(), &mut v as *mut T as *mut libc::c_void, &mut len, std::ptr::null_mut(), 0) };
    v
}

#[cfg(target_os = "macos")]
pub fn sample() -> Sample {
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct XswUsage { total: u64, avail: u64, used: u64, pagesize: u32, encrypted: u32 }
    let swap: XswUsage = sysctl("vm.swapusage");
    let storage = storage_path();
    let (free, total) = disk(&storage);
    Sample {
        at_ms: now_ms(),
        mem_total_mib: sysctl::<u64>("hw.memsize") >> 20,
        mem_free_pct: sysctl::<i32>("kern.memorystatus_level").max(0) as u32,
        pressure: sysctl::<i32>("kern.memorystatus_vm_pressure_level").max(1) as u32,
        swap_total_mib: swap.total >> 20,
        swap_used_mib: swap.used >> 20,
        disk_free_mib: free,
        disk_total_mib: total,
        storage_missing: total == 0,
        storage,
    }
}

#[cfg(target_os = "linux")]
pub fn sample() -> Sample {
    let mi = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let kb = |k: &str| mi.lines().find(|l| l.starts_with(k)).and_then(|l| l.split_whitespace().nth(1)).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
    let (total, avail, st, sf) = (kb("MemTotal:"), kb("MemAvailable:"), kb("SwapTotal:"), kb("SwapFree:"));
    let psi = std::fs::read_to_string("/proc/pressure/memory").unwrap_or_default();
    let avg10 = |kind: &str| psi.lines().find(|l| l.starts_with(kind)).and_then(|l| l.split_whitespace().find(|w| w.starts_with("avg10="))).and_then(|w| w[6..].parse::<f64>().ok()).unwrap_or(0.0);
    let pressure = if avg10("full") > 5.0 { 4 } else if avg10("some") > 10.0 { 2 } else { 1 };
    let storage = storage_path();
    let (free, dtotal) = disk(&storage);
    Sample { at_ms: now_ms(), mem_total_mib: total >> 10, mem_free_pct: if total > 0 { (avail * 100 / total) as u32 } else { 0 }, pressure,
        swap_total_mib: st >> 10, swap_used_mib: (st - sf) >> 10, disk_free_mib: free, disk_total_mib: dtotal, storage_missing: dtotal == 0, storage }
}

/// Windows: memory and the page file from GlobalMemoryStatusEx (platform/windows.rs), free space on the drive the
/// WSL distro's disk is on (`pavilion-node storage`).
#[cfg(windows)]
pub fn sample() -> Sample {
    let m = crate::platform::windows::memory();
    let storage = storage_path();
    let (free, total) = disk(&storage);
    Sample { at_ms: now_ms(), mem_total_mib: m.total_mib, mem_free_pct: m.free_pct, pressure: m.pressure, swap_total_mib: m.swap_total_mib, swap_used_mib: m.swap_used_mib,
        disk_free_mib: free, disk_total_mib: total, storage_missing: total == 0, storage }
}

/// Keeps the last minute of samples to see how fast swap grows.
#[derive(Default)]
pub struct Watch { history: std::collections::VecDeque<Sample> }
impl Watch {
    pub fn push(&mut self, s: Sample) -> f64 {
        while self.history.front().map_or(false, |f| s.at_ms - f.at_ms > 60_000) { self.history.pop_front(); }
        let growth = self.history.front().map_or(0.0, |f| {
            let mins = (s.at_ms - f.at_ms) as f64 / 60_000.0;
            if mins < 0.1 { 0.0 } else { (s.swap_used_mib as f64 - f.swap_used_mib as f64) / mins }
        });
        self.history.push_back(s);
        growth
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn mac16() -> Sample { Sample { mem_total_mib: 16384, mem_free_pct: 60, pressure: 1, swap_total_mib: 2048, swap_used_mib: 100, disk_free_mib: 40_000, disk_total_mib: 233_000, ..Default::default() } }
    #[test]
    fn a_16_gb_mac_keeps_4_gb_for_the_owner_and_2_for_macos() {
        let s = mac16();
        let l = Limits::defaults(&s);
        assert_eq!(l.owner_reserve_mib, 4096);
        assert_eq!(l.vm_budget_mib(&s), 10240);
        assert_eq!(slots(&s, &l, 1024), 10);
        assert_eq!(slots(&s, &l, 3072), 3);
        // With the owner's apps using a third of memory (67% free, as measured): about 3 full-size slots now.
        assert_eq!(slots_now(&Sample { mem_free_pct: 67, ..s.clone() }, &l, 1024, 0), 3);
        assert_eq!(slots_now(&Sample { mem_free_pct: 95, ..s.clone() }, &l, 1024, 0), 8);
        assert_eq!(slots_now(&Sample { mem_free_pct: 95, ..s.clone() }, &l, 1024, 4), 10);
    }
    #[test]
    fn levels() {
        let s = mac16(); let l = Limits::defaults(&s);
        assert_eq!(level(&s, &l, 0.0).0, Level::Green);
        assert_eq!(level(&Sample { pressure: 2, ..s.clone() }, &l, 0.0).0, Level::Amber);
        assert_eq!(level(&s, &l, 500.0).0, Level::Amber);
        assert_eq!(level(&Sample { pressure: 4, ..s.clone() }, &l, 0.0).0, Level::Red);
        assert_eq!(level(&Sample { swap_used_mib: 1900, pressure: 2, ..s.clone() }, &l, 0.0).0, Level::Red);
        assert_eq!(level(&Sample { disk_free_mib: 10_000, ..s.clone() }, &l, 0.0).0, Level::Red);
        assert_eq!(level(&Sample { disk_free_mib: 2_000, ..s.clone() }, &l, 0.0).0, Level::Critical);
        assert_eq!(level(&Sample { mem_free_pct: 3, ..s.clone() }, &l, 0.0).0, Level::Critical);
        assert_eq!(level(&Sample { storage_missing: true, storage: "/Volumes/VMs".into(), ..s.clone() }, &l, 0.0).0, Level::Critical);
    }
    /// The owner's Mac on 21 Nov 2026: 46% memory free, normal pressure, swap 84% used and not growing. It was Red
    /// ("swap 84% full") and held a job ~15 minutes; swap only counts as Red with pressure or growth behind it.
    fn busy_mac() -> Sample { Sample { mem_total_mib: 24_576, mem_free_pct: 46, pressure: 1, swap_total_mib: 4096, swap_used_mib: 3441, disk_free_mib: 400_000, disk_total_mib: 1_900_000, ..Default::default() } }
    #[test]
    fn swap_is_judged_with_pressure_and_growth() {
        let s = busy_mac(); let l = Limits::defaults(&s);
        let at = |pct: u64, pressure: u32, growth: f64| level(&Sample { swap_used_mib: (s.swap_total_mib * pct).div_ceil(100), pressure, ..s.clone() }, &l, growth);
        // High but steady, pressure normal: Amber (no new jobs, nothing stopped), with what the owner can do.
        let (lvl, why) = at(84, 1, 0.0);
        assert_eq!(lvl, Level::Amber);
        assert_eq!(why, "swap 84% full but steady, memory pressure normal: new jobs wait. Close apps you aren't using, or raise guard.swap_high_pct in config.json");
        assert_eq!(at(99, 1, 50.0).0, Level::Amber, "nearly full, steady, normal pressure");
        assert_eq!(at(74, 1, 0.0).0, Level::Green, "under the high mark");
        // Nearly full with memory pressure, or still growing: Red.
        assert_eq!(at(92, 2, 0.0), (Level::Red, "swap 92% full and memory pressure is up: jobs are being stopped. Close apps you aren't using".into()));
        assert_eq!(at(92, 1, 250.0), (Level::Red, "swap 92% full and growing 250 MiB/min: jobs are being stopped. Close apps you aren't using".into()));
        // High (not yet nearly full) and growing fast: Red; growing at the ordinary rate: Amber.
        assert_eq!(at(80, 1, 1500.0).0, Level::Red);
        assert_eq!(at(80, 1, 300.0).0, Level::Amber);
        // High with pressure "warn" but under nearly full: Amber, for the pressure.
        assert_eq!(at(80, 2, 0.0), (Level::Amber, "memory pressure warn: new jobs wait until it eases. Close apps you aren't using to start them sooner".into()));
        // A machine without swap (Linux servers often) never trips on it.
        assert_eq!(level(&Sample { swap_total_mib: 0, swap_used_mib: 0, ..s.clone() }, &l, 0.0).0, Level::Green);
    }
    #[test]
    fn the_owner_sets_the_swap_rule_per_machine() {
        let s = busy_mac();
        let cfg = serde_json::json!({ "vm_storage": "/Volumes/X", "guard": { "swap_high_pct": 90, "swap_full_pct": 97, "swap_fast_mib_per_min": 2000 } });
        let l = Limits { swap: SwapRule::from_config(&cfg), ..Limits::defaults(&s) };
        assert_eq!((l.swap.swap_high_pct, l.swap.swap_full_pct, l.swap.swap_growth_mib_per_min, l.swap.swap_fast_mib_per_min), (90, 97, 200, 2000));
        assert_eq!(l.swap.from_config, vec!["swap_high_pct", "swap_full_pct", "swap_fast_mib_per_min"]);
        assert!(l.swap.problems.is_empty());
        assert_eq!(level(&s, &l, 0.0).0, Level::Green, "84% is under this Mac's own high mark");
        assert_eq!(level(&Sample { swap_used_mib: 4000, pressure: 2, ..s.clone() }, &l, 0.0).0, Level::Red);
        assert!(SwapRule::from_config(&cfg).describe().contains("config.json sets swap_high_pct, swap_full_pct, swap_fast_mib_per_min"));
        // No "guard": the defaults, said as such.
        let d = SwapRule::from_config(&serde_json::json!({ "vm_storage": "/Volumes/X" }));
        assert_eq!(d, SwapRule::default());
        assert!(d.describe().contains("swap is high at 75%") && d.describe().contains("nearly full at 90%") && d.describe().contains("the defaults"));
        // Out of range or the wrong type is set aside and said, never read as 0 (which would make every sample Red).
        let bad = SwapRule::from_config(&serde_json::json!({ "guard": { "swap_high_pct": 0, "swap_full_pct": "95", "swap_growth_mib_per_min": 300 } }));
        assert_eq!((bad.swap_high_pct, bad.swap_full_pct, bad.swap_growth_mib_per_min), (75, 90, 300));
        assert_eq!(bad.problems, vec!["guard.swap_high_pct must be a whole number from 1 to 100; using 75", "guard.swap_full_pct must be a whole number from 1 to 100; using 90"]);
        assert!(bad.describe().contains("NOT USED: guard.swap_high_pct"));
        // Nearly full under high is read as both at the high mark.
        let crossed = SwapRule::from_config(&serde_json::json!({ "guard": { "swap_high_pct": 95, "swap_full_pct": 80 } }));
        assert_eq!((crossed.swap_high_pct, crossed.swap_full_pct, crossed.problems.len()), (95, 95, 1));
        assert_eq!(SwapRule::from_config(&serde_json::json!({ "guard": 75 })).problems.len(), 1);
    }
    #[test]
    fn every_reason_fits_what_the_gate_keeps_and_says_what_to_do() {
        let s = busy_mac(); let l = Limits::defaults(&s);
        let samples = [
            Sample { storage_missing: true, storage: "/Volumes/PavilionModels".into(), ..s.clone() }, Sample { mem_free_pct: 3, ..s.clone() },
            Sample { disk_free_mib: 2_000, storage: "/System/Volumes/Data".into(), ..s.clone() }, Sample { pressure: 4, ..s.clone() }, Sample { mem_free_pct: 8, ..s.clone() },
            Sample { swap_used_mib: 4000, pressure: 2, ..s.clone() }, Sample { swap_used_mib: 4000, ..s.clone() }, Sample { pressure: 2, ..s.clone() },
            Sample { disk_free_mib: 90_000, storage: "/System/Volumes/Data".into(), ..s.clone() }, Sample { disk_free_mib: 100_000, storage: "/System/Volumes/Data".into(), ..s.clone() },
        ];
        for x in samples.iter() {
            for g in [0.0, 300.0, 5000.0] {
                let (lvl, why) = level(x, &l, g);
                if lvl == Level::Green { continue; }
                assert!(why.chars().count() <= 200, "{why}");
                assert!(["Close apps", "Free some space", "Plug the drive in"].iter().any(|a| why.contains(a)), "{lvl:?}: {why}");
            }
        }
    }
    #[test]
    fn admission_never_overcommits() {
        let s = mac16(); let l = Limits::defaults(&s);
        assert!(admit(&s, &l, Level::Green, 8192, 2048, 1024).is_ok());
        assert!(admit(&s, &l, Level::Green, 9216, 2048, 1024).unwrap_err().starts_with("no memory"));
        assert!(admit(&s, &l, Level::Amber, 0, 512, 0).is_err());
        assert!(admit(&Sample { disk_free_mib: 12_000, ..s.clone() }, &l, Level::Green, 0, 512, 2048).unwrap_err().starts_with("no disk"));
    }
}
