//! The resource guard (docs/DESIGN.md): the node gives up jobs before the host gives up.
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
    /// 1 normal, 2 warn, 4 critical (macOS kern.memorystatus_vm_pressure_level; Linux mapped from PSI).
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
}

impl Limits {
    pub fn defaults(s: &Sample) -> Limits {
        Limits {
            owner_reserve_mib: (s.mem_total_mib / 4).max(4096),
            os_reserve_mib: 2048,
            disk_floor_mib: (s.disk_total_mib / 20).max(10 * 1024),
        }
    }
    /// Memory all running VMs together may have: never more than this (no overcommit).
    pub fn vm_budget_mib(&self, s: &Sample) -> u64 { s.mem_total_mib.saturating_sub(self.owner_reserve_mib + self.os_reserve_mib) }
}

/// The level for this sample. `swap_growth_mib_per_min` comes from the previous samples.
pub fn level(s: &Sample, l: &Limits, swap_growth_mib_per_min: f64) -> (Level, String) {
    let swap_pct = if s.swap_total_mib > 0 { s.swap_used_mib * 100 / s.swap_total_mib } else { 0 };
    if s.storage_missing { return (Level::Critical, format!("VM storage {} isn't mounted", s.storage)); }
    if s.mem_free_pct < 5 { return (Level::Critical, format!("free memory {}%", s.mem_free_pct)); }
    if s.disk_free_mib < 3 * 1024 { return (Level::Critical, format!("free disk {} MiB", s.disk_free_mib)); }
    if s.pressure >= 4 { return (Level::Red, "memory pressure critical".into()); }
    if s.mem_free_pct < 10 { return (Level::Red, format!("free memory {}%", s.mem_free_pct)); }
    if swap_pct > 75 { return (Level::Red, format!("swap {swap_pct}% full")); }
    if s.disk_free_mib < l.disk_floor_mib { return (Level::Red, format!("free disk {} MiB, under the floor of {} MiB", s.disk_free_mib, l.disk_floor_mib)); }
    if s.pressure >= 2 { return (Level::Amber, "memory pressure warn".into()); }
    if swap_growth_mib_per_min > 200.0 { return (Level::Amber, format!("swap growing {swap_growth_mib_per_min:.0} MiB/min")); }
    if s.disk_free_mib < l.disk_floor_mib + 5 * 1024 { return (Level::Amber, format!("free disk {} MiB, near the floor", s.disk_free_mib)); }
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

/// How many jobs of a size fit at once on an empty machine: the slots (docs/DESIGN.md).
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
pub fn storage_path() -> String {
    let cfg = crate::state::dir().join("config.json");
    if let Some(p) = std::fs::read(&cfg).ok().and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok()).and_then(|v| v["vm_storage"].as_str().map(String::from)) { return p; }
    if cfg!(target_os = "macos") { "/System/Volumes/Data".into() } else { "/".into() }
}

/* ---------- sampling ---------- */

fn now_ms() -> u64 { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64 }

fn disk(path: &str) -> (u64, u64) {
    let c = std::ffi::CString::new(path).unwrap();
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 { return (0, 0); }
    let f = st.f_frsize as u64;
    ((st.f_bavail as u64 * f) >> 20, (st.f_blocks as u64 * f) >> 20)
}

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
        assert_eq!(level(&Sample { swap_used_mib: 1800, ..s.clone() }, &l, 0.0).0, Level::Red);
        assert_eq!(level(&Sample { disk_free_mib: 10_000, ..s.clone() }, &l, 0.0).0, Level::Red);
        assert_eq!(level(&Sample { disk_free_mib: 2_000, ..s.clone() }, &l, 0.0).0, Level::Critical);
        assert_eq!(level(&Sample { mem_free_pct: 3, ..s.clone() }, &l, 0.0).0, Level::Critical);
        assert_eq!(level(&Sample { storage_missing: true, storage: "/Volumes/VMs".into(), ..s.clone() }, &l, 0.0).0, Level::Critical);
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
