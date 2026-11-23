//! The local ceiling (docs/MACHINES.md §3): limits set by whoever installed the node, which the cloud can never raise.
//! The file is owned by root (Administrators on Windows): the node reads it, and refuses to trust it if anyone else
//! could have written it. Two sections are read here, each on its own, so a mistake in one never changes the other:
//! `devices:` (docs/DEVICES.md §3b) and `jobs:` (docs/MACHINES.md §3).
//!
//! ```text
//! # /Library/Application Support/pavilion-node/ceiling   (macOS; /etc/pavilion-node/ceiling on Linux,
//! #  %ProgramData%\pavilion-node\ceiling on Windows)
//! devices:
//!   capabilities: camera, mic, ble, lan     # each one is off until it's listed here
//!   agents: [agt_linkcheck, agt_doorwatch]  # which agents may ask at all (by id)
//!   quiet: 22:00-07:00                      # no requests at night (this computer's local time)
//!   unattended: look, read                  # kinds this computer may allow with nobody here (never captures or acts)
//! jobs:
//!   kinds: command, agent, media            # job kinds this computer runs; no kinds line means all four
//!   images:                                 # the only images a sandbox may run; no images line means any
//!     - pavilion-dev:1
//!     - docker.io/library/alpine@sha256:…   # pinned by digest: what the docs recommend
//! ```
//!
//! Devices: no file, `devices: none`, an unreadable or untrusted file, or any mistake in the section all mean no devices.
//! Jobs: no file or no `jobs:` section means today's defaults (every kind, any image with a sane name); `jobs: none`
//! means no jobs; a `jobs:` section the node can't trust or read, or with any mistake, means no jobs at all.
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::path::PathBuf;

/// The capability names the Gate and the phones use (docs/DEVICES-PROTOCOL.md §4b).
/// `obd`, `home`, `cast`, `print` and `industrial` switch on the first set of standards (DEVICES.md §4b); `serial` is
/// for the serial tools that come later (an OBD-II adapter on a serial port needs only `obd`).
pub const CAPABILITIES: &[&str] = &["camera", "mic", "speaker", "screen", "ble", "lan", "location", "sensors", "nfc", "usb", "midi", "home", "cast", "serial", "obd", "print", "health", "industrial"];
/// Kinds this computer may allow by itself, when the ceiling says so. Captures and acts always need the person here.
pub const UNATTENDED_KINDS: &[&str] = &["look", "read"];

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Devices {
    pub capabilities: BTreeSet<String>,
    pub agents: BTreeSet<String>,
    /// Minutes after local midnight: (from, to). `to` may be before `from` (over midnight).
    pub quiet: Option<(u16, u16)>,
    pub unattended: BTreeSet<String>,
}

#[derive(Clone, Debug)]
pub struct Ceiling {
    pub devices: Devices,
    /// Where it came from, in words for `pavilion-node devices status`.
    pub source: String,
    /// Why the file was set aside (devices are then all off).
    pub problem: Option<String>,
}

#[cfg_attr(windows, allow(unreachable_code))]
pub fn path() -> PathBuf {
    if let Ok(p) = std::env::var("PAVILION_CEILING") { return PathBuf::from(p); }
    #[cfg(windows)]
    return PathBuf::from(std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into())).join("pavilion-node").join("ceiling");
    if cfg!(target_os = "macos") { PathBuf::from("/Library/Application Support/pavilion-node/ceiling") } else { PathBuf::from("/etc/pavilion-node/ceiling") }
}

/// The ceiling as it is on disk now. Never fails: anything wrong reads as `devices: none`, with the reason.
pub fn load() -> Ceiling {
    let p = path();
    let none = |problem: Option<String>| Ceiling { devices: Devices::default(), source: p.display().to_string(), problem };
    let text = match std::fs::read_to_string(&p) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ceiling { devices: Devices::default(), source: format!("no ceiling file at {} (devices: none)", p.display()), problem: None },
        Err(e) => return none(Some(format!("can't read {}: {e}", p.display()))),
    };
    if let Err(why) = trusted(&p) { return none(Some(why)); }
    match parse(&text) {
        Ok(d) => Ceiling { devices: d, source: p.display().to_string(), problem: None },
        Err(why) => none(Some(format!("{}: {why}; devices are off until it's fixed", p.display()))),
    }
}

/// Only root (or an administrator) may have written it: owned by root, not writable by group or others.
#[cfg(unix)]
fn trusted(p: &std::path::Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    if cfg!(test) { return Ok(()); }
    let m = std::fs::metadata(p).map_err(|e| e.to_string())?;
    if m.uid() != 0 { return Err(format!("{} isn't owned by root, so the node can't trust it (sudo chown root:wheel it)", p.display())); }
    if m.mode() & 0o022 != 0 { return Err(format!("{} can be changed by others than root (sudo chmod 644 it)", p.display())); }
    // Its folder too: whoever can write the folder can swap the file.
    if let Some(d) = p.parent() {
        let dm = std::fs::metadata(d).map_err(|e| e.to_string())?;
        if dm.uid() != 0 || dm.mode() & 0o022 != 0 { return Err(format!("{} must be owned by root and writable only by root", d.display())); }
    }
    Ok(())
}
#[cfg(windows)]
fn trusted(p: &std::path::Path) -> Result<(), String> {
    if cfg!(test) { return Ok(()); }
    crate::platform::windows::admin_owned(p)
}

fn list(v: &str) -> Vec<String> {
    v.trim().trim_start_matches('[').trim_end_matches(']').split(',').map(|s| s.trim().trim_matches('"').trim_matches('\'').to_string()).filter(|s| !s.is_empty()).collect()
}

fn hhmm(s: &str) -> Result<u16, String> {
    let (h, m) = s.trim().split_once(':').ok_or_else(|| format!("{s:?} isn't a time like 22:00"))?;
    let (h, m): (u16, u16) = (h.parse().map_err(|_| format!("{s:?} isn't a time"))?, m.parse().map_err(|_| format!("{s:?} isn't a time"))?);
    if h > 23 || m > 59 || s.trim().len() != 5 { return Err(format!("{s:?} isn't a time like 07:30")); }
    Ok(h * 60 + m)
}

/// Reads the `devices:` section. Strict: an unknown key or name is an error, so a typo can't switch something on.
pub fn parse(text: &str) -> Result<Devices, String> {
    let mut d = Devices::default();
    let mut in_devices = false;
    let mut seen_devices = false;
    let mut current: Option<String> = None; // a key whose list continues on "- item" lines
    let set = |d: &mut Devices, key: &str, items: Vec<String>| -> Result<(), String> {
        match key {
            "capabilities" => for c in items {
                if !CAPABILITIES.contains(&c.as_str()) { return Err(format!("{c:?} isn't a capability (one of {})", CAPABILITIES.join(", "))); }
                d.capabilities.insert(c);
            },
            "agents" => for a in items {
                if a.len() > 64 || !a.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') { return Err(format!("{a:?} isn't an agent id")); }
                d.agents.insert(a);
            },
            "unattended" => for k in items {
                if !UNATTENDED_KINDS.contains(&k.as_str()) { return Err(format!("unattended can only list look and read, not {k:?}: captures and acts always ask the person here")); }
                d.unattended.insert(k);
            },
            "quiet" => {
                let v = items.join(",");
                if v == "none" || v == "off" { d.quiet = None; return Ok(()); }
                let (a, b) = v.split_once('-').ok_or_else(|| format!("quiet: {v:?} should look like 22:00-07:00"))?;
                d.quiet = Some((hhmm(a)?, hhmm(b)?));
            }
            k => return Err(format!("{k:?} isn't a devices setting (capabilities, agents, quiet, unattended)")),
        }
        Ok(())
    };
    for raw in text.lines() {
        let line = raw.split(" #").next().unwrap_or("");
        let line = if line.trim_start().starts_with('#') { "" } else { line };
        if line.trim().is_empty() { continue; }
        let indented = line.starts_with(' ') || line.starts_with('\t');
        if !indented {
            current = None;
            let (k, v) = line.split_once(':').map(|(k, v)| (k.trim(), v.trim())).unwrap_or((line.trim(), ""));
            in_devices = k == "devices";
            if in_devices {
                if seen_devices { return Err("devices: appears twice".into()); }
                seen_devices = true;
                if v == "none" { in_devices = false; }
                else if !v.is_empty() { return Err(format!("devices: {v:?}: write `devices: none` or a section below it")); }
            }
            continue;
        }
        if !in_devices { continue; }
        let t = line.trim();
        if let Some(item) = t.strip_prefix("- ").or_else(|| (t == "-").then_some("")) {
            let key = current.clone().ok_or_else(|| format!("{t:?} isn't under a setting"))?;
            set(&mut d, &key, list(item))?;
            continue;
        }
        let (k, v) = t.split_once(':').ok_or_else(|| format!("{t:?} should be `setting: value`"))?;
        let (k, v) = (k.trim(), v.trim());
        if k == "quiet" { set(&mut d, k, vec![v.to_string()])?; current = None; continue; }
        if v.is_empty() { set(&mut d, k, vec![])?; current = Some(k.to_string()); } else { set(&mut d, k, list(v))?; current = None; }
    }
    Ok(d)
}

/// The ceiling capability a tool needs (DEVICES-PROTOCOL.md §5).
pub fn capability_of(tool: &str) -> Option<&'static str> {
    Some(match tool {
        "camera_snapshot" | "camera_clip" => "camera",
        "record_audio" => "mic",
        "play_audio" => "speaker",
        "screen_capture" => "screen",
        "ble_scan" | "ble_read" | "ble_write" | "ble_subscribe" => "ble",
        "lan_discover" | "lan_request" => "lan",
        "location" => "location",
        "sensor_read" => "sensors",
        "nfc_read" | "nfc_write" => "nfc",
        // The first set of standards. MQTT counts as home automation; IP camera snapshots are the camera.
        "obd_info" | "obd_read" | "obd_codes" | "obd_monitor" | "obd_clear_codes" => "obd",
        "home_list" | "home_state" | "home_command" | "mqtt_read" | "mqtt_publish" => "home",
        "cast_media" | "media_control" => "cast",
        "print" => "print",
        "modbus_read" | "modbus_write" => "industrial",
        _ => return None,
    })
}

impl Devices {
    pub fn is_none(&self) -> bool { self.capabilities.is_empty() }
    /// Whether `minute` (after local midnight) falls in quiet hours.
    pub fn quiet_at(&self, minute: u16) -> bool {
        match self.quiet { None => false, Some((a, b)) if a <= b => minute >= a && minute < b, Some((a, b)) => minute >= a || minute < b }
    }
    /// Whether this action fits the ceiling, and why not.
    pub fn allows(&self, tool: &str, agent: &str, local_minute: u16) -> Result<(), String> {
        if self.is_none() { return Err("this computer's ceiling allows no devices (devices: none)".into()); }
        let cap = capability_of(tool).ok_or_else(|| format!("{tool} isn't a device tool this computer knows"))?;
        if !self.capabilities.contains(cap) { return Err(format!("{cap} is switched off in this computer's ceiling")); }
        if !self.agents.contains(agent) { return Err(format!("the agent {agent} isn't one this computer's ceiling lets ask")); }
        if self.quiet_at(local_minute) { return Err("it's quiet hours on this computer".into()); }
        Ok(())
    }
    /// What `PUT …/node/devices/ceiling` sends (DEVICES-PROTOCOL.md §4b).
    pub fn mirror(&self) -> Value {
        let hm = |m: u16| format!("{:02}:{:02}", m / 60, m % 60);
        json!({ "capabilities": self.capabilities, "agents": self.agents,
            "quiet": self.quiet.map(|(a, b)| json!({ "from": hm(a), "to": hm(b), "tz": local_tz() })), "dedicated": false })
    }
}

/* ---------- jobs: which kinds of job this computer runs, and in which images ---------- */

/// The job kinds the node knows: commands, agent jobs (agent.rs), CLI connector jobs (cli.rs), media jobs (media/).
pub const JOB_KINDS: &[&str] = &["command", "agent", "cli", "media"];

/// The `jobs:` section. `None` means no limit from the ceiling; an empty set means nothing is allowed.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Jobs {
    pub kinds: Option<BTreeSet<String>>,
    pub images: Option<BTreeSet<String>>,
}

/// The node's own rule for an image name, whatever the ceiling says: 3 to 200 characters, lowercase letters, digits and
/// `. / _ : @ -`, starting with a letter or digit (so it can never be read as an option by the sandbox's command line).
pub fn image_shape_ok(i: &str) -> bool {
    (3..=200).contains(&i.len()) && i.as_bytes()[0].is_ascii_alphanumeric()
        && i.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"./_:@-".contains(&b))
}

/// Whether an image is pinned by digest (`name@sha256:<64 hex>`), so it always means the same bytes.
pub fn pinned(i: &str) -> bool {
    i.split_once("@sha256:").map_or(false, |(name, h)| !name.is_empty() && h.len() == 64 && h.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
}

/// Reads the `jobs:` section: `None` when the file has none. Strict like `devices:`: an unknown setting, kind or image
/// name is an error, so a typo can't let more through. `kinds:` or `images:` written at the left edge (outside the
/// section) is a mistake too: whoever wrote it meant a limit.
pub fn parse_jobs(text: &str) -> Result<Option<Jobs>, String> {
    let mut j = Jobs::default();
    let (mut in_jobs, mut seen) = (false, false);
    let mut current: Option<String> = None; // a key whose list continues on "- item" lines
    let mut keys: BTreeSet<String> = BTreeSet::new();
    let add = |j: &mut Jobs, key: &str, items: Vec<String>| -> Result<(), String> {
        match key {
            "kinds" => {
                let k = j.kinds.get_or_insert_with(BTreeSet::new);
                for x in items {
                    if !JOB_KINDS.contains(&x.as_str()) { return Err(format!("{x:?} isn't a job kind (one of {})", JOB_KINDS.join(", "))); }
                    k.insert(x);
                }
            }
            "images" => {
                let s = j.images.get_or_insert_with(BTreeSet::new);
                for x in items {
                    if !image_shape_ok(&x) { return Err(format!("{x:?} isn't an image name (lowercase letters, digits and . / _ : @ -)")); }
                    if x.contains('@') && !pinned(&x) { return Err(format!("{x:?}: a digest is written name@sha256: and 64 hex characters")); }
                    s.insert(x);
                }
            }
            k => return Err(format!("{k:?} isn't a jobs setting (kinds, images)")),
        }
        Ok(())
    };
    for raw in text.lines() {
        let line = raw.split(" #").next().unwrap_or("");
        let line = if line.trim_start().starts_with('#') { "" } else { line };
        if line.trim().is_empty() { continue; }
        if !(line.starts_with(' ') || line.starts_with('\t')) {
            current = None;
            let (k, v) = line.split_once(':').map(|(k, v)| (k.trim(), v.trim())).unwrap_or((line.trim(), ""));
            if k == "kinds" || k == "images" { return Err(format!("{k}: belongs under jobs:, indented")); }
            in_jobs = k == "jobs";
            if in_jobs {
                if seen { return Err("jobs: appears twice".into()); }
                seen = true;
                if v == "none" { j.kinds = Some(BTreeSet::new()); in_jobs = false; }
                else if !v.is_empty() { return Err(format!("jobs: {v:?}: write `jobs: none` or a section below it")); }
            }
            continue;
        }
        if !in_jobs { continue; }
        let t = line.trim();
        if let Some(item) = t.strip_prefix("- ").or_else(|| (t == "-").then_some("")) {
            let key = current.clone().ok_or_else(|| format!("{t:?} isn't under a setting"))?;
            add(&mut j, &key, list(item))?;
            continue;
        }
        let (k, v) = t.split_once(':').ok_or_else(|| format!("{t:?} should be `setting: value`"))?;
        let (k, v) = (k.trim(), v.trim());
        if !keys.insert(k.to_string()) { return Err(format!("{k}: appears twice under jobs:")); }
        add(&mut j, k, list(v))?;
        current = v.is_empty().then(|| k.to_string());
    }
    Ok(seen.then_some(j))
}

/// The job limits on disk now. No file, or a file without a `jobs:` section: the defaults (every kind, any image with a
/// sane name). Err, with the reason, when the node can't use what someone wrote: every job is then refused.
pub fn load_jobs() -> Result<Jobs, String> {
    let p = path();
    let text = match std::fs::read_to_string(&p) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Jobs::default()),
        // It may hold a jobs: section the node can't see; run nothing rather than guess.
        Err(e) => return Err(format!("the node can't read this computer's ceiling file {} ({e}), so it runs no jobs until it can", p.display())),
    };
    jobs_from(&p, &text, trusted(&p))
}

/// `load_jobs` once the file is read: only a file that has a `jobs:` section can stop jobs.
fn jobs_from(p: &std::path::Path, text: &str, trust: Result<(), String>) -> Result<Jobs, String> {
    let parsed = parse_jobs(text);
    if let Ok(None) = parsed { return Ok(Jobs::default()); }
    if let Err(why) = trust { return Err(format!("{why}; until then it runs no jobs, since the file sets job limits")); }
    match parsed {
        Ok(j) => Ok(j.unwrap_or_default()),
        Err(why) => Err(format!("the jobs: section of {} has a mistake ({why}), so this computer runs no jobs until it's fixed", p.display())),
    }
}

impl Jobs {
    /// Whether the ceiling lets this computer run a job of this kind, and why not.
    pub fn allows_kind(&self, kind: &str) -> Result<(), String> {
        match &self.kinds {
            None => Ok(()),
            Some(k) if k.is_empty() => Err("this computer's ceiling allows no jobs (jobs: none)".into()),
            Some(k) if k.contains(kind) => Ok(()),
            Some(k) => Err(format!("this computer's ceiling doesn't allow {kind} jobs (jobs: kinds: {})", k.iter().cloned().collect::<Vec<_>>().join(", "))),
        }
    }
    /// Whether a sandbox may run this image: always a sane name, and on the list when there is one (compared exactly).
    pub fn allows_image(&self, image: &str) -> Result<(), String> {
        if image.is_empty() { return Err("the job names no image".into()); }
        if !image_shape_ok(image) { return Err(format!("{image:?} isn't an image name this computer will run (lowercase letters, digits and . / _ : @ -, starting with a letter or digit)")); }
        match &self.images {
            Some(list) if !list.contains(image) => Err(format!("the image {image} isn't on this computer's image list (jobs: images); its owner adds it to the ceiling file")),
            _ => Ok(()),
        }
    }
    /// In words, for `pavilion-node status`.
    pub fn describe(&self) -> String {
        let kinds = match &self.kinds {
            None => "job kinds: all".to_string(),
            Some(k) if k.is_empty() => return "jobs: none (this computer runs no jobs)".into(),
            Some(k) => format!("job kinds: {} only", k.iter().cloned().collect::<Vec<_>>().join(", ")),
        };
        let images = match &self.images {
            None => "images: any, if the name is sane".to_string(),
            Some(l) if l.is_empty() => "images: none listed, so no command, agent or cli job can run".to_string(),
            Some(l) => {
                let tags = l.iter().filter(|i| !pinned(i)).count();
                format!("images: only the {} listed{}", l.len(), match tags {
                    0 => " (all pinned by digest)".to_string(),
                    n => format!(" ({n} by tag, which whoever publishes it can point at a different image; a digest can't change)"),
                })
            }
        };
        format!("{kinds} · {images}")
    }
}

/// What the network of a job's sandbox is. Not set in the ceiling: it is always this (sandbox.rs).
pub const NETWORK: &str = "network: each sandbox gets a host-only network of its own, no DNS, and only this node's broker to talk to, which passes on just what the job's grants allow, through the Gate (cli jobs get no network at all); no LAN and no direct internet, and the ceiling can't open either; jobs wait until a check finds none of this computer's own services reachable from a sandbox";

/// The ceiling in one line, for `pavilion-node status`: the job limits, the network, the devices.
pub fn status_line() -> String {
    let jobs = match load_jobs() {
        Ok(j) => format!("{}{}", j.describe(), if j == Jobs::default() { " (no jobs: limits in the ceiling)" } else { "" }),
        Err(why) => format!("jobs: ALL REFUSED: {why}"),
    };
    let c = load();
    let devices = match (&c.problem, c.devices.is_none()) {
        (Some(p), _) => format!("devices: none ({p})"),
        (None, true) => "devices: none".to_string(),
        (None, false) => format!("devices: {} (pavilion-node devices status)", c.devices.capabilities.iter().cloned().collect::<Vec<_>>().join(", ")),
    };
    let file = if path().exists() { path().display().to_string() } else { format!("no file at {}", path().display()) };
    format!("ceiling ({file}): {jobs} · {NETWORK} · {devices}")
}

/// Minutes after midnight, this computer's local time.
pub fn local_minute() -> u16 {
    #[cfg(unix)]
    unsafe {
        let t = libc::time(std::ptr::null_mut());
        let mut tm: libc::tm = std::mem::zeroed();
        libc::localtime_r(&t, &mut tm);
        (tm.tm_hour * 60 + tm.tm_min) as u16
    }
    #[cfg(windows)]
    { crate::platform::windows::local_minute() }
}

/// The IANA name of this computer's time zone where it can be read (macOS, Linux), else "local".
pub fn local_tz() -> String {
    if let Ok(tz) = std::env::var("TZ") { if !tz.is_empty() { return tz.trim_start_matches(':').to_string(); } }
    std::fs::read_link("/etc/localtime").ok().and_then(|p| p.to_string_lossy().split("zoneinfo/").nth(1).map(String::from)).unwrap_or_else(|| "local".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn no_section_or_none_means_no_devices() {
        assert!(parse("").unwrap().is_none());
        assert!(parse("lan: never\nimages: []\n").unwrap().is_none());
        assert!(parse("devices: none\n").unwrap().is_none());
        assert!(parse("devices: none\n").unwrap().allows("lan_discover", "agt_a", 600).unwrap_err().contains("devices: none"));
    }

    #[test]
    fn a_section_in_both_list_styles() {
        let d = parse("lan: never\ndevices:\n  capabilities: [camera, ble]   # the camera and Bluetooth\n  agents:\n    - agt_linkcheck\n    - agt_doorwatch\n  quiet: 22:00-07:00\n  unattended: look\nimages: []\n").unwrap();
        assert_eq!(d.capabilities, ["ble", "camera"].iter().map(|s| s.to_string()).collect());
        assert_eq!(d.agents.len(), 2);
        assert_eq!(d.quiet, Some((22 * 60, 7 * 60)));
        assert!(d.unattended.contains("look"));
        assert_eq!(d.mirror()["quiet"]["from"], "22:00");
        assert_eq!(d.mirror()["dedicated"], false);
    }

    #[test]
    fn refusals_say_why() {
        let d = parse("devices:\n  capabilities: lan, ble\n  agents: agt_a\n  quiet: 22:00-07:00\n").unwrap();
        assert!(d.allows("lan_discover", "agt_a", 12 * 60).is_ok());
        assert!(d.allows("camera_snapshot", "agt_a", 12 * 60).unwrap_err().contains("camera is switched off"));
        assert!(d.allows("screen_capture", "agt_a", 12 * 60).unwrap_err().contains("screen is switched off"));
        assert!(d.allows("lan_discover", "agt_b", 12 * 60).unwrap_err().contains("agt_b"));
        assert!(d.allows("lan_discover", "agt_a", 23 * 60).unwrap_err().contains("quiet"));
        assert!(d.allows("lan_discover", "agt_a", 3 * 60).unwrap_err().contains("quiet"));
        assert!(d.allows("lan_discover", "agt_a", 7 * 60).is_ok());
        assert!(d.allows("shell", "agt_a", 12 * 60).is_err());
    }

    #[test]
    fn mistakes_switch_everything_off() {
        assert!(parse("devices:\n  capabilites: camera\n").is_err()); // typo
        assert!(parse("devices:\n  capabilities: camera, everything\n").is_err());
        assert!(parse("devices:\n  unattended: capture\n").is_err()); // captures always ask
        assert!(parse("devices:\n  quiet: 25:00-07:00\n").is_err());
        assert!(parse("devices: all\n").is_err());
        assert!(parse("devices:\n  capabilities: lan\ndevices:\n  capabilities: camera\n").is_err());
        assert!(parse("devices:\n  agents: agt a\n").is_err());
    }

    #[test]
    fn standards_need_their_own_capability() {
        let d = parse("devices:\n  capabilities: lan, home, obd\n  agents: agt_a\n").unwrap();
        assert!(d.allows("home_command", "agt_a", 600).is_ok());
        assert!(d.allows("mqtt_publish", "agt_a", 600).is_ok());
        assert!(d.allows("obd_clear_codes", "agt_a", 600).is_ok());
        assert!(d.allows("print", "agt_a", 600).unwrap_err().contains("print is switched off"));
        assert!(d.allows("modbus_read", "agt_a", 600).unwrap_err().contains("industrial is switched off"));
        assert!(d.allows("cast_media", "agt_a", 600).unwrap_err().contains("cast is switched off"));
        assert!(parse("devices:\n  capabilities: serial, print, industrial, cast\n").is_ok());
        assert!(parse("devices:\n  capabilities: modbus\n").is_err()); // the capability is industrial
    }

    #[test]
    fn the_example_file_parses() {
        let d = parse(include_str!("../macos/ceiling.example")).unwrap();
        assert_eq!(d.capabilities.len(), 2);
        assert!(d.agents.is_empty() && d.unattended.is_empty());
        assert!(d.allows("lan_discover", "agt_x", 12 * 60).unwrap_err().contains("agt_x"));
        // Its jobs: section is commented out (installing the example keeps today's defaults); uncommented, it parses.
        let text = include_str!("../macos/ceiling.example");
        assert_eq!(parse_jobs(text).unwrap(), None);
        let at = text.find("\n#jobs:").unwrap() + 1;
        let on = format!("{}{}", &text[..at], text[at..].lines().map(|l| l.strip_prefix('#').unwrap_or(l)).collect::<Vec<_>>().join("\n"));
        let j = parse_jobs(&on).unwrap().unwrap();
        assert_eq!(j.kinds, Some(set(&["agent", "command", "media"])));
        assert!(j.allows_image("pavilion-dev:1").is_ok() && j.allows_image("docker.io/library/alpine:3.22").is_err());
        assert_eq!(parse(&on).unwrap(), d);
    }

    const DIGEST: &str = "docker.io/library/alpine@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    fn set(xs: &[&str]) -> BTreeSet<String> { xs.iter().map(|s| s.to_string()).collect() }

    #[test]
    fn jobs_in_both_list_styles() {
        let j = parse_jobs(&format!("jobs:\n  kinds: [command, cli]   # no agents here\n  images:\n    - pavilion-dev:1\n    - {DIGEST}\n")).unwrap().unwrap();
        assert_eq!(j.kinds, Some(set(&["cli", "command"])));
        assert_eq!(j.images, Some(set(&["pavilion-dev:1", DIGEST])));
        let j = parse_jobs("jobs:\n  kinds:\n    - media\n  images: pavilion-dev:1, 'local/exiftool:12.76'\n").unwrap().unwrap();
        assert_eq!(j.kinds, Some(set(&["media"])));
        assert_eq!(j.images, Some(set(&["local/exiftool:12.76", "pavilion-dev:1"])));
    }

    #[test]
    fn jobs_mistakes_are_errors() {
        assert!(parse_jobs("jobs:\n  kind: command\n").unwrap_err().contains("isn't a jobs setting")); // typo
        assert!(parse_jobs("jobs:\n  kinds: command, shell\n").unwrap_err().contains("isn't a job kind"));
        assert!(parse_jobs("jobs:\n  images: Alpine:latest\n").is_err()); // uppercase
        assert!(parse_jobs("jobs:\n  images: --privileged\n").is_err()); // would read as an option
        assert!(parse_jobs("jobs:\n  images: alpine@sha256:abc\n").unwrap_err().contains("digest"));
        assert!(parse_jobs("jobs:\n  kinds: command\njobs:\n  kinds: agent\n").unwrap_err().contains("twice"));
        assert!(parse_jobs("jobs:\n  kinds: command\n  kinds: agent\n").unwrap_err().contains("twice"));
        assert!(parse_jobs("jobs: all\n").is_err());
        assert!(parse_jobs("images: [pavilion-dev:1]\n").unwrap_err().contains("under jobs:")); // meant a limit
        assert!(parse_jobs("jobs:\n  - command\n").is_err());
    }

    #[test]
    fn jobs_none_and_the_defaults() {
        let none = parse_jobs("jobs: none\n").unwrap().unwrap();
        for k in JOB_KINDS { assert_eq!(none.allows_kind(k).unwrap_err(), "this computer's ceiling allows no jobs (jobs: none)"); }
        assert!(none.describe().contains("runs no jobs"));
        // No section: None, which load_jobs turns into the defaults (every kind, any sane image).
        assert_eq!(parse_jobs("").unwrap(), None);
        let d = Jobs::default();
        for k in JOB_KINDS { assert!(d.allows_kind(k).is_ok()); }
        assert!(d.allows_image("docker.io/library/alpine:3.22").is_ok());
        assert!(d.allows_image("--privileged").unwrap_err().contains("isn't an image name"));
        assert_eq!(d.allows_image("").unwrap_err(), "the job names no image");
        assert_eq!(d.describe(), "job kinds: all · images: any, if the name is sane");
        // An empty section limits nothing.
        assert_eq!(parse_jobs("jobs:\n").unwrap(), Some(Jobs::default()));
    }

    #[test]
    fn jobs_refusals_say_why() {
        let j = parse_jobs(&format!("jobs:\n  kinds: command, cli\n  images: [pavilion-dev:1, {DIGEST}]\n")).unwrap().unwrap();
        assert!(j.allows_kind("command").is_ok() && j.allows_kind("cli").is_ok());
        assert_eq!(j.allows_kind("agent").unwrap_err(), "this computer's ceiling doesn't allow agent jobs (jobs: kinds: cli, command)");
        assert!(j.allows_kind("media").is_err());
        assert!(j.allows_image(DIGEST).is_ok());
        assert_eq!(j.allows_image("docker.io/library/alpine:3.22").unwrap_err(),
            "the image docker.io/library/alpine:3.22 isn't on this computer's image list (jobs: images); its owner adds it to the ceiling file");
        // Compared exactly: the short spelling of a listed image is another name.
        assert!(j.allows_image("alpine@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef").is_err());
        assert!(j.describe().contains("1 by tag"));
        let empty = parse_jobs("jobs:\n  images: []\n").unwrap().unwrap();
        assert!(empty.allows_kind("media").is_ok());
        assert!(empty.allows_image("pavilion-dev:1").is_err());
    }

    #[test]
    fn devices_and_jobs_dont_touch_each_other() {
        // A devices-only file leaves jobs at their defaults.
        let devices_only = "devices:\n  capabilities: lan\n  agents: agt_a\n";
        assert_eq!(parse_jobs(devices_only).unwrap(), None);
        assert_eq!(jobs_from(Path::new("/c"), devices_only, Ok(())).unwrap(), Jobs::default());
        // A jobs-only file leaves devices off.
        let jobs_only = "jobs:\n  kinds: command\n";
        assert!(parse(jobs_only).unwrap().is_none());
        // A mistake in one section doesn't change the other.
        let bad_devices = "devices:\n  capabilites: lan\njobs:\n  kinds: command\n";
        assert!(parse(bad_devices).is_err());
        assert_eq!(parse_jobs(bad_devices).unwrap().unwrap().kinds, Some(set(&["command"])));
        let bad_jobs = "devices:\n  capabilities: lan\njobs:\n  kinds: comand\n";
        assert!(parse_jobs(bad_jobs).is_err());
        assert!(parse(bad_jobs).unwrap().capabilities.contains("lan"));
    }

    #[test]
    fn a_jobs_section_the_node_cant_use_stops_every_job() {
        let untrusted = || Err("/c isn't owned by root, so the node can't trust it (sudo chown root:wheel it)".to_string());
        // Untrusted with job limits in it: no jobs, and why.
        let why = jobs_from(Path::new("/c"), "jobs:\n  kinds: command\n", untrusted()).unwrap_err();
        assert!(why.contains("isn't owned by root") && why.contains("runs no jobs"));
        // Untrusted without a jobs: section: nothing to enforce, so the defaults (it can't be used to stop jobs either).
        assert_eq!(jobs_from(Path::new("/c"), "devices: none\n", untrusted()).unwrap(), Jobs::default());
        // A mistake: no jobs.
        assert!(jobs_from(Path::new("/c"), "jobs:\n  kinds: everything\n", Ok(())).unwrap_err().contains("has a mistake"));
    }

    #[test]
    fn a_missing_file_means_no_devices() {
        std::env::set_var("PAVILION_CEILING", "/nonexistent/pavilion-ceiling");
        let (c, j, line) = (load(), load_jobs(), status_line());
        std::env::remove_var("PAVILION_CEILING");
        assert!(c.devices.is_none() && c.problem.is_none());
        assert_eq!(j, Ok(Jobs::default()));
        println!("{line}");
        assert!(line.starts_with("ceiling (no file at /nonexistent/pavilion-ceiling): job kinds: all · images: any"));
        assert!(line.contains(NETWORK) && line.ends_with("devices: none"));
    }
}
