//! The live line and model limits (docs/WORK-ROUTING.md §4, §8). Both go on the socket the machine already holds.
//!
//! **The live line** is what the pavilion's router reads to place work: guard level, memory a new sandbox can have
//! now, slots, free memory and disk, what is running, the loaded model, the warm sandboxes, and this machine's account
//! slots with their states (accounts.rs: labels and states only, never a credential). It is sent when it changes
//! in a way that matters, and at least once a minute; a host renewal carries it instead when one falls due first (one
//! message, not two). The Gate stops routing to a machine whose last line is 90 seconds old. A message on an open
//! socket bills at a twentieth of a request, and a line every few seconds would keep the pavilion's object awake all
//! day, so nothing here runs on a timer of its own: the guard's 2-second tick decides whether a line is due.
//!
//! **A model limit** is seen by the broker on the way back from the Gate (the provider's status and rate-limit headers),
//! never by reading a credential: `{"t":"limit", job, host, status, retry_after_s, reset_at_s, rejected}`, plus `slot`
//! when the call went out on one of this machine's account slots (the slot is parked here too). The pavilion
//! pauses the item instead of failing it, and asks this node to stop the job (`job.stop`) so the machine is free.
use serde_json::{json, Value};
use std::sync::Mutex;
use tokio::sync::mpsc;

/// The socket's outgoing channel while it is up (set by link.rs), for lines and limits sent from anywhere.
static SOCKET: Mutex<Option<mpsc::UnboundedSender<Value>>> = Mutex::new(None);
/// The last line sent, and when (ms since 1970).
static SENT: Mutex<Option<(u64, Value)>> = Mutex::new(None);
/// The latest line computed, for a host renewal to carry.
static CURRENT: Mutex<Option<Value>> = Mutex::new(None);

/// Sent at least this often while nothing changes. The Gate's staleness rule is 90 s.
pub const KEEPALIVE_MS: u64 = 60_000;
/// Changes closer together than this wait for the next tick (a burst of job starts is one line).
pub const MIN_GAP_MS: u64 = 5_000;
/// Free memory or disk moving by this much is a change that matters.
const MEM_STEP_MIB: u64 = 512;
const DISK_STEP_MIB: u64 = 1024;

pub fn socket_up(tx: mpsc::UnboundedSender<Value>) { *SOCKET.lock().unwrap() = Some(tx); *SENT.lock().unwrap() = None; }
pub fn socket_down() { *SOCKET.lock().unwrap() = None; *CURRENT.lock().unwrap() = None; }

/// What the router needs, from one guard sample. `used_mib` is what this node's sandboxes hold now.
pub fn line(s: &crate::guard::Sample, l: &crate::guard::Limits, level: crate::guard::Level, running: usize, used_mib: u64, loaded: Option<String>, warm: Vec<String>, accounts: Value) -> Value {
    let budget = l.vm_budget_mib(s).saturating_sub(used_mib);
    let vm_free = crate::guard::slots_now(s, l, 1, 0).min(budget);
    json!({
        "level": level, "vm_free_mib": vm_free,
        "small_now": crate::guard::slots_now(s, l, 1024, 0).min(budget / 1024), "large_now": crate::guard::slots_now(s, l, 3072, 0).min(budget / 3072),
        "memory_free_mib": s.mem_total_mib * s.mem_free_pct as u64 / 100, "disk_free_mib": s.disk_free_mib,
        "running": running, "macos_vms": 0, "loaded_model": loaded, "warm": warm, "accounts": accounts,
    })
}

/// Whether a line is due: the first on this socket, a change that matters, or a minute since the last one.
pub fn due(prev: Option<&(u64, Value)>, line: &Value, now: u64) -> bool {
    let Some((at, was)) = prev else { return true };
    if now.saturating_sub(*at) >= KEEPALIVE_MS { return true; }
    if now.saturating_sub(*at) < MIN_GAP_MS { return false; }
    let moved = |k: &str, step: u64| was[k].as_u64().unwrap_or(0).abs_diff(line[k].as_u64().unwrap_or(0)) >= step;
    // A slot signed in, taken, limited or freed is news at once: the router leases slots on what this says. Its token
    // count (WORK-ROUTING §12) is not: it rides on the next line, so a running turn doesn't send one every 5 seconds.
    let slots = |v: &Value| -> Value { v["accounts"].as_array().map(|a| a.iter().map(|s| { let mut s = s.clone(); if let Some(o) = s.as_object_mut() { o.remove("used_today"); o.remove("used_day"); } s }).collect()).unwrap_or(Value::Null) };
    ["level", "small_now", "large_now", "running", "macos_vms", "loaded_model", "warm"].iter().any(|k| was[*k] != line[*k]) || slots(was) != slots(line)
        || moved("vm_free_mib", MEM_STEP_MIB) || moved("disk_free_mib", DISK_STEP_MIB)
}

fn now_ms() -> u64 { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0) }

/// Called on the guard's tick with the line it just computed: kept for a renewal, and the message to send if one is due.
pub fn tick(line: Value) -> Option<Value> {
    let now = now_ms();
    *CURRENT.lock().unwrap() = Some(line.clone());
    let mut sent = SENT.lock().unwrap();
    if !due(sent.as_ref(), &line, now) { return None; }
    *sent = Some((now, line.clone()));
    Some(json!({ "t": "live", "live": line }))
}

/// For a host renewal: the latest line, which then counts as sent (a renewal every 30 s keeps the line fresh too).
pub fn for_renewal() -> Option<Value> {
    let line = CURRENT.lock().unwrap().clone()?;
    *SENT.lock().unwrap() = Some((now_ms(), line.clone()));
    Some(line)
}

/// A model limit, from a response's status and headers: 429 or 402, or Anthropic's unified status `rejected`. Only the
/// provider's own words about its limit are read; never a body, never a credential.
pub fn limit_from<'a>(status: u16, headers: impl Iterator<Item = (&'a str, &'a str)>) -> Option<Value> {
    let (mut retry, mut reset, mut rejected) = (None::<u64>, None::<u64>, false);
    for (k, v) in headers {
        match k.to_ascii_lowercase().as_str() {
            "retry-after" => retry = v.trim().parse::<u64>().ok(),
            "anthropic-ratelimit-unified-status" => rejected |= v.trim() == "rejected",
            "anthropic-ratelimit-unified-reset" => reset = v.trim().parse::<u64>().ok().or(reset),
            // Codex: when each window resets, in seconds since 1970 (codex-rs `codex-api/src/rate_limits.rs`, checked at
            // rust-v0.153.4); the later of the two windows a 429 names is the safe one. OpenAI's API: seconds to wait.
            "x-codex-primary-reset-at" | "x-codex-secondary-reset-at" => if let Ok(t) = v.trim().parse::<u64>() { reset = Some(reset.map_or(t, |r| r.max(t))) },
            "x-ratelimit-reset-requests" => if retry.is_none() { retry = v.trim().trim_end_matches('s').parse::<f64>().ok().map(|f| f.ceil() as u64) },
            _ => {}
        }
    }
    if status != 429 && status != 402 && !rejected { return None; }
    Some(json!({ "status": status, "retry_after_s": retry, "reset_at_s": reset, "rejected": rejected }))
}

/// The broker saw a limit for this job's call to `host`: reported on the socket, once per response.
pub fn report_limit(job: &str, host: &str, mut l: Value) {
    if job.is_empty() { return; } // a hosted role's sandbox: its own lease rules, not the router's
    l["t"] = json!("limit"); l["job"] = json!(job); l["host"] = json!(host);
    if let Some(tx) = SOCKET.lock().unwrap().as_ref() { let _ = tx.send(l); }
}

/// Anything else the broker says about a job's calls (a slot's token budget, `{"t":"budget"}`): on the socket.
pub fn report(job: &str, mut m: Value) {
    if job.is_empty() { return; }
    m["job"] = json!(job);
    if let Some(tx) = SOCKET.lock().unwrap().as_ref() { let _ = tx.send(m); }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample() -> crate::guard::Sample {
        crate::guard::Sample { at_ms: 0, mem_total_mib: 16384, mem_free_pct: 60, pressure: 1, swap_total_mib: 0, swap_used_mib: 0, disk_free_mib: 100_000, disk_total_mib: 500_000,
            storage_missing: false, storage: "/".into() }
    }

    #[test]
    fn a_line_says_what_a_new_sandbox_can_have_now() {
        let s = sample(); let l = crate::guard::Limits::defaults(&s);
        let slots = json!([{ "slot": "slt_abc123", "harness": "claude-code", "label": "work", "state": "ready", "limited_until": null, "last_used_at": null, "last_limited_at": null }]);
        let v = line(&s, &l, crate::guard::Level::Green, 1, 2048, Some("flux-2-klein".into()), vec!["shop/tsk_abc".into()], slots.clone());
        assert_eq!(v["accounts"], slots);
        assert_eq!(v["level"], "green");
        let free = v["vm_free_mib"].as_u64().unwrap();
        assert!(free <= l.vm_budget_mib(&s) - 2048, "{v}");
        assert_eq!(v["small_now"].as_u64().unwrap(), free / 1024);
        assert_eq!(v["running"], 1);
        assert_eq!(v["warm"], json!(["shop/tsk_abc"]));
        assert!(v.get("memory_free_mib").is_some() && v.get("disk_free_mib").is_some());
    }

    #[test]
    fn a_line_is_due_on_a_change_that_matters_or_every_minute() {
        let a = json!({ "level": "green", "vm_free_mib": 4096, "small_now": 4, "running": 0, "disk_free_mib": 100_000, "warm": [] });
        assert!(due(None, &a, 1_000));
        let prev = (1_000u64, a.clone());
        assert!(!due(Some(&prev), &a, 30_000), "nothing changed");
        assert!(due(Some(&prev), &a, 1_000 + KEEPALIVE_MS), "the minute's line");
        // A slot's token count alone is not news (WORK-ROUTING §12): it rides on the next line.
        let mut t = a.clone(); t["accounts"] = json!([{ "slot": "slt_a", "state": "in-use", "used_today": 5 }]);
        let mut t2 = t.clone(); t2["accounts"][0]["used_today"] = json!(9000);
        assert!(!due(Some(&(0, t.clone())), &t2, 10_000));
        let mut t3 = t.clone(); t3["accounts"][0]["state"] = json!("limited");
        assert!(due(Some(&(0, t)), &t3, 10_000));
        let mut b = a.clone(); b["running"] = json!(1);
        assert!(due(Some(&prev), &b, 7_000), "a job started");
        assert!(!due(Some(&prev), &b, 3_000), "but not within 5 s of the last line");
        let mut c = a.clone(); c["vm_free_mib"] = json!(4096 - 100);
        assert!(!due(Some(&prev), &c, 7_000), "a little memory moving is not news");
        c["vm_free_mib"] = json!(4096 - 600);
        assert!(due(Some(&prev), &c, 7_000));
        let mut d = a.clone(); d["level"] = json!("amber");
        assert!(due(Some(&prev), &d, 7_000));
        let mut e = a.clone(); e["accounts"] = json!([{ "slot": "slt_abc123", "state": "limited" }]);
        assert!(due(Some(&prev), &e, 7_000), "a slot changing state is news");
    }

    #[test]
    fn limits_come_from_the_status_and_the_providers_own_headers() {
        let l = limit_from(429, [("Retry-After", "30"), ("content-type", "application/json")].into_iter()).unwrap();
        assert_eq!(l, json!({ "status": 429, "retry_after_s": 30, "reset_at_s": null, "rejected": false }));
        let l = limit_from(200, [("anthropic-ratelimit-unified-status", "rejected"), ("anthropic-ratelimit-unified-reset", "1763208000")].into_iter()).unwrap();
        assert_eq!(l["rejected"], true); assert_eq!(l["reset_at_s"], 1763208000u64);
        assert_eq!(limit_from(402, std::iter::empty()).unwrap()["status"], 402);
        assert!(limit_from(200, [("anthropic-ratelimit-unified-status", "allowed")].into_iter()).is_none());
        assert!(limit_from(500, std::iter::empty()).is_none(), "a server error is not a limit");
        let c = limit_from(429, [("x-codex-primary-used-percent", "100"), ("x-codex-primary-reset-at", "1763208000"), ("x-codex-secondary-reset-at", "1763290000")].into_iter()).unwrap();
        assert_eq!(c["reset_at_s"], 1763290000u64, "Codex's windows: the later reset");
        assert!(limit_from(200, [("x-codex-primary-reset-at", "1763208000")].into_iter()).is_none(), "a reset time alone is not a limit");
        assert_eq!(limit_from(429, [("x-ratelimit-reset-requests", "12.5s")].into_iter()).unwrap()["retry_after_s"], 13);
    }

    #[test]
    fn a_limit_goes_on_the_socket_with_its_job_and_host() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        socket_up(tx);
        report_limit("job_abc", "api.anthropic.com", limit_from(429, std::iter::empty()).unwrap());
        report_limit("", "api.anthropic.com", limit_from(429, std::iter::empty()).unwrap());
        let m = rx.try_recv().unwrap();
        assert_eq!((m["t"].as_str(), m["job"].as_str(), m["host"].as_str()), (Some("limit"), Some("job_abc"), Some("api.anthropic.com")));
        let mut l = limit_from(429, std::iter::empty()).unwrap(); l["slot"] = json!("slt_abc123");
        report_limit("job_abc", "api.anthropic.com", l);
        assert_eq!(rx.try_recv().unwrap()["slot"], "slt_abc123", "a slot's limit names the slot");
        assert!(rx.try_recv().is_err(), "a role's sandbox reports nothing");
        socket_down();
    }
}
