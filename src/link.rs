//! The link to the pavilion: one WebSocket out (no open ports here), numbered events with resume, signed jobs,
//! and the resource guard running alongside.
use crate::guard::{self, Level};
use crate::sandbox;
use crate::signing::{signed_headers, unb64, verify_pavilion};
use crate::state::{self, State};
use anyhow::{anyhow, Result};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::tungstenite::{client::IntoClientRequest, Message};

struct Running { started_ms: u64, memory_mib: u64 }

/// What a sandbox could reach on this machine at the last probe. Jobs are refused unless it's empty.
#[derive(Clone, Default)]
struct Exposure { ports: Vec<u16>, open: Vec<String>, checked: bool, error: Option<String> }

async fn check_exposure() -> Exposure {
    let ports = sandbox::exposed_ports();
    match sandbox::probe_exposure().await {
        Ok(open) => { if !open.is_empty() { eprintln!("exposure: sandboxes can reach {}", open.join(", ")); } Exposure { ports, open, checked: true, error: None } }
        Err(e) => { eprintln!("exposure probe: {e}"); Exposure { ports, open: vec![], checked: false, error: Some(e.to_string()) } }
    }
}
fn exposure_json(x: &Exposure) -> Value { json!({ "checked": x.checked, "open": x.open, "listening": x.ports, "error": x.error }) }

pub async fn run_forever() -> Result<()> {
    let swept = sandbox::sweep().await;
    if !swept.is_empty() { eprintln!("stopped {} sandbox(es) left over from an earlier run: {}", swept.len(), swept.join(", ")); }
    // Stopping the node (Ctrl-C, or a service stop) removes its sandboxes, warm ones included.
    tokio::spawn(async {
        #[cfg(unix)]
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("signal handler");
        #[cfg(unix)]
        tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = term.recv() => {} }
        let n = sandbox::sweep().await.len();
        eprintln!("stopping: removed {n} sandbox(es)");
        std::process::exit(0);
    });
    let running: Arc<Mutex<HashMap<String, Running>>> = Arc::default();
    let mut backoff = 1u64;
    loop {
        match session(running.clone()).await {
            Ok(()) => backoff = 1,
            Err(e) => eprintln!("link: {e}"),
        }
        let jitter = rand::random::<u64>() % 1000;
        tokio::time::sleep(Duration::from_millis(backoff * 1000 + jitter)).await;
        backoff = (backoff * 2).min(60);
    }
}

async fn session(running: Arc<Mutex<HashMap<String, Running>>>) -> Result<()> {
    let st = state::load()?;
    let key = state::key()?;
    let url = reqwest::Url::parse(&st.gate)?;
    let host = url.host_str().unwrap_or_default().to_string() + &url.port().map(|p| format!(":{p}")).unwrap_or_default();
    let path = format!("/p/{}/node/socket", st.pavilion);
    let ws_url = format!("{}{}", st.gate.replacen("https://", "wss://", 1).replacen("http://", "ws://", 1).trim_end_matches('/'), path);
    let mut req = ws_url.into_client_request()?;
    for (k, v) in signed_headers(&key, &host, "GET", &path, b"") { req.headers_mut().insert(k, v.parse()?); }
    let (ws, _) = tokio_tungstenite::connect_async(req).await.map_err(|e| anyhow!("connecting: {e}"))?;
    let (mut tx, mut rx) = ws.split();
    eprintln!("connected to {} as {} ({})", st.pavilion, st.name, st.machine);

    tx.send(Message::text(json!({ "t": "hello", "lastSeq": st.last_seq }).to_string())).await?;
    let send_inventory = |x: &Exposure| { let x = exposure_json(x); async move { let mut inv = crate::inventory::collect().await; inv["sandbox_exposure"] = x; json!({ "t": "inventory", "inventory": inv }).to_string() } };
    // Report what this machine is first, then check what its sandboxes can reach. No jobs until that check is clean.
    tx.send(Message::text(send_inventory(&Exposure::default()).await)).await?;
    let mut exposure = check_exposure().await;
    tx.send(Message::text(send_inventory(&exposure).await)).await?;
    let mut recheck = tokio::time::interval(Duration::from_secs(60));
    let mut reap = tokio::time::interval(Duration::from_secs(30));
    recheck.tick().await;

    // Everything that wants to talk to the pavilion goes through one channel.
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Value>();
    let mut ping = tokio::time::interval(Duration::from_secs(30));
    let mut tick = tokio::time::interval(Duration::from_secs(2));
    let mut watch = guard::Watch::default();
    let mut last_level = Level::Green;
    let mut st = st;

    loop {
        tokio::select! {
            m = rx.next() => {
                let Some(m) = m else { return Ok(()) };
                let m = m?;
                let Message::Text(t) = m else { if let Message::Close(_) = m { return Ok(()) } continue };
                let Ok(v) = serde_json::from_str::<Value>(&t) else { continue };
                if v["t"] == "event" && v["event"]["t"] == "job" {
                    handle_job(&mut st, &v["event"], &running, &out_tx, last_level, &exposure).await;
                }
            }
            Some(v) = out_rx.recv() => { tx.send(Message::text(v.to_string())).await?; }
            _ = ping.tick() => { tx.send(Message::text(r#"{"t":"ping"}"#)).await?; }
            _ = reap.tick() => { let n = sandbox::reap_warm(false).await; if n > 0 { eprintln!("removed {n} warm sandbox(es) idle past their time"); } }
            _ = recheck.tick() => {
                // Probe again when the set of listening ports changes (a new dev server, Screen Sharing turned on…).
                if sandbox::exposed_ports() != exposure.ports && running.lock().await.is_empty() {
                    exposure = check_exposure().await;
                    tx.send(Message::text(send_inventory(&exposure).await)).await?;
                }
            }
            _ = tick.tick() => {
                let s = guard::sample();
                let growth = watch.push(s.clone());
                let (lvl, why) = guard::level(&s, &guard::Limits::defaults(&s), growth);
                if lvl != last_level {
                    eprintln!("guard: {:?} → {:?} ({why})", last_level, lvl);
                    tx.send(Message::text(json!({ "t": "pressure", "level": lvl, "why": why, "sample": s }).to_string())).await?;
                    last_level = lvl;
                }
                shed(lvl, &why, &running).await;
            }
        }
    }
}

/// Red: stop the newest job (least work lost), one at a time. Critical: stop them all. Never anything the node didn't start.
async fn shed(lvl: Level, why: &str, running: &Arc<Mutex<HashMap<String, Running>>>) {
    if lvl < Level::Amber { return; }
    // Idle sandboxes go first: warm ones kept for a task's next step give their memory back before any job is stopped.
    let freed = sandbox::reap_warm(true).await;
    if freed > 0 { eprintln!("guard: removed {freed} idle warm sandbox(es) ({why})"); }
    if lvl < Level::Red { return; }
    let victims: Vec<String> = {
        let r = running.lock().await;
        let mut v: Vec<(&String, &Running)> = r.iter().collect();
        v.sort_by_key(|(_, x)| std::cmp::Reverse((x.started_ms, x.memory_mib)));
        if lvl == Level::Critical { v.iter().map(|(k, _)| (*k).clone()).collect() } else { v.first().map(|(k, _)| vec![(*k).clone()]).unwrap_or_default() }
    };
    for job in victims { eprintln!("guard: stopping {job} ({why})"); sandbox::stop(&job).await; }
}

async fn handle_job(st: &mut State, ev: &Value, running: &Arc<Mutex<HashMap<String, Running>>>, out: &mpsc::UnboundedSender<Value>, level: Level, exposure: &Exposure) {
    let (payload, sig) = (ev["payload"].as_str().unwrap_or_default(), ev["sig"].as_str().unwrap_or_default());
    let report = |job: &str, status: &str, extra: Value| { let mut m = json!({ "t": "job", "job": job, "status": status }); if let (Some(o), Some(e)) = (m.as_object_mut(), extra.as_object()) { o.extend(e.clone()); } let _ = out.send(m); };
    // Signed by the pavilion's key pinned when joining; for this machine; newer than anything seen; not expired.
    if !verify_pavilion(&st.pavilion_key, payload, sig) { eprintln!("refused a job with a bad signature"); return; }
    let Ok(env) = unb64(payload).map_err(|e| e.to_string()).and_then(|b| serde_json::from_slice::<Value>(&b).map_err(|e| e.to_string())) else { return };
    let job = env["job"].as_str().unwrap_or_default().to_string();
    let seq = env["seq"].as_u64().unwrap_or(0);
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
    if env["machine"] != st.machine.as_str() { report(&job, "refused", json!({ "note": "meant for another machine" })); return; }
    if seq <= st.last_seq { return; } // already handled (replayed on reconnect)
    st.last_seq = seq;
    let _ = state::save(st);
    if now > env["expiresAt"].as_u64().unwrap_or(0) { report(&job, "refused", json!({ "note": "the job expired before it arrived" })); return; }
    if env["kind"] != "command" { report(&job, "refused", json!({ "note": "phase 0 runs command jobs only" })); return; }

    if !exposure.open.is_empty() {
        report(&job, "refused", json!({ "note": format!("sandboxes on this machine can reach its own services ({}). Load the firewall rule: sudo node/pf/install.sh", exposure.open.join(", ")) }));
        return;
    }
    if !exposure.checked {
        report(&job, "refused", json!({ "note": format!("couldn't check whether sandboxes can reach this machine's services: {}", exposure.error.clone().unwrap_or_else(|| "not checked yet".into())) }));
        return;
    }
    let memory_mib = env["memoryMiB"].as_u64().unwrap_or(1024);
    let s = guard::sample();
    let used = (running.lock().await.values().map(|r| r.memory_mib).sum::<u64>() + sandbox::warm_idle_memory_mib().await).max(sandbox::running_memory_mib().await);
    // A first pull unpacks the image; count 3 GiB of disk for it (we saw 2.2 GB for a 5 MB image).
    if let Err(why) = guard::admit(&s, &guard::Limits::defaults(&s), level, used, memory_mib, 3 * 1024) {
        report(&job, "refused", json!({ "note": why })); return;
    }
    let grants = env["grants"].as_array().cloned().unwrap_or_default().into_iter().filter_map(|g| Some((
        g["secret"].as_str()?.to_string(),
        crate::broker::Grant { id: g["id"].as_str()?.to_string(), hosts: g["hosts"].as_array()?.iter().filter_map(|h| h.as_str().map(String::from)).collect() },
    ))).collect();
    let spec = sandbox::JobSpec {
        job: job.clone(), project: env["project"].as_str().unwrap_or("default").into(), image: env["image"].as_str().unwrap_or_default().into(),
        cmd: env["cmd"].as_str().unwrap_or_default().into(), cpus: env["cpus"].as_u64().unwrap_or(2) as u32, memory_mib, timeout_s: env["timeoutS"].as_u64().unwrap_or(600), grants,
        warm: env["warm"]["key"].as_str().filter(|k| k.len() <= 200).map(|k| sandbox::Warm { key: k.to_string(), keep_s: env["warm"]["keepS"].as_u64().unwrap_or(600) }),
    };
    running.lock().await.insert(job.clone(), Running { started_ms: now, memory_mib });
    report(&job, "running", json!({}));
    let (gate, pavilion, out, running) = (st.gate.clone(), st.pavilion.clone(), out.clone(), running.clone());
    let key = match state::key() { Ok(k) => k, Err(e) => { report(&job, "failed", json!({ "note": e.to_string() })); return; } };
    tokio::spawn(async move {
        let r = sandbox::run(spec, &gate, &pavilion, key).await;
        running.lock().await.remove(&job);
        let msg = match r {
            Ok(o) => json!({ "t": "job", "job": job, "status": if o.exit_code == 0 { "done" } else { "failed" }, "exitCode": o.exit_code, "output": o.output, "note": o.note }),
            Err(e) => json!({ "t": "job", "job": job, "status": "failed", "note": e.to_string() }),
        };
        let _ = out.send(msg);
    });
}
