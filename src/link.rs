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
    // The owner's swap rule for this machine (config.json `guard`): anything set aside is said once, here.
    for p in guard::SwapRule::configured().problems { eprintln!("guard: config.json: {p}"); }
    let swept = sandbox::sweep().await;
    if !swept.is_empty() { eprintln!("stopped {} sandbox(es) left over from an earlier run: {}", swept.len(), swept.join(", ")); }
    // Stopping the node (Ctrl-C, or a service stop) removes its sandboxes, warm ones included.
    tokio::spawn(async {
        #[cfg(unix)]
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("signal handler");
        #[cfg(unix)]
        tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = term.recv() => {} }
        #[cfg(windows)]
        crate::platform::windows::wait_for_stop().await;
        crate::media::kill_running();
        let n = sandbox::sweep().await.len();
        eprintln!("stopping: removed {n} sandbox(es)");
        std::process::exit(0);
    });
    // Media jobs come over HTTP, alongside the socket (docs/MEDIA.md): one at a time, while the guard allows.
    if let Err(e) = crate::media::store::ensure_attached() { eprintln!("models: {e}"); }
    tokio::spawn(crate::media::run_loop());
    // The host role (roles.rs): the Steward and project orchestrators in long-lived sandboxes, when an owner chose this machine.
    tokio::spawn(crate::roles::run_loop());
    // Device actions (docs/DEVICES.md): the inbox is polled as a fallback for socket messages, and the ceiling mirrored.
    tokio::spawn(crate::devices::run_loop());
    // A LAN broker's plugs and sensors as connected devices, this machine their gateway (bridge.rs, IOT.md step 6).
    tokio::spawn(crate::bridge::run_loop());
    // macOS's "about to sleep" notice becomes `machine.sleep` on the link (platform/sleep.rs, docs/MODEL-ACCOUNTS.md §7.3).
    crate::platform::sleep::watch();
    let running: Arc<Mutex<HashMap<String, Running>>> = Arc::default();
    let mut backoff = 1u64;
    loop {
        match session(running.clone()).await {
            Ok(()) => backoff = 1,
            Err(e) => eprintln!("link: {e}"),
        }
        // A model call's frames go on the socket that is gone: stop them (the Gate has failed them already).
        crate::relay::cancel_all("machine_offline", "the machine's link dropped");
        crate::roles::socket_down(); // host renewals go back to HTTP until the socket is up again
        crate::live::socket_down();
        crate::platform::sleep::link_down();
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
    crate::roles::nudge(); // renew host roles at once after a reconnect

    tx.send(Message::text(json!({ "t": "hello", "lastSeq": st.last_seq }).to_string())).await?;
    let send_inventory = |x: &Exposure| { let x = exposure_json(x); async move { let mut inv = crate::inventory::collect().await; inv["sandbox_exposure"] = x; json!({ "t": "inventory", "inventory": inv }).to_string() } };
    // Report what this machine is first, then check what its sandboxes can reach. No jobs until that check is clean.
    tx.send(Message::text(send_inventory(&Exposure::default()).await)).await?;
    let mut exposure = check_exposure().await;
    tx.send(Message::text(send_inventory(&exposure).await)).await?;
    let mut recheck = tokio::time::interval(Duration::from_secs(60));
    // Media models change when one is verified, added or its drive comes and goes, and with the loaded model: checked
    // every 15 s, sent only when something changed.
    let mut media_check = tokio::time::interval(Duration::from_secs(15));
    crate::media::inventory_changed();
    let mut reap = tokio::time::interval(Duration::from_secs(30));
    // The full record again every 15 minutes (docs/WORK-ROUTING.md §4): power and simulators change without an event.
    let mut full = tokio::time::interval(Duration::from_secs(900));
    full.tick().await;
    recheck.tick().await;

    // Everything that wants to talk to the pavilion goes through one channel.
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Value>();
    // The host role renews on this socket rather than posting every 30 s (docs/COSTS.md §5, finding 4).
    crate::roles::socket_up(out_tx.clone());
    crate::live::socket_up(out_tx.clone()); // the live line and model limits (live.rs, docs/WORK-ROUTING.md §4, §8)
    crate::platform::sleep::link_up(out_tx.clone());
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
                if crate::devices::incoming(&v) {
                    // a device action: checked, asked and done in devices/ (one at a time)
                } else if v["t"] == "event" && v["event"]["t"] == "job" {
                    handle_job(&mut st, &v["event"], &running, &out_tx, last_level, &exposure).await;
                } else if v["t"] == "job.stop" {
                    // The pavilion paused or cancelled this job (a model limit, WORK-ROUTING §8): the machine is free at once.
                    // Only a job this node started, by its id; it then reports it like any stopped job.
                    if let Some(job) = v["job"].as_str().filter(|j| j.len() <= 40) {
                        if running.lock().await.contains_key(job) {
                            eprintln!("stopping {job}: {}", v["why"].as_str().unwrap_or("the pavilion asked").chars().take(120).collect::<String>());
                            let j = job.to_string(); tokio::spawn(async move { sandbox::stop(&j).await });
                        }
                    }
                } else if v["t"] == "host" {
                    crate::roles::nudge(); // a role changed, or work is waiting for one this machine holds
                } else if v["t"] == "host.roles" {
                    crate::roles::socket_answer(&v); // the answer to a renewal sent on this socket
                } else if v["t"] == "model.call" {
                    // A local model, used from elsewhere in the pavilion (relay.rs): checked, then streamed back as frames.
                    let cfg = crate::state::config();
                    let cx = crate::relay::Ctx { reg: crate::relay::global().clone(), pavilion_key: st.pavilion_key.clone(), pavilion: st.pavilion.clone(), machine: st.machine.clone(),
                        level: last_level, out: out_tx.clone(), bases: crate::relay::Bases::from_config(&cfg), settings: crate::relay::settings_from(&cfg), timing: Default::default() };
                    tokio::spawn(async move { crate::relay::handle(&v, cx).await });
                } else if v["t"] == "still.lease" {
                    // A glimpse asks for low-rate stills of an agent's screen (CONSOLE-REDESIGN §8 step 13). No sandbox here
                    // has a display yet (MACHINES §8 phase 2), so this node says so at once rather than staying silent.
                    // It never answers with the host's own screen (that is devices/, owner-only, with its preview).
                    if let Some(a) = still_answer(&v) { let _ = out_tx.send(a); }
                } else if v["t"] == "model.cancel" {
                    crate::relay::cancel(v["id"].as_str().unwrap_or_default(), v["reason"].as_str().map(|r| match r { "client-gone" => "the caller went away", "deadline" => "the call ran past its deadline", "stopped" => "the owner stopped it", _ => "cancelled" }).unwrap_or("cancelled"));
                }
            }
            Some(v) = out_rx.recv() => { tx.send(Message::text(v.to_string())).await?; }
            _ = ping.tick() => { tx.send(Message::text(r#"{"t":"ping"}"#)).await?; }
            _ = full.tick() => { tx.send(Message::text(send_inventory(&exposure).await)).await?; }
            _ = reap.tick() => { let n = sandbox::reap_warm(false).await; if n > 0 { eprintln!("removed {n} warm sandbox(es) idle past their time"); } }
            _ = media_check.tick() => {
                if crate::media::inventory_changed() { tx.send(Message::text(send_inventory(&exposure).await)).await?; }
            }
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
                let (lvl, why) = guard::level(&s, &guard::Limits::configured(&s), growth);
                if lvl != last_level {
                    eprintln!("guard: {:?} → {:?} ({why})", last_level, lvl);
                    tx.send(Message::text(json!({ "t": "pressure", "level": lvl, "why": why, "sample": s }).to_string())).await?;
                    last_level = lvl;
                }
                crate::media::set_level(lvl);
                crate::relay::on_level(lvl);
                shed(lvl, &why, &running).await;
                // The live line, when it is due (live.rs): what the router reads to place work here.
                let (n, used) = { let r = running.lock().await; (r.len(), r.values().map(|x| x.memory_mib).sum::<u64>()) };
                let used = used + sandbox::warm_idle_memory_mib().await + crate::roles::memory_mib();
                let line = crate::live::line(&s, &guard::Limits::defaults(&s), lvl, n, used, crate::media::loaded_model(), sandbox::warm_keys().await, crate::accounts::current());
                if let Some(m) = crate::live::tick(line) { tx.send(Message::text(m.to_string())).await?; }
            }
        }
    }
}

/// The answer to a keyframe lease (`still.lease`, gate/src/stills.ts): `still.none`, with why, for the lease and agent it
/// names. A sandbox display and its capture are MACHINES §8 phase 2; until then there is never a picture to send.
fn still_answer(v: &Value) -> Option<Value> {
    let lease = v["lease"].as_str().filter(|s| s.len() <= 40)?;
    let agent = v["agent"].as_str().filter(|s| s.len() <= 80)?;
    Some(json!({ "t": "still.none", "lease": lease, "agent": agent,
        "why": "this machine's sandboxes have no display yet (MACHINES §8 phase 2): only the agent's terminal text exists" }))
}

#[cfg(test)]
mod still_tests {
    use super::*;
    #[test]
    fn a_lease_is_answered_with_none_for_its_lease_and_agent() {
        let a = still_answer(&json!({ "t": "still.lease", "lease": "lse_0123456789abcdef", "agent": "shop", "ttl_ms": 6000 })).unwrap();
        assert_eq!(a["t"], "still.none");
        assert_eq!(a["lease"], "lse_0123456789abcdef");
        assert_eq!(a["agent"], "shop");
        assert!(a["why"].as_str().unwrap().contains("phase 2"));
        assert!(still_answer(&json!({ "t": "still.lease", "agent": "shop" })).is_none());
        assert!(still_answer(&json!({ "t": "still.lease", "lease": "x".repeat(41), "agent": "shop" })).is_none());
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
    // The local ceiling's `jobs:` section (ceiling.rs), read once for this job: the kind first, the image once it's known.
    // A section the node can't use refuses every job, with why.
    let limits = crate::ceiling::load_jobs();
    if let Some(kind) = env["kind"].as_str().filter(|k| ["command", "agent", "cli"].contains(k)) {
        if let Err(why) = limits.as_ref().map_err(Clone::clone).and_then(|j| j.allows_kind(kind)) { report(&job, "refused", json!({ "note": why })); return; }
    }
    // Command jobs, agent jobs (agent.rs: Claude Code on a task branch), and a CLI connector's operation (cli.rs). Nothing else.
    let mut cli_job = None;
    let agent = match env["kind"].as_str() {
        Some("command") => None,
        Some("agent") => match crate::agent::validate(&env, now) { Ok(a) => Some(a), Err(why) => { report(&job, "refused", json!({ "note": why })); return; } },
        Some("cli") => match crate::cli::validate(&env, &crate::cli::configured_tools()) { Ok(c) => { cli_job = Some(c); None } Err(why) => { report(&job, "refused", json!({ "note": why })); return; } },
        _ => { report(&job, "refused", json!({ "note": "this node runs command, agent and cli jobs only" })); return; }
    };
    // The image the sandbox would actually run: the node's own for an agent job, the configured tool's for a cli job,
    // the job's for a command. Checked against the ceiling's image list (and always for a sane name).
    let image = match (&agent, &cli_job) {
        (Some(_), _) => crate::agent::image(),
        (_, Some(c)) => c.image.clone(),
        _ => env["image"].as_str().unwrap_or_default().to_string(),
    };
    if let Err(why) = limits.and_then(|j| j.allows_image(&image)) { report(&job, "refused", json!({ "note": why })); return; }

    if !exposure.open.is_empty() {
        report(&job, "refused", json!({ "note": format!("sandboxes on this machine can reach its own services ({}). Load the firewall rule: {}", exposure.open.join(", "), crate::platform::firewall_hint()) }));
        return;
    }
    if !exposure.checked {
        report(&job, "refused", json!({ "note": format!("couldn't check whether sandboxes can reach this machine's services: {}", exposure.error.clone().unwrap_or_else(|| "not checked yet".into())) }));
        return;
    }
    if let Some(a) = &agent {
        match crate::agent::image_for(a.harness).await {
            Some(_) => {}
            None if !crate::agent::ready().await => { report(&job, "refused", json!({ "note": format!("this machine has no agent image ({}); build it with node/images/dev/build.sh", crate::agent::image()) })); return; }
            None => { report(&job, "refused", json!({ "note": format!("this machine's agent image has no {} CLI; rebuild it with node/images/dev/build.sh", a.harness) })); return; }
        }
    }
    let memory_mib = cli_job.as_ref().map(|c| c.memory_mib).unwrap_or_else(|| agent.as_ref().map_or(env["memoryMiB"].as_u64().unwrap_or(1024), |a| a.memory_mib));
    let s = guard::sample();
    let used = (running.lock().await.values().map(|r| r.memory_mib).sum::<u64>() + sandbox::warm_idle_memory_mib().await + crate::roles::memory_mib()).max(sandbox::running_memory_mib().await);
    // A first pull unpacks the image; count 3 GiB of disk for it (we saw 2.2 GB for a 5 MB image).
    if let Err(why) = guard::admit(&s, &guard::Limits::defaults(&s), level, used, memory_mib, 3 * 1024) {
        report(&job, "refused", json!({ "note": why })); return;
    }
    let grants = crate::agent::grants_of(&env);
    let spec = sandbox::JobSpec {
        job: job.clone(), project: env["project"].as_str().unwrap_or("default").into(), image,
        cmd: env["cmd"].as_str().unwrap_or_default().into(), cpus: env["cpus"].as_u64().unwrap_or(2) as u32, memory_mib, timeout_s: env["timeoutS"].as_u64().unwrap_or(600), grants, env: vec![],
        warm: env["warm"]["key"].as_str().filter(|k| k.len() <= 200).map(|k| sandbox::Warm { key: k.to_string(), keep_s: env["warm"]["keepS"].as_u64().unwrap_or(600) }),
        slot: None,
    };
    // An agent job on one of this machine's account slots takes the slot now: one job per slot at a time, whatever the
    // pavilion's lease says (accounts.rs). It is given back when the job ends, however it ends.
    let slot = agent.as_ref().and_then(|a| a.slot.clone());
    if let (Some(s), Some(a)) = (&slot, &agent) { if let Err(why) = crate::accounts::take(s, &job, a.harness) { report(&job, "refused", json!({ "note": why })); return; } }
    running.lock().await.insert(job.clone(), Running { started_ms: now, memory_mib });
    report(&job, "running", json!({}));
    let (gate, pavilion, out, running) = (st.gate.clone(), st.pavilion.clone(), out.clone(), running.clone());
    let key = match state::key() { Ok(k) => k, Err(e) => { report(&job, "failed", json!({ "note": e.to_string() })); return; } };
    if let Some(c) = cli_job {
        // A CLI connector's operation: its own sandbox, no network, an argument array (cli.rs).
        tokio::spawn(async move {
            let msg = crate::cli::run(c, &gate, &pavilion, key).await;
            running.lock().await.remove(&job);
            let _ = out.send(msg);
        });
        return;
    }
    tokio::spawn(async move {
        // An agent job also reports its result lines, parsed (summary, branch, diff stat, pushed), beside the output.
        let r = match agent {
            Some(a) => crate::agent::run(a, &gate, &pavilion, key).await.map(|(o, r)| (o, Some(r.to_json()))),
            None => sandbox::run(spec, &gate, &pavilion, key).await.map(|o| (o, None)),
        };
        if let Some(s) = &slot { crate::accounts::release(s, &job); }
        running.lock().await.remove(&job);
        let msg = match r {
            Ok((o, result)) => {
                let mut m = json!({ "t": "job", "job": job, "status": if o.exit_code == 0 { "done" } else { "failed" }, "exitCode": o.exit_code, "output": o.output, "note": o.note });
                if let Some(r) = result { m["result"] = r; }
                m
            }
            Err(e) => json!({ "t": "job", "job": job, "status": "failed", "note": e.to_string() }),
        };
        let _ = out.send(msg);
    });
}
