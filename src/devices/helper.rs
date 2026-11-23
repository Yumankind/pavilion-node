//! macOS: the Swift helper inside `Pavilion Node.app` (node/macos/helper/main.swift) does what needs Apple's
//! frameworks: AVFoundation (camera, mic), ScreenCaptureKit, CoreLocation, AVSpeechSynthesizer, LocalAuthentication
//! and the windows the person answers. Bluetooth and Bonjour stay in Rust (caps.rs).
//!
//! One helper process per request, so a camera is never left open between actions. The request is one typed JSON
//! line on stdin (`op` is one of a fixed list; there is no "run this" request) and the answer is one JSON line on
//! stdout. Captures are written to a private folder the node names, read back, and removed.
//!
//! Why a helper and not `objc2`: these frameworks are delegate- and async-heavy (capture sessions, ScreenCaptureKit's
//! async API, LAContext, CLLocationManager, AppKit windows on the main thread), which is a few lines of Swift each and
//! hundreds of unsafe lines through bindings; a separate process also keeps AppKit's main-thread rules out of the
//! node's tokio runtime. The helper lives in the same signed bundle, so macOS asks for permissions once, for
//! "Pavilion Node".
use super::caps::{round_position, Op, Output};
use super::{Ask, Decision, Preview};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub const APP_NAME: &str = "Pavilion Node.app";
const HELPER: &str = "pavilion-devices";

/// Where the app is installed (or being built), first match: next to this binary, ~/Applications, /Applications.
pub fn app_path() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    // …/Pavilion Node.app/Contents/MacOS/pavilion-node
    if let Some(app) = exe.parent().and_then(|p| p.parent()).and_then(|p| p.parent()).filter(|p| p.extension().map_or(false, |e| e == "app")) { return Some(app.to_path_buf()); }
    let home = std::env::var("HOME").unwrap_or_default();
    [PathBuf::from(&home).join("Applications").join(APP_NAME), PathBuf::from("/Applications").join(APP_NAME)].into_iter().find(|p| p.join("Contents/MacOS").join(HELPER).exists())
}
pub fn helper_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("PAVILION_DEVICES_HELPER") { return Some(PathBuf::from(p)); }
    app_path().map(|a| a.join("Contents/MacOS").join(HELPER)).filter(|p| p.exists())
}
pub fn app_label() -> String { app_path().map(|p| p.display().to_string()).unwrap_or_else(|| "Pavilion Node (not installed)".into()) }

/// Whether this process was started by launchd (the LaunchAgent, or `open`), so macOS attributes permissions to the
/// app rather than to the Terminal it was typed in.
fn launched_by_launchd() -> bool { unsafe { libc::getppid() == 1 } }

/// `pavilion-node devices scan …` / `test …` typed in Terminal: run it as the app, so macOS asks for (and remembers)
/// Bluetooth, Local Network, camera… for "Pavilion Node", not for Terminal. Returns true if it ran that way.
pub fn delegate_to_app(args: &[String]) -> anyhow::Result<bool> {
    if launched_by_launchd() || std::env::var("PAVILION_IN_TERMINAL").is_ok() { return Ok(false); }
    let Some(app) = app_path() else { return Ok(false) };
    let dir = super::dir().join("run");
    std::fs::create_dir_all(&dir)?;
    let (out, err) = (dir.join("stdout"), dir.join("stderr"));
    let _ = std::fs::remove_file(&out);
    let _ = std::fs::remove_file(&err);
    eprintln!("(running inside {} so macOS asks for its permissions; set PAVILION_IN_TERMINAL=1 to run in this Terminal instead)", app.display());
    let st = std::process::Command::new("/usr/bin/open").args(["-W", "-n", "-g", "-a"]).arg(&app).arg("--stdout").arg(&out).arg("--stderr").arg(&err)
        .arg("--args").arg("devices").args(args).status()?;
    print!("{}", std::fs::read_to_string(&out).unwrap_or_default());
    eprint!("{}", std::fs::read_to_string(&err).unwrap_or_default());
    if !st.success() { anyhow::bail!("the app didn't run ({st})"); }
    Ok(true)
}

/// One request to the helper; its one answer. `ok: false` answers become errors.
pub async fn call(req: Value, timeout: Duration) -> Result<Value, String> {
    let path = helper_path().ok_or("Pavilion Node.app isn't installed (node/macos/build-app.sh), so this Mac can't ask or capture")?;
    let mut child = tokio::process::Command::new(&path).stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped())
        .env_clear().env("HOME", std::env::var("HOME").unwrap_or_default()).env("PATH", "/usr/bin:/bin").kill_on_drop(true)
        .spawn().map_err(|e| format!("starting the helper: {e}"))?;
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(format!("{req}\n").as_bytes()).await.map_err(|e| e.to_string())?;
    drop(stdin);
    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let work = async {
        let (mut o, mut e) = (String::new(), String::new());
        let _ = tokio::join!(stdout.read_to_string(&mut o), stderr.read_to_string(&mut e));
        let _ = child.wait().await;
        (o, e)
    };
    let (o, e) = tokio::time::timeout(timeout, work).await.map_err(|_| format!("the helper took longer than {} s", timeout.as_secs()))?;
    let v: Value = o.lines().rev().find_map(|l| serde_json::from_str(l).ok()).ok_or_else(|| format!("the helper gave no answer{}", if e.trim().is_empty() { String::new() } else { format!(": {}", e.trim().chars().take(300).collect::<String>()) }))?;
    if v["ok"] != true { return Err(v["error"].as_str().unwrap_or("the helper failed").to_string()); }
    Ok(v)
}

fn scratch(ext: &str) -> Result<PathBuf, String> {
    let d = super::dir().join("capture");
    std::fs::create_dir_all(&d).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    { use std::os::unix::fs::PermissionsExt; let _ = std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)); }
    Ok(d.join(format!("{}.{ext}", crate::signing::random_b64(12))))
}

async fn capture(req: Value, ext: &str, ctype: &str, timeout: Duration) -> Result<Output, String> {
    let out = scratch(ext)?;
    let mut req = req;
    req["out"] = json!(out.to_string_lossy());
    let r = call(req, timeout).await;
    let bytes = std::fs::read(&out);
    let _ = std::fs::remove_file(&out);
    r?;
    let bytes = bytes.map_err(|e| format!("the helper wrote nothing: {e}"))?;
    Ok(Output::Bytes { ctype: ctype.to_string(), bytes })
}

pub async fn run(op: &Op, asset: Option<Vec<u8>>) -> Result<Output, String> {
    let t = op.budget();
    match op {
        Op::CameraSnapshot { camera, max_px } => capture(json!({ "op": "camera_snapshot", "camera": camera, "max_px": max_px }), "jpg", "image/jpeg", t).await,
        Op::CameraClip { camera, seconds } => capture(json!({ "op": "camera_clip", "camera": camera, "seconds": seconds }), "mp4", "video/mp4", t).await,
        Op::RecordAudio { seconds } => capture(json!({ "op": "record_audio", "seconds": seconds }), "m4a", "audio/mp4", t).await,
        Op::ScreenCapture => capture(json!({ "op": "screen_capture" }), "png", "image/png", t).await,
        Op::Location { accuracy_m } => {
            let v = call(json!({ "op": "location", "accuracy_m": accuracy_m }), t).await?;
            let (lat, lon) = (v["lat"].as_f64().ok_or("no latitude")?, v["lon"].as_f64().ok_or("no longitude")?);
            let (lat, lon) = round_position(lat, lon, *accuracy_m);
            let acc = v["accuracy_m"].as_f64().unwrap_or(0.0).max(*accuracy_m as f64).round();
            Ok(Output::Json(json!({ "lat": (lat * 1e6).round() / 1e6, "lon": (lon * 1e6).round() / 1e6, "accuracy_m": acc, "at": super::now() })))
        }
        Op::PlayAudio { text, .. } => {
            let mut req = json!({ "op": "play_audio" });
            if let Some(t) = text { req["text"] = json!(t); }
            let tmp = match asset { Some(b) => { let p = scratch("audio")?; std::fs::write(&p, b).map_err(|e| e.to_string())?; req["path"] = json!(p.to_string_lossy()); Some(p) } None => None };
            let r = call(req, t).await;
            if let Some(p) = tmp { let _ = std::fs::remove_file(p); }
            r.map(|_| Output::Json(json!({ "done": true })))
        }
        _ => Err("not a helper operation".into()),
    }
}

/// The window the person answers, then Touch ID or the login password for presence actions.
pub async fn ask(a: &Ask) -> Result<Decision, String> {
    let left = a.expires_at.saturating_sub(super::now());
    if left == 0 { return Ok(Decision::NoAnswer); }
    let v = call(json!({ "op": "ask", "text": a.text, "reason": a.reason, "agent": a.agent, "device": a.device, "detail": a.detail, "presence": a.presence, "seconds": left }),
        Duration::from_secs(left + 60)).await?;
    Ok(match v["decision"].as_str() { Some("allow") if !a.presence || v["presence"] == true => Decision::Allow, Some("allow") | Some("deny") => Decision::Deny, _ => Decision::NoAnswer })
}

pub async fn preview(p: &Preview) -> Result<bool, String> {
    let v = call(json!({ "op": "preview", "kind": p.kind, "path": p.path.as_ref().map(|x| x.to_string_lossy().to_string()), "text": p.text, "seconds": p.seconds }), Duration::from_secs(p.seconds as u64 + 120)).await?;
    Ok(v["send"] == true)
}

/// What this Mac has granted the app, read without asking (no prompts).
pub async fn permissions() -> Result<Value, String> {
    let v = call(json!({ "op": "permissions" }), Duration::from_secs(10)).await?;
    Ok(v["permissions"].clone())
}
