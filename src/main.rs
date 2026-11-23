//! pavilion-node: your own machine in a Cloud Pavilion (docs/MACHINES.md). Phase 0.
//!
//!   pavilion-node join [<CODE>|<link>]   the eight characters from Machines › Pair a machine (or its QR), or the link
//!                             from Machines › Add a machine; with neither, paste one when asked (kept out of shell
//!                             history). A link shows a 6-digit code to type in the console (onboard.rs, ONBOARDING.md §5)
//!   pavilion-node accounts [add claude|codex|gemini <label>|disable|enable|remove <label>]   your own plan kept on this
//!                             machine as a named slot; the pavilion sees the label, the provider and its state only
//!                             (accounts.rs, slot_auth.rs, WORK-ROUTING §9). Plan logins stay on your machine; the
//!                             pavilion's vault holds API keys only
//!   pavilion-node login claude|codex   the same as `accounts add` (it says so): the vault path for plan logins is
//!                             retired (onboard.rs, ONBOARDING §6)
//!   pavilion-node run         stay connected; run jobs in fresh sandboxes; guard memory and disk; host the Steward and orchestrators (roles.rs)
//!   pavilion-node inventory   print exactly what this machine reports
//!   pavilion-node guard       memory, disk, level and slots right now
//!   pavilion-node status      which pavilion this machine belongs to
//!   pavilion-node storage [folder]   where VM images and disks live, e.g. a folder on an external drive
//!   pavilion-node models …    the media model catalog, where models live, add and verify one (media/store.rs)
//!   pavilion-node wsl …       Windows: install, check or remove the WSL distro jobs run in (sandbox/wsl.rs)
//!   pavilion-node service …   Windows: start the node at logon (platform/windows.rs)
//!   pavilion-node project push|pull <project> <folder>   a project's files to and from the pavilion (project.rs)
//!   pavilion-node devices status|history|scan …   device actions on this computer (devices/, docs/DEVICES.md)
//!   pavilion-node bridge add <broker> … | code | status | run | remove   a LAN broker's plugs and sensors as connected
//!                             devices, with this machine as their gateway (bridge.rs, docs/IOT.md step 6)
mod accounts;
mod bridge;
mod mqtt_ws;
mod agent;
mod broker;
mod ceiling;
mod cli;
mod devices;
mod guard;
mod inventory;
mod link;
mod live;
mod media;
mod onboard;
mod platform;
mod project;
mod relay;
mod roles;
mod sandbox;
mod signing;
mod slot_auth;
mod state;

use anyhow::{anyhow, bail, Result};
use serde_json::{json, Value};
use signing::{b64, commit_to, join_code, key_id, random_b64, sha256, signed_headers, verify_member};
use std::time::Duration;

#[tokio::main]
async fn main() {
    let cmd = std::env::args().nth(1).unwrap_or_default();
    let r = match cmd.as_str() {
        "version" | "--version" | "-V" => { println!("pavilion-node {}", env!("CARGO_PKG_VERSION")); Ok(()) }
        "join" => onboard::join(&std::env::args().skip(2).collect::<Vec<_>>()).await,
        "login" => onboard::login(&std::env::args().skip(2).collect::<Vec<_>>()).await,
        "accounts" => accounts::cli(&std::env::args().skip(2).collect::<Vec<_>>()).await,
        "run" => { vm_storage_up(); link::run_forever().await }
        "inventory" => { println!("{}", serde_json::to_string_pretty(&inventory::collect().await).unwrap()); Ok(()) }
        "guard" => { guard_now(); Ok(()) }
        "storage" => storage(std::env::args().nth(2)).await,
        "exposure" => exposure().await,
        "models" => media::store::cli(&std::env::args().skip(2).collect::<Vec<_>>()).await,
        "project" => project::cli(&std::env::args().skip(2).collect::<Vec<_>>()).await,
        "devices" => devices::cli(&std::env::args().skip(2).collect::<Vec<_>>()).await,
        "bridge" => bridge::cli(&std::env::args().skip(2).collect::<Vec<_>>()).await,
        "cli-tools" => cli::cli(&std::env::args().skip(2).collect::<Vec<_>>()),
        "status" => state::load().map(|s| println!("{} · pavilion {} · machine {} · last event {}\n{}\n{}", s.name, s.pavilion, s.machine, s.last_seq, guard::SwapRule::configured().describe(), ceiling::status_line())),
        #[cfg(windows)]
        "wsl" => sandbox::wsl::cli(&std::env::args().skip(2).collect::<Vec<_>>()).await,
        #[cfg(windows)]
        "service" => platform::windows::service(&std::env::args().skip(2).collect::<Vec<_>>()),
        #[cfg(not(windows))]
        "wsl" | "service" => Err(anyhow!("`{cmd}` is for Windows")),
        _ => { eprintln!("usage: pavilion-node version | join [<CODE> [--gate <url>] | <link>] | login claude|codex | accounts [add claude <label>|disable|enable|remove <label>] | run | inventory | guard | status | storage [folder] | exposure | models [storage|add|verify] | project push|pull <project> <folder> | devices status|history|scan … | bridge add <broker>|code|status|run|remove | cli-tools [list|add|remove]{}",
            if cfg!(windows) { " | wsl [install <rootfs.tar>|status|remove] | service [install|uninstall|status]" } else { "" }); std::process::exit(2) }
    };
    if let Err(e) = r { eprintln!("error: {e:#}"); std::process::exit(1); }
}

fn guard_now() {
    let s = guard::sample();
    let l = guard::Limits::configured(&s);
    let (lvl, why) = guard::level(&s, &l, 0.0);
    println!("{}", serde_json::to_string_pretty(&json!({ "level": lvl, "why": why, "sample": s, "limits": l,
        "vm_budget_mib": l.vm_budget_mib(&s), "slots_1gib": guard::slots(&s, &l, 1024), "slots_3gib": guard::slots(&s, &l, 3072) })).unwrap());
}

/// Where VM images and disks live. With a folder: check the drive, move Apple container's data there, remember it.
/// On Windows: where the WSL distro's disk lives (platform/windows.rs).
#[cfg_attr(windows, allow(unreachable_code))]
async fn storage(path: Option<String>) -> Result<()> {
    let Some(path) = path else {
        let s = guard::sample();
        println!("VM storage: {} · {} GiB free of {} GiB{}", s.storage, s.disk_free_mib / 1024, s.disk_total_mib / 1024, if s.storage_missing { " · NOT MOUNTED" } else { "" });
        return Ok(());
    };
    #[cfg(windows)]
    return platform::windows::storage(&path).await;
    if !cfg!(target_os = "macos") { bail!("on Linux, set Podman's graphroot in storage.conf (phase 1)"); }
    let p = std::fs::canonicalize(&path).map_err(|_| anyhow!("{path} doesn't exist; make the folder first"))?;
    if !p.is_dir() { bail!("{} isn't a folder", p.display()); }
    let info = String::from_utf8_lossy(&std::process::Command::new("diskutil").arg("info").arg(&p).output()?.stdout).to_string();
    let field = |k: &str| info.lines().find(|l| l.trim_start().starts_with(k)).and_then(|l| l.split_once(':')).map(|(_, v)| v.trim().to_string()).unwrap_or_default();
    let (fs, encrypted, location) = (field("File System Personality"), field("FileVault").to_lowercase() == "yes" || field("Encrypted").to_lowercase() == "yes", field("Device Location"));
    println!("{} · {fs} · {} · {}", p.display(), if location.is_empty() { "location unknown".into() } else { location }, if encrypted { "encrypted" } else { "NOT encrypted" });
    if !fs.contains("APFS") { bail!("VM storage must be APFS (Apple container clones image files, which needs APFS); this is {fs}"); }
    if !encrypted { eprintln!("warning: this drive isn't encrypted. VM disks hold job workspaces; anyone who unplugs the drive can read them. Encrypt it in Disk Utility."); }
    let busy = String::from_utf8_lossy(&std::process::Command::new("container").args(["list", "--format", "json"]).output()?.stdout).contains("pavilion.job");
    if busy { bail!("jobs are running; stop the node (or wait) before moving VM storage"); }
    let root = p.join("pavilion-vms");
    std::fs::create_dir_all(&root)?;
    eprintln!("Restarting Apple container with its data in {} (images are downloaded again there)…", root.display());
    let _ = std::process::Command::new("container").args(["system", "stop"]).status();
    start_container_at(&root)?;
    state::set_config("vm_storage", json!(p.to_string_lossy()))?;
    let s = guard::sample();
    println!("VM storage is now {} · {} GiB free. The guard watches this drive, and stops every job if it's unplugged.", s.storage, s.disk_free_mib / 1024);
    Ok(())
}

/// Which of this machine's services a sandbox can reach. Anything but "none" means the firewall rule is missing.
async fn exposure() -> Result<()> {
    println!("listening beyond this machine: {:?}", sandbox::exposed_ports());
    let open = sandbox::probe_exposure().await?;
    if open.is_empty() { println!("a sandbox can reach none of them"); }
    else { println!("a sandbox CAN reach: {}\nLoad the firewall rule: {}", open.join(", "), platform::firewall_hint()); }
    Ok(())
}

async fn post(http: &reqwest::Client, gate: &str, host: &str, key: &ed25519_dalek::SigningKey, path: &str, body: &Value) -> Result<Value> {
    let bytes = serde_json::to_vec(body)?;
    let mut rb = http.post(format!("{gate}{path}")).header("content-type", "application/json");
    for (k, v) in signed_headers(key, host, "POST", path, &bytes) { rb = rb.header(k, v); }
    let r = rb.body(bytes).send().await?;
    let status = r.status();
    let v: Value = r.json().await.unwrap_or(json!({}));
    if !status.is_success() || v.get("error").is_some() { bail!("{}", v["error"].as_str().unwrap_or(status.as_str())); }
    Ok(v)
}

/// The join protocol itself (MACHINES.md §3): a new key, the commit, the reveal, the 6 digits, the owner's signed
/// confirmation checked and pinned. Reached from a machine link, or from a pairing code exchanged for one (onboard.rs join).
async fn join_with(gate: &str, pavilion: &str, token: &str, name: &str) -> Result<()> {
    let (gate, pavilion) = (gate.to_string(), pavilion.to_string());
    let host = reqwest::Url::parse(&gate)?.host_str().unwrap_or_default().to_string() + &reqwest::Url::parse(&gate)?.port().map(|p| format!(":{p}")).unwrap_or_default();
    let http = reqwest::Client::new();

    let key = state::new_key()?;
    let pubkey = b64(key.verifying_key().as_bytes());
    let my_id = key_id(&key.verifying_key());
    let node_nonce = random_b64(32);

    // 1. Our key and a commitment to our random value.
    let j = post(&http, &gate, &host, &key, &format!("/p/{pavilion}/node/join"),
        &json!({ "token": token, "alg": "Ed25519", "publicKey": pubkey, "name": "machine", "commit": commit_to(&node_nonce) })).await?;
    let (machine, pav_nonce, pavilion_key, owner) = (j["machine"].as_str().unwrap_or_default().to_string(), j["pavNonce"].as_str().unwrap_or_default().to_string(),
        j["pavilionKey"].as_str().unwrap_or_default().to_string(), j["owner"].as_str().unwrap_or_default().to_string());
    // 2. Reveal it. Both sides now know the code; the pavilion never shows it.
    post(&http, &gate, &host, &key, &format!("/p/{pavilion}/node/join/reveal"), &json!({ "nodeNonce": node_nonce })).await?;
    let code = join_code(&node_nonce, &pav_nonce, &pubkey, &pavilion_key, &owner);
    eprintln!("\n  Type this code in the console, on the machine waiting to join:\n\n      {} {}\n", &code[..3], &code[3..]);

    // 3. Wait for the owner, then check their signed confirmation ourselves.
    let path = format!("/p/{pavilion}/node/join/status");
    for _ in 0..300 {
        tokio::time::sleep(Duration::from_secs(3)).await;
        let mut rb = http.get(format!("{gate}{path}"));
        for (k, v) in signed_headers(&key, &host, "GET", &path, b"") { rb = rb.header(k, v); }
        let v: Value = rb.send().await?.json().await.unwrap_or(json!({}));
        match v["status"].as_str() {
            Some("active") => {
                let c = &v["confirm"];
                let (alg, pk, kid) = (c["alg"].as_str().unwrap_or(""), c["publicKey"].as_str().unwrap_or(""), c["keyId"].as_str().unwrap_or(""));
                let msg = signing::canonical(c["host"].as_str().unwrap_or(""), c["method"].as_str().unwrap_or(""), c["path"].as_str().unwrap_or(""),
                    c["time"].as_str().unwrap_or(""), c["nonce"].as_str().unwrap_or(""), c["body"].as_str().unwrap_or("").as_bytes());
                let body: Value = serde_json::from_str(c["body"].as_str().unwrap_or("{}")).unwrap_or(json!({}));
                let derived = b64(&sha256(&[format!("{alg}:").as_bytes(), &signing::unb64(pk).unwrap_or_default()].concat()))[..22].to_string();
                if !verify_member(alg, pk, &msg, c["signature"].as_str().unwrap_or("")) || derived != kid
                    || body["code"].as_str() != Some(&code) || body["machineKey"].as_str() != Some(&my_id) || (!owner.is_empty() && kid != owner) {
                    bail!("the confirmation isn't signed by the owner for this code and this machine; not joining");
                }
                state::save(&state::State { gate: gate.clone(), pavilion: pavilion.clone(), machine: machine.clone(), name: name.into(), pavilion_key,
                    owner_key_id: kid.into(), owner_alg: alg.into(), owner_public_key: pk.into(), last_seq: 0 })?;
                eprintln!("Joined {pavilion} as {machine}. Confirmed by {} ({kid}). Run `pavilion-node run` to stay connected.", c["name"].as_str().unwrap_or("the owner"));
                return Ok(());
            }
            Some("revoked") => bail!("the pavilion cancelled this join"),
            _ => {}
        }
    }
    bail!("nobody confirmed the code within 15 minutes")
}

/// Where the running Apple container service keeps its data (`paths.appRoot`), or None when it isn't running.
#[cfg(target_os = "macos")]
fn container_root() -> Option<std::path::PathBuf> {
    let out = std::process::Command::new("container").args(["system", "status"]).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let running = text.lines().any(|l| l.split_whitespace().collect::<Vec<_>>() == ["status", "running"]);
    let root = text.lines().find_map(|l| l.strip_prefix("paths.appRoot").map(|v| v.trim().trim_end_matches('/').to_string()))?;
    running.then(|| std::path::PathBuf::from(root))
}

/// Starts Apple container with its data in `root`. `container system start --app-root` writes the service's launchd
/// file into the app root, and launchd refuses to load one from an external volume ("Bootstrap failed: 5: Input/output
/// error", seen 13 Nov 2026 with ownership on or off). So when the plain start doesn't come up there, the same file is
/// copied into the node's own folder on the boot disk and loaded from that copy, then the kernel is installed if the new
/// root has none. Nothing else about the service changes.
#[cfg(target_os = "macos")]
fn start_container_at(root: &std::path::Path) -> Result<()> {
    use std::process::Command;
    let want = root.to_path_buf();
    let here = |r: &Option<std::path::PathBuf>| r.as_ref().map_or(false, |r| std::fs::canonicalize(r).ok() == std::fs::canonicalize(&want).ok());
    if Command::new("container").args(["system", "start", "--enable-kernel-install", "--app-root"]).arg(root).status()?.success() && here(&container_root()) {
        return Ok(());
    }
    let plist = root.join("apiserver/apiserver.plist");
    if !plist.exists() { bail!("container system start --app-root {} failed, and it wrote no launchd file to load instead", root.display()); }
    std::fs::create_dir_all(state::dir())?;
    let local = state::dir().join("container-apiserver.plist");
    std::fs::copy(&plist, &local)?;
    let uid = String::from_utf8_lossy(&Command::new("id").arg("-u").output()?.stdout).trim().to_string();
    let _ = Command::new("launchctl").args(["bootout", &format!("gui/{uid}/com.apple.container.apiserver")]).status();
    if !Command::new("launchctl").args(["bootstrap", &format!("gui/{uid}")]).arg(&local).status()?.success() {
        bail!("launchctl couldn't load {} either", local.display());
    }
    for _ in 0..20 {
        if here(&container_root()) { break; }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    if !here(&container_root()) { bail!("Apple container didn't come up with its data in {}", root.display()); }
    // A new app root has no kernel yet; installing the recommended one is what `--enable-kernel-install` would have done.
    let has_kernel = std::fs::read_dir(root.join("kernels")).map_or(false, |mut d| d.next().is_some());
    if !has_kernel { let _ = Command::new("container").args(["system", "kernel", "set", "--recommended"]).status(); }
    eprintln!("Apple container runs with its data in {} (loaded from {}, since launchd won't load it from that drive)", root.display(), local.display());
    Ok(())
}
#[cfg(not(target_os = "macos"))]
fn start_container_at(_root: &std::path::Path) -> Result<()> { Ok(()) }

/// At `run`: if VM storage was moved (`vm_storage`) and the drive is there, make sure Apple container uses it. After a
/// restart the service comes back on its default root, which is the boot disk, so without this jobs would quietly fill
/// it. If the drive isn't mounted, the guard already refuses work (guard.rs); this only says so.
fn vm_storage_up() {
    #[cfg(target_os = "macos")]
    {
        let Some(base) = state::config()["vm_storage"].as_str().map(std::path::PathBuf::from) else { return };
        if !base.is_dir() { eprintln!("VM storage {} isn't mounted; jobs wait until it is", base.display()); return; }
        let root = base.join("pavilion-vms");
        let ok = container_root().map_or(false, |r| std::fs::canonicalize(&r).ok() == std::fs::canonicalize(&root).ok());
        if !ok {
            let _ = std::process::Command::new("container").args(["system", "stop"]).status();
            if let Err(e) = start_container_at(&root) { eprintln!("couldn't start Apple container on {}: {e:#}", root.display()); }
        }
    }
}
