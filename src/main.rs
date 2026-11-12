//! pavilion-node: your own machine in a Cloud Pavilion (docs/DESIGN.md). Phase 0.
//!
//!   pavilion-node join        paste the link from Machines › Add a machine; shows a 6-digit code to type in the console
//!   pavilion-node run         stay connected; run jobs in fresh sandboxes; guard memory and disk
//!   pavilion-node inventory   print exactly what this machine reports
//!   pavilion-node guard       memory, disk, level and slots right now
//!   pavilion-node status      which pavilion this machine belongs to
//!   pavilion-node storage [folder]   where VM images and disks live, e.g. a folder on an external drive
mod broker;
mod guard;
mod inventory;
mod link;
mod sandbox;
mod signing;
mod state;

use anyhow::{anyhow, bail, Result};
use serde_json::{json, Value};
use signing::{b64, commit_to, join_code, key_id, random_b64, sha256, signed_headers, verify_member};
use std::time::Duration;

#[tokio::main]
async fn main() {
    let cmd = std::env::args().nth(1).unwrap_or_default();
    let r = match cmd.as_str() {
        "join" => join().await,
        "run" => link::run_forever().await,
        "inventory" => { println!("{}", serde_json::to_string_pretty(&inventory::collect().await).unwrap()); Ok(()) }
        "guard" => { guard_now(); Ok(()) }
        "storage" => storage(std::env::args().nth(2)).await,
        "exposure" => exposure().await,
        "status" => state::load().map(|s| println!("{} · pavilion {} · machine {} · last event {}", s.name, s.pavilion, s.machine, s.last_seq)),
        _ => { eprintln!("usage: pavilion-node join | run | inventory | guard | status | storage [folder] | exposure"); std::process::exit(2) }
    };
    if let Err(e) = r { eprintln!("error: {e:#}"); std::process::exit(1); }
}

fn guard_now() {
    let s = guard::sample();
    let l = guard::Limits::defaults(&s);
    let (lvl, why) = guard::level(&s, &l, 0.0);
    println!("{}", serde_json::to_string_pretty(&json!({ "level": lvl, "why": why, "sample": s, "limits": l,
        "vm_budget_mib": l.vm_budget_mib(&s), "slots_1gib": guard::slots(&s, &l, 1024), "slots_3gib": guard::slots(&s, &l, 3072) })).unwrap());
}

/// Where VM images and disks live. With a folder: check the drive, move Apple container's data there, remember it.
async fn storage(path: Option<String>) -> Result<()> {
    let Some(path) = path else {
        let s = guard::sample();
        println!("VM storage: {} · {} GiB free of {} GiB{}", s.storage, s.disk_free_mib / 1024, s.disk_total_mib / 1024, if s.storage_missing { " · NOT MOUNTED" } else { "" });
        return Ok(());
    };
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
    let ok = std::process::Command::new("container").args(["system", "start", "--enable-kernel-install", "--app-root"]).arg(&root).status()?.success();
    if !ok { bail!("container system start --app-root {} failed", root.display()); }
    std::fs::create_dir_all(state::dir())?;
    std::fs::write(state::dir().join("config.json"), serde_json::to_vec_pretty(&json!({ "vm_storage": p.to_string_lossy() }))?)?;
    let s = guard::sample();
    println!("VM storage is now {} · {} GiB free. The guard watches this drive, and stops every job if it's unplugged.", s.storage, s.disk_free_mib / 1024);
    Ok(())
}

/// Which of this machine's services a sandbox can reach. Anything but "none" means the firewall rule is missing.
async fn exposure() -> Result<()> {
    println!("listening beyond this machine: {:?}", sandbox::exposed_ports());
    let open = sandbox::probe_exposure().await?;
    if open.is_empty() { println!("a sandbox can reach none of them"); }
    else { println!("a sandbox CAN reach: {}\nLoad the firewall rule: sudo node/pf/install.sh", open.join(", ")); }
    Ok(())
}

/// `https://<gate>/m/<pavilion>/<token>` → (gate, pavilion, token)
fn parse_link(link: &str) -> Result<(String, String, String)> {
    let u = reqwest::Url::parse(link.trim()).map_err(|_| anyhow!("that isn't a link"))?;
    let segs: Vec<&str> = u.path_segments().map(|s| s.collect()).unwrap_or_default();
    let frag: Vec<&str> = u.fragment().unwrap_or("").trim_start_matches('/').split('/').collect();
    let parts = if segs.first() == Some(&"m") { segs } else { frag };
    if parts.len() != 3 || parts[0] != "m" { bail!("expected a machine link like https://…/m/<pavilion>/<token>"); }
    let origin = format!("{}://{}{}", u.scheme(), u.host_str().unwrap_or_default(), u.port().map(|p| format!(":{p}")).unwrap_or_default());
    Ok((origin, parts[1].to_string(), parts[2].to_string()))
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

async fn join() -> Result<()> {
    eprint!("Paste the link from Machines › Add a machine (it isn't shown or saved): ");
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    let (gate, pavilion, token) = parse_link(&line)?;
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
                state::save(&state::State { gate: gate.clone(), pavilion: pavilion.clone(), machine: machine.clone(), name: "machine".into(), pavilion_key,
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
