//! Command-line connectors (docs/CONNECTORS.md §8b, step 6b): one operation of a CLI connector, run as a job of kind
//! `cli` in a fresh sandbox. The Gate sends the program's name and an argument array it built and checked
//! (gate/src/connector-cli.ts); this checks them again, copies the job's input files into a working folder of its own,
//! and runs the program with no shell, no network and stdin closed:
//!
//!   1. a working folder: `in/` (the files the Gate named, fetched with this machine's key, sizes and hashes checked) and
//!      an empty `out/`; nothing else from this machine is in the sandbox;
//!   2. the sandbox: the image the owner set for that program (config.json `cli_tools`), read-only, `/tmp` in memory,
//!      `in/` mounted read-only and `out/` writable at /work, no DNS and no route out (an internal network with no broker
//!      on macOS, `--network none` with Podman);
//!   3. the version asked first, in the same sandbox: outside the manifest's range, the operation never runs;
//!   4. the operation: `<command> <argv…>` as an array, stdout read up to its cap (past it the run stops and fails),
//!      the first 2 KB of stderr, the time limit;
//!   5. the sandbox and its network removed, then `out/<file>` (a regular file, never a link) sent back as an asset;
//!      the working folder deleted.
use crate::sandbox::{self, Runtime};
use crate::signing::{sha256, signed_headers};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;

/// A program the owner said this machine's sandbox can run: the program, the image that has it, its version.
#[derive(Clone, Debug, PartialEq)]
pub struct CliTool { pub command: String, pub image: String, pub version: Option<String> }

#[derive(Clone, Debug)]
pub struct CliJob {
    pub job: String,
    pub project: String,
    pub image: String,
    pub cpus: u32,
    pub memory_mib: u64,
    pub mode: String,
    pub command: String,
    pub argv: Vec<String>,
    pub version: Option<(Vec<String>, Option<String>)>,
    pub files: Vec<InFile>,
    pub from: String,
    pub out_file: Option<String>,
    pub max_bytes: usize,
    pub timeout_s: u64,
    pub max_in_mb: u64,
    pub max_out_mb: u64,
}
#[derive(Clone, Debug)]
pub struct InFile { pub asset: String, pub path: String, pub size: u64, pub sha256: String }

pub const HELP_FLAGS: [&str; 7] = ["--help", "-h", "--version", "-help", "-version", "-ver", ""];
const MAX_BYTES: usize = 262_144;
const STDERR_BYTES: usize = 2048;

/// Programs no CLI job may name, whatever the envelope says (mirrors the floor in gate/src/connector-cli.ts).
const FLOOR: &[&str] = &["sh", "bash", "zsh", "dash", "ksh", "fish", "csh", "tcsh", "ash", "busybox", "env", "xargs", "sudo", "su", "doas", "python", "python3",
    "perl", "ruby", "node", "deno", "bun", "php", "lua", "osascript", "npm", "npx", "pnpm", "yarn", "pip", "pip3", "brew", "apt", "apt-get", "apk", "dnf", "yum",
    "awk", "sed", "make", "docker", "podman", "container", "launchctl", "systemctl", "security", "pavilion-node", "chroot", "nsenter", "mount"];

fn command_ok(c: &str) -> bool {
    !c.is_empty() && c.len() <= 41 && c.chars().next().map_or(false, |x| x.is_ascii_lowercase() || x.is_ascii_digit())
        && c.chars().all(|x| x.is_ascii_lowercase() || x.is_ascii_digit() || "._+-".contains(x)) && !FLOOR.contains(&c)
}
fn plain_name(s: &str, max: usize) -> bool { !s.is_empty() && s.len() <= max && !s.starts_with('.') && !s.starts_with('-') && s.chars().all(|x| x.is_ascii_alphanumeric() || "._-".contains(x)) }
fn in_path_ok(p: &str) -> bool {
    let Some(rest) = p.strip_prefix("in/") else { return false };
    let mut it = rest.splitn(2, '.');
    let (n, ext) = (it.next().unwrap_or(""), it.next().unwrap_or(""));
    !n.is_empty() && n.len() <= 2 && n.chars().all(|c| c.is_ascii_digit()) && !ext.is_empty() && ext.len() <= 8 && ext.chars().all(|c| c.is_ascii_alphanumeric())
}
/// An argument never reaches outside the working folder from here: no absolute path, no home, no `..`.
fn arg_ok(a: &str) -> bool {
    let v = a.split_once('=').map_or(a, |(_, v)| v);
    a.len() <= 300 && !a.contains('\0') && ![a, v].iter().any(|x| x.starts_with('/') || x.starts_with('~') || x.split(['/', '\\']).any(|seg| seg == ".."))
}

/// The tools set in config.json: `cli_tools: [{command, image, version}]`. Damaged entries are skipped.
pub fn configured_tools() -> Vec<CliTool> { tools_from(&crate::state::config()) }
pub fn tools_from(cfg: &Value) -> Vec<CliTool> {
    cfg["cli_tools"].as_array().cloned().unwrap_or_default().iter().filter_map(|t| {
        let command = t["command"].as_str()?.to_string();
        let image = t["image"].as_str()?.to_string();
        if !command_ok(&command) || image.len() < 3 || image.len() > 200 || !image.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "./_:@-".contains(c)) { return None; }
        Some(CliTool { command, image, version: t["version"].as_str().map(|v| v.chars().take(40).collect()) })
    }).take(50).collect()
}
/// What the inventory says (the router's `tools:` match, gate/src/connector-cli.ts `cliMachines`): a claim, never trusted.
pub fn inventory() -> Value { Value::Array(configured_tools().into_iter().map(|t| json!({ "command": t.command, "image": t.image, "version": t.version })).collect()) }

/// Every check on a `kind: "cli"` envelope, after its signature, machine, sequence and expiry were checked (link.rs).
pub fn validate(env: &Value, tools: &[CliTool]) -> Result<CliJob, String> {
    let c = &env["cli"];
    let mode = c["mode"].as_str().unwrap_or("");
    if mode != "run" && mode != "help" { return Err("a cli job's mode is run or help".into()); }
    let command = c["command"].as_str().unwrap_or("").to_string();
    if !command_ok(&command) { return Err(format!("{command:?} isn't a program a CLI connector may run")); }
    let image = env["image"].as_str().unwrap_or("").to_string();
    if !tools.iter().any(|t| t.command == command && t.image == image) { return Err(format!("this machine has no {command} in image {image}; the owner sets cli_tools in config.json")); }
    if c["network"] != "none" { return Err("this node runs CLI jobs with no network only".into()); }
    let argv: Vec<String> = c["argv"].as_array().ok_or("argv is an array")?.iter().map(|a| a.as_str().map(String::from).ok_or("each argument is a string")).collect::<Result<_, _>>()?;
    if argv.len() > 40 || !argv.iter().all(|a| arg_ok(a)) { return Err("an argument reaches outside the working folder, or there are too many".into()); }
    if mode == "help" && (argv.len() > 1 || argv.iter().any(|a| !HELP_FLAGS.contains(&a.as_str()))) { return Err("tool help asks --help, -h or --version, nothing else".into()); }
    let version = match &c["version"] {
        Value::Null => None,
        v => {
            let args: Vec<String> = v["args"].as_array().ok_or("version.args is an array")?.iter().filter_map(|a| a.as_str().map(String::from)).collect();
            if args.len() > 3 || !args.iter().all(|a| a.len() <= 22 && a.trim_start_matches('-').chars().all(|x| x.is_ascii_alphanumeric() || x == '-')) { return Err("version.args is up to three plain flags".into()); }
            Some((args, v["range"].as_str().map(String::from)))
        }
    };
    let files: Vec<InFile> = c["files"].as_array().cloned().unwrap_or_default().iter().map(|f| {
        let asset = f["asset"].as_str().unwrap_or("").to_string();
        let path = f["path"].as_str().unwrap_or("").to_string();
        let sha = f["sha256"].as_str().unwrap_or("").to_string();
        if !(asset.len() == 28 && asset.starts_with("ast_") && asset[4..].chars().all(|x| x.is_ascii_hexdigit())) { return Err("a file is an asset id".to_string()); }
        if !in_path_ok(&path) { return Err(format!("{path:?} isn't a path the runner chooses (in/<n>.<ext>)")); }
        if sha.len() != 64 || !sha.chars().all(|x| x.is_ascii_hexdigit()) { return Err("a file carries its sha256".into()); }
        Ok(InFile { asset, path, size: f["size"].as_u64().unwrap_or(0), sha256: sha })
    }).collect::<Result<_, _>>()?;
    if files.len() > 8 { return Err("a CLI job takes up to 8 files".into()); }
    let from = c["result"]["from"].as_str().unwrap_or("").to_string();
    if !["stdout", "file", "exit"].contains(&from.as_str()) { return Err("result.from is stdout, file or exit".into()); }
    let out_file = c["result"]["file"].as_str().map(String::from);
    if from == "file" { match &out_file { Some(f) if f.strip_prefix("out/").map_or(false, |n| plain_name(n, 81)) => {}, _ => return Err("result.file is out/<name>".into()) } }
    let max_bytes = c["result"]["max_bytes"].as_u64().unwrap_or(65_536) as usize;
    let timeout_s = c["result"]["timeout_s"].as_u64().unwrap_or(30);
    if max_bytes > MAX_BYTES || timeout_s == 0 || timeout_s > 300 { return Err("max_bytes is up to 256 KB and timeout_s 1 to 300".into()); }
    let (max_in_mb, max_out_mb) = (c["max_in_mb"].as_u64().unwrap_or(64).clamp(1, 512), c["max_out_mb"].as_u64().unwrap_or(64).clamp(1, 512));
    if files.iter().map(|f| f.size).sum::<u64>() > max_in_mb << 20 { return Err("the files are bigger than the job's in folder".into()); }
    Ok(CliJob { job: env["job"].as_str().unwrap_or("").to_string(), project: env["project"].as_str().unwrap_or("default").to_string(), image,
        cpus: env["cpus"].as_u64().unwrap_or(1).clamp(1, 8) as u32, memory_mib: env["memoryMiB"].as_u64().unwrap_or(1024).clamp(256, 16384),
        mode: mode.into(), command, argv, version, files, from, out_file, max_bytes, timeout_s, max_in_mb, max_out_mb })
}

/* ---------------------------------------------------------------- versions (mirrors inRange in gate/src/connector-cli.ts) */

pub fn parse_version(s: &str) -> Option<Vec<u64>> {
    let start = s.find(|c: char| c.is_ascii_digit())?;
    let tail: String = s[start..].chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
    let v: Vec<u64> = tail.trim_end_matches('.').split('.').take(4).filter_map(|x| x.parse().ok()).collect();
    if v.is_empty() { None } else { Some(v) }
}
pub fn in_range(version: &str, range: &str) -> bool {
    let Some(v) = parse_version(version) else { return false };
    range.split_whitespace().all(|p| {
        let (op, num) = ["<=", ">=", "<", ">", "="].iter().find_map(|o| p.strip_prefix(o).map(|r| (*o, r))).unwrap_or(("=", p));
        let Some(b) = parse_version(num) else { return false };
        let ord = (0..v.len().max(b.len())).map(|i| v.get(i).copied().unwrap_or(0).cmp(&b.get(i).copied().unwrap_or(0))).find(|o| o.is_ne()).unwrap_or(std::cmp::Ordering::Equal);
        match op { ">=" => ord.is_ge(), ">" => ord.is_gt(), "<=" => ord.is_le(), "<" => ord.is_lt(), _ => ord.is_eq() }
    })
}

/* ---------------------------------------------------------------- the sandbox */

/// `run -d …`: the sandbox kept up for the version and the operation, with nothing of the host in it but the two folders.
pub fn start_args(rt: &Runtime, name: &str, net: Option<&str>, work: &Path, j: &CliJob) -> Vec<String> {
    let (inp, out) = (work.join("in").to_string_lossy().to_string(), work.join("out").to_string_lossy().to_string());
    let mut a: Vec<String> = vec!["run".into(), "-d".into()];
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<String>>();
    match rt {
        Runtime::Apple => {
            a.extend(s(&["--progress", "none", "--name", name, "--network", net.unwrap_or(name), "--no-dns", "--arch", "arm64"]));
            a.extend(s(&["-m", &format!("{}M", j.memory_mib), "-c", &j.cpus.to_string()]));
            a.extend(s(&["--mount", &format!("type=bind,source={inp},target=/work/in,readonly"), "--mount", &format!("type=bind,source={out},target=/work/out")]));
        }
        Runtime::Podman { oci } => {
            a.extend(s(&["--name", name, "--network", "none", "--runtime", oci, "--memory", &format!("{}m", j.memory_mib), "--cpus", &j.cpus.to_string(),
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "256"]));
            a.extend(s(&["--mount", &format!("type=bind,source={inp},target=/work/in,ro=true"), "--mount", &format!("type=bind,source={out},target=/work/out")]));
        }
    }
    a.extend(s(&["--read-only", "--tmpfs", "/tmp", "--label", &format!("pavilion.job={}", j.job), "--label", &format!("pavilion.project={}", j.project),
        "--entrypoint", "sleep", &j.image, &(j.timeout_s + 120).to_string()]));
    a
}
/// `exec -w /work <name> <command> <argv…>`: an array to the program, never `sh -c`.
pub fn exec_args(name: &str, command: &str, argv: &[String]) -> Vec<String> {
    let mut a: Vec<String> = vec!["exec".into(), "-w".into(), "/work".into(), name.into(), command.into()];
    a.extend(argv.iter().cloned());
    a
}

struct Ran { exit: Option<i32>, stdout: Vec<u8>, over: bool, stderr: String, timed_out: bool }

/// One process in the sandbox: stdin closed, stdout read up to `cap` (one byte more means "over" and it is stopped),
/// the first 2 KB of stderr kept, the rest drained, the time limit held.
async fn exec_capped(rt: &Runtime, args: &[String], cap: usize, timeout_s: u64) -> Ran {
    let mut cmd = sandbox::runtime_command(match rt { Runtime::Apple => "container", Runtime::Podman { .. } => "podman" });
    cmd.args(args).stdin(std::process::Stdio::null()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).kill_on_drop(true);
    let Ok(mut child) = cmd.spawn() else { return Ran { exit: None, stdout: vec![], over: false, stderr: "couldn't start the sandbox's process".into(), timed_out: false } };
    let (mut so, mut se) = (child.stdout.take().unwrap(), child.stderr.take().unwrap());
    let err = tokio::spawn(async move {
        let (mut keep, mut buf) = (Vec::new(), [0u8; 4096]);
        while let Ok(n) = se.read(&mut buf).await { if n == 0 { break; } if keep.len() < STDERR_BYTES { keep.extend_from_slice(&buf[..n.min(STDERR_BYTES - keep.len())]); } }
        String::from_utf8_lossy(&keep).to_string()
    });
    let read = async {
        let (mut out, mut buf, mut over) = (Vec::new(), [0u8; 8192], false);
        loop {
            match so.read(&mut buf).await { Ok(0) | Err(_) => break, Ok(n) => { out.extend_from_slice(&buf[..n]); if out.len() > cap { out.truncate(cap); over = true; break; } } }
        }
        (out, over)
    };
    match tokio::time::timeout(Duration::from_secs(timeout_s), read).await {
        Ok((stdout, over)) => {
            if over { let _ = child.kill().await; }
            let exit = if over { None } else { tokio::time::timeout(Duration::from_secs(10), child.wait()).await.ok().and_then(|r| r.ok()).and_then(|s| s.code()) };
            let stderr = tokio::time::timeout(Duration::from_secs(2), err).await.ok().and_then(|r| r.ok()).unwrap_or_default();
            Ran { exit, stdout, over, stderr, timed_out: false }
        }
        Err(_) => { let _ = child.kill().await; Ran { exit: None, stdout: vec![], over: false, stderr: String::new(), timed_out: true } }
    }
}

/* ---------------------------------------------------------------- the Gate: inputs in, the one file out */

struct Gate { http: reqwest::Client, base: String, host: String, pav: String, key: ed25519_dalek::SigningKey }
impl Gate {
    fn new(gate: &str, pavilion: &str, key: ed25519_dalek::SigningKey) -> Result<Gate, String> {
        let url = reqwest::Url::parse(gate).map_err(|e| e.to_string())?;
        let host = url.host_str().unwrap_or_default().to_string() + &url.port().map(|p| format!(":{p}")).unwrap_or_default();
        Ok(Gate { http: reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).timeout(Duration::from_secs(120)).build().map_err(|e| e.to_string())?,
            base: gate.trim_end_matches('/').to_string(), host, pav: pavilion.into(), key })
    }
    async fn send(&self, method: &str, path: &str, ctype: &str, body: Vec<u8>) -> Result<reqwest::Response, String> {
        let mut rb = self.http.request(method.parse().unwrap(), format!("{}{path}", self.base));
        for (k, v) in signed_headers(&self.key, &self.host, method, path, &body) { rb = rb.header(k, v); }
        if !body.is_empty() { rb = rb.header("content-type", ctype).body(body); }
        rb.send().await.map_err(|e| format!("the Gate: {e}"))
    }
    /// One input, checked against the size and hash the envelope named (the envelope is signed; the file isn't).
    async fn fetch(&self, job: &str, f: &InFile, dest: &Path) -> Result<(), String> {
        let r = self.send("GET", &format!("/p/{}/node/jobs/{job}/files/{}", self.pav, f.asset), "", vec![]).await?;
        if !r.status().is_success() { return Err(format!("the Gate didn't give {}: {}", f.asset, r.status())); }
        let bytes = r.bytes().await.map_err(|e| format!("reading {}: {e}", f.asset))?;
        let got: String = sha256(&bytes).iter().map(|b| format!("{b:02x}")).collect();
        if bytes.len() as u64 != f.size || got != f.sha256.to_ascii_lowercase() { return Err(format!("{} isn't the file the job named (size or hash differs)", f.asset)); }
        std::fs::write(dest, &bytes).map_err(|e| e.to_string())
    }
    async fn upload(&self, job: &str, name: &str, bytes: Vec<u8>) -> Result<String, String> {
        let r = self.send("PUT", &format!("/p/{}/node/jobs/{job}/out?name={name}", self.pav), media_type(name), bytes).await?;
        let status = r.status();
        let v: Value = r.json().await.unwrap_or(json!({}));
        if !status.is_success() || v.get("error").is_some() { return Err(format!("sending {name}: {}", v["error"].as_str().unwrap_or(status.as_str()))); }
        Ok(v["asset"].as_str().unwrap_or("").to_string())
    }
}
fn media_type(name: &str) -> &'static str {
    match name.rsplit('.').next().unwrap_or("").to_ascii_lowercase().as_str() {
        "pdf" => "application/pdf", "png" => "image/png", "jpg" | "jpeg" => "image/jpeg", "webp" => "image/webp", "gif" => "image/gif", "json" => "application/json",
        "txt" | "md" => "text/plain", "csv" => "text/csv", "html" => "text/html", "mp4" => "video/mp4", "mp3" => "audio/mpeg", "wav" => "audio/wav", "zip" => "application/zip",
        _ => "application/octet-stream",
    }
}

/// The one result file, read only if it is a regular file (never a link the program made pointing at the host), within the cap.
pub fn read_out(work: &Path, out_file: &str, max_out_mb: u64) -> Result<Vec<u8>, String> {
    let out_dir = work.join("out");
    let total: u64 = std::fs::read_dir(&out_dir).map_err(|e| e.to_string())?.filter_map(|e| e.ok()).filter_map(|e| e.path().symlink_metadata().ok()).map(|m| m.len()).sum();
    if total > max_out_mb << 20 { return Err(format!("the out folder holds more than {max_out_mb} MB")); }
    let p = work.join(out_file);
    let meta = std::fs::symlink_metadata(&p).map_err(|_| format!("{out_file} wasn't written"))?;
    if !meta.file_type().is_file() { return Err(format!("{out_file} isn't a plain file")); }
    if meta.len() > max_out_mb << 20 { return Err(format!("{out_file} is bigger than {max_out_mb} MB")); }
    #[cfg(unix)]
    { use std::io::Read; use std::os::unix::fs::OpenOptionsExt;
      let mut f = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(&p).map_err(|e| e.to_string())?;
      let mut b = Vec::new(); f.read_to_end(&mut b).map_err(|e| e.to_string())?; Ok(b) }
    #[cfg(not(unix))]
    { std::fs::read(&p).map_err(|e| e.to_string()) }
}

fn workdir(job: &str) -> PathBuf { crate::state::dir().join("cli-work").join(job) }

/// Runs one job and returns the message for the pavilion: `{t: job, job, status, exitCode, note, result}`.
pub async fn run(j: CliJob, gate: &str, pavilion: &str, key: ed25519_dalek::SigningKey) -> Value {
    let t0 = Instant::now();
    let work = workdir(&j.job);
    let r = run_in(&j, &work, gate, pavilion, key).await;
    let _ = std::fs::remove_dir_all(&work);
    let seconds = (t0.elapsed().as_secs_f64() * 10.0).round() / 10.0;
    match r {
        Ok(mut result) => {
            result["seconds"] = json!(seconds);
            let exit = result["exit_code"].as_i64();
            let ok = exit.is_some() && !result["timed_out"].as_bool().unwrap_or(false) && !result["stdout_over"].as_bool().unwrap_or(false);
            json!({ "t": "job", "job": j.job, "status": if ok { "done" } else { "failed" }, "exitCode": exit, "note": result["note"].clone(), "result": result })
        }
        Err(why) => json!({ "t": "job", "job": j.job, "status": "failed", "note": why, "result": { "exit_code": null, "note": why, "seconds": seconds } }),
    }
}

async fn run_in(j: &CliJob, work: &Path, gate: &str, pavilion: &str, key: ed25519_dalek::SigningKey) -> Result<Value, String> {
    let rt = sandbox::detect().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(work.join("in")).and_then(|_| std::fs::create_dir_all(work.join("out"))).map_err(|e| format!("the working folder: {e}"))?;
    let g = Gate::new(gate, pavilion, key)?;
    let mut total = 0u64;
    for f in &j.files { g.fetch(&j.job, f, &work.join(&f.path)).await?; total += f.size; if total > j.max_in_mb << 20 { return Err(format!("the files are over the in folder's {} MB", j.max_in_mb)); } }
    let name = format!("pav-{}", j.job);
    // No route out: on macOS an internal network with no broker on it (the packet filter lets sandboxes reach brokers
    // only, and none answers this subnet); Podman's `--network none`.
    let net = if rt == Runtime::Apple { Some(sandbox::make_network(&rt, &name, &format!("pavilion.job={}", j.job)).await.map_err(|e| e.to_string())?) } else { None };
    let started = sandbox::cli_run(&rt, &start_args(&rt, &name, net.as_ref().map(|_| name.as_str()), work, j)).await;
    let r = match started {
        Err(e) => Err(format!("couldn't start the sandbox: {e}")),
        Ok(_) => operate(&rt, &name, j).await,
    };
    sandbox::remove_named(&name).await; // the sandbox and its network go before anything it wrote is read
    let mut result = r?;
    if j.from == "file" && result["exit_code"].is_i64() {
        let f = j.out_file.clone().unwrap_or_default();
        match read_out(work, &f, j.max_out_mb) {
            Ok(bytes) => match g.upload(&j.job, f.trim_start_matches("out/"), bytes).await { Ok(a) => result["file"] = json!(a), Err(e) => result["note"] = json!(e) },
            Err(e) => result["note"] = json!(e),
        }
    }
    Ok(result)
}

async fn operate(rt: &Runtime, name: &str, j: &CliJob) -> Result<Value, String> {
    let mut version: Value = Value::Null;
    if let Some((args, range)) = j.version.as_ref().filter(|_| j.mode == "run") {
        let v = exec_capped(rt, &exec_args(name, &j.command, args), 4096, 20).await;
        let text = format!("{}\n{}", String::from_utf8_lossy(&v.stdout), v.stderr);
        let found = parse_version(&text).map(|v| v.iter().map(|x| x.to_string()).collect::<Vec<_>>().join("."));
        version = found.clone().map_or(Value::Null, Value::String);
        match (found, range) {
            (None, Some(_)) => return Ok(json!({ "exit_code": null, "version": null, "note": format!("couldn't read {}'s version", j.command) })),
            (Some(f), Some(r)) if !in_range(&f, r) => return Ok(json!({ "exit_code": null, "version": f, "note": format!("{} {f} is outside {r}; the operation didn't run", j.command) })),
            _ => {}
        }
    }
    let ran = exec_capped(rt, &exec_args(name, &j.command, &j.argv), j.max_bytes, j.timeout_s).await;
    Ok(json!({ "exit_code": if ran.timed_out { Value::Null } else { json!(ran.exit) }, "stdout_b64": base64_std(&ran.stdout), "stdout_bytes": ran.stdout.len(),
        "stdout_over": ran.over, "stderr": ran.stderr, "version": version, "timed_out": ran.timed_out,
        "note": if ran.timed_out { format!("stopped after the {} s time limit", j.timeout_s) } else { format!("sandbox: {}, no network", rt.describe()) } }))
}
fn base64_std(b: &[u8]) -> String { use base64::Engine; base64::engine::general_purpose::STANDARD.encode(b) }

/* ---------------------------------------------------------------- `pavilion-node cli-tools` */

/// `pavilion-node cli-tools [list | add <command> <image> <version> | remove <command>]`: which programs this
/// machine's sandboxes offer to CLI connectors. The image must already be on this machine; nothing is pulled here.
pub fn cli(args: &[String]) -> anyhow::Result<()> {
    let mut tools: Vec<Value> = crate::state::config()["cli_tools"].as_array().cloned().unwrap_or_default();
    match args.first().map(String::as_str) {
        None | Some("list") => { for t in tools_from(&json!({ "cli_tools": tools })) { println!("{} {} · {}", t.command, t.version.unwrap_or_else(|| "?".into()), t.image); } Ok(()) }
        Some("add") if args.len() == 4 => {
            let t = json!({ "command": args[1], "image": args[2], "version": args[3] });
            if tools_from(&json!({ "cli_tools": [t.clone()] })).is_empty() { anyhow::bail!("{} can't be offered (a program's name, an image name; shells, interpreters and package managers never)", args[1]); }
            tools.retain(|x| x["command"] != args[1].as_str());
            tools.push(t);
            crate::state::set_config("cli_tools", Value::Array(tools))?;
            println!("offered {} {} from {}; the pavilion sees it with the next inventory", args[1], args[3], args[2]);
            Ok(())
        }
        Some("remove") if args.len() == 2 => { tools.retain(|x| x["command"] != args[1].as_str()); crate::state::set_config("cli_tools", Value::Array(tools))?; Ok(()) }
        _ => anyhow::bail!("usage: pavilion-node cli-tools [list | add <command> <image> <version> | remove <command>]"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn tools() -> Vec<CliTool> { vec![CliTool { command: "exiftool".into(), image: "local/exiftool:12.76".into(), version: Some("12.76".into()) }] }
    fn env(cli: Value) -> Value { json!({ "kind": "cli", "job": "job_abc", "project": "default", "image": "local/exiftool:12.76", "cpus": 1, "memoryMiB": 1024, "cli": cli }) }
    fn good() -> Value {
        json!({ "mode": "run", "command": "exiftool", "argv": ["-json", "-n", "in/1.jpg"], "version": { "args": ["-ver"], "range": ">=12.70" },
            "files": [{ "asset": format!("ast_{}", "a".repeat(24)), "path": "in/1.jpg", "size": 10, "sha256": "0".repeat(64) }],
            "result": { "from": "stdout", "file": null, "max_bytes": 65536, "timeout_s": 30 }, "network": "none", "max_in_mb": 64, "max_out_mb": 64 })
    }

    #[test]
    fn a_good_envelope_and_what_is_refused() {
        let j = validate(&env(good()), &tools()).unwrap();
        assert_eq!(j.argv, vec!["-json", "-n", "in/1.jpg"]);
        let with = |k: &str, v: Value| { let mut g = good(); g[k] = v; validate(&env(g), &tools()) };
        assert!(with("command", json!("sh")).unwrap_err().contains("isn't a program"));
        assert!(with("command", json!("/usr/bin/exiftool")).is_err());
        assert!(with("command", json!("python3")).is_err());
        assert!(with("argv", json!(["-json", "/etc/passwd"])).is_err(), "an absolute path");
        assert!(with("argv", json!(["-o", "../../x"])).is_err(), "..");
        assert!(with("argv", json!(["--out=~/x"])).is_err(), "a home");
        assert!(with("argv", json!("-json -n in/1.jpg")).is_err(), "a string, not an array");
        assert!(with("network", json!({ "hosts": ["example.com"] })).is_err());
        assert!(with("files", json!([{ "asset": format!("ast_{}", "a".repeat(24)), "path": "/etc/x", "size": 1, "sha256": "0".repeat(64) }])).is_err());
        assert!(with("files", json!([{ "asset": format!("ast_{}", "a".repeat(24)), "path": "in/../x", "size": 1, "sha256": "0".repeat(64) }])).is_err());
        // The image must be one the owner offered for that program.
        let mut e = env(good()); e["image"] = json!("docker.io/library/alpine:3.22");
        assert!(validate(&e, &tools()).unwrap_err().contains("no exiftool"));
        // Help asks one of the help flags and nothing else.
        let mut h = good(); h["mode"] = json!("help"); h["argv"] = json!(["--help"]);
        assert!(validate(&env(h.clone()), &tools()).is_ok());
        h["argv"] = json!(["-if", "1"]);
        assert!(validate(&env(h), &tools()).is_err());
    }

    #[test]
    fn versions_and_ranges() {
        assert_eq!(parse_version("12.76\n"), Some(vec![12, 76]));
        assert_eq!(parse_version("pandoc 3.1.11.1\nFeatures"), Some(vec![3, 1, 11, 1]));
        assert!(in_range("12.76", ">=12.70"));
        assert!(!in_range("12.40", ">=12.70"));
        assert!(in_range("1.5", ">=1.2 <2"));
        assert!(!in_range("2.0", ">=1.2 <2"));
        assert!(!in_range("nonsense", ">=1"));
    }

    #[test]
    fn the_sandbox_gets_an_array_and_only_its_two_folders() {
        let j = validate(&env(good()), &tools()).unwrap();
        let w = Path::new("/tmp/pav-cli/job_abc");
        let a = start_args(&Runtime::Apple, "pav-job_abc", Some("pav-job_abc"), w, &j);
        let s = a.join(" ");
        assert!(s.contains("--no-dns") && s.contains("--read-only") && s.contains("--entrypoint sleep local/exiftool:12.76"), "{s}");
        assert!(s.contains("source=/tmp/pav-cli/job_abc/in,target=/work/in,readonly") && s.contains("source=/tmp/pav-cli/job_abc/out,target=/work/out"), "{s}");
        assert!(!s.contains("-v ") && !s.contains("PAVILION_BROKER"), "no other folder, no broker: {s}");
        let p = start_args(&Runtime::Podman { oci: "krun" }, "pav-job_abc", None, w, &j).join(" ");
        assert!(p.contains("--network none") && p.contains("--cap-drop ALL") && p.contains("ro=true"), "{p}");
        let e = exec_args("pav-job_abc", "exiftool", &["-json".into(), "; rm -rf ~".into()]);
        assert_eq!(e, vec!["exec", "-w", "/work", "pav-job_abc", "exiftool", "-json", "; rm -rf ~"], "one argument, never a shell");
    }

    #[test]
    fn a_result_file_is_never_a_link() {
        let w = std::env::temp_dir().join(format!("pav-cli-test-{}", std::process::id()));
        std::fs::create_dir_all(w.join("out")).unwrap();
        std::fs::write(w.join("out/brief.pdf"), b"%PDF-1.7").unwrap();
        assert_eq!(read_out(&w, "out/brief.pdf", 1).unwrap(), b"%PDF-1.7");
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("/etc/hosts", w.join("out/leak.txt")).unwrap();
            assert!(read_out(&w, "out/leak.txt", 1).unwrap_err().contains("isn't a plain file"));
        }
        assert!(read_out(&w, "out/missing.pdf", 1).is_err());
        let _ = std::fs::remove_dir_all(&w);
    }

    #[test]
    fn tools_from_config_skip_what_cant_be_offered() {
        let t = tools_from(&json!({ "cli_tools": [{ "command": "exiftool", "image": "local/exiftool:12.76", "version": "12.76" },
            { "command": "bash", "image": "x/y:1" }, { "command": "pandoc", "image": "BAD IMAGE" }] }));
        assert_eq!(t, tools());
    }
}
