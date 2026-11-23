//! A project's files from this machine (gate/src/project-files.ts):
//!
//!   pavilion-node project push <project> <folder> [-m message] [--branch b]
//!   pavilion-node project pull <project> <folder> [--version n] [--branch b]
//!
//! Push makes the project's tree equal to the folder, as one new version (history keeps the old ones). Files are hashed
//! here; only those the Gate doesn't have are sent (files over 50 MB in 16 MB parts, which a later push resumes).
//! Skipped: junk (.DS_Store, ._*), .git/, node_modules/, .env files, whatever .pavilionignore lists, and symlinks,
//! which are never followed, so nothing outside the folder is read. Pull writes the files of a version into a folder,
//! checking each one's hash, and leaves files that are only local alone. Every request is signed by this machine's key;
//! the Gate allows only projects that list this machine as a worker.
use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Component, Path, PathBuf};

const SINGLE_PUT: u64 = 50 * 1024 * 1024;
const MAX_FILES: usize = 50_000;
const MAX_BLOB: u64 = 2 * 1024 * 1024 * 1024;
const FILE: u32 = 0o100644;
const EXEC: u32 = 0o100755;
/// Skipped by default, as in the console (gate/src/files.ts DEFAULT_IGNORE).
pub const DEFAULT_IGNORE: &str = ".DS_Store\n._*\nThumbs.db\ndesktop.ini\n.git/\nnode_modules/\n__MACOSX/\n.Spotlight-V100/\n.Trashes/\n.env\n.env.*\n!.env.example\n";

/* ---------- what to skip: gitignore's common forms ---------- */

#[derive(Debug, Clone)]
pub struct Rule { pat: String, negate: bool, dir_only: bool, anchored: bool }

pub fn parse_ignore(text: &str) -> Vec<Rule> {
    let mut out = vec![];
    for line in text.lines() {
        let mut l = line.trim_end();
        if l.is_empty() || l.starts_with('#') { continue; }
        let negate = l.starts_with('!');
        if negate { l = &l[1..]; }
        let dir_only = l.ends_with('/');
        let l = l.trim_end_matches('/');
        let anchored = l.contains('/');
        let l = l.trim_start_matches('/');
        if l.is_empty() { continue; }
        out.push(Rule { pat: l.to_string(), negate, dir_only, anchored });
    }
    out
}

/// `*` and `?` stay inside one name; `**` crosses folders; `**/` is any number of folders, none included.
fn glob(p: &[u8], s: &[u8]) -> bool {
    if p.is_empty() { return s.is_empty(); }
    if p.starts_with(b"**/") {
        if glob(&p[3..], s) { return true; }
        return (0..s.len()).any(|i| s[i] == b'/' && glob(&p[3..], &s[i + 1..]));
    }
    if p.starts_with(b"**") { return (0..=s.len()).any(|i| glob(&p[2..], &s[i..])); }
    match p[0] {
        b'*' => {
            for i in 0..=s.len() {
                if glob(&p[1..], &s[i..]) { return true; }
                if i < s.len() && s[i] == b'/' { break; }
            }
            false
        }
        b'?' => !s.is_empty() && s[0] != b'/' && glob(&p[1..], &s[1..]),
        c => !s.is_empty() && s[0] == c && glob(&p[1..], &s[1..]),
    }
}

/// The last rule that matches decides; a skipped folder skips everything in it.
pub fn ignored(path: &str, rules: &[Rule], is_dir: bool) -> bool {
    let segs: Vec<&str> = path.split('/').collect();
    for i in 1..=segs.len() {
        let sub = segs[..i].join("/");
        let dir = i < segs.len() || is_dir;
        let mut hit = false;
        for r in rules {
            if r.dir_only && !dir { continue; }
            let target = if r.anchored { sub.as_str() } else { segs[i - 1] };
            if glob(r.pat.as_bytes(), target.as_bytes()) { hit = !r.negate; }
        }
        if hit { return true; }
    }
    false
}

/* ---------- the folder ---------- */

#[derive(Debug, Clone)]
pub struct Local { pub path: String, pub full: PathBuf, pub size: u64, pub sha256: String, pub mode: u32 }

/// A name the Gate takes: UTF-8, no control characters or backslashes, short enough.
fn name_ok(n: &str) -> bool { !n.is_empty() && n != "." && n != ".." && n.len() <= 255 && !n.chars().any(|c| c.is_control() || c == '\\') }

fn hash_file(p: &Path) -> Result<(String, u64)> {
    use std::io::Read;
    let mut f = std::fs::File::open(p)?;
    let (mut h, mut buf, mut n) = (Sha256::new(), vec![0u8; 1 << 20], 0u64);
    loop { let k = f.read(&mut buf)?; if k == 0 { break; } h.update(&buf[..k]); n += k as u64; }
    Ok((hex(&h.finalize()), n))
}
fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }

#[cfg(unix)]
fn mode_of(m: &std::fs::Metadata) -> u32 { use std::os::unix::fs::PermissionsExt; if m.permissions().mode() & 0o111 != 0 { EXEC } else { FILE } }
#[cfg(not(unix))]
fn mode_of(_m: &std::fs::Metadata) -> u32 { FILE }
#[cfg(unix)]
fn set_exec(p: &Path, exec: bool) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perm = std::fs::metadata(p)?.permissions();
    perm.set_mode(if exec { 0o755 } else { 0o644 });
    Ok(std::fs::set_permissions(p, perm)?)
}
#[cfg(not(unix))]
fn set_exec(_p: &Path, _exec: bool) -> Result<()> { Ok(()) }

/// Every file to push, and what was skipped (and why). Symlinks are never followed.
pub fn scan(root: &Path) -> Result<(Vec<Local>, Vec<String>)> {
    let root = std::fs::canonicalize(root).with_context(|| format!("{} doesn't exist", root.display()))?;
    if !root.is_dir() { bail!("{} isn't a folder", root.display()); }
    let mut text = DEFAULT_IGNORE.to_string();
    if let Ok(own) = std::fs::read_to_string(root.join(".pavilionignore")) { text.push_str(&own); }
    let rules = parse_ignore(&text);
    let (mut files, mut skipped) = (vec![], vec![]);
    let mut stack = vec![(root.clone(), String::new())];
    while let Some((dir, rel)) = stack.pop() {
        let mut entries: Vec<_> = std::fs::read_dir(&dir)?.filter_map(|e| e.ok()).collect();
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            let Some(name) = e.file_name().to_str().map(str::to_string) else { skipped.push(format!("{rel}{} (not UTF-8)", e.file_name().to_string_lossy())); continue };
            let path = if rel.is_empty() { name.clone() } else { format!("{rel}/{name}") };
            if !name_ok(&name) || path.len() > 1024 { skipped.push(format!("{path} (name the Gate doesn't take)")); continue; }
            // symlink_metadata: the link itself, never what it points at.
            let md = std::fs::symlink_metadata(e.path())?;
            let ft = md.file_type();
            if ft.is_symlink() { skipped.push(format!("{path} (symlink, not followed)")); continue; }
            if ft.is_dir() {
                if ignored(&path, &rules, true) { skipped.push(format!("{path}/")); continue; }
                stack.push((e.path(), path));
            } else if ft.is_file() {
                if ignored(&path, &rules, false) { skipped.push(path); continue; }
                if md.len() > MAX_BLOB { skipped.push(format!("{path} (over 2 GB)")); continue; }
                let (sha256, size) = hash_file(&e.path())?;
                files.push(Local { path, full: e.path(), size, sha256, mode: mode_of(&md) });
                if files.len() > MAX_FILES { bail!("more than {MAX_FILES} files; add a .pavilionignore or push a smaller folder"); }
            } else { skipped.push(format!("{path} (not a regular file)")); }
        }
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));
    Ok((files, skipped))
}

/* ---------- talking to the Gate, signed ---------- */

pub struct Client { pub http: reqwest::Client, pub gate: String, pub host: String, pub pavilion: String, pub key: ed25519_dalek::SigningKey }

/// Percent-encodes a query value the way the Gate will see it (everything but unreserved characters).
pub fn enc(s: &str) -> String {
    s.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
}

impl Client {
    pub fn from_state() -> Result<Client> {
        let s = crate::state::load()?;
        let key = crate::state::key()?;
        let u = reqwest::Url::parse(&s.gate)?;
        let host = u.host_str().unwrap_or_default().to_string() + &u.port().map(|p| format!(":{p}")).unwrap_or_default();
        Ok(Client { http: reqwest::Client::new(), gate: s.gate.trim_end_matches('/').to_string(), host, pavilion: s.pavilion, key })
    }
    fn files(&self, project: &str, rest: &str) -> String { format!("/p/{}/node/projects/{project}/files/{rest}", self.pavilion) }
    async fn send(&self, method: reqwest::Method, path: &str, body: Vec<u8>, ctype: &str) -> Result<reqwest::Response> {
        let mut rb = self.http.request(method.clone(), format!("{}{path}", self.gate));
        if !body.is_empty() { rb = rb.header("content-type", ctype); }
        for (k, v) in crate::signing::signed_headers(&self.key, &self.host, method.as_str(), path, &body) { rb = rb.header(k, v); }
        Ok(rb.body(body).send().await?)
    }
    async fn json(&self, method: reqwest::Method, path: &str, body: Option<&Value>) -> Result<Value> {
        let bytes = body.map(|b| serde_json::to_vec(b)).transpose()?.unwrap_or_default();
        let r = self.send(method, path, bytes, "application/json").await?;
        let status = r.status();
        let v: Value = r.json().await.unwrap_or(json!({}));
        if !status.is_success() || v.get("error").is_some() { bail!("{}", v["error"].as_str().unwrap_or(status.as_str())); }
        Ok(v)
    }
}

pub struct PushReport { pub files: usize, pub uploaded: usize, pub bytes: u64, pub version: Option<u64>, pub unchanged: bool, pub skipped: Vec<String> }

/// Upload one file: whole when it's 50 MB or less, else in parts (resuming parts already sent).
async fn upload(c: &Client, project: &str, f: &Local) -> Result<()> {
    if f.size <= SINGLE_PUT {
        let bytes = std::fs::read(&f.full)?;
        if hex(&Sha256::digest(&bytes)) != f.sha256 { bail!("{} changed while pushing; push again", f.path); }
        let r = c.send(reqwest::Method::PUT, &c.files(project, &format!("blobs/{}", f.sha256)), bytes, "application/octet-stream").await?;
        if !r.status().is_success() { let v: Value = r.json().await.unwrap_or(json!({})); bail!("{}: {}", f.path, v["error"].as_str().unwrap_or("upload refused")); }
        return Ok(());
    }
    use std::io::{Read, Seek, SeekFrom};
    let u = c.json(reqwest::Method::POST, &c.files(project, "uploads"), Some(&json!({ "sha256": f.sha256, "size": f.size }))).await?;
    if u["exists"].as_bool() == Some(true) { return Ok(()); }
    let id = u["id"].as_str().ok_or_else(|| anyhow!("no upload id"))?.to_string();
    let part = u["part_size"].as_u64().ok_or_else(|| anyhow!("no part size"))?;
    let done: Vec<u64> = u["parts"].as_array().map(|a| a.iter().filter_map(|x| x.as_u64()).collect()).unwrap_or_default();
    let count = f.size.div_ceil(part);
    let mut file = std::fs::File::open(&f.full)?;
    for n in 1..=count {
        if done.contains(&n) { continue; }
        let len = if n < count { part } else { f.size - part * (count - 1) };
        let mut buf = vec![0u8; len as usize];
        file.seek(SeekFrom::Start(part * (n - 1)))?;
        file.read_exact(&mut buf)?;
        let r = c.send(reqwest::Method::PUT, &c.files(project, &format!("uploads/{id}/parts/{n}")), buf, "application/octet-stream").await?;
        if !r.status().is_success() { let v: Value = r.json().await.unwrap_or(json!({})); bail!("{} part {n}: {}", f.path, v["error"].as_str().unwrap_or("refused")); }
        eprint!("\r  {} part {n}/{count}", f.path);
    }
    eprintln!();
    c.json(reqwest::Method::POST, &c.files(project, &format!("uploads/{id}/complete")), None).await?;
    Ok(())
}

pub async fn push(c: &Client, project: &str, root: &Path, message: &str, branch: Option<&str>) -> Result<PushReport> {
    let (files, skipped) = scan(root)?;
    let mut uniq: Vec<&Local> = vec![];
    for f in &files { if !uniq.iter().any(|u| u.sha256 == f.sha256) { uniq.push(f); } }
    let mut missing: Vec<String> = vec![];
    for chunk in uniq.chunks(2000) {
        let v = c.json(reqwest::Method::POST, &c.files(project, "missing"), Some(&json!({ "hashes": chunk.iter().map(|f| &f.sha256).collect::<Vec<_>>() }))).await?;
        missing.extend(v["missing"].as_array().into_iter().flatten().filter_map(|x| x.as_str().map(String::from)));
    }
    let (mut uploaded, mut bytes) = (0, 0);
    for f in uniq.iter().filter(|f| missing.contains(&f.sha256)) {
        upload(c, project, f).await?;
        uploaded += 1; bytes += f.size;
    }
    let mut body = json!({ "message": message, "replace": true, "changes": files.iter().map(|f| json!({ "path": f.path, "sha256": f.sha256, "mode": f.mode })).collect::<Vec<_>>() });
    if let Some(b) = branch { body["branch"] = json!(b); }
    let v = c.json(reqwest::Method::POST, &c.files(project, "commit"), Some(&body)).await?;
    Ok(PushReport { files: files.len(), uploaded, bytes, version: v["version"].as_u64(), unchanged: v["unchanged"].as_bool() == Some(true), skipped })
}

/// A path from the Gate as a place under `root`: relative, plain names only, never through a symlink.
fn local_path(root: &Path, rel: &str) -> Result<PathBuf> {
    let p = Path::new(rel);
    if rel.is_empty() || !p.components().all(|c| matches!(c, Component::Normal(_))) || rel.split('/').any(|s| !name_ok(s)) { bail!("refusing the path {rel:?}"); }
    // Never into a .git folder: a hook pulled there runs on this computer at the next commit, outside every sandbox
    // (security audit 23 Nov 2026 #6). The Gate refuses such paths too; this holds even if it didn't.
    if rel.split('/').any(|s| s.eq_ignore_ascii_case(".git")) { bail!("refusing {rel:?}: a project's files never go into a .git folder"); }
    let mut at = root.to_path_buf();
    for c in p.components() {
        at.push(c);
        if let Ok(md) = std::fs::symlink_metadata(&at) { if md.file_type().is_symlink() { bail!("{} is a symlink; not writing through it", at.display()); } }
    }
    Ok(at)
}

pub struct PullReport { pub version: Option<u64>, pub written: usize, pub same: usize }

pub async fn pull(c: &Client, project: &str, root: &Path, version: Option<u64>, branch: Option<&str>) -> Result<PullReport> {
    let q = match (version, branch) { (Some(v), _) => format!("?version={v}"), (None, Some(b)) => format!("?branch={}", enc(b)), _ => String::new() };
    let t = c.json(reqwest::Method::GET, &c.files(project, &format!("tree{q}")), None).await?;
    std::fs::create_dir_all(root)?;
    let root = std::fs::canonicalize(root)?;
    let ver = t["version"].as_u64();
    let (mut written, mut same) = (0, 0);
    for f in t["files"].as_array().into_iter().flatten() {
        let (rel, sha, mode) = (f["path"].as_str().unwrap_or(""), f["sha256"].as_str().unwrap_or(""), f["mode"].as_u64().unwrap_or(FILE as u64) as u32);
        let dest = local_path(&root, rel)?;
        if dest.is_file() && hash_file(&dest).map(|(h, _)| h == sha).unwrap_or(false) { set_exec(&dest, mode == EXEC)?; same += 1; continue; }
        if let Some(parent) = dest.parent() { std::fs::create_dir_all(parent)?; }
        let vq = ver.map(|v| format!("&version={v}")).unwrap_or_default();
        let r = c.send(reqwest::Method::GET, &c.files(project, &format!("raw?path={}{vq}", enc(rel))), vec![], "").await?;
        if !r.status().is_success() { bail!("{rel}: {}", r.status()); }
        // Written beside, hashed as it comes, then moved into place.
        use futures_util::StreamExt;
        use std::io::Write;
        let tmp = dest.with_file_name(format!(".{}.pavilion-part", dest.file_name().unwrap().to_string_lossy()));
        let mut out = std::fs::File::create(&tmp)?;
        let mut h = Sha256::new();
        let mut stream = r.bytes_stream();
        while let Some(chunk) = stream.next().await { let chunk = chunk?; h.update(&chunk); out.write_all(&chunk)?; }
        out.sync_all()?;
        drop(out);
        if hex(&h.finalize()) != sha { let _ = std::fs::remove_file(&tmp); bail!("{rel} didn't match its hash; not written"); }
        std::fs::rename(&tmp, &dest)?;
        set_exec(&dest, mode == EXEC)?;
        written += 1;
    }
    Ok(PullReport { version: ver, written, same })
}

pub async fn cli(args: &[String]) -> Result<()> {
    let usage = "usage: pavilion-node project push <project> <folder> [-m message] [--branch b]\n       pavilion-node project pull <project> <folder> [--version n] [--branch b]";
    let (Some(cmd), Some(project), Some(folder)) = (args.first(), args.get(1), args.get(2)) else { bail!("{usage}") };
    let flag = |f: &str| args.iter().position(|a| a == f).and_then(|i| args.get(i + 1)).cloned();
    if !project.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') || project.is_empty() { bail!("{project} isn't a project id"); }
    let c = Client::from_state()?;
    match cmd.as_str() {
        "push" => {
            let root = PathBuf::from(folder);
            let name = std::fs::canonicalize(&root).ok().and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string())).unwrap_or_else(|| folder.clone());
            let msg = flag("-m").unwrap_or_else(|| format!("Pushed {name} from this machine"));
            let r = push(&c, project, &root, &msg, flag("--branch").as_deref()).await?;
            if !r.skipped.is_empty() { eprintln!("skipped {}: {}", r.skipped.len(), r.skipped.iter().take(12).cloned().collect::<Vec<_>>().join(", ") + if r.skipped.len() > 12 { ", …" } else { "" }); }
            if r.unchanged { println!("{} files, {} uploaded: nothing changed in {project}", r.files, r.uploaded); }
            else { println!("{} files, {} uploaded ({} MB): {project} is now version {}", r.files, r.uploaded, r.bytes / 1_048_576, r.version.map(|v| v.to_string()).unwrap_or_default()); }
        }
        "pull" => {
            let v = flag("--version").map(|v| v.parse::<u64>()).transpose().map_err(|_| anyhow!("--version is a number"))?;
            let r = pull(&c, project, Path::new(folder), v, flag("--branch").as_deref()).await?;
            match r.version { Some(v) => println!("version {v} of {project}: {} written, {} already the same", r.written, r.same), None => println!("{project} has no files yet") }
        }
        _ => bail!("{usage}"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};
    use hyper::{body::Incoming, Request, Response};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    #[test]
    fn pull_never_writes_into_a_git_folder() {
        let root = std::env::temp_dir().join(format!("pav-pull-{}", rand::random::<u32>()));
        std::fs::create_dir_all(&root).unwrap();
        for bad in [".git/hooks/pre-commit", "app/.git/config", ".GIT/HEAD", "../x", "/etc/passwd", ""] { assert!(local_path(&root, bad).is_err(), "{bad}"); }
        for ok in [".github/workflows/ci.yml", "docs/.gitignore", "a.git/x"] { assert!(local_path(&root, ok).is_ok(), "{ok}"); }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn ignore_rules() {
        let r = parse_ignore(&format!("{DEFAULT_IGNORE}*.log\n/build/\ndocs/**/draft-*.md\n!keep.log\n"));
        for p in [".DS_Store", "a/.DS_Store", "a/._x.png", ".git/config", "app/node_modules/x/index.js", ".env", "api/.env.local", "x/y.log", "build/out.js", "docs/a/b/draft-1.md", "docs/draft-2.md"] {
            assert!(ignored(p, &r, false), "{p}");
        }
        for p in ["src/main.rs", "node_modules.txt", ".env.example", "keep.log", "src/build/out.js", "build", "docs/a/final.md"] { assert!(!ignored(p, &r, false), "{p}"); }
        assert!(ignored("build", &r, true));
    }
    #[test]
    fn paths_from_the_gate_stay_inside() {
        let d = std::env::temp_dir().join(format!("pv-proj-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        assert!(local_path(&d, "a/b.txt").is_ok());
        for bad in ["../x", "/etc/passwd", "a/../../x", "", "a//b", "a\\b"] { assert!(local_path(&d, bad).is_err(), "{bad}"); }
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("/tmp", d.join("link")).unwrap();
            assert!(local_path(&d, "link/x.txt").is_err());
        }
        std::fs::remove_dir_all(&d).unwrap();
    }
    #[test]
    fn scan_skips_junk_and_never_follows_symlinks() {
        let d = std::env::temp_dir().join(format!("pv-scan-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let (root, outside) = (d.join("root"), d.join("outside"));
        for p in [root.join("src"), root.join("node_modules/dep"), root.join(".git"), outside.clone()] { std::fs::create_dir_all(p).unwrap(); }
        for (p, t) in [("src/a.rs", "fn a() {}"), ("node_modules/dep/x.js", "x"), (".git/HEAD", "ref"), (".DS_Store", "junk"), ("notes.log", "log"), (".pavilionignore", "*.log\n")] { std::fs::write(root.join(p), t).unwrap(); }
        std::fs::write(outside.join("secret.txt"), "secret").unwrap();
        #[cfg(unix)]
        { std::os::unix::fs::symlink(&outside, root.join("escape")).unwrap(); std::os::unix::fs::symlink(outside.join("secret.txt"), root.join("s.txt")).unwrap(); }
        let (files, skipped) = scan(&root).unwrap();
        assert_eq!(files.iter().map(|f| f.path.as_str()).collect::<Vec<_>>(), vec![".pavilionignore", "src/a.rs"]);
        assert!(skipped.iter().any(|s| s.starts_with("escape") && s.contains("symlink")), "{skipped:?}");
        assert!(skipped.iter().any(|s| s == "node_modules/") && skipped.iter().any(|s| s == "notes.log"), "{skipped:?}");
        assert_eq!(files[1].sha256, hex(&Sha256::digest(b"fn a() {}")));
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// A stand-in Gate: blobs by hash, one tree per commit; records which blobs were sent.
    #[derive(Default)]
    struct Fake { blobs: HashMap<String, Vec<u8>>, tree: Vec<Value>, puts: usize, version: u64 }
    async fn serve(state: Arc<Mutex<Fake>>) -> String {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((s, _)) = l.accept().await else { break };
                let st = state.clone();
                tokio::spawn(async move {
                    let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
                        let st = st.clone();
                        async move {
                            assert!(req.headers().contains_key("x-pavilion-signature"));
                            let (method, uri) = (req.method().clone(), req.uri().clone());
                            let body = req.into_body().collect().await.unwrap().to_bytes().to_vec();
                            let path = uri.path().to_string();
                            let mut g = st.lock().unwrap();
                            let reply = if path.ends_with("/missing") {
                                let v: Value = serde_json::from_slice(&body).unwrap();
                                json!({ "missing": v["hashes"].as_array().unwrap().iter().filter(|h| !g.blobs.contains_key(h.as_str().unwrap())).collect::<Vec<_>>() }).to_string()
                            } else if let Some(sha) = path.split("/blobs/").nth(1) {
                                assert_eq!(hex(&Sha256::digest(&body)), sha);
                                g.blobs.insert(sha.to_string(), body); g.puts += 1; json!({ "ok": true }).to_string()
                            } else if path.ends_with("/commit") {
                                let v: Value = serde_json::from_slice(&body).unwrap();
                                let files = v["changes"].as_array().unwrap().clone();
                                if files == g.tree { json!({ "version": g.version, "unchanged": true }).to_string() } else { g.tree = files; g.version += 1; json!({ "version": g.version }).to_string() }
                            } else if path.ends_with("/tree") {
                                json!({ "version": g.version, "files": g.tree }).to_string()
                            } else if path.ends_with("/raw") {
                                let q = uri.query().unwrap_or("");
                                let want = q.split('&').find_map(|kv| kv.strip_prefix("path=")).unwrap().replace("%2F", "/");
                                let sha = g.tree.iter().find(|f| f["path"] == want.as_str()).unwrap()["sha256"].as_str().unwrap().to_string();
                                return Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from(g.blobs[&sha].clone()))));
                            } else { panic!("{method} {path}") };
                            Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from(reply))))
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(s), svc).await;
                });
            }
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn push_sends_only_new_files_and_pull_gets_them_back() {
        let st = Arc::new(Mutex::new(Fake::default()));
        let gate = serve(st.clone()).await;
        let c = Client { http: reqwest::Client::new(), host: gate.trim_start_matches("http://").to_string(), gate, pavilion: "pv".into(), key: ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]) };
        let d = std::env::temp_dir().join(format!("pv-push-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let (src, dst) = (d.join("src"), d.join("dst"));
        std::fs::create_dir_all(src.join("a")).unwrap();
        std::fs::write(src.join("a/one.txt"), "same").unwrap();
        std::fs::write(src.join("two.txt"), "same").unwrap();
        std::fs::write(src.join("three.bin"), [0u8, 1, 2]).unwrap();
        let r = push(&c, "site", &src, "first", None).await.unwrap();
        assert_eq!((r.files, r.uploaded, r.version), (3, 2, Some(1)));
        let r = push(&c, "site", &src, "again", None).await.unwrap();
        assert!(r.unchanged && r.uploaded == 0);
        std::fs::write(src.join("two.txt"), "changed").unwrap();
        let r = push(&c, "site", &src, "edit", None).await.unwrap();
        assert_eq!((r.uploaded, r.version), (1, Some(2)));
        assert_eq!(st.lock().unwrap().puts, 3);
        let p = pull(&c, "site", &dst, None, None).await.unwrap();
        assert_eq!((p.written, p.same), (3, 0));
        for f in ["a/one.txt", "two.txt", "three.bin"] { assert_eq!(std::fs::read(src.join(f)).unwrap(), std::fs::read(dst.join(f)).unwrap()); }
        let p = pull(&c, "site", &dst, None, None).await.unwrap();
        assert_eq!((p.written, p.same), (0, 3));
        std::fs::remove_dir_all(&d).unwrap();
    }
}
