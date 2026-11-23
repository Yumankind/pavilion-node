//! Where models live, and the owner's ways of putting them there (docs/MEDIA.md §5: adding a model is an owner action,
//! never a job). Models can live on another drive: a folder on an APFS drive, or an APFS sparse bundle on a drive that
//! can't hold the HF cache's symlinks (exFAT, FAT, NTFS). Nothing here runs from a job.
//!
//!   pavilion-node models storage                          where models live, and free space
//!   pavilion-node models storage <folder> [--move [--all]] [--yes] [--size-gb N]
//!   pavilion-node models storage --adopt <mount-or-image> use an existing folder or sparse bundle as it is
//!   pavilion-node models add <id> [--dry-run]             install a manifest's runner and weights, checksums checked
//!   pavilion-node models verify <id>                      a tiny real generation; marks the model verified
use super::catalog::{self, hub_in, manifests, repo_dir, Manifest};
use anyhow::{anyhow, bail, Result};
use serde_json::{json, Value};
use std::path::{Component, Path, PathBuf};

/// Hosts an install step may fetch from.
pub const HOSTS: &[&str] = &["huggingface.co", "cdn-lfs.huggingface.co", "github.com", "objects.githubusercontent.com"];
/// Free space kept on the boot disk: macOS needs room to swap with a model resident.
pub const BOOT_FLOOR_MB: u64 = 8 * 1024;
/// Margin kept on any other drive.
pub const DRIVE_MARGIN_MB: u64 = 2 * 1024;

/* ---------- install steps: a closed vocabulary, never a shell line ---------- */

fn safe_name(s: &str) -> bool { !s.is_empty() && s.len() <= 200 && s.chars().all(|c| c.is_ascii_alphanumeric() || "._-[],=<>!~ @:/+".contains(c)) && !s.starts_with('-') }
fn url_host(u: &str) -> Option<&str> { u.strip_prefix("https://")?.split('/').next() }

/// Checks one install step: `{kind: "uv_tool", package, with?}`, `{kind: "hf", repo, revision?, include?}`, `{kind: "git", repo, dir}`.
pub fn check_step(s: &Value) -> Result<(), String> {
    let repo_ok = |r: &str| { let p: Vec<&str> = r.split('/').collect(); p.len() == 2 && p.iter().all(|x| !x.is_empty() && !x.starts_with('.') && x.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))) };
    match s["kind"].as_str() {
        Some("uv_tool") => {
            let pkg = s["package"].as_str().ok_or("uv_tool needs a package")?;
            if !safe_name(pkg) || pkg.contains("://") { return Err(format!("bad package {pkg}")); }
            for w in s["with"].as_array().cloned().unwrap_or_default() {
                let w = w.as_str().ok_or("with is a list of packages")?;
                if !safe_name(w) { return Err(format!("bad package {w}")); }
                // A direct link (`name @ https://…`) only from an allowed host.
                if let Some((_, url)) = w.split_once(" @ ") { if !url_host(url.trim()).map_or(false, |h| HOSTS.contains(&h)) { return Err(format!("{url} isn't from an allowed host")); } }
                else if w.contains("://") { return Err(format!("bad package {w}")); }
            }
            Ok(())
        }
        Some("hf") => {
            let r = s["repo"].as_str().ok_or("hf needs a repo")?;
            if !repo_ok(r) { return Err(format!("bad repo {r}")); }
            if let Some(rev) = s["revision"].as_str() { if !(rev.len() == 40 && rev.chars().all(|c| c.is_ascii_hexdigit())) { return Err("revision is a commit hash".into()); } }
            for p in s["include"].as_array().cloned().unwrap_or_default() { let p = p.as_str().ok_or("include is a list of patterns")?; if p.contains("..") || p.starts_with('/') { return Err(format!("bad pattern {p}")); } }
            Ok(())
        }
        Some("git") => {
            let r = s["repo"].as_str().ok_or("git needs a repo")?;
            let r = r.strip_prefix("https://github.com/").or_else(|| r.strip_prefix("github.com/")).unwrap_or(r);
            if !repo_ok(r.trim_end_matches(".git")) { return Err(format!("bad repo {r} (github.com/org/name)")); }
            let d = s["dir"].as_str().ok_or("git needs a dir")?;
            if !relative_inside(d) { return Err(format!("dir {d} must stay inside model storage")); }
            Ok(())
        }
        // A step the owner does by hand (an installer script the node won't run): shown, never executed. `done_if` names
        // a path in model storage that exists once it's done.
        Some("manual") => {
            let n = s["note"].as_str().ok_or("manual needs a note")?;
            if n.is_empty() || n.len() > 400 { return Err("manual note is 1–400 characters".into()); }
            if let Some(d) = s["done_if"].as_str() { if !relative_inside(d) { return Err(format!("done_if {d} must stay inside model storage")); } }
            Ok(())
        }
        // Links a runner's own weights folder to files of a Hugging Face snapshot in model storage (Stable Audio's sa3
        // reads fixed paths next to itself).
        Some("link") => {
            let r = s["repo"].as_str().ok_or("link needs a repo")?;
            if !repo_ok(r) { return Err(format!("bad repo {r}")); }
            let d = s["dir"].as_str().ok_or("link needs a dir")?;
            if !relative_inside(d) { return Err(format!("dir {d} must stay inside model storage")); }
            let files = s["files"].as_array().ok_or("link needs files")?;
            if files.is_empty() || files.iter().any(|f| f.as_str().map_or(true, |f| !relative_inside(f))) { return Err("files are paths inside the snapshot".into()); }
            Ok(())
        }
        k => Err(format!("unknown install step {k:?}")),
    }
}
fn relative_inside(d: &str) -> bool { let p = Path::new(d); !d.is_empty() && p.components().all(|c| matches!(c, Component::Normal(_))) }

/* ---------- space ---------- */

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Space {
    /// Free on the volume the files land on (for a sparse bundle: what it can still grow into).
    pub volume_free_mb: u64,
    /// Free on the physical drive under a disk image.
    pub physical_free_mb: Option<u64>,
    /// The target is the Mac's own disk.
    pub boot: bool,
}

/// Whether `need_mb` more fits: a margin of 2 GB on another drive, 8 GB on the boot disk, which is never left under 8 GB.
pub fn space_ok(need_mb: u64, s: &Space) -> Result<(), String> {
    let gb = |mb: u64| format!("{:.1} GB", mb as f64 / 1024.0);
    let margin = if s.boot { BOOT_FLOOR_MB } else { DRIVE_MARGIN_MB };
    let free = s.physical_free_mb.map_or(s.volume_free_mb, |p| p.min(s.volume_free_mb));
    if free < need_mb + margin {
        return Err(format!("not enough space: this needs {} plus {} kept free{}, and {} is free{}", gb(need_mb), gb(margin),
            if s.boot { " on the boot disk" } else { "" }, gb(free),
            if s.boot { ". Put models on another drive: pavilion-node models storage <folder> --move" } else { "" }));
    }
    Ok(())
}

#[cfg(unix)]
fn dev_of(p: &Path) -> Option<u64> { use std::os::unix::fs::MetadataExt; std::fs::metadata(p).ok().map(|m| m.dev()) }
/// Windows: models live in the WSL distro's disk, on the drive `pavilion-node storage` chose.
#[cfg(windows)]
fn dev_of(_p: &Path) -> Option<u64> { None }
/// Whether `p` is on the Mac's own disk (the system or data volume).
pub fn on_boot_disk(p: &Path) -> bool {
    let p = p.ancestors().find(|a| a.exists()).unwrap_or(Path::new("/"));
    let d = dev_of(p);
    d.is_some() && (d == dev_of(Path::new("/")) || d == dev_of(Path::new("/System/Volumes/Data")))
}
pub fn space_at(hub: &Path, image: Option<&Path>) -> Space {
    let probe = hub.ancestors().find(|a| a.exists()).unwrap_or(Path::new("/")).to_path_buf();
    let (free, _) = catalog::disk(&probe);
    let physical = image.and_then(|i| i.parent()).map(|d| catalog::disk(d).0);
    Space { volume_free_mb: free, physical_free_mb: physical, boot: image.map_or_else(|| on_boot_disk(&probe), |i| on_boot_disk(i)) }
}

/* ---------- disk images ---------- */

/// The file system type ("apfs", "hfs", "exfat", "msdos", "ntfs"…) and mount point of the volume holding `p`.
#[cfg(target_os = "macos")]
pub fn fs_of(p: &Path) -> (String, PathBuf) {
    let Ok(c) = std::ffi::CString::new(p.as_os_str().to_string_lossy().as_bytes()) else { return (String::new(), PathBuf::from("/")) };
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(c.as_ptr(), &mut st) } != 0 { return (String::new(), PathBuf::from("/")); }
    let s = |a: &[libc::c_char]| unsafe { std::ffi::CStr::from_ptr(a.as_ptr()) }.to_string_lossy().to_string();
    (s(&st.f_fstypename), PathBuf::from(s(&st.f_mntonname)))
}
#[cfg(not(target_os = "macos"))]
pub fn fs_of(_p: &Path) -> (String, PathBuf) { (String::new(), PathBuf::from("/")) }

fn diskutil_field(p: &Path, key: &str) -> String {
    let out = std::process::Command::new("diskutil").arg("info").arg(p).output().map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
    out.lines().find(|l| l.trim_start().starts_with(key)).and_then(|l| l.split_once(':')).map(|(_, v)| v.trim().to_string()).unwrap_or_default()
}

/// Attaches the models' disk image when it isn't mounted. Ok(false) when there's no image or its drive is unplugged.
pub fn ensure_attached() -> Result<bool> {
    let st = catalog::storage();
    let (Some(image), Some(mount)) = (st.image.clone(), st.chosen.clone()) else { return Ok(false) };
    if mount.is_dir() { return Ok(true); }
    if !image.exists() { return Ok(false); }
    let out = std::process::Command::new("hdiutil").args(["attach", "-nobrowse"]).arg(&image).output()?;
    if !out.status.success() { bail!("hdiutil attach {}: {}", image.display(), String::from_utf8_lossy(&out.stderr).trim()); }
    Ok(mount.is_dir())
}

/// Mount point of an attached image, from `hdiutil info`.
fn mount_of(image: &Path) -> Option<PathBuf> {
    let out = String::from_utf8_lossy(&std::process::Command::new("hdiutil").arg("info").output().ok()?.stdout).to_string();
    let canon = std::fs::canonicalize(image).ok()?;
    let mut in_it = false;
    for l in out.lines() {
        if let Some(p) = l.strip_prefix("image-path") { in_it = std::fs::canonicalize(p.trim_start_matches([' ', ':']).trim()).ok().as_ref() == Some(&canon); continue; }
        if l.starts_with("====") { in_it = false; }
        if in_it { if let Some(i) = l.find("/Volumes/") { return Some(PathBuf::from(l[i..].trim())); } }
    }
    None
}

/* ---------- the CLI ---------- */

pub async fn cli(args: &[String]) -> Result<()> {
    let flag = |f: &str| args.iter().any(|a| a == f);
    let opt = |f: &str| args.iter().position(|a| a == f).and_then(|i| args.get(i + 1)).cloned();
    match args.first().map(String::as_str) {
        None | Some("list") => {
            let _ = ensure_attached();
            let st = catalog::storage();
            println!("{}", serde_json::to_string_pretty(&json!({ "model_storage": catalog::storage_report(&st), "media_models": catalog::report(&catalog::catalog()) }))?);
            Ok(())
        }
        Some("storage") => {
            #[cfg(windows)]
            if args.len() > 1 { bail!("on Windows, models live in the pavilion WSL distro, on its disk; move that with: pavilion-node storage <folder>"); }
            if let Some(a) = opt("--adopt") { return adopt(Path::new(&a)); }
            match args.get(1).filter(|a| !a.starts_with("--")) {
                None => { let _ = ensure_attached(); let st = catalog::storage(); let r = catalog::storage_report(&st);
                    println!("models: {} · {} GiB free of {} GiB{}{}", r["path"].as_str().unwrap_or(""), r["free_mib"].as_u64().unwrap_or(0) / 1024, r["total_mib"].as_u64().unwrap_or(0) / 1024,
                        st.image.as_ref().map(|i| format!(" · disk image {}", i.display())).unwrap_or_default(), if st.missing { " · NOT MOUNTED" } else { "" }); Ok(()) }
                Some(folder) => choose(Path::new(folder), flag("--move"), flag("--all"), flag("--yes"), opt("--size-gb").and_then(|s| s.parse().ok()).unwrap_or(200)).await,
            }
        }
        Some("add") => { let id = args.get(1).ok_or_else(|| anyhow!("which model? pavilion-node models add <id>"))?; add(id, flag("--dry-run")).await }
        Some("verify") => { let id = args.get(1).ok_or_else(|| anyhow!("which model? pavilion-node models verify <id>"))?; super::verify(id).await }
        Some(x) => bail!("unknown: models {x}. Use: models | models storage [folder] [--move [--all]] | models storage --adopt <path> | models add <id> [--dry-run] | models verify <id>"),
    }
}

/// Points the node at models already in place: a folder (its huggingface/hub inside), a mounted image, or a sparse bundle.
fn adopt(p: &Path) -> Result<()> {
    let s = p.to_string_lossy();
    if s.ends_with(".sparsebundle") || s.ends_with(".sparseimage") || s.ends_with(".dmg") {
        let image = std::fs::canonicalize(p).map_err(|_| anyhow!("{} doesn't exist", p.display()))?;
        let mount = match mount_of(&image) { Some(m) => m, None => {
            let out = std::process::Command::new("hdiutil").args(["attach", "-nobrowse"]).arg(&image).output()?;
            if !out.status.success() { bail!("couldn't attach {}: {}", image.display(), String::from_utf8_lossy(&out.stderr).trim()); }
            mount_of(&image).ok_or_else(|| anyhow!("attached {}, but can't see where", image.display()))?
        } };
        crate::state::set_config("model_storage", json!({ "image": image.to_string_lossy(), "mount": mount.to_string_lossy() }))?;
    } else {
        let mount = std::fs::canonicalize(p).map_err(|_| anyhow!("{} doesn't exist", p.display()))?;
        // A mounted volume that is a disk image: remember the image too, so the node can attach it again after a restart.
        let image = image_behind(&mount);
        crate::state::set_config("model_storage", match &image { Some(i) => json!({ "image": i.to_string_lossy(), "mount": mount.to_string_lossy() }), None => json!(mount.to_string_lossy()) })?;
    }
    let st = catalog::storage();
    let found: Vec<String> = manifests().iter().filter_map(|m| m.weights.as_ref().filter(|w| catalog::snapshot(&st.hub, &w.hf, w.revision.as_deref()).is_some()).map(|_| m.id.clone())).collect();
    println!("models now live in {}{} · found here: {}", st.hub.display(), st.image.as_ref().map(|i| format!(" (disk image {})", i.display())).unwrap_or_default(),
        if found.is_empty() { "none of the catalog's models".into() } else { found.join(", ") });
    Ok(())
}
fn image_behind(mount: &Path) -> Option<PathBuf> {
    let out = String::from_utf8_lossy(&std::process::Command::new("hdiutil").arg("info").output().ok()?.stdout).to_string();
    let mut image = None;
    for l in out.lines() {
        if let Some(p) = l.strip_prefix("image-path") { image = Some(PathBuf::from(p.trim_start_matches([' ', ':']).trim())); }
        if l.contains(&*mount.to_string_lossy()) && l.contains("/Volumes/") { return image; }
    }
    None
}

async fn choose(folder: &Path, do_move: bool, all: bool, yes: bool, size_gb: u64) -> Result<()> {
    if !cfg!(target_os = "macos") { bail!("on Linux, point HF_HUB_CACHE at the drive (phase 1)"); }
    let p = std::fs::canonicalize(folder).map_err(|_| anyhow!("{} doesn't exist; make the folder first", folder.display()))?;
    if !p.is_dir() { bail!("{} isn't a folder", p.display()); }
    let probe = p.join(format!(".pavilion-write-test-{}", rand::random::<u32>()));
    std::fs::write(&probe, b"").map_err(|_| anyhow!("can't write in {}", p.display()))?;
    let _ = std::fs::remove_file(&probe);
    let (fs, mnt) = fs_of(&p);
    let encrypted = diskutil_field(&mnt, "FileVault").eq_ignore_ascii_case("yes") || diskutil_field(&mnt, "Encrypted").eq_ignore_ascii_case("yes");
    println!("{} · {} on {} · {}", p.display(), if fs.is_empty() { "file system unknown" } else { &fs }, mnt.display(), if encrypted { "encrypted" } else { "NOT encrypted" });
    if !encrypted { eprintln!("warning: this drive isn't encrypted. Model files aren't secret, but outputs aren't kept here either; encrypt it in Disk Utility if it travels."); }
    let symlinks_ok = ["apfs", "hfs"].contains(&fs.as_str());
    let mount = if symlinks_ok { p.clone() } else {
        // exFAT, FAT and NTFS can't hold the HF cache's symlinks (and gather ._ files): use an APFS sparse bundle on it.
        let image = p.join("pavilion-models.sparsebundle");
        println!("{fs} can't hold the model cache's links. A disk image on it can: {} (APFS, grows as needed up to {size_gb} GB).", image.display());
        if !yes && !confirm("Create it? [y/N] ") { bail!("not changed"); }
        if !image.exists() {
            let ok = std::process::Command::new("hdiutil").args(["create", "-type", "SPARSEBUNDLE", "-fs", "APFS", "-volname", "PavilionModels", "-size", &format!("{size_gb}g")]).arg(&image).status()?.success();
            if !ok { bail!("hdiutil create failed"); }
        }
        let out = std::process::Command::new("hdiutil").args(["attach", "-nobrowse"]).arg(&image).output()?;
        if !out.status.success() && mount_of(&image).is_none() { bail!("couldn't attach {}", image.display()); }
        let m = mount_of(&image).ok_or_else(|| anyhow!("attached {}, but can't see where", image.display()))?;
        let old = catalog::storage();
        if do_move { move_models(&old.hub, &hub_in(&m), all, old.image.is_none() && old.chosen.is_none()).await?; }
        crate::state::set_config("model_storage", json!({ "image": image.to_string_lossy(), "mount": m.to_string_lossy() }))?;
        println!("models now live in {}", hub_in(&m).display());
        return Ok(());
    };
    let old = catalog::storage();
    if do_move { move_models(&old.hub, &hub_in(&mount), all, old.image.is_none() && old.chosen.is_none()).await?; }
    crate::state::set_config("model_storage", json!(mount.to_string_lossy()))?;
    println!("models now live in {}", hub_in(&mount).display());
    Ok(())
}

fn confirm(q: &str) -> bool {
    use std::io::Write;
    eprint!("{q}"); let _ = std::io::stderr().flush();
    let mut l = String::new();
    std::io::stdin().read_line(&mut l).is_ok() && l.trim().eq_ignore_ascii_case("y")
}

/* ---------- moving models (only ours, unless --all) ---------- */

/// Lexically resolves `target` relative to `base` (no filesystem access).
fn resolve(base: &Path, target: &Path) -> PathBuf {
    let mut out = if target.is_absolute() { PathBuf::new() } else { base.to_path_buf() };
    for c in target.components() { match c { Component::ParentDir => { out.pop(); } Component::CurDir => {} c => out.push(c.as_os_str()) } }
    out
}

/// Walks a repo folder: (path, is_link).
fn walk(dir: &Path) -> Vec<(PathBuf, bool)> {
    let mut v = vec![]; let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            let p = e.path(); let Ok(t) = e.file_type() else { continue };
            let n = e.file_name().to_string_lossy().to_string();
            if n.starts_with("._") || n == ".DS_Store" { continue; } // AppleDouble litter from exFAT drives
            if t.is_dir() { stack.push(p); } else { v.push((p, t.is_symlink())); }
        }
    }
    v
}

/// Copies one HF repo from `old_hub` to `new_hub`, links kept as links. Blobs it links to outside its folder (the shared
/// store) are copied too and returned. Files already there with the right size are kept (a move can resume).
pub fn copy_repo(old_hub: &Path, new_hub: &Path, name: &str) -> Result<Vec<PathBuf>, String> {
    let (src, dst) = (old_hub.join(name), new_hub.join(name));
    let mut shared = vec![];
    for (p, link) in walk(&src) {
        let rel = p.strip_prefix(&src).unwrap();
        let to = dst.join(rel);
        std::fs::create_dir_all(to.parent().unwrap()).map_err(|e| e.to_string())?;
        if link {
            let target = std::fs::read_link(&p).map_err(|e| e.to_string())?;
            let real = resolve(p.parent().unwrap(), &target);
            if !real.starts_with(old_hub) { return Err(format!("{} links outside the model cache; not moving it", p.display())); }
            if !real.starts_with(&src) {
                let rel_shared = real.strip_prefix(old_hub).unwrap().to_path_buf();
                copy_file(&real, &new_hub.join(&rel_shared))?;
                if !shared.contains(&rel_shared) { shared.push(rel_shared); }
            }
            #[cfg(unix)]
            if std::fs::symlink_metadata(&to).is_err() { std::os::unix::fs::symlink(&target, &to).map_err(|e| e.to_string())?; }
            #[cfg(windows)]
            return Err(format!("{}: moving models isn't done on Windows (they live in the WSL distro)", target.display()));
        } else {
            copy_file(&p, &to)?;
        }
    }
    // Check: every file of the copy is there, links resolve, sizes match.
    for (p, _) in walk(&src) {
        let to = dst.join(p.strip_prefix(&src).unwrap());
        let (a, b) = (std::fs::metadata(&p).map(|m| m.len()), std::fs::metadata(&to).map(|m| m.len()));
        if a.is_ok() && a.as_ref().ok() != b.as_ref().ok() { return Err(format!("{} didn't copy completely", to.display())); }
    }
    Ok(shared)
}
fn copy_file(from: &Path, to: &Path) -> Result<(), String> {
    let len = std::fs::metadata(from).map_err(|e| format!("{}: {e}", from.display()))?.len();
    if std::fs::metadata(to).map(|m| m.len() == len).unwrap_or(false) { return Ok(()); }
    std::fs::create_dir_all(to.parent().unwrap()).map_err(|e| e.to_string())?;
    let tmp = to.with_extension("pavilion-copy");
    std::fs::copy(from, &tmp).map_err(|e| format!("copying {}: {e}", from.display()))?;
    std::fs::rename(&tmp, to).map_err(|e| e.to_string())
}

/// Removes the old copy of a moved repo, and shared blobs no remaining repo in `old_hub` links to.
pub fn remove_old(old_hub: &Path, names: &[String], shared: &[PathBuf]) -> Result<(), String> {
    for n in names { std::fs::remove_dir_all(old_hub.join(n)).map_err(|e| e.to_string())?; }
    let mut still_used = std::collections::HashSet::new();
    for e in std::fs::read_dir(old_hub).into_iter().flatten().flatten() {
        if !e.file_name().to_string_lossy().starts_with("models--") { continue; }
        for (p, link) in walk(&e.path()) {
            if link { if let Ok(t) = std::fs::read_link(&p) { still_used.insert(resolve(p.parent().unwrap(), &t)); } }
        }
    }
    for s in shared { let p = old_hub.join(s); if !still_used.contains(&p) { let _ = std::fs::remove_file(&p); } }
    Ok(())
}

async fn move_models(old_hub: &Path, new_hub: &Path, all: bool, _from_default: bool) -> Result<()> {
    if super::busy() { bail!("a media job is running; wait for it (or stop the node) before moving models"); }
    if old_hub == new_hub { println!("the models are already there"); return Ok(()); }
    let ours: Vec<String> = manifests().iter().filter_map(|m| m.weights.as_ref()).flat_map(|w| std::iter::once(w.hf.clone()).chain(w.also.iter().cloned()))
        .map(|r| repo_dir(Path::new(""), &r).to_string_lossy().to_string()).collect();
    let names: Vec<String> = std::fs::read_dir(old_hub).into_iter().flatten().flatten().map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.starts_with("models--") && (all || ours.contains(n))).collect();
    if names.is_empty() { println!("no models to move in {}", old_hub.display()); return Ok(()); }
    let need: u64 = names.iter().map(|n| walk(&old_hub.join(n)).iter().filter_map(|(p, _)| std::fs::metadata(p).ok()).map(|m| m.len()).sum::<u64>()).sum::<u64>() >> 20;
    let st = catalog::storage();
    space_ok(need, &space_at(new_hub, st.image.as_deref())).map_err(|e| anyhow!(e))?;
    std::fs::create_dir_all(new_hub)?;
    let mut shared = vec![];
    for n in &names { println!("copying {n}…"); shared.extend(copy_repo(old_hub, new_hub, n).map_err(|e| anyhow!(e))?); }
    remove_old(old_hub, &names, &shared).map_err(|e| anyhow!(e))?;
    println!("moved {} model(s), {:.1} GB, to {}", names.len(), need as f64 / 1024.0, new_hub.display());
    Ok(())
}

/* ---------- adding a model ---------- */

/// A Python that has huggingface_hub: one of the media tools' own environments.
fn hf_python() -> Option<PathBuf> {
    for tool in ["mflux-generate", "mlx_whisper", "mlx_audio.tts.generate"] {
        let Some(b) = catalog::program(tool) else { continue };
        let Ok(real) = std::fs::canonicalize(b) else { continue };
        let py = real.parent()?.join("python");
        if py.exists() { return Some(py); }
    }
    None
}

const HF_FETCH: &str = "import sys, json\nfrom huggingface_hub import snapshot_download\na = json.loads(sys.argv[1])\nprint(snapshot_download(repo_id=a['repo'], revision=a.get('revision'), cache_dir=a['cache'], allow_patterns=a.get('include')))\n";

/// Model storage's own folder, from its HF cache (<root>/huggingface/hub): where `runners/` lives too.
fn root_of(hub: &Path) -> PathBuf { hub.parent().and_then(|p| p.parent()).unwrap_or(hub).to_path_buf() }

/// What `models add` would do, step by step.
pub fn plan_add(m: &Manifest, hub: &Path) -> Vec<String> {
    m.install.iter().map(|s| match s["kind"].as_str().unwrap_or("") {
        "uv_tool" => format!("uv tool install {}{}", s["package"].as_str().unwrap_or(""), s["with"].as_array().map(|w| w.iter().filter_map(|x| x.as_str()).map(|x| format!(" --with '{x}'")).collect::<String>()).unwrap_or_default()),
        "hf" => format!("download {}{} from huggingface.co into {}{}", s["repo"].as_str().unwrap_or(""), s["revision"].as_str().map(|r| format!("@{}", &r[..r.len().min(12)])).unwrap_or_default(),
            hub.display(), s["include"].as_array().map(|i| format!(", only {}", i.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(" "))).unwrap_or_default()),
        "manual" => format!("by hand: {}", s["note"].as_str().unwrap_or("")),
        "link" => format!("link {} file(s) of {} into {}", s["files"].as_array().map_or(0, |f| f.len()), s["repo"].as_str().unwrap_or(""), root_of(hub).join(s["dir"].as_str().unwrap_or("")).display()),
        "git" => format!("git clone --depth 1 https://github.com/{} into {}", s["repo"].as_str().unwrap_or("").trim_start_matches("https://github.com/").trim_start_matches("github.com/"), root_of(hub).join(s["dir"].as_str().unwrap_or("")).display()),
        k => format!("unknown step {k}"),
    }).collect()
}

async fn add(id: &str, dry_run: bool) -> Result<()> {
    let m = manifests().into_iter().find(|m| m.id == id).ok_or_else(|| anyhow!("no model {id} in the catalog"))?;
    if m.unsupported { let p = catalog::platform(); bail!("{id} has no version for this machine ({} {} {})", p.os, p.arch, p.accel); }
    for s in &m.install { check_step(s).map_err(|e| anyhow!("{id}: {e}"))?; }
    let _ = ensure_attached();
    let st = catalog::storage();
    if st.missing { bail!("model storage {} isn't mounted; plug the drive in", st.chosen.as_ref().map(|c| c.display().to_string()).unwrap_or_default()); }
    let need = (m.size_gb * 1024.0).ceil() as u64;
    let space = space_at(&st.hub, st.image.as_deref());
    let fits = space_ok(need, &space);
    println!("{id}: {} · {} · {}", m.license, if m.commercial { "commercial use OK" } else { "NOT for commercial use" }, if m.gated { "gated (needs a Hugging Face login)" } else { "public" });
    for (i, s) in plan_add(&m, &st.hub).iter().enumerate() { println!("  {}. {s}", i + 1); }
    match &fits { Ok(()) => println!("  space: {:.1} GB in all, {:.1} GB free{}", m.size_gb, space.physical_free_mb.map_or(space.volume_free_mb, |p| p.min(space.volume_free_mb)) as f64 / 1024.0, if space.boot { " (boot disk)" } else { "" }),
        Err(e) => println!("  space: {e}") }
    if dry_run { println!("(dry run: nothing downloaded)"); return Ok(()); }
    fits.map_err(|e| anyhow!(e))?;
    for s in &m.install {
        match s["kind"].as_str().unwrap_or("") {
            "uv_tool" => {
                let uv = catalog::program("uv").ok_or_else(|| anyhow!("uv isn't installed (https://docs.astral.sh/uv/)"))?;
                let mut a = vec!["tool".to_string(), "install".into(), s["package"].as_str().unwrap_or("").into()];
                for w in s["with"].as_array().cloned().unwrap_or_default() { a.extend(["--with".into(), w.as_str().unwrap_or("").into()]); }
                let mut c = std::process::Command::new(uv);
                c.args(&a);
                // Windows: in the WSL distro (platform/mod.rs), like every program here.
                if !crate::platform::linux_cmd(c).status()?.success() { bail!("uv tool install failed"); }
            }
            "hf" => {
                let repo = s["repo"].as_str().unwrap_or("").to_string();
                if catalog::hubs(&st).iter().any(|h| catalog::snapshot(h, &repo, s["revision"].as_str()).is_some()) { println!("  {repo} is there already"); continue; }
                let py = hf_python().ok_or_else(|| anyhow!("no Python with huggingface_hub: install the model's runner first"))?;
                std::fs::create_dir_all(&st.hub)?;
                let arg = json!({ "repo": repo, "revision": s["revision"], "cache": st.hub.to_string_lossy(), "include": s["include"] }).to_string();
                // HF_HUB_DISABLE_XET: the xet path has crashed mid-download ("Unable to parse string as hex hash value").
                let mut c = std::process::Command::new(py);
                c.args(["-I", "-c", HF_FETCH, &arg]).env("HF_HUB_DISABLE_XET", "1").env("HF_HUB_DISABLE_TELEMETRY", "1").env_remove("HF_HUB_OFFLINE");
                let mut c = crate::platform::linux_cmd(c);
                c.stdout(std::process::Stdio::piped());
                let mut child = tokio::process::Command::from(c).spawn()?;
                let dir = repo_dir(&st.hub, &repo);
                let total = need.max(1) << 20;
                loop {
                    tokio::select! {
                        r = child.wait() => { if !r?.success() { bail!("downloading {repo} failed (run it again to resume)"); } break; }
                        _ = tokio::time::sleep(std::time::Duration::from_secs(2)) => {
                            let landed: u64 = walk(&dir).iter().filter(|(_, l)| !l).filter_map(|(p, _)| std::fs::metadata(p).ok()).map(|m| m.len()).sum();
                            eprint!("\r  {repo}: {:.1} of {:.1} GB ({}%)   ", landed as f64 / (1u64 << 30) as f64, m.size_gb, (landed * 100 / total).min(100));
                        }
                    }
                }
                eprintln!();
                let bad = verify_blobs(&dir)?;
                if !bad.is_empty() { bail!("checksums don't match for {} file(s) of {repo}; removed them, run it again", bad.len()); }
            }
            "manual" => {
                if s["done_if"].as_str().map_or(false, |d| root_of(&st.hub).join(d).exists()) { println!("  done already: {}", s["note"].as_str().unwrap_or("")); continue; }
                println!("Finish by hand, then run this again: pavilion-node models add {id}\n  {}", s["note"].as_str().unwrap_or(""));
                return Ok(());
            }
            "link" => {
                let repo = s["repo"].as_str().unwrap_or("");
                let snap = catalog::hubs(&st).into_iter().find_map(|h| catalog::snapshot(&h, repo, None)).ok_or_else(|| anyhow!("{repo} isn't downloaded yet"))?;
                let dir = root_of(&st.hub).join(s["dir"].as_str().unwrap_or(""));
                std::fs::create_dir_all(&dir)?;
                for f in s["files"].as_array().cloned().unwrap_or_default() {
                    let f = f.as_str().unwrap_or("");
                    let (from, to) = (snap.join(f), dir.join(Path::new(f).file_name().unwrap_or_default()));
                    if !from.is_file() { bail!("{repo} has no {f}"); }
                    // Only links are replaced, never a real file.
                    match std::fs::symlink_metadata(&to) { Ok(m) if !m.file_type().is_symlink() => bail!("{} is a file, not a link; not touching it", to.display()), Ok(_) => std::fs::remove_file(&to)?, Err(_) => {} }
                    #[cfg(unix)]
                    std::os::unix::fs::symlink(&from, &to)?;
                    #[cfg(windows)]
                    std::os::windows::fs::symlink_file(&from, &to)?;
                }
                println!("  linked {} into {}", repo, dir.display());
            }
            "git" => {
                let r = s["repo"].as_str().unwrap_or("").trim_start_matches("https://github.com/").trim_start_matches("github.com/").trim_end_matches(".git").to_string();
                let dir = root_of(&st.hub).join(s["dir"].as_str().unwrap_or(""));
                if dir.exists() { println!("  {} is there already", dir.display()); continue; }
                let mut c = std::process::Command::new("git");
                c.args(["clone", "--depth", "1", &format!("https://github.com/{r}")]).arg(&dir);
                if !crate::platform::linux_cmd(c).status()?.success() { bail!("git clone failed"); }
            }
            _ => {}
        }
    }
    println!("{id} installed. Check it on this machine: pavilion-node models verify {id}");
    Ok(())
}

/// LFS blobs are named by their SHA-256: checks each, removes the ones that don't match. Returns those.
pub fn verify_blobs(repo: &Path) -> Result<Vec<PathBuf>> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut bad = vec![];
    for e in std::fs::read_dir(repo.join("blobs")).into_iter().flatten().flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if name.len() != 64 || !name.chars().all(|c| c.is_ascii_hexdigit()) { continue; }
        let mut f = std::fs::File::open(e.path())?;
        let mut h = Sha256::new();
        let mut buf = vec![0u8; 1 << 20];
        loop { let n = f.read(&mut buf)?; if n == 0 { break; } h.update(&buf[..n]); }
        let got: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
        if got != name.to_lowercase() { let _ = std::fs::remove_file(e.path()); bad.push(e.path()); }
    }
    Ok(bad)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    fn manifests_for_mac() -> Vec<Manifest> { catalog::manifests_for(&catalog::Platform { os: "macos".into(), arch: "arm64".into(), accel: "mlx".into(), vram_gb: None }) }
    fn tmp(n: &str) -> PathBuf { let d = std::env::temp_dir().join(format!("pavilion-store-{n}-{}", rand::random::<u32>())); std::fs::create_dir_all(&d).unwrap(); d }

    #[test]
    fn install_steps_are_a_closed_vocabulary() {
        assert!(check_step(&json!({ "kind": "uv_tool", "package": "mflux==0.19.1" })).is_ok());
        assert!(check_step(&json!({ "kind": "uv_tool", "package": "mlx-audio", "with": ["misaki[en]", "en_core_web_sm @ https://github.com/explosion/spacy-models/releases/download/x.whl"] })).is_ok());
        assert!(check_step(&json!({ "kind": "uv_tool", "package": "x", "with": ["evil @ https://evil.example/x.whl"] })).is_err());
        assert!(check_step(&json!({ "kind": "uv_tool", "package": "--index-url=https://evil.example" })).is_err());
        assert!(check_step(&json!({ "kind": "uv_tool", "package": "x; rm -rf /" })).is_err());
        assert!(check_step(&json!({ "kind": "hf", "repo": "org/model", "revision": "794cd159538149ad9830848508c31f0ea7088e58", "include": ["*.json"] })).is_ok());
        assert!(check_step(&json!({ "kind": "hf", "repo": "../../etc" })).is_err());
        assert!(check_step(&json!({ "kind": "hf", "repo": "org/model", "revision": "main; x" })).is_err());
        assert!(check_step(&json!({ "kind": "hf", "repo": "org/model", "include": ["../x"] })).is_err());
        assert!(check_step(&json!({ "kind": "git", "repo": "comfyanonymous/ComfyUI", "dir": "comfy/ComfyUI" })).is_ok());
        assert!(check_step(&json!({ "kind": "git", "repo": "comfyanonymous/ComfyUI", "dir": "../../outside" })).is_err());
        assert!(check_step(&json!({ "kind": "git", "repo": "https://evil.example/x/y", "dir": "x" })).is_err());
        assert!(check_step(&json!({ "kind": "shell", "cmd": "curl | sh" })).is_err());
        assert!(check_step(&json!({ "kind": "manual", "note": "run ./install.sh by hand" })).is_ok());
        assert!(check_step(&json!({ "kind": "manual" })).is_err());
        assert!(check_step(&json!({ "kind": "manual", "note": "x", "done_if": "../../etc" })).is_err());
        assert!(check_step(&json!({ "kind": "link", "repo": "org/m", "files": ["MLX/a.npz"], "dir": "runners/x/models" })).is_ok());
        assert!(check_step(&json!({ "kind": "link", "repo": "org/m", "files": ["/etc/passwd"], "dir": "runners/x" })).is_err());
        assert!(check_step(&json!({ "kind": "link", "repo": "org/m", "files": ["a"], "dir": "../x" })).is_err());
    }

    #[test]
    fn space_decisions() {
        let ext = Space { volume_free_mb: 10_000, physical_free_mb: None, boot: false };
        assert!(space_ok(7_000, &ext).is_ok());
        assert!(space_ok(8_500, &ext).unwrap_err().contains("plus 2.0 GB kept free"));
        // A sparse bundle that could grow, on a nearly full drive: the drive decides.
        let img = Space { volume_free_mb: 200_000, physical_free_mb: Some(5_000), boot: false };
        assert!(space_ok(4_400, &img).is_err());
        assert!(space_ok(2_000, &img).is_ok());
        // The boot disk keeps 8 GB: 13 GB free takes a 4.4 GB model, 7.5 GB free takes nothing.
        let boot = Space { volume_free_mb: 13 * 1024, physical_free_mb: None, boot: true };
        assert!(space_ok(4_400, &boot).is_ok());
        assert!(space_ok(6_000, &boot).unwrap_err().contains("on the boot disk"));
        let low = Space { volume_free_mb: 7_680, physical_free_mb: None, boot: true };
        assert!(space_ok(100, &low).unwrap_err().contains("models storage <folder> --move"));
        assert!(on_boot_disk(&std::env::temp_dir()));
        #[cfg(target_os = "macos")]
        assert_eq!(fs_of(&std::env::temp_dir()).0, "apfs");
    }

    #[test]
    fn plan_names_size_and_place() {
        let m = manifests_for_mac().into_iter().find(|m| m.id == "flux2-klein-4b").unwrap();
        let p = plan_add(&m, Path::new("/Volumes/X/huggingface/hub"));
        assert!(p.iter().any(|s| s.starts_with("uv tool install mflux")));
        assert!(p.iter().any(|s| s.contains("mflux-community/flux2-klein-4b-mflux-q4@794cd1595381 from huggingface.co into /Volumes/X/huggingface/hub")), "{p:?}");
        let ltx = manifests_for_mac().into_iter().find(|m| m.id == "ltx-2.3-distilled-q4").unwrap();
        assert!(plan_add(&ltx, Path::new("/Volumes/X/huggingface/hub")).iter().any(|s| s.ends_with("into /Volumes/X/runners/ltx-2-mlx")));
    }

    /// An HF cache like the real one: snapshot → repo blob → shared store, plus another app's repo sharing nothing.
    fn fake_hub(hub: &Path, repo: &str, store_name: &str, data: &[u8]) {
        let r = hub.join(repo);
        std::fs::create_dir_all(r.join("snapshots/abc")).unwrap();
        std::fs::create_dir_all(r.join("blobs")).unwrap();
        std::fs::create_dir_all(r.join("refs")).unwrap();
        std::fs::write(r.join("refs/main"), "abc").unwrap();
        std::fs::create_dir_all(hub.join("blobs/78")).unwrap();
        std::fs::write(hub.join("blobs/78").join(store_name), data).unwrap();
        symlink(format!("../../blobs/78/{store_name}"), r.join("blobs/big")).unwrap();
        std::fs::write(r.join("blobs/cfg"), b"{}").unwrap();
        symlink("../../blobs/big", r.join("snapshots/abc/model.safetensors")).unwrap();
        symlink("../../blobs/cfg", r.join("snapshots/abc/config.json")).unwrap();
        std::fs::write(r.join("snapshots/abc/._model.safetensors"), b"appledouble").unwrap();
    }

    #[test]
    fn moving_copies_links_and_the_shared_store_and_leaves_others_alone() {
        let (old, new) = (tmp("old"), tmp("new"));
        fake_hub(&old, "models--org--ours", "s1", b"weights-ours");
        fake_hub(&old, "models--other--app", "s2", b"weights-other");
        let shared = copy_repo(&old, &new, "models--org--ours").unwrap();
        assert_eq!(shared, vec![PathBuf::from("blobs/78/s1")]);
        assert_eq!(std::fs::read(new.join("models--org--ours/snapshots/abc/model.safetensors")).unwrap(), b"weights-ours");
        assert!(std::fs::symlink_metadata(new.join("models--org--ours/snapshots/abc/model.safetensors")).unwrap().file_type().is_symlink());
        assert!(!new.join("models--org--ours/snapshots/abc/._model.safetensors").exists(), "AppleDouble litter isn't copied");
        assert!(catalog::snapshot(&new, "org/ours", None).is_some());
        // Copying again resumes (nothing to do) and still checks.
        assert!(copy_repo(&old, &new, "models--org--ours").is_ok());
        remove_old(&old, &["models--org--ours".into()], &shared).unwrap();
        assert!(!old.join("models--org--ours").exists());
        assert!(!old.join("blobs/78/s1").exists(), "our shared blob goes with us");
        assert!(old.join("blobs/78/s2").exists() && catalog::snapshot(&old, "other/app", None).is_some(), "another app's model is untouched");
        // A link pointing outside the cache is refused.
        let evil = old.join("models--org--evil/snapshots/abc");
        std::fs::create_dir_all(&evil).unwrap();
        symlink("/etc/hosts", evil.join("x")).unwrap();
        assert!(copy_repo(&old, &new, "models--org--evil").unwrap_err().contains("outside"));
    }

    #[test]
    fn blob_checksums() {
        let r = tmp("blobs");
        std::fs::create_dir_all(r.join("blobs")).unwrap();
        let good = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"; // sha256("hello")
        std::fs::write(r.join("blobs").join(good), b"hello").unwrap();
        let bad = "0000000000000000000000000000000000000000000000000000000000000000";
        std::fs::write(r.join("blobs").join(bad), b"hello").unwrap();
        std::fs::write(r.join("blobs/a6344aac8c09253b3b630fb776ae94478aa0275b"), b"git-sha1 named, not checked").unwrap();
        let v = verify_blobs(&r).unwrap();
        assert_eq!(v.len(), 1);
        assert!(r.join("blobs").join(good).exists() && !r.join("blobs").join(bad).exists());
    }
}
