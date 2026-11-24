//! Starting the node by itself, as the person who owns this computer: a LaunchAgent on macOS, a systemd user unit on
//! Linux (Windows has its own, platform/windows.rs). `pavilion-node join` installs it, so a machine comes back after a
//! restart or a power cut without anyone typing `pavilion-node run`. `pavilion-node service uninstall` takes it away.
//!
//! The service only ever runs `<this program> run`: nothing from the pavilion chooses what it starts.
#![cfg(unix)]

use anyhow::{anyhow, bail, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

pub const LABEL: &str = "com.cloudpavilion.node";
pub const UNIT: &str = "pavilion-node.service";

fn home() -> Result<PathBuf> { std::env::var_os("HOME").map(PathBuf::from).ok_or_else(|| anyhow!("HOME isn't set")) }

/// The program the service starts: this one, with symlinks resolved (`~/.local/bin/pavilion-node` points into the app).
fn exe() -> Result<PathBuf> { Ok(std::fs::canonicalize(std::env::current_exe()?)?) }

/// The PATH the service runs with. launchd starts programs with only /usr/bin:/bin:/usr/sbin:/sbin, where Apple
/// `container` (Homebrew), Podman on some systems, and the CLIs the node drives aren't. So the service gets the PATH of
/// the person installing it, keeping only absolute folders (a relative entry such as `.` would run whatever is in the
/// folder the node happens to be in), without characters systemd or a plist would read differently, then the usual
/// system folders.
pub fn service_path(current: Option<&str>) -> String {
    let mut out: Vec<String> = Vec::new();
    let usual = ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"];
    for d in current.unwrap_or("").split(':').chain(usual) {
        let d = d.trim_end_matches('/');
        if !d.starts_with('/') || d.contains(['"', '\\', '\n', '\r', '%', '$', '&', '<', '>']) || out.iter().any(|o| o == d) { continue; }
        out.push(d.to_string());
    }
    out.join(":")
}

fn xml(s: &str) -> String { s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;") }

/// The LaunchAgent. `KeepAlive` restarts the node if it stops on an error, but not when it exits cleanly (another
/// `pavilion-node run` already holds this computer's link, state::run_lock), so the two never take turns.
pub fn launch_agent(exe: &Path, logs: &Path, path: &str) -> String {
    let in_app = exe.to_string_lossy().contains(".app/Contents/MacOS/");
    format!(r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{LABEL}</string>
  <key>ProgramArguments</key>
  <array><string>{}</string><string>run</string></array>{}
  <key>EnvironmentVariables</key><dict><key>PATH</key><string>{}</string></dict>
  <key>LimitLoadToSessionType</key><string>Aqua</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>ProcessType</key><string>Interactive</string>
  <key>StandardOutPath</key><string>{}</string>
  <key>StandardErrorPath</key><string>{}</string>
</dict>
</plist>
"#, xml(&exe.to_string_lossy()),
        if in_app { format!("\n  <key>AssociatedBundleIdentifiers</key><string>{LABEL}</string>") } else { String::new() }, xml(path),
        xml(&logs.join("node.out.log").to_string_lossy()), xml(&logs.join("node.err.log").to_string_lossy()))
}

/// The systemd user unit. systemd splits ExecStart on spaces, so the path is quoted (and refused if it holds a quote,
/// a backslash or a line break, which systemd would read as something else).
pub fn systemd_unit(exe: &Path, path: &str) -> Result<String> {
    let p = exe.to_string_lossy();
    if p.contains(['"', '\\', '\n', '\r', '%', '$']) { bail!("can't start {p} from systemd: the path has a character systemd treats specially"); }
    Ok(format!("[Unit]\nDescription=Cloud Pavilion node: this computer in its pavilion\nWants=network-online.target\nAfter=network-online.target\n\n\
[Service]\nEnvironment=\"PATH={path}\"\nExecStart=\"{p}\" run\nRestart=on-failure\nRestartSec=10\n\n[Install]\nWantedBy=default.target\n"))
}

fn plist_path() -> Result<PathBuf> { Ok(home()?.join("Library/LaunchAgents").join(format!("{LABEL}.plist"))) }
fn unit_path() -> Result<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from).filter(|p| p.is_absolute()).map_or_else(|| home().map(|h| h.join(".config")), Ok)?;
    Ok(base.join("systemd/user").join(UNIT))
}
fn uid() -> String { unsafe { libc::getuid() }.to_string() }
fn quiet(c: &mut Command) -> bool { c.stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status().map_or(false, |s| s.success()) }

/// Installs and starts the service. Returns what to tell the person.
pub fn install() -> Result<String> {
    let exe = exe()?;
    if cfg!(target_os = "macos") {
        let (plist, logs) = (plist_path()?, home()?.join("Library/Logs/pavilion-node"));
        std::fs::create_dir_all(plist.parent().unwrap())?;
        std::fs::create_dir_all(&logs)?;
        std::fs::write(&plist, launch_agent(&exe, &logs, &service_path(std::env::var("PATH").ok().as_deref())))?;
        let _ = quiet(Command::new("launchctl").args(["bootout", &format!("gui/{}/{LABEL}", uid())]));
        let out = Command::new("launchctl").args(["bootstrap", &format!("gui/{}", uid())]).arg(&plist).output()?;
        if !out.status.success() { bail!("launchctl couldn't load {}: {}", plist.display(), String::from_utf8_lossy(&out.stderr).trim()); }
        Ok(format!("It runs in the background now and starts again whenever you log in (logs in {}).", logs.display()))
    } else {
        let unit = unit_path()?;
        std::fs::create_dir_all(unit.parent().unwrap())?;
        std::fs::write(&unit, systemd_unit(&exe, &service_path(std::env::var("PATH").ok().as_deref()))?)?;
        if !quiet(Command::new("systemctl").args(["--user", "daemon-reload"])) {
            bail!("wrote {} but `systemctl --user` isn't available here; start `pavilion-node run` yourself (or from your init system)", unit.display());
        }
        let out = Command::new("systemctl").args(["--user", "enable", "--now", UNIT]).output()?;
        if !out.status.success() { bail!("systemctl --user enable --now {UNIT}: {}", String::from_utf8_lossy(&out.stderr).trim()); }
        let user = std::env::var("USER").unwrap_or_else(|_| "$USER".into());
        let linger = Command::new("loginctl").args(["show-user", &user, "-p", "Linger"]).output().ok()
            .map_or(false, |o| String::from_utf8_lossy(&o.stdout).trim() == "Linger=yes");
        Ok(format!("It runs in the background now (systemd: {UNIT}, logs with `journalctl --user -u {UNIT}`).{}",
            if linger { "" } else { "\nIt starts when you log in. To start it at boot without a login, run once: sudo loginctl enable-linger $USER" }))
    }
}

pub fn uninstall() -> Result<String> {
    if cfg!(target_os = "macos") {
        let plist = plist_path()?;
        let _ = quiet(Command::new("launchctl").args(["bootout", &format!("gui/{}/{LABEL}", uid())]));
        let had = plist.exists();
        if had { std::fs::remove_file(&plist)?; }
        Ok(if had { "Removed: the node no longer starts by itself. `pavilion-node run` still works.".into() } else { "It wasn't installed.".into() })
    } else {
        let unit = unit_path()?;
        let _ = quiet(Command::new("systemctl").args(["--user", "disable", "--now", UNIT]));
        let had = unit.exists();
        if had { std::fs::remove_file(&unit)?; let _ = quiet(Command::new("systemctl").args(["--user", "daemon-reload"])); }
        Ok(if had { "Removed: the node no longer starts by itself. `pavilion-node run` still works.".into() } else { "It wasn't installed.".into() })
    }
}

pub fn status() -> Result<String> {
    let (installed, running) = if cfg!(target_os = "macos") {
        let p = plist_path()?;
        (p.exists(), quiet(Command::new("launchctl").args(["print", &format!("gui/{}/{LABEL}", uid())])))
    } else {
        (unit_path()?.exists(), quiet(Command::new("systemctl").args(["--user", "is-active", "--quiet", UNIT])))
    };
    let holder = crate::state::run_holder();
    Ok(format!("{} · {}{}",
        if installed { "starts by itself" } else { "doesn't start by itself (pavilion-node service install)" },
        if running { "service loaded" } else { "service not loaded" },
        holder.map(|pid| format!(" · pavilion-node run is running (pid {pid})")).unwrap_or_else(|| " · pavilion-node run isn't running".into())))
}

pub fn cli(args: &[String]) -> Result<()> {
    match args.first().map(String::as_str) {
        Some("install") => {
            // An installed service's own run holds the lock: stop it first (it is started again below), then only a
            // run someone started by hand is in the way.
            if cfg!(target_os = "macos") { let _ = quiet(Command::new("launchctl").args(["bootout", &format!("gui/{}/{LABEL}", uid())])); }
            else { let _ = quiet(Command::new("systemctl").args(["--user", "stop", UNIT])); }
            for _ in 0..20 { if crate::state::run_holder().is_none() { break; } std::thread::sleep(std::time::Duration::from_millis(500)); }
            if let Some(pid) = crate::state::run_holder() { bail!("pavilion-node run is already running here (pid {pid}); stop it first, then install the service so it is the one that runs"); }
            println!("{}", install()?);
        }
        Some("uninstall") | Some("remove") => println!("{}", uninstall()?),
        None | Some("status") => println!("{}", status()?),
        Some(x) => bail!("unknown: service {x}. Use: service install | service uninstall | service status"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_launch_agent_runs_only_this_program_and_escapes_its_path() {
        let p = launch_agent(Path::new("/Users/a&b/Applications/Pavilion Node.app/Contents/MacOS/pavilion-node"), Path::new("/Users/a&b/Library/Logs/pavilion-node"), "/opt/homebrew/bin:/usr/bin");
        assert!(p.contains("<array><string>/Users/a&amp;b/Applications/Pavilion Node.app/Contents/MacOS/pavilion-node</string><string>run</string></array>"));
        assert!(p.contains("<key>AssociatedBundleIdentifiers</key><string>com.cloudpavilion.node</string>"));
        assert!(p.contains("<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>"));
        assert!(!p.contains("a&b"));
        assert!(p.contains("<key>PATH</key><string>/opt/homebrew/bin:/usr/bin</string>"));
        let bare = launch_agent(Path::new("/usr/local/bin/pavilion-node"), Path::new("/tmp/l"), "/usr/bin");
        assert!(!bare.contains("AssociatedBundleIdentifiers"));
    }

    #[test]
    fn the_systemd_unit_quotes_the_path_and_refuses_what_systemd_would_reinterpret() {
        let u = systemd_unit(Path::new("/home/me/my apps/pavilion-node"), "/usr/bin:/bin").unwrap();
        assert!(u.contains("Environment=\"PATH=/usr/bin:/bin\"\n"));
        assert!(u.contains("ExecStart=\"/home/me/my apps/pavilion-node\" run\n"));
        assert!(u.contains("Restart=on-failure"));
        for bad in ["/home/me/a\"b", "/home/me/a\\b", "/home/me/a\nExecStartPre=/bin/sh", "/home/%h/x", "/home/$USER/x"] {
            assert!(systemd_unit(Path::new(bad), "/usr/bin").is_err(), "{bad:?} should be refused");
        }
    }

    #[test]
    fn the_service_path_keeps_absolute_folders_and_adds_the_usual_ones() {
        assert_eq!(service_path(Some("/Users/me/.local/bin:.:bin::/opt/homebrew/bin/:/odd$dir:/usr/bin")),
            "/Users/me/.local/bin:/opt/homebrew/bin:/usr/bin:/usr/local/bin:/bin:/usr/sbin:/sbin");
        assert_eq!(service_path(None), "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin");
    }
}
