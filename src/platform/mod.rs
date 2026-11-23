//! What differs between the hosts the node runs on: small hooks the rest of the node calls. macOS and Linux run
//! everything on the host. Windows keeps only the node on Windows; sandboxes, media runners, input re-encoding and
//! model storage live in the pavilion WSL distro (sandbox/wsl.rs), so the Linux code paths run there unchanged.
pub mod sleep;
pub mod windows;

use std::path::{Path, PathBuf};

/// Whether process `pid` (of this machine) is running.
pub fn pid_alive(pid: i32) -> bool {
    #[cfg(unix)]
    { pid > 0 && unsafe { libc::kill(pid, 0) } == 0 }
    #[cfg(windows)]
    { windows::pid_alive(pid) }
}

/// Free and total MiB of the volume holding `p` (0, 0 when it isn't there).
pub fn disk(p: &Path) -> (u64, u64) {
    #[cfg(unix)]
    {
        let Ok(c) = std::ffi::CString::new(p.as_os_str().to_string_lossy().as_bytes()) else { return (0, 0) };
        let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 { return (0, 0); }
        let f = st.f_frsize as u64;
        ((st.f_bavail as u64 * f) >> 20, (st.f_blocks as u64 * f) >> 20)
    }
    #[cfg(windows)]
    { windows::disk(p) }
}

/// A host program (an install step, a test recording) made ready to start: unchanged on macOS and Linux; on Windows
/// the same program, arguments, environment and folder, run in the WSL distro.
pub fn linux_cmd(cmd: std::process::Command) -> std::process::Command {
    #[cfg(windows)]
    { crate::sandbox::wsl::wrap(&cmd, false) }
    #[cfg(not(windows))]
    { cmd }
}

/// A media runner: in its own process group, so stopping it stops everything it started (`kill_runner`).
pub fn runner_cmd(#[allow(unused_mut)] mut cmd: std::process::Command) -> std::process::Command {
    #[cfg(unix)]
    { use std::os::unix::process::CommandExt; cmd.process_group(0); cmd }
    #[cfg(windows)]
    { crate::sandbox::wsl::wrap(&cmd, true) }
}

/// Stops the runner started with `runner_cmd` (`pid` is what spawning it returned) and its group. Never 0 or 1.
pub fn kill_runner(pid: i32, hard: bool) {
    if pid <= 1 { return; }
    #[cfg(unix)]
    unsafe { libc::kill(-pid, if hard { libc::SIGKILL } else { libc::SIGTERM }); }
    #[cfg(windows)]
    crate::sandbox::wsl::kill_runner(hard);
}

/// A host path as the sandbox runtime sees it (a bind mount's source): itself, or on Windows the distro's Linux path.
pub fn runtime_path(p: &Path) -> String {
    #[cfg(windows)]
    { crate::sandbox::wsl::to_linux(&p.to_string_lossy()) }
    #[cfg(not(windows))]
    { p.display().to_string() }
}

/// Where media job folders live: the node's own folder; on Windows the distro's, where runners and re-encoding run.
pub fn media_dir() -> PathBuf {
    #[cfg(windows)]
    { crate::sandbox::wsl::unc(&format!("{}/media", crate::sandbox::wsl::HOME)) }
    #[cfg(not(windows))]
    { crate::state::dir().join("media") }
}

/// What to run when sandboxes can reach this machine's services.
pub fn firewall_hint() -> &'static str {
    if cfg!(windows) { "in PowerShell as administrator: node\\windows\\install.ps1" } else if cfg!(target_os = "macos") { "sudo node/pf/install.sh" } else { "a firewall rule for 10.89.0.0/16 (node/pf/pavilion.conf shows what it must do)" }
}
