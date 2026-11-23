//! The node on Windows itself (compile-checked from macOS, not run yet: node/windows/TESTING.md): its folder and key
//! file (owner-only ACL), the guard's readings from the Windows API, listening ports, VM storage on any NTFS or ReFS
//! drive, running at logon, and stopping cleanly. Programs are always started with an argument list from System32,
//! never through cmd or a command string.
#![cfg_attr(not(windows), allow(dead_code))]
use std::path::PathBuf;

/// A folder or file the owner names: a full path on a drive letter (an external drive is fine). Network paths, `.`
/// and `..`, alternate data streams, reserved device names and characters Windows refuses are turned away.
pub fn check_path(s: &str) -> Result<PathBuf, String> {
    let s = s.trim();
    if s.starts_with(r"\\") || s.starts_with("//") { return Err("network (UNC) paths aren't accepted: use a drive letter, like D:\\Pavilion".into()); }
    let b = s.as_bytes();
    if b.len() < 3 || !b[0].is_ascii_alphabetic() || b[1] != b':' || !(b[2] == b'\\' || b[2] == b'/') { return Err(format!("{s:?} isn't a full path: use a drive letter, like D:\\Pavilion")); }
    let mut parts = vec![];
    for p in s[3..].split(['\\', '/']).filter(|p| !p.is_empty()) {
        if p == "." || p == ".." { return Err("no '.' or '..' in the path, please".into()); }
        if p.contains(':') { return Err("a path has one ':', after the drive letter".into()); }
        if p.chars().any(|c| c.is_control() || "<>\"|?*".contains(c)) || p.ends_with('.') || p.ends_with(' ') { return Err(format!("{p:?} isn't a name Windows allows")); }
        let stem = p.split('.').next().unwrap_or("").to_ascii_uppercase();
        let reserved = ["CON", "PRN", "AUX", "NUL"].contains(&stem.as_str()) || ((stem.starts_with("COM") || stem.starts_with("LPT")) && stem.len() == 4 && stem.as_bytes()[3].is_ascii_digit());
        if reserved { return Err(format!("{p:?} is a device name on Windows")); }
        parts.push(p);
    }
    Ok(PathBuf::from(format!("{}:\\{}", (b[0] as char).to_ascii_uppercase(), parts.join("\\"))))
}

/// "D:\" for a path checked by `check_path`.
pub fn drive_root(p: &std::path::Path) -> String { p.to_string_lossy().chars().next().map(|d| format!("{}:\\", d.to_ascii_uppercase())).unwrap_or_default() }

/// TCP ports listening beyond loopback, from `netstat -ano -p TCP` and `-p TCPv6`. The state column is translated on
/// non-English Windows, so a listening socket is the one whose foreign address is 0.0.0.0:0 or [::]:0.
pub fn parse_netstat(out: &str) -> Vec<u16> {
    let mut ports = std::collections::BTreeSet::new();
    for l in out.lines() {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() < 3 || !f[0].eq_ignore_ascii_case("TCP") || !(f[2] == "0.0.0.0:0" || f[2] == "[::]:0") { continue; }
        let Some((addr, port)) = f[1].rsplit_once(':') else { continue };
        let a = addr.trim_start_matches('[').trim_end_matches(']').to_ascii_lowercase();
        if a.starts_with("127.") || a == "::1" || a.starts_with("fe80") { continue; }
        let Ok(p) = port.parse::<u16>() else { continue };
        if (47100..=47199).contains(&p) { continue; } // our own brokers
        ports.insert(p);
    }
    ports.into_iter().collect()
}

/// IPv4 addresses, one per line (from Get-NetIPAddress): checked, without loopback and link-local.
pub fn parse_ipv4s(out: &str) -> Vec<std::net::Ipv4Addr> {
    let mut v: Vec<std::net::Ipv4Addr> = out.lines().filter_map(|l| l.trim().parse().ok()).filter(|ip: &std::net::Ipv4Addr| !ip.is_loopback() && !ip.is_link_local() && !ip.is_unspecified()).collect();
    v.sort(); v.dedup(); v
}

/// The SID in `whoami /user /fo csv /nh` ("pc\name","S-1-5-21-…").
pub fn parse_sid(out: &str) -> Option<String> {
    out.split(',').map(|f| f.trim().trim_matches('"')).find(|f| f.starts_with("S-1-") && f.len() < 200 && f[4..].bytes().all(|b| b.is_ascii_digit() || b == b'-')).map(String::from)
}

/// icacls arguments that leave `path` to its owner alone: inherited entries removed, full control for `sid` only.
/// Files made later in a folder treated this way inherit the same.
pub fn icacls_args(path: &str, sid: &str, dir: bool) -> Vec<String> {
    vec![path.into(), "/inheritance:r".into(), "/grant:r".into(), format!("*{sid}:{}F", if dir { "(OI)(CI)" } else { "" }), "/Q".into()]
}

/// Shell's System.Volume.BitLockerProtection: 1 on, 3 encrypting, 5 on but suspended… 2 off, 4 decrypting.
pub fn bitlocker(v: &str) -> Option<bool> {
    match v.trim() { "1" | "3" | "5" | "6" => Some(true), "0" | "2" | "4" => Some(false), _ => None }
}

/// The guard's memory reading on Windows.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Mem { pub total_mib: u64, pub free_pct: u32, pub pressure: u32, pub swap_total_mib: u64, pub swap_used_mib: u64 }

/// From GlobalMemoryStatusEx. Windows fails allocations when the commit charge reaches its limit (RAM plus the page
/// file), so pressure follows the commit charge as well as the memory load. "Swap" is the page file: its size is the
/// commit limit beyond RAM, its use the commit charge beyond RAM.
pub fn mem_from(load: u32, total_phys: u64, avail_phys: u64, commit_limit: u64, commit_avail: u64) -> Mem {
    if total_phys == 0 { return Mem::default(); }
    let commit_used = commit_limit.saturating_sub(commit_avail);
    let commit_pct = if commit_limit > 0 { commit_used * 100 / commit_limit } else { 100 };
    let pressure = if commit_pct >= 95 || load >= 95 { 4 } else if commit_pct >= 85 || load >= 85 { 2 } else { 1 };
    Mem { total_mib: total_phys >> 20, free_pct: (avail_phys.min(total_phys) * 100 / total_phys) as u32, pressure,
        swap_total_mib: commit_limit.saturating_sub(total_phys) >> 20, swap_used_mib: commit_used.saturating_sub(total_phys) >> 20 }
}

fn xml(s: &str) -> String { s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&apos;") }

pub const TASK: &str = "Cloud Pavilion node";

/// The scheduled task that runs `pavilion-node run` when `user` logs on (WSL distros belong to a user, so a Windows
/// service, which runs as another account, couldn't reach them). No time limit (the default stops a task after 3
/// days), restarted when it stops, on battery too. `conhost --headless` keeps it from opening a console window.
pub fn task_xml(exe: &str, user: &str) -> Result<String, String> {
    if exe.contains('"') || exe.starts_with(r"\\") || !exe.to_ascii_lowercase().ends_with(".exe") { return Err(format!("can't register {exe}: put pavilion-node.exe in a folder on a drive")); }
    let dir = std::path::Path::new(exe).parent().map(|d| d.to_string_lossy().to_string()).unwrap_or_default();
    Ok(format!(r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Cloud Pavilion: keeps this PC connected to its pavilion (pavilion-node run).</Description></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>{user}</UserId><Delay>PT30S</Delay></LogonTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>{user}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <RestartOnFailure><Interval>PT1M</Interval><Count>999</Count></RestartOnFailure>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author"><Exec><Command>{conhost}</Command><Arguments>--headless "{exe}" run</Arguments><WorkingDirectory>{dir}</WorkingDirectory></Exec></Actions>
</Task>
"#, user = xml(user), exe = xml(exe), dir = xml(&dir), conhost = xml(&system32("conhost.exe").to_string_lossy())))
}

/// A program in Windows' System32 (never looked up on PATH or in the current folder).
pub fn system32(name: &str) -> PathBuf {
    let root = std::env::var("SystemRoot").ok().filter(|r| check_path(r).is_ok()).unwrap_or_else(|| r"C:\Windows".into());
    PathBuf::from(root).join("System32").join(name)
}

/* ---------- the Windows side (Windows only) ---------- */

#[cfg(windows)]
pub use self::win::*;

#[cfg(windows)]
mod win {
    use super::*;
    use anyhow::{anyhow, bail, Context, Result};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::process::CommandExt;
    use std::path::Path;

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    fn sys(name: &str) -> std::process::Command { let mut c = std::process::Command::new(system32(name)); c.creation_flags(CREATE_NO_WINDOW); c }
    fn powershell(script: &str) -> Option<String> {
        let out = sys(r"WindowsPowerShell\v1.0\powershell.exe").args(["-NoProfile", "-NonInteractive", "-Command", script]).output().ok()?;
        out.status.success().then(|| String::from_utf8_lossy(&out.stdout).to_string())
    }
    fn wide(p: &Path) -> Vec<u16> {
        let mut s = p.as_os_str().to_os_string();
        if !s.to_string_lossy().ends_with('\\') { s.push("\\"); }
        s.encode_wide().chain(Some(0)).collect()
    }

    /// %LOCALAPPDATA%\pavilion-node
    pub fn state_dir() -> PathBuf {
        let base = std::env::var("LOCALAPPDATA").ok().or_else(|| std::env::var("USERPROFILE").ok().map(|u| format!(r"{u}\AppData\Local"))).unwrap_or_else(|| ".".into());
        PathBuf::from(base).join("pavilion-node")
    }
    /// Where VM data lives unless the owner picks a folder: next to the node's own.
    pub fn default_vm_storage() -> String { std::env::var("LOCALAPPDATA").unwrap_or_else(|_| r"C:\".into()) }

    fn sid() -> Result<String> {
        static S: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
        S.get_or_init(|| sys("whoami.exe").args(["/user", "/fo", "csv", "/nh"]).output().ok().and_then(|o| parse_sid(&String::from_utf8_lossy(&o.stdout))))
            .clone().ok_or_else(|| anyhow!("couldn't tell this user's SID (whoami /user)"))
    }
    /// Leaves `path` to this user alone (the node's folder before its key is written, the key file after).
    pub fn private(path: &Path, dir: bool) -> Result<()> {
        let out = sys("icacls.exe").args(icacls_args(&path.to_string_lossy(), &sid()?, dir)).output().context("running icacls")?;
        if !out.status.success() { bail!("icacls {}: {}", path.display(), String::from_utf8_lossy(&out.stdout).trim()); }
        Ok(())
    }

    pub fn memory() -> Mem {
        use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
        let mut m: MEMORYSTATUSEX = unsafe { std::mem::zeroed() };
        m.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
        if unsafe { GlobalMemoryStatusEx(&mut m) } == 0 { return Mem::default(); }
        mem_from(m.dwMemoryLoad, m.ullTotalPhys, m.ullAvailPhys, m.ullTotalPageFile, m.ullAvailPageFile)
    }

    pub fn disk(p: &Path) -> (u64, u64) {
        use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
        let w = wide(p);
        let (mut avail, mut total, mut free) = (0u64, 0u64, 0u64);
        if unsafe { GetDiskFreeSpaceExW(w.as_ptr(), &mut avail, &mut total, &mut free) } == 0 { return (0, 0); }
        (avail >> 20, total >> 20)
    }

    /// NTFS, ReFS, exFAT… of the volume at `root` ("D:\").
    pub fn fs_name(root: &str) -> String {
        use windows_sys::Win32::Storage::FileSystem::GetVolumeInformationW;
        let w = wide(Path::new(root));
        let mut name = [0u16; 64];
        let ok = unsafe { GetVolumeInformationW(w.as_ptr(), std::ptr::null_mut(), 0, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), name.as_mut_ptr(), name.len() as u32) };
        if ok == 0 { return String::new(); }
        String::from_utf16_lossy(&name[..name.iter().position(|c| *c == 0).unwrap_or(name.len())])
    }

    /// The local ceiling must be owned by Administrators or SYSTEM, so a program running as this user can't have
    /// written it (ceiling.rs). node/windows/ceiling.ps1 makes the folder and file that way.
    pub fn admin_owned(p: &Path) -> std::result::Result<(), String> {
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
        use windows_sys::Win32::Security::{IsWellKnownSid, WinBuiltinAdministratorsSid, WinLocalSystemSid, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID};
        let w: Vec<u16> = p.as_os_str().encode_wide().chain(Some(0)).collect();
        let (mut owner, mut sd): (PSID, PSECURITY_DESCRIPTOR) = (std::ptr::null_mut(), std::ptr::null_mut());
        let r = unsafe { GetNamedSecurityInfoW(w.as_ptr(), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &mut owner, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), &mut sd) };
        if r != 0 { return Err(format!("can't read who owns {} (error {r})", p.display())); }
        let ok = unsafe { IsWellKnownSid(owner, WinBuiltinAdministratorsSid) != 0 || IsWellKnownSid(owner, WinLocalSystemSid) != 0 };
        unsafe { LocalFree(sd as _) };
        if ok { Ok(()) } else { Err(format!("{} isn't owned by Administrators, so the node can't trust it (run node\\windows\\ceiling.ps1 as administrator)", p.display())) }
    }

    /// Minutes after midnight, local time.
    pub fn local_minute() -> u16 {
        use windows_sys::Win32::System::SystemInformation::GetLocalTime;
        let mut t = unsafe { std::mem::zeroed() };
        unsafe { GetLocalTime(&mut t) };
        t.wHour * 60 + t.wMinute
    }

    pub fn pid_alive(pid: i32) -> bool {
        use windows_sys::Win32::Foundation::{CloseHandle, STILL_ACTIVE};
        use windows_sys::Win32::System::Threading::{GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
        if pid <= 0 { return false; }
        let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid as u32) };
        if h.is_null() { return false; }
        let mut code = 0u32;
        let ok = unsafe { GetExitCodeProcess(h, &mut code) } != 0;
        unsafe { CloseHandle(h) };
        ok && code == STILL_ACTIVE as u32
    }

    pub fn exposed_ports() -> Vec<u16> {
        let mut all = String::new();
        for p in ["TCP", "TCPv6"] { if let Ok(o) = sys("netstat.exe").args(["-ano", "-p", p]).output() { all.push_str(&String::from_utf8_lossy(&o.stdout)); } }
        parse_netstat(&all)
    }

    /// This PC's IPv4 addresses, the one WSL reaches it on (vEthernet (WSL)) included.
    pub fn host_ipv4s() -> Vec<String> {
        powershell("Get-NetIPAddress -AddressFamily IPv4 | ForEach-Object IPAddress").map(|o| parse_ipv4s(&o).iter().map(|i| i.to_string()).collect()).unwrap_or_default()
    }

    /// Some(true) when BitLocker protects drive `root` ("D:\"), read the way Explorer does (no administrator needed,
    /// and unlike manage-bde's output, not translated).
    pub fn bitlocker_on(root: &str) -> Option<bool> {
        let d = root.chars().next().filter(|c| c.is_ascii_alphabetic())?;
        bitlocker(&powershell(&format!("(New-Object -ComObject Shell.Application).NameSpace('{d}:').Self.ExtendedProperty('System.Volume.BitLockerProtection')"))?)
    }

    /// `pavilion-node storage <folder>`: where the distro's disk (VHDX) lives. Any NTFS or ReFS drive, external too.
    pub async fn storage(path: &str) -> Result<()> {
        let p = check_path(path).map_err(|e| anyhow!(e))?;
        if !p.is_dir() { bail!("{} doesn't exist; make the folder first", p.display()); }
        let root = drive_root(&p);
        let fs = fs_name(&root);
        let enc = bitlocker_on(&root);
        println!("{} · {} · {}", p.display(), if fs.is_empty() { "file system unknown" } else { &fs },
            match enc { Some(true) => "BitLocker on", Some(false) => "NOT encrypted", None => "encryption unknown" });
        if !["NTFS", "REFS"].contains(&fs.to_ascii_uppercase().as_str()) { bail!("the distro's disk must be on NTFS or ReFS (WSL keeps it as a VHDX file); this is {fs}"); }
        if enc != Some(true) { eprintln!("warning: this drive isn't known to be encrypted. The distro's disk holds job workspaces and models; anyone who unplugs the drive can read them. Turn on BitLocker (BitLocker To Go for an external drive)."); }
        if crate::sandbox::wsl::registered() {
            let busy = crate::sandbox::wsl::podman().args(["ps", "--filter", "label=pavilion.job", "--format", "{{.Names}}"]).output().await.map(|o| !o.stdout.is_empty()).unwrap_or(true);
            if busy || crate::media::busy() { bail!("jobs are running; stop the node (or wait) before moving VM storage"); }
            let to = p.join("pavilion-wsl");
            eprintln!("Moving the pavilion distro's disk to {}…", to.display());
            crate::sandbox::wsl::move_disk(&to)?;
        }
        crate::state::set_config("vm_storage", serde_json::json!(p.to_string_lossy()))?;
        let s = crate::guard::sample();
        println!("VM storage is now {} · {} GiB free. The guard watches this drive, and stops every job if it's unplugged.", s.storage, s.disk_free_mib / 1024);
        Ok(())
    }

    /// `pavilion-node service install | uninstall | status`: a scheduled task at logon.
    pub fn service(args: &[String]) -> Result<()> {
        match args.first().map(String::as_str) {
            Some("install") => {
                let exe = std::env::current_exe()?.to_string_lossy().to_string();
                let user = String::from_utf8_lossy(&sys("whoami.exe").output()?.stdout).trim().to_string();
                if user.is_empty() { bail!("couldn't tell who is logged on (whoami)"); }
                let x = task_xml(&exe, &user).map_err(|e| anyhow!(e))?;
                // Task Scheduler reads UTF-16 with a byte order mark.
                let f = crate::state::dir().join("task.xml");
                std::fs::create_dir_all(crate::state::dir())?;
                std::fs::write(&f, [vec![0xFF, 0xFE], x.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()].concat())?;
                let st = sys("schtasks.exe").args(["/Create", "/TN", TASK, "/XML"]).arg(&f).arg("/F").status();
                let _ = std::fs::remove_file(&f);
                if !st?.success() { bail!("schtasks /Create failed"); }
                println!("pavilion-node now starts when {user} logs on (Task Scheduler › {TASK}). Start it now: schtasks /Run /TN \"{TASK}\"");
                Ok(())
            }
            Some("uninstall") => {
                let _ = sys("schtasks.exe").args(["/End", "/TN", TASK]).status();
                if !sys("schtasks.exe").args(["/Delete", "/TN", TASK, "/F"]).status()?.success() { bail!("schtasks /Delete failed"); }
                println!("removed; sandboxes it left are stopped the next time the node runs");
                Ok(())
            }
            None | Some("status") => { let _ = sys("schtasks.exe").args(["/Query", "/TN", TASK, "/V", "/FO", "LIST"]).creation_flags(0).status()?; Ok(()) }
            Some(x) => bail!("unknown: service {x}. Use: service install | service uninstall | service status"),
        }
    }

    /// Waits for Ctrl-C, Ctrl-Break, the console closing, logoff or shutdown.
    pub async fn wait_for_stop() {
        use tokio::signal::windows::{ctrl_break, ctrl_c, ctrl_close, ctrl_logoff, ctrl_shutdown};
        let (mut a, mut b, mut c, mut d, mut e) = (ctrl_c().expect("signal handler"), ctrl_break().expect("signal handler"), ctrl_close().expect("signal handler"),
            ctrl_logoff().expect("signal handler"), ctrl_shutdown().expect("signal handler"));
        tokio::select! { _ = a.recv() => {}, _ = b.recv() => {}, _ = c.recv() => {}, _ = d.recv() => {}, _ = e.recv() => {} }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_paths_need_a_drive_and_nothing_tricky() {
        assert_eq!(check_path(r"d:\Pavilion\VMs").unwrap(), PathBuf::from(r"D:\Pavilion\VMs"));
        assert_eq!(check_path("E:/pavilion//vms/").unwrap(), PathBuf::from(r"E:\pavilion\vms"));
        assert_eq!(check_path(r"F:\").unwrap(), PathBuf::from(r"F:\"));
        for bad in [r"\\nas\share\vms", "//nas/share", r"\\?\D:\x", r"\\.\PhysicalDrive0", r"Pavilion\VMs", r"D:Pavilion", r"D:\a\..\Windows", r"D:\a\.\b", r"D:\x:stream",
            r"D:\con", r"D:\Lpt1.txt", r"D:\a|b", "D:\\a\u{0}b", r"D:\trailing.", r"D:\space \x", "", "C"] {
            assert!(check_path(bad).is_err(), "{bad:?}");
        }
        assert_eq!(drive_root(&check_path(r"g:\x").unwrap()), r"G:\");
    }

    #[test]
    fn listening_ports_from_netstat_in_any_language() {
        let out = "\nActive Connections\n\n  Proto  Local Address          Foreign Address        State           PID\n\
            \x20 TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1100\n\
            \x20 TCP    0.0.0.0:445            0.0.0.0:0              ABHÖREN         4\n\
            \x20 TCP    127.0.0.1:5939         0.0.0.0:0              LISTENING       4520\n\
            \x20 TCP    0.0.0.0:47100          0.0.0.0:0              LISTENING       9000\n\
            \x20 TCP    192.168.1.20:50112     20.42.73.29:443        ESTABLISHED     7000\n\
            \x20 TCP    192.168.1.20:3000      0.0.0.0:0              LISTENING       7100\n\
            \x20 TCP    [::]:135               [::]:0                 LISTENING       1100\n\
            \x20 TCP    [::1]:8080             [::]:0                 LISTENING       1200\n\
            \x20 TCP    [fe80::1%12]:9000      [::]:0                 LISTENING       1300\n\
            \x20 TCP    [::]:5357              [::]:0                 LISTENING       4\n\
            \x20 UDP    0.0.0.0:5353           *:*                                    2000\n";
        assert_eq!(parse_netstat(out), vec![135, 445, 3000, 5357]);
        assert!(parse_netstat("").is_empty());
    }

    #[test]
    fn addresses_sids_and_bitlocker() {
        assert_eq!(parse_ipv4s("192.168.1.20\r\n127.0.0.1\r\n172.22.16.1\r\n169.254.3.4\r\nnot an ip\r\n192.168.1.20\r\n").iter().map(|i| i.to_string()).collect::<Vec<_>>(),
            vec!["172.22.16.1", "192.168.1.20"]);
        assert_eq!(parse_sid("\"desktop-1\\bruno\",\"S-1-5-21-111-222-333-1001\"\r\n").as_deref(), Some("S-1-5-21-111-222-333-1001"));
        assert_eq!(parse_sid("\"x\",\"S-1-5-21-1; del *\""), None);
        assert_eq!(icacls_args(r"C:\Users\b\AppData\Local\pavilion-node", "S-1-5-21-1-1001", true),
            vec![r"C:\Users\b\AppData\Local\pavilion-node", "/inheritance:r", "/grant:r", "*S-1-5-21-1-1001:(OI)(CI)F", "/Q"]);
        assert_eq!(icacls_args("k", "S-1-5-21-1-1001", false)[3], "*S-1-5-21-1-1001:F");
        assert_eq!(bitlocker("1\r\n"), Some(true));
        assert_eq!(bitlocker("2"), Some(false));
        assert_eq!(bitlocker(""), None);
    }

    #[test]
    fn memory_readings_map_to_the_guard() {
        let gib = 1u64 << 30;
        // 32 GB, half free, 12 GB committed of a 40 GB limit (an 8 GB page file).
        let m = mem_from(50, 32 * gib, 16 * gib, 40 * gib, 28 * gib);
        assert_eq!((m.total_mib, m.free_pct, m.pressure, m.swap_total_mib, m.swap_used_mib), (32768, 50, 1, 8192, 0));
        // The commit charge near its limit: critical even with memory free (allocations start failing there).
        assert_eq!(mem_from(50, 32 * gib, 16 * gib, 40 * gib, gib).pressure, 4);
        assert_eq!(mem_from(88, 32 * gib, 4 * gib, 40 * gib, 20 * gib).pressure, 2);
        // Committed beyond RAM is counted as page file use.
        assert_eq!(mem_from(90, 16 * gib, gib, 24 * gib, 4 * gib).swap_used_mib, 4096);
        assert_eq!(mem_from(0, 0, 0, 0, 0), Mem::default());
        let s = crate::guard::Sample { mem_total_mib: m.total_mib, mem_free_pct: m.free_pct, pressure: m.pressure, swap_total_mib: m.swap_total_mib, swap_used_mib: m.swap_used_mib,
            disk_free_mib: 200_000, disk_total_mib: 500_000, ..Default::default() };
        assert_eq!(crate::guard::level(&s, &crate::guard::Limits::defaults(&s), 0.0).0, crate::guard::Level::Green);
    }

    /// install.ps1's rules: from WSL, every TCP port but the brokers' and DNS is blocked, every UDP port but DNS.
    #[test]
    fn the_firewall_rules_leave_wsl_only_the_brokers_and_dns() {
        let ps = include_str!("../../windows/install.ps1");
        let ports = |needle: &str| -> std::collections::BTreeSet<u32> {
            let l = ps.lines().find(|l| l.contains(needle)).unwrap_or_else(|| panic!("{needle}"));
            let list = &l[l.find("-LocalPort").unwrap() + 10..];
            let list = list[..list.find('|').unwrap()].trim().trim_start_matches("@(").trim_end_matches(')');
            list.split(',').map(|r| r.trim().trim_matches('\'')).flat_map(|r| { let (a, b) = r.split_once('-').unwrap_or((r, r)); a.parse::<u32>().unwrap()..=b.parse::<u32>().unwrap() }).collect()
        };
        let all: std::collections::BTreeSet<u32> = (1..=65535).collect();
        let brokers: std::collections::BTreeSet<u32> = (47100..=47199).collect();
        let tcp = ports("block WSL from this PC (TCP)");
        assert_eq!(all.difference(&tcp).copied().collect::<Vec<_>>(), [vec![53], brokers.iter().copied().collect()].concat());
        assert_eq!(all.difference(&ports("block WSL from this PC (UDP)")).copied().collect::<Vec<_>>(), vec![53]);
        assert_eq!(ports("may reach pavilion-node brokers"), brokers);
        assert!(ps.contains("#Requires -RunAsAdministrator") && ps.contains("-User 'SYSTEM'") && ps.contains("$env:ProgramFiles"));
    }

    #[test]
    fn the_logon_task_has_no_time_limit_and_quotes_safely() {
        let x = task_xml(r"C:\Program Files\Pavilion & Co\pavilion-node.exe", r"DESKTOP\bruno").unwrap();
        assert!(x.contains("<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>") && x.contains("<LogonType>InteractiveToken</LogonType>") && x.contains("<RunLevel>LeastPrivilege</RunLevel>"));
        assert!(x.contains(r#"<Arguments>--headless "C:\Program Files\Pavilion &amp; Co\pavilion-node.exe" run</Arguments>"#), "{x}");
        assert!(x.contains(r"<UserId>DESKTOP\bruno</UserId>") && x.contains(r"conhost.exe</Command>"));
        assert!(task_xml(r#"C:\a"b\pavilion-node.exe"#, "u").is_err());
        assert!(task_xml(r"\\nas\x\pavilion-node.exe", "u").is_err());
        assert!(task_xml(r"C:\x\pavilion-node", "u").is_err());
    }
}
