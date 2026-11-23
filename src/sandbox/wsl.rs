//! Windows: job sandboxes run inside one dedicated WSL2 distro, "pavilion", as rootless Podman containers with krun or
//! gVisor (the same rule as on Linux: plain crun is refused), built from the Linux code path's own arguments.
//! Compile-checked from macOS, not run on Windows yet (node/windows/TESTING.md).
//!
//!   The distro: imported from a rootfs tarball pinned by SHA-256 (node/windows/rootfs/), its disk (a VHDX) in the folder
//!   `pavilion-node storage` names. /etc/wsl.conf turns off Windows interop and drive mounting; its user is `pavilion`
//!   (uid 47000), with no sudo. Before every job the node, as the distro's root, unmounts what WSL shares in anyway
//!   (WSLg's sockets, /mnt/wsl, any Windows folder except the GPU driver's) and loads an nftables table.
//!   The network: WSL in NAT mode (the default; mirrored mode is refused, it would let the distro reach Windows'
//!   loopback services). Each job's Podman network is `--internal`; its gateway lives in Podman's rootless network
//!   namespace, where a relay passes connections from that job's subnet to that job's broker on Windows, through a Unix
//!   socket, and nothing else. The nftables table keeps uid 47000 (the distro's user, the relays, Podman's helpers) from
//!   private addresses except the broker ports on Windows, DNS and HTTPS (image pulls). node/windows/install.ps1 keeps
//!   WSL's subnet away from Windows' own services; the exposure probe checks all three layers.
//!
//! Residual risks: WSL2 runs every distro of this Windows user in one Hyper-V utility VM, with one Linux kernel and one
//! network namespace. A kernel escape from a sandbox reaches the user's other distros, which usually have interop and
//! so the user's Windows account. The nftables table lives in that shared namespace (root in any distro can remove
//! it), and the Windows firewall rules apply to all of WSL, not just this distro. Windows programs of this user can
//! read and write the distro's files through \\wsl.localhost\pavilion.
#![cfg_attr(not(windows), allow(dead_code))]
use std::net::Ipv4Addr;

pub const DISTRO: &str = "pavilion";
pub const USER: &str = "pavilion";
pub const UID: u32 = 47000;
pub const HOME: &str = "/home/pavilion";
/// The rootfs tarballs this node accepts, by SHA-256 (node/windows/rootfs/build.sh prints it). None released yet: until
/// then the owner pins their own build with PAVILION_ROOTFS_SHA256.
pub const ROOTFS_SHA256: &[&str] = &[];
/// The distro's files, as Windows sees them.
const UNC: &[&str] = &[r"\\wsl.localhost\pavilion", r"\\wsl$\pavilion"];
/// Windows folders WSL mounts that stay: the GPU driver's libraries (CUDA), read-only.
const KEEP_MOUNTS: &[&str] = &["/usr/lib/wsl/lib", "/usr/lib/wsl/drivers"];
/// Where a media runner's process group is written, so it can be stopped from Windows.
const RUNNER_PID: &str = "/home/pavilion/.runner.pid";

/// /etc/wsl.conf for the distro (also shipped in the rootfs: node/windows/rootfs/wsl.conf).
pub fn wsl_conf() -> String {
    "# pavilion-node's WSL distro (node/src/sandbox/wsl.rs): it runs job sandboxes and gets nothing from Windows.\n\
     [boot]\nsystemd=true\n\
     [user]\ndefault=pavilion\n\
     [interop]\nenabled=false\nappendWindowsPath=false\n\
     [automount]\nenabled=false\nmountFsTab=false\n\
     [network]\ngenerateHosts=true\ngenerateResolvConf=true\nhostname=pavilion\n".into()
}

fn env_key_ok(k: &str) -> bool { !k.is_empty() && k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') && !k.as_bytes()[0].is_ascii_digit() }

/// wsl.exe's arguments for running `argv` in the distro as `user`: never through a shell (`--exec`), in `cwd`, with a
/// clean environment (`env -i`, then the basics, then `env`). Nothing from Windows' environment crosses.
pub fn wsl_args(user: &str, cwd: &str, env: &[(String, String)], argv: &[String]) -> Vec<String> {
    let mut a: Vec<String> = ["-d", DISTRO, "-u", user, "--cd", cwd, "--exec", "/usr/bin/env", "-i"].iter().map(|s| s.to_string()).collect();
    let (home, path) = if user == "root" { ("/root", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin") } else { (HOME, "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin") };
    let base = [("PATH", path.to_string()), ("HOME", home.into()), ("LANG", "C.UTF-8".into()), ("XDG_RUNTIME_DIR", format!("/run/user/{UID}")),
        ("DBUS_SESSION_BUS_ADDRESS", format!("unix:path=/run/user/{UID}/bus"))];
    for (k, v) in base.iter().map(|(k, v)| (k.to_string(), v.clone())).chain(env.iter().cloned()) { if env_key_ok(&k) { a.push(format!("{k}={v}")); } }
    // `env` would take a first word with '=' in it for a variable, and the next word for the program.
    match argv.first() { Some(p) if !p.is_empty() && !p.contains('=') && !p.starts_with('-') => a.extend(argv.iter().cloned()), _ => a.push("/bin/false".into()) }
    a
}

/// Paths of the distro written the Windows way (\\wsl.localhost\pavilion\home\…, also JSON-escaped) as Linux paths,
/// wherever they appear in `s` (a PATH list, `--flag=path`, a JSON argument). Anything else is left as it is.
pub fn to_linux(s: &str) -> String {
    let pats: Vec<(String, bool)> = UNC.iter().flat_map(|u| [(u.to_string(), false), (u.replace('\\', r"\\"), true)]).collect();
    // A path ends where a list or a quoted string goes on (paths in the distro have no such characters).
    let stop = |c: char| matches!(c, ':' | ';' | ',' | '"' | '\'' | '=' | '\n');
    let (mut out, mut rest) = (String::new(), s);
    loop {
        let hit = pats.iter().filter_map(|(p, esc)| {
            let i = rest.to_ascii_lowercase().find(&p.to_ascii_lowercase())?;
            let after = &rest[i + p.len()..];
            (after.is_empty() || after.starts_with('\\') || after.starts_with('/') || after.starts_with(stop)).then_some((i, p.len(), *esc))
        }).min_by_key(|h| (h.0, std::cmp::Reverse(h.1)));
        let Some((i, n, esc)) = hit else { out.push_str(rest); return out };
        out.push_str(&rest[..i]);
        rest = &rest[i + n..];
        let end = rest.find(stop).unwrap_or(rest.len());
        let p = if esc { rest[..end].replace(r"\\", "/") } else { rest[..end].replace('\\', "/") };
        out.push_str(if p.is_empty() { "/" } else { &p });
        rest = &rest[end..];
    }
}

/// A Linux path in the distro, as Windows reaches it.
pub fn unc(linux: &str) -> std::path::PathBuf { std::path::PathBuf::from(format!(r"{}{}", UNC[0], linux.replace('/', "\\"))) }

/// The nftables table loaded into WSL's (shared) network namespace: uid 47000 and its containers' uids may reach the
/// brokers on Windows, DNS and HTTPS on the internet, and no private or local address. Other uids are left alone.
pub fn nft_rules(winhost: Ipv4Addr, nameservers: &[Ipv4Addr]) -> String {
    let mut r = format!("table inet pavilion\ndelete table inet pavilion\ntable inet pavilion {{\n\tchain out {{\n\t\ttype filter hook output priority 0; policy accept;\n\
        \t\tmeta skuid != {{ {UID}, {lo}-{hi} }} accept\n\t\tmeta nfproto ipv6 drop\n\t\tip daddr {winhost} tcp dport 47100-47199 accept\n", lo = UID * 10_000, hi = UID * 10_000 + 65_535);
    if !nameservers.is_empty() {
        let ns: Vec<String> = nameservers.iter().map(|n| n.to_string()).collect();
        r.push_str(&format!("\t\tip daddr {{ {} }} meta l4proto {{ tcp, udp }} th dport 53 accept\n", ns.join(", ")));
    }
    r.push_str("\t\tip daddr { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/3 } drop\n\
        \t\ttcp dport 443 accept\n\t\tdrop\n\t}\n}\n");
    r
}

/// As root, before jobs: unmount what WSL shares into every distro, then load the nftables table (from stdin).
const HARDEN: &str = r#"for m in /tmp/.X11-unix /mnt/wslg /mnt/wsl; do mountpoint -q "$m" 2>/dev/null && umount -l "$m"; done
awk '($3=="9p"||$3=="drvfs"||$3=="virtiofs") && $2!="/usr/lib/wsl/lib" && $2!="/usr/lib/wsl/drivers" {print $2}' /proc/mounts | while IFS= read -r m; do umount -l "$m"; done
exec nft -f -"#;

/// What the distro has and shares, one fact per line (parsed by `Facts::parse`).
const FACTS: &str = r#"for b in podman socat nc nft krun runsc; do command -v $b >/dev/null 2>&1 && echo "has $b"; done
[ -e /dev/kvm ] && echo kvm
ls /run/WSL 2>/dev/null | grep -q _interop && echo interop
for m in /mnt/wslg /mnt/wsl /tmp/.X11-unix; do mountpoint -q "$m" 2>/dev/null && echo "shared $m"; done
echo "net $(wslinfo --networking-mode 2>/dev/null)"
ip -4 route show default | sed 's/^/route /'
ip -4 -o addr show dev eth0 | sed 's/^/addr /'
sed -n 's/^nameserver /ns /p' /etc/resolv.conf
awk '$3=="9p"||$3=="drvfs"||$3=="virtiofs"{print "mount "$2}' /proc/mounts
echo "uid $(id -u)""#;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Facts {
    pub has: Vec<String>,
    pub kvm: bool,
    /// Windows interop is running in this distro (it must not be).
    pub interop: bool,
    /// WSLg's sockets, /mnt/wsl (shared by all distros): unmounted before jobs.
    pub shared: Vec<String>,
    /// wslinfo --networking-mode: nat, mirrored… (empty on older WSL, which only has NAT).
    pub net: String,
    pub gateway: Option<Ipv4Addr>,
    pub addr: Option<(Ipv4Addr, u8)>,
    pub nameservers: Vec<Ipv4Addr>,
    pub mounts: Vec<String>,
    pub uid: Option<u32>,
}

impl Facts {
    pub fn parse(out: &str) -> Facts {
        let mut f = Facts::default();
        for l in out.lines().map(str::trim) {
            let (k, v) = l.split_once(' ').unwrap_or((l, ""));
            let v = v.trim();
            match k {
                "has" => f.has.push(v.into()),
                "kvm" => f.kvm = true,
                "interop" => f.interop = true,
                "shared" => f.shared.push(v.into()),
                "net" => f.net = v.to_lowercase(),
                "route" => f.gateway = v.split_whitespace().skip_while(|w| *w != "via").nth(1).and_then(|g| g.parse().ok()).or(f.gateway),
                "addr" => f.addr = v.split_whitespace().skip_while(|w| *w != "inet").nth(1).and_then(|c| { let (ip, b) = c.split_once('/')?; Some((ip.parse().ok()?, b.parse::<u8>().ok().filter(|b| *b <= 32)?)) }).or(f.addr),
                "ns" => if let Ok(ip) = v.parse() { f.nameservers.push(ip) },
                "mount" => f.mounts.push(v.into()),
                "uid" => f.uid = v.parse().ok(),
                _ => {}
            }
        }
        f
    }
    pub fn has(&self, b: &str) -> bool { self.has.iter().any(|h| h == b) }
    /// Windows folders mounted in the distro beyond the GPU driver's.
    pub fn foreign_mounts(&self) -> Vec<String> { self.mounts.iter().filter(|m| !KEEP_MOUNTS.contains(&m.as_str())).cloned().collect() }
    /// WSL's subnet, as the broker sees the relays: (network, mask).
    pub fn subnet(&self) -> Option<(u32, u32)> { self.addr.and_then(|(ip, b)| crate::broker::parse_subnet(&format!("{ip}/{b}"))) }
}

/// The sandbox runtime from what the distro has, or why there's none. The same rule as Linux: a VM per job (krun, with
/// nested virtualization giving WSL /dev/kvm) or gVisor; never plain crun. Interop and mirrored networking are refused.
pub fn choose(f: &Facts) -> Result<&'static str, String> {
    if f.uid != Some(UID) { return Err(format!("the distro's user isn't uid {UID}; reinstall it from the pinned rootfs (pavilion-node wsl install)")); }
    if f.interop { return Err("Windows interop is on in the pavilion distro; its /etc/wsl.conf must turn it off (pavilion-node wsl install writes it)".into()); }
    if !(f.net.is_empty() || f.net == "nat") { return Err(format!("WSL networking is {}; the node needs NAT, the default (remove networkingMode from %UserProfile%\\.wslconfig)", f.net)); }
    for b in ["podman", "socat", "nc", "nft"] { if !f.has(b) { return Err(format!("the pavilion distro has no {b}; reinstall it from the pinned rootfs")); } }
    if f.kvm && f.has("krun") { return Ok("krun"); }
    if f.has("runsc") { return Ok("runsc"); }
    Err("no strong sandbox in the pavilion distro: it needs gVisor's runsc (in the rootfs) or krun with nested virtualization".into())
}

/// The relay for one job: in Podman's rootless network namespace it takes connections from the job's subnet on the
/// broker's port, and passes them through a Unix socket to a second relay outside it, which reaches the broker on
/// Windows. Only the numbers below come in, as arguments, never as script text.
const RELAY: &str = r#"socat UNIX-LISTEN:"$1",unlink-early,mode=600,fork TCP:"$2" &
exec podman unshare --rootless-netns socat TCP-LISTEN:"$3",reuseaddr,fork,range="$4" UNIX-CONNECT:"$1""#;
pub fn relay_argv(winhost: Ipv4Addr, port: u16, job_cidr: &str) -> Vec<String> {
    vec!["/bin/sh".into(), "-c".into(), RELAY.into(), "sh".into(), format!("{HOME}/.pav-relay-{port}.sock"), format!("{winhost}:{port}"), port.to_string(), job_cidr.into()]
}
pub fn cidr((net, mask): (u32, u32)) -> String { format!("{}/{}", Ipv4Addr::from(net), mask.count_ones()) }

/// The same reachability check as the sandbox probe, run in the distro itself (as its user, then as root).
pub fn probe_script(targets: &[Ipv4Addr], ports: &[u16]) -> String {
    format!("for h in {}; do for p in {}; do (timeout 2 nc -w 1 $h $p </dev/null >/dev/null 2>&1 && echo OPEN $h:$p) & done; done; wait; true",
        targets.iter().map(|t| t.to_string()).collect::<Vec<_>>().join(" "), ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(" "))
}

/// wsl.exe prints its own messages in UTF-16 (unless WSL_UTF8=1, which older versions ignore); Linux programs' output is UTF-8.
pub fn decode(b: &[u8]) -> String {
    let b16 = b.strip_prefix(&[0xFF, 0xFE]).unwrap_or(b);
    if b16.len() >= 2 && b16.len() % 2 == 0 && b16.iter().skip(1).step_by(2).filter(|x| **x == 0).count() * 2 >= b16.len() / 2 {
        return String::from_utf16_lossy(&b16.chunks(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect::<Vec<_>>());
    }
    String::from_utf8_lossy(b).into_owned()
}
/// `wsl --list --quiet` names our distro.
pub fn listed(out: &str) -> bool { out.lines().any(|l| l.trim().trim_matches('\0').eq_ignore_ascii_case(DISTRO)) }

/// The largest NVIDIA GPU's memory in GiB from `nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits`.
pub fn vram_gib(out: &str) -> Option<f64> {
    let mib = out.lines().filter_map(|l| l.trim().parse::<f64>().ok()).fold(0.0, f64::max);
    (mib > 0.0).then(|| (mib / 1024.0 * 10.0).round() / 10.0)
}

/// Whether a rootfs tarball's SHA-256 is one this node accepts: pinned in this build, or pinned by the owner for a
/// rootfs they built themselves (PAVILION_ROOTFS_SHA256).
pub fn rootfs_ok(sha: &str, pins: &[&str], owner_pin: Option<&str>) -> Result<(), String> {
    let sha = sha.to_ascii_lowercase();
    if pins.iter().any(|p| p.eq_ignore_ascii_case(&sha)) { return Ok(()); }
    match owner_pin.map(|p| p.trim().to_ascii_lowercase()) {
        Some(p) if p.len() == 64 && p == sha => Ok(()),
        Some(p) if p.len() == 64 => Err(format!("this rootfs's SHA-256 is {sha}, not the {p} you pinned")),
        Some(_) => Err("PAVILION_ROOTFS_SHA256 must be a SHA-256 (64 hex characters)".into()),
        None if pins.is_empty() => Err(format!("this build pins no rootfs yet. Build one (node/windows/rootfs/build.sh) and pin it: set PAVILION_ROOTFS_SHA256={sha} if this is it")),
        None => Err(format!("this rootfs (SHA-256 {sha}) isn't one this node accepts")),
    }
}

/* ---------- running things in the distro (Windows only) ---------- */

#[cfg(windows)]
pub use self::win::*;

#[cfg(windows)]
mod win {
    use super::*;
    use crate::sandbox::Runtime;
    use anyhow::{anyhow, bail, Context, Result};
    use std::os::windows::process::CommandExt;
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    /// No console window for each call when the node runs at logon without one.
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    pub fn wsl_exe() -> std::path::PathBuf { crate::platform::windows::system32("wsl.exe") }

    fn std_cmd(user: &str, cwd: &str, env: &[(String, String)], argv: &[String]) -> std::process::Command {
        let mut c = std::process::Command::new(wsl_exe());
        c.args(wsl_args(user, cwd, env, argv)).env("WSL_UTF8", "1").env_remove("WSLENV").creation_flags(CREATE_NO_WINDOW);
        c
    }
    fn tokio_cmd(user: &str, argv: &[String]) -> tokio::process::Command {
        let mut c = tokio::process::Command::new(wsl_exe());
        c.args(wsl_args(user, if user == "root" { "/root" } else { HOME }, &[], argv)).env("WSL_UTF8", "1").env_remove("WSLENV").creation_flags(CREATE_NO_WINDOW);
        c
    }

    /// `podman`, inside the distro as its user; the caller adds Podman's arguments (the same as on Linux).
    pub fn podman() -> tokio::process::Command { tokio_cmd(USER, &["/usr/bin/podman".into()]) }

    /// A host command (a media runner, `models add`) run in the distro instead: its program, arguments, environment
    /// and folder with the distro's paths in Linux form. `track`: in its own session, written down so it can be stopped.
    pub fn wrap(cmd: &std::process::Command, track: bool) -> std::process::Command {
        let mut argv: Vec<String> = vec![];
        if track { argv.extend(["/usr/bin/setsid".into(), "-w".into(), "/bin/sh".into(), "-c".into(), format!("echo $$ > {RUNNER_PID}; exec \"$@\""), "sh".into()]); }
        argv.push(to_linux(&cmd.get_program().to_string_lossy()));
        argv.extend(cmd.get_args().map(|a| to_linux(&a.to_string_lossy())));
        let env: Vec<(String, String)> = cmd.get_envs().filter_map(|(k, v)| Some((k.to_string_lossy().into_owned(), to_linux(&v?.to_string_lossy())))).collect();
        let cwd = cmd.get_current_dir().map(|d| to_linux(&d.to_string_lossy())).filter(|d| d.starts_with('/')).unwrap_or_else(|| HOME.into());
        std_cmd(USER, &cwd, &env, &argv)
    }

    /// Stops the media runner started with `wrap(_, true)`, and its whole group.
    pub fn kill_runner(hard: bool) {
        let script = format!("p=$(cat {RUNNER_PID} 2>/dev/null) && [ \"$p\" -gt 1 ] && kill -$1 -- -$p");
        let _ = std_cmd(USER, HOME, &[], &["/bin/sh".into(), "-c".into(), script, "sh".into(), if hard { "KILL" } else { "TERM" }.into()]).spawn();
    }

    fn run_sync(user: &str, argv: &[String]) -> Result<String> {
        let out = std_cmd(user, if user == "root" { "/root" } else { HOME }, &[], argv).output().context("running wsl.exe")?;
        if !out.status.success() { bail!("wsl: {}", decode(&out.stderr).trim().chars().take(300).collect::<String>()); }
        Ok(decode(&out.stdout))
    }
    fn wsl_sync(args: &[&str]) -> Result<String> {
        let out = std::process::Command::new(wsl_exe()).args(args).env("WSL_UTF8", "1").creation_flags(CREATE_NO_WINDOW).output().context("running wsl.exe")?;
        if !out.status.success() { bail!("wsl {}: {}", args.join(" "), decode(&out.stdout).trim().chars().take(300).collect::<String>()); }
        Ok(decode(&out.stdout))
    }

    pub fn registered() -> bool { wsl_sync(&["--list", "--quiet"]).map(|o| listed(&o)).unwrap_or(false) }
    pub fn facts_sync() -> Result<Facts> { Ok(Facts::parse(&run_sync(USER, &["/bin/sh".into(), "-c".into(), FACTS.into()])?)) }
    async fn facts() -> Result<Facts> { tokio::task::spawn_blocking(facts_sync).await? }

    /// The runtime, checked at most once a minute (each check starts wsl.exe, and the first may boot WSL).
    pub fn detect() -> Result<Runtime> {
        static C: Mutex<Option<(Instant, Result<&'static str, String>)>> = Mutex::new(None);
        let mut c = C.lock().unwrap();
        if let Some((t, r)) = &*c { if t.elapsed() < Duration::from_secs(60) { return r.clone().map(|oci| Runtime::Podman { oci }).map_err(|e| anyhow!(e)); } }
        let r = if !wsl_exe().exists() { Err("WSL isn't installed (wsl --install, then restart)".to_string()) }
            else if !registered() { Err("the pavilion WSL distro isn't installed: pavilion-node wsl install <rootfs.tar>".to_string()) }
            else { facts_sync().map_err(|e| e.to_string()).and_then(|f| choose(&f)) };
        *c = Some((Instant::now(), r.clone()));
        r.map(|oci| Runtime::Podman { oci }).map_err(|e| anyhow!(e))
    }

    /// What the broker and relays need: the Windows host as WSL reaches it, and WSL's subnet.
    pub struct Net { pub winhost: Ipv4Addr, pub subnet: (u32, u32) }

    /// Before each job and probe: the distro shares nothing from Windows but the GPU driver, and its egress table is
    /// loaded (WSL resets both when it restarts).
    pub async fn ensure_ready() -> Result<Net> {
        let f = facts().await?;
        choose(&f).map_err(|e| anyhow!(e))?;
        let (winhost, subnet) = (f.gateway.ok_or_else(|| anyhow!("WSL has no default route"))?, f.subnet().ok_or_else(|| anyhow!("WSL's eth0 has no IPv4 address"))?);
        let mut child = tokio_cmd("root", &["/bin/sh".into(), "-c".into(), HARDEN.into()]).stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped()).spawn().context("running wsl.exe")?;
        {
            use tokio::io::AsyncWriteExt;
            let mut sin = child.stdin.take().unwrap();
            sin.write_all(nft_rules(winhost, &f.nameservers).as_bytes()).await?;
        }
        let out = child.wait_with_output().await?;
        if !out.status.success() { bail!("loading the distro's egress rules: {}", decode(&out.stderr).trim()); }
        let f2 = facts().await?;
        let left: Vec<String> = f2.foreign_mounts().into_iter().chain(f2.shared.clone()).collect();
        if !left.is_empty() { bail!("the pavilion distro still shares {} with Windows or other distros", left.join(", ")); }
        Ok(Net { winhost, subnet })
    }

    /// One job's relay, stopped when dropped.
    pub struct Relay { port: u16, _child: tokio::process::Child }
    impl Drop for Relay {
        fn drop(&mut self) {
            let _ = std_cmd(USER, HOME, &[], &["/usr/bin/pkill".into(), "-u".into(), USER.into(), "-f".into(), format!("pav-relay-{}\\.sock", self.port)]).spawn();
        }
    }
    pub async fn relay(net: &Net, port: u16, job_sub: (u32, u32)) -> Result<Relay> {
        let child = tokio_cmd(USER, &relay_argv(net.winhost, port, &cidr(job_sub))).stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null()).kill_on_drop(true).spawn().context("starting the broker relay in WSL")?;
        // Both listeners are up in well under a second; a job's first call can come right away.
        tokio::time::sleep(Duration::from_millis(700)).await;
        Ok(Relay { port, _child: child })
    }
    /// Relays left by an earlier run.
    pub async fn sweep_relays() { let _ = tokio_cmd(USER, &["/usr/bin/pkill".into(), "-u".into(), USER.into(), "-f".into(), "pav-relay-".into()]).output().await; }

    /// What `user` in the distro (outside any container) reaches on Windows' addresses. DNS (53) stays open to WSL
    /// (install.ps1; WSL resolves names through Windows), so it isn't tried.
    pub async fn probe(user: &str, targets: &[Ipv4Addr], ports: &[u16]) -> Result<Vec<String>> {
        if targets.is_empty() { return Ok(vec![]); }
        let ports: Vec<u16> = ports.iter().copied().filter(|p| *p != 53).collect();
        let run = tokio_cmd(user, &["/bin/sh".into(), "-c".into(), probe_script(targets, &ports)]).stdin(std::process::Stdio::null()).kill_on_drop(true).output();
        let out = tokio::time::timeout(Duration::from_secs(120), run).await.map_err(|_| anyhow!("the WSL exposure probe timed out"))??;
        Ok(decode(&out.stdout).lines().filter_map(|l| l.strip_prefix("OPEN ")).map(String::from).collect())
    }

    /// Media on Windows: the Linux variants, in the distro; CUDA when WSL's GPU passthrough shows an NVIDIA GPU.
    pub fn media_accel() -> (String, Option<f64>) {
        match run_sync(USER, &["/usr/lib/wsl/lib/nvidia-smi".into(), "--query-gpu=memory.total".into(), "--format=csv,noheader,nounits".into()]).ok().and_then(|o| vram_gib(&o)) {
            Some(v) => ("cuda".into(), Some(v)),
            None => ("cpu".into(), None),
        }
    }

    /// For the inventory.
    pub fn inventory() -> serde_json::Value {
        let rt = detect();
        serde_json::json!({ "runtime": "podman-wsl", "distro": DISTRO, "isolation": "wsl2+container", "available": rt.is_ok(),
            "error": rt.as_ref().err().map(|e| e.to_string()), "gvisor": matches!(rt, Ok(Runtime::Podman { oci: "runsc" })), "krun": matches!(rt, Ok(Runtime::Podman { oci: "krun" })),
            "kvm": matches!(rt, Ok(Runtime::Podman { oci: "krun" })) })
    }

    fn sha256_file(p: &std::path::Path) -> Result<String> {
        use sha2::Digest;
        use std::io::Read;
        let mut f = std::fs::File::open(p).with_context(|| format!("opening {}", p.display()))?;
        let (mut h, mut buf) = (sha2::Sha256::new(), vec![0u8; 1 << 20]);
        loop { let n = f.read(&mut buf)?; if n == 0 { break; } h.update(&buf[..n]); }
        Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
    }

    /// Where the distro's disk lives: `<storage>\pavilion-wsl`.
    pub fn disk_dir() -> std::path::PathBuf { std::path::PathBuf::from(crate::guard::storage_path()).join("pavilion-wsl") }

    /// `pavilion-node wsl install <rootfs.tar> | status | remove`.
    pub async fn cli(args: &[String]) -> Result<()> {
        match args.first().map(String::as_str) {
            Some("install") => {
                let tar = crate::platform::windows::check_path(args.get(1).ok_or_else(|| anyhow!("which rootfs? pavilion-node wsl install <rootfs.tar>"))?).map_err(|e| anyhow!(e))?;
                if !wsl_exe().exists() { bail!("WSL isn't installed: run `wsl --install --no-distribution` as administrator, then restart"); }
                if registered() { bail!("the pavilion distro is installed already (pavilion-node wsl status; `pavilion-node wsl remove` deletes it)"); }
                let sha = sha256_file(&tar)?;
                rootfs_ok(&sha, ROOTFS_SHA256, std::env::var("PAVILION_ROOTFS_SHA256").ok().as_deref()).map_err(|e| anyhow!(e))?;
                let dir = disk_dir();
                std::fs::create_dir_all(&dir)?;
                eprintln!("Importing the pavilion distro (rootfs {}) into {}…", &sha[..16], dir.display());
                let ok = std::process::Command::new(wsl_exe()).args(["--import", DISTRO]).arg(&dir).arg(&tar).args(["--version", "2"]).creation_flags(CREATE_NO_WINDOW).status()?.success();
                if !ok { bail!("wsl --import failed"); }
                let mut c = std_cmd("root", "/root", &[], &["/bin/sh".into(), "-c".into(), "cat > /etc/wsl.conf".into()]);
                let mut child = c.stdin(std::process::Stdio::piped()).spawn()?;
                { use std::io::Write; child.stdin.take().unwrap().write_all(wsl_conf().as_bytes())?; }
                if !child.wait()?.success() { bail!("couldn't write /etc/wsl.conf in the distro"); }
                // The settings apply when the distro next starts.
                let _ = wsl_sync(&["--terminate", DISTRO]);
                let f = facts_sync()?;
                match choose(&f) {
                    Ok(oci) => println!("Installed. Sandboxes: rootless Podman + {oci} in WSL distro {DISTRO}. Next, as administrator: node\\windows\\install.ps1; then: pavilion-node exposure"),
                    Err(e) => println!("Installed, but jobs can't run yet: {e}"),
                }
                Ok(())
            }
            None | Some("status") => {
                if !registered() { println!("the pavilion distro isn't installed (pavilion-node wsl install <rootfs.tar>)"); return Ok(()); }
                let f = facts_sync()?;
                println!("distro {DISTRO} · disk in {} · networking {} · {}", disk_dir().display(), if f.net.is_empty() { "nat" } else { &f.net },
                    match choose(&f) { Ok(oci) => format!("sandboxes: rootless Podman + {oci}"), Err(e) => format!("NOT ready: {e}") });
                let (accel, vram) = media_accel();
                println!("media: linux variants, {accel}{}", vram.map(|v| format!(" ({v} GiB)")).unwrap_or_default());
                if !f.foreign_mounts().is_empty() || !f.shared.is_empty() { println!("shares now (unmounted before each job): {}", f.foreign_mounts().into_iter().chain(f.shared).collect::<Vec<_>>().join(", ")); }
                Ok(())
            }
            Some("remove") => {
                eprint!("This deletes the pavilion distro and its disk (images, models, job folders) for good. Type yes: ");
                let mut l = String::new();
                std::io::stdin().read_line(&mut l)?;
                if l.trim() != "yes" { bail!("not removed"); }
                wsl_sync(&["--unregister", DISTRO])?;
                println!("removed");
                Ok(())
            }
            Some(x) => bail!("unknown: wsl {x}. Use: wsl install <rootfs.tar> | wsl status | wsl remove"),
        }
    }

    /// Moves the distro's disk to `dir` (WSL 2.3 and later). Stops the distro first.
    pub fn move_disk(dir: &std::path::Path) -> Result<()> {
        let _ = wsl_sync(&["--terminate", DISTRO]);
        let ok = std::process::Command::new(wsl_exe()).args(["--manage", DISTRO, "--move"]).arg(dir).creation_flags(CREATE_NO_WINDOW).status()?.success();
        if !ok { bail!("wsl --manage {DISTRO} --move failed (WSL 2.3 or later needed: wsl --update)"); }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wsl_command_line_never_goes_through_a_shell() {
        let a = wsl_args(USER, HOME, &[("HF_HUB_OFFLINE".into(), "1".into()), ("bad key".into(), "x".into()), ("PATH".into(), "/opt/bin".into())],
            &["/usr/bin/podman".into(), "run".into(), "img".into(), "sh".into(), "-c".into(), "echo $HOME; rm -rf / \"x\"".into()]);
        assert_eq!(&a[..9], &["-d", "pavilion", "-u", "pavilion", "--cd", "/home/pavilion", "--exec", "/usr/bin/env", "-i"]);
        assert!(a.contains(&"HF_HUB_OFFLINE=1".to_string()) && !a.iter().any(|x| x.starts_with("bad key")));
        // A later PATH wins over the basic one (env applies them in order).
        let paths: Vec<&String> = a.iter().filter(|x| x.starts_with("PATH=")).collect();
        assert_eq!(paths.last().unwrap().as_str(), "PATH=/opt/bin");
        // The job's command is one argument, as it was given.
        assert_eq!(a.last().unwrap(), "echo $HOME; rm -rf / \"x\"");
        assert_eq!(a.iter().position(|x| x == "/usr/bin/podman").unwrap() + 5, a.len() - 1);
        // A program `env` would read as a variable or an option is refused.
        for bad in ["X=1", "-u", ""] { assert_eq!(wsl_args(USER, HOME, &[], &[bad.into(), "y".into()]).last().unwrap(), "/bin/false"); }
        assert!(wsl_args("root", "/root", &[], &["/bin/true".into()]).contains(&"HOME=/root".to_string()));
    }

    #[test]
    fn distro_paths_become_linux_paths() {
        assert_eq!(to_linux(r"\\wsl.localhost\pavilion\home\pavilion\media\jobs\mj_1"), "/home/pavilion/media/jobs/mj_1");
        assert_eq!(to_linux(r"\\wsl$\pavilion\usr\bin\ffmpeg"), "/usr/bin/ffmpeg");
        assert_eq!(to_linux(r"\\WSL.LOCALHOST\PAVILION\tmp"), "/tmp");
        assert_eq!(to_linux(r"\\wsl.localhost\pavilion"), "/");
        // In a PATH list, a --flag=path, and a JSON argument.
        assert_eq!(to_linux(r"\\wsl.localhost\pavilion\usr\bin:/usr/bin:/bin"), "/usr/bin:/usr/bin:/bin");
        assert_eq!(to_linux(r"--out=\\wsl.localhost\pavilion\home\pavilion\out\0.png"), "--out=/home/pavilion/out/0.png");
        let json = serde_json::json!({ "cache": r"\\wsl.localhost\pavilion\home\pavilion\.cache/huggingface\hub", "repo": "a/b" }).to_string();
        assert_eq!(to_linux(&json), r#"{"cache":"/home/pavilion/.cache/huggingface/hub","repo":"a/b"}"#);
        // Other paths, other distros and look-alikes stay as they are.
        assert_eq!(to_linux(r"C:\Users\x\file.txt"), r"C:\Users\x\file.txt");
        assert_eq!(to_linux(r"\\wsl.localhost\Ubuntu\home\x"), r"\\wsl.localhost\Ubuntu\home\x");
        assert_eq!(to_linux(r"\\wsl.localhost\pavilion2\x"), r"\\wsl.localhost\pavilion2\x");
        assert_eq!(to_linux("-hide_banner"), "-hide_banner");
        assert_eq!(unc("/home/pavilion/media"), std::path::PathBuf::from(r"\\wsl.localhost\pavilion\home\pavilion\media"));
        assert_eq!(to_linux(&unc("/home/pavilion/x y/z").to_string_lossy()), "/home/pavilion/x y/z");
    }

    #[test]
    fn wsl_conf_turns_off_interop_and_drive_mounting() {
        let c = wsl_conf();
        for want in ["[interop]\nenabled=false\nappendWindowsPath=false", "[automount]\nenabled=false\nmountFsTab=false", "[user]\ndefault=pavilion", "systemd=true"] { assert!(c.contains(want), "{want}"); }
        // The rootfs ships the same file.
        assert_eq!(include_str!("../../windows/rootfs/wsl.conf"), c);
    }

    #[test]
    fn the_egress_table_only_touches_the_distros_user() {
        let r = nft_rules("172.22.16.1".parse().unwrap(), &["10.255.255.254".parse().unwrap()]);
        assert!(r.starts_with("table inet pavilion\ndelete table inet pavilion\n"));
        assert!(r.contains("meta skuid != { 47000, 470000000-470065535 } accept"));
        let (broker, dns, private, https) = (r.find("ip daddr 172.22.16.1 tcp dport 47100-47199 accept").unwrap(), r.find("ip daddr { 10.255.255.254 } meta l4proto { tcp, udp } th dport 53 accept").unwrap(),
            r.find("192.168.0.0/16").unwrap(), r.find("tcp dport 443 accept").unwrap());
        assert!(broker < private && dns < private && private < https, "allow the broker and DNS before dropping private addresses, then HTTPS");
        assert!(r.contains("127.0.0.0/8") && r.contains("172.16.0.0/12") && r.contains("meta nfproto ipv6 drop") && r.trim_end().ends_with("drop\n\t}\n}"));
        assert!(!nft_rules("172.22.16.1".parse().unwrap(), &[]).contains("dport 53"));
    }

    const FACTS_OUT: &str = "has podman\nhas socat\nhas nc\nhas nft\nhas runsc\nshared /mnt/wslg\nnet nat\nroute default via 172.22.16.1 dev eth0 proto kernel\n\
        addr 2: eth0    inet 172.22.20.5/20 brd 172.22.31.255 scope global eth0\\       valid_lft forever preferred_lft forever\nns 10.255.255.254\n\
        mount /usr/lib/wsl/drivers\nmount /usr/lib/wsl/lib\nmount /mnt/c\nuid 47000\n";

    #[test]
    fn facts_from_the_distro() {
        let f = Facts::parse(FACTS_OUT);
        assert_eq!(f.gateway, Some("172.22.16.1".parse().unwrap()));
        assert_eq!(f.addr, Some(("172.22.20.5".parse().unwrap(), 20)));
        assert_eq!(f.subnet(), crate::broker::parse_subnet("172.22.16.0/20"));
        assert_eq!(f.nameservers, vec!["10.255.255.254".parse::<Ipv4Addr>().unwrap()]);
        assert_eq!(f.foreign_mounts(), vec!["/mnt/c".to_string()]);
        assert_eq!(f.shared, vec!["/mnt/wslg".to_string()]);
        assert_eq!(choose(&f), Ok("runsc"));
        assert_eq!(choose(&Facts { kvm: true, has: [f.has.clone(), vec!["krun".into()]].concat(), ..f.clone() }), Ok("krun"));
        // krun without /dev/kvm (no nested virtualization) and no gVisor: refused, never plain crun.
        assert!(choose(&Facts { has: vec!["podman".into(), "socat".into(), "nc".into(), "nft".into(), "krun".into()], ..f.clone() }).unwrap_err().contains("no strong sandbox"));
        assert!(choose(&Facts { interop: true, ..f.clone() }).unwrap_err().contains("interop"));
        assert!(choose(&Facts { net: "mirrored".into(), ..f.clone() }).unwrap_err().contains("NAT"));
        assert!(choose(&Facts { uid: Some(1000), ..f.clone() }).unwrap_err().contains("47000"));
        assert!(choose(&Facts { net: String::new(), ..f.clone() }).is_ok(), "older WSL has no wslinfo and only NAT");
        assert!(choose(&Facts { has: vec!["podman".into(), "runsc".into()], ..f.clone() }).unwrap_err().contains("no socat"));
    }

    #[test]
    fn relays_and_probes_take_numbers_not_script_text() {
        let a = relay_argv("172.22.16.1".parse().unwrap(), 47123, &cidr(crate::broker::parse_subnet("10.89.7.0/24").unwrap()));
        assert_eq!(&a[4..], &["/home/pavilion/.pav-relay-47123.sock", "172.22.16.1:47123", "47123", "10.89.7.0/24"]);
        assert!(a[2].contains("range=\"$4\"") && a[2].contains("--rootless-netns") && !a[2].contains("47123"));
        let s = probe_script(&["172.22.16.1".parse().unwrap(), "192.168.1.20".parse().unwrap()], &[22, 445]);
        assert!(s.starts_with("for h in 172.22.16.1 192.168.1.20; do for p in 22 445; do"));
    }

    #[test]
    fn wsl_exe_output_in_utf16_or_utf8() {
        let utf16: Vec<u8> = "Ubuntu\r\npavilion\r\n".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        assert_eq!(decode(&utf16), "Ubuntu\r\npavilion\r\n");
        assert!(listed(&decode(&utf16)));
        assert!(listed(&decode(b"Ubuntu\npavilion\n")));
        assert!(!listed("Ubuntu\npavilion-old\n"));
        assert_eq!(decode("héllo".as_bytes()), "héllo");
    }

    #[test]
    fn gpus_and_rootfs_pins() {
        assert_eq!(vram_gib("24564\n8192\n"), Some(24.0));
        assert_eq!(vram_gib("No devices were found\n"), None);
        let sha = "ab".repeat(32);
        assert!(rootfs_ok(&sha, &[], None).unwrap_err().contains("PAVILION_ROOTFS_SHA256="));
        assert!(rootfs_ok(&sha, &[], Some(&sha.to_uppercase())).is_ok());
        assert!(rootfs_ok(&sha, &[], Some(&"cd".repeat(32))).is_err());
        assert!(rootfs_ok(&sha, &[], Some("yes")).is_err());
        assert!(rootfs_ok(&sha, &[sha.as_str()], None).is_ok());
        assert!(rootfs_ok(&"00".repeat(32), &[sha.as_str()], None).is_err());
    }
}
