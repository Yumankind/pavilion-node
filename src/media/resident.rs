//! Runners that are servers (ACE-Step): started on 127.0.0.1 when a job needs one, kept between jobs while they're used,
//! given up before any other model runs (one generation on the machine at a time), and stopped after 3 idle minutes
//! on a machine under 24 GB.
use super::{Ctl, Stop};
use std::path::Path;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};

pub struct Spec<'a> {
    pub name: &'static str,
    pub port: u16,
    pub argv: Vec<String>,
    pub cwd: &'a Path,
    pub env: Vec<(String, String)>,
    pub health: &'static str,
    pub ready_within: Duration,
}

struct Running { name: &'static str, port: u16, pgid: i32, last: Instant, child: tokio::process::Child }

fn slot() -> &'static tokio::sync::Mutex<Option<Running>> {
    static S: std::sync::OnceLock<tokio::sync::Mutex<Option<Running>>> = std::sync::OnceLock::new();
    S.get_or_init(Default::default)
}
/// The running server's process group, for stopping it when the node stops.
static PGID: AtomicI32 = AtomicI32::new(0);

/// How long a server may sit idle on a machine under 24 GB.
pub const IDLE: Duration = Duration::from_secs(180);

fn kill(pgid: i32, hard: bool) { crate::platform::kill_runner(pgid, hard) }

/// Stops the server now (the node is stopping).
pub fn kill_now() { kill(PGID.swap(0, Ordering::Relaxed), true); }

/// The name of the server running now, if any.
pub async fn current() -> Option<&'static str> { slot().lock().await.as_ref().map(|r| r.name) }

/// Stops the running server (its whole process group) and waits a moment for it to go.
pub async fn evict() {
    let Some(mut r) = slot().lock().await.take() else { return };
    eprintln!("media: stopping the {} server", r.name);
    kill(r.pgid, false);
    if tokio::time::timeout(Duration::from_secs(10), r.child.wait()).await.is_err() { kill(r.pgid, true); let _ = r.child.wait().await; }
    kill(r.pgid, true);
    PGID.store(0, Ordering::Relaxed);
}

/// Stops a server that has been idle too long, when memory is tight (under 24 GB).
pub async fn reap_idle(ram_gb: u64) {
    let idle = slot().lock().await.as_ref().map_or(false, |r| r.last.elapsed() > IDLE);
    if idle && ram_gb < 24 { evict().await; }
}

/// The running server's process group (for measuring its memory).
pub fn pgid() -> i32 { PGID.load(Ordering::Relaxed) }

/// How the server ended, if it has: "exit code N" or "signal N" (9 is usually macOS reclaiming memory).
pub async fn ended() -> Option<String> {
    let mut g = slot().lock().await;
    let st = g.as_mut()?.child.try_wait().ok()??;
    #[cfg(unix)]
    { use std::os::unix::process::ExitStatusExt; if let Some(sg) = st.signal() { return Some(format!("signal {sg}")); } }
    Some(st.code().map_or("unknown".into(), |c| format!("exit code {c}")))
}

pub async fn touch() { if let Some(r) = slot().lock().await.as_mut() { r.last = Instant::now(); } }

async fn healthy(c: &reqwest::Client, url: &str) -> bool { c.get(url).send().await.map(|r| r.status().is_success()).unwrap_or(false) }

/// The server `spec` describes, running and answering: started if it isn't (another one is stopped first). Returns its
/// base URL. Stoppable while it starts.
pub async fn ensure(spec: Spec<'_>, ctl: &Ctl) -> Result<String, Stop> {
    let base = format!("http://127.0.0.1:{}", spec.port);
    let c = reqwest::Client::builder().no_proxy().timeout(Duration::from_secs(5)).build().map_err(|e| Stop::Failed(e.to_string()))?;
    {
        let mut g = slot().lock().await;
        if let Some(r) = g.as_mut() {
            if r.name == spec.name && r.port == spec.port && matches!(r.child.try_wait(), Ok(None)) && healthy(&c, &format!("{base}{}", spec.health)).await {
                r.last = Instant::now();
                return Ok(base);
            }
        }
    }
    evict().await;
    // The port must be free: something else answering there isn't ours to send jobs to.
    if std::net::TcpListener::bind(("127.0.0.1", spec.port)).is_err() { return Err(Stop::Failed(format!("port {} on this machine is taken by another program", spec.port))); }
    let log_path = crate::platform::media_dir().join(format!("{}.log", spec.name));
    let _ = std::fs::create_dir_all(log_path.parent().unwrap());
    let log = std::fs::OpenOptions::new().create(true).append(true).open(&log_path).map_err(|e| Stop::Failed(e.to_string()))?;
    // Like any runner: its own process group (on Windows, in the WSL distro), so stopping it stops all of it.
    let mut sc = std::process::Command::new(&spec.argv[0]);
    sc.args(&spec.argv[1..]).current_dir(spec.cwd).env_clear().envs(spec.env.iter().cloned()).stdin(std::process::Stdio::null())
        .stdout(log.try_clone().map_err(|e| Stop::Failed(e.to_string()))?).stderr(log);
    let mut cmd = tokio::process::Command::from(crate::platform::runner_cmd(sc));
    let child = cmd.spawn().map_err(|e| Stop::Failed(format!("couldn't start the {} server: {e}", spec.name)))?;
    let pgid = child.id().unwrap_or(0) as i32;
    PGID.store(pgid, Ordering::Relaxed);
    eprintln!("media: starting the {} server on 127.0.0.1:{}", spec.name, spec.port);
    *slot().lock().await = Some(Running { name: spec.name, port: spec.port, pgid, last: Instant::now(), child });
    let until = Instant::now() + spec.ready_within;
    loop {
        if healthy(&c, &format!("{base}{}", spec.health)).await { return Ok(base); }
        let exited = slot().lock().await.as_mut().map_or(true, |r| !matches!(r.child.try_wait(), Ok(None)));
        if exited { evict().await; return Err(Stop::Failed(format!("the {} server stopped while starting (its log: media/{}.log in the node's folder)", spec.name, spec.name))); }
        if ctl.stopped() { evict().await; return Err(Stop::from(ctl)); }
        if Instant::now() > until { evict().await; return Err(Stop::Failed(format!("the {} server didn't answer within {} s", spec.name, spec.ready_within.as_secs()))); }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}
