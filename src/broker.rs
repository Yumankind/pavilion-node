//! The broker for one job (docs/MACHINES.md §5–6). It's the sandbox's only way out: its host-only network reaches this
//! Mac and nothing else. It answers only peers on the job's own subnet, takes the explicit form
//! `http://<broker>/<SECRET>/<host>/<path>`, and forwards to the Gate's `/node/egress/<grant>/<host>/<path>`, signed by
//! this machine's key. The Gate adds the secret and scrubs it from the reply; the value never reaches this machine.
//! It also answers OpenAI-compatible media calls, `http://<broker>/v1/…` (images, speech, transcripts), forwarded to the
//! Gate's `/node/jobs/<job>/v1/…` for this job only: the Gate makes media jobs of the job's project (docs/MEDIA.md §2).
//! And SSH (docs/SECRETS.md §7b): the sandbox's ProxyCommand sends `CONNECT <host>:<port>` here with its throwaway public
//! key; the broker opens a WebSocket, signed by this machine, to the Gate's `/node/jobs/<job>/ssh/<host>/<port>`, which
//! bridges it to the pavilion's SSH proxy. The real keys stay in the Gate; this machine never sees them either.
//! A hosted role's sandbox (roles.rs) gets a broker of its own with a `RoleDoor`: `http://<broker>/mcp` reaches the
//! role's tools at the Gate (`/node/mcp/steward` or `/node/mcp/orchestrator/<project>`, or `/node/mcp/lead/<project>`
//! from an older Gate) with the lease epoch, signed by this machine; its model key is an egress grant like any other;
//! `/local/v1/messages` reaches a local model (Ollama) for an orchestrator. No media doors and no SSH for roles: the same tools as in the cloud, nothing more.
use bytes::Bytes;
use ed25519_dalek::SigningKey;
use futures_util::TryStreamExt;
use http_body_util::{combinators::BoxBody, BodyExt, Full, Limited, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::{Request, Response, StatusCode};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::{self, client::IntoClientRequest, Message};

#[derive(Clone, Debug)]
pub struct Grant { pub id: String, pub hosts: Vec<String> }

pub struct Broker {
    pub gate: String,
    pub pavilion: String,
    /// The job this broker serves; media calls are made for it.
    pub job: String,
    pub key: SigningKey,
    /// secret name → grant, for this job only.
    pub grants: HashMap<String, Grant>,
    /// e.g. 192.168.128.0/24: the job's host-only network.
    pub subnet: (u32, u32),
    pub http: reqwest::Client,
    /// Set for a hosted role's sandbox (roles.rs) instead of a job.
    pub role: Option<Arc<RoleDoor>>,
    /// An agent job on one of this machine's own account slots (accounts.rs): the broker adds the slot's token itself,
    /// on the way to the provider, for the model API only. The token never enters the VM and never goes to the pavilion.
    pub slot: Option<Arc<crate::accounts::SlotDoor>>,
}

/// Counts one slot call's tokens when its answer ends (WORK-ROUTING §12), and sends the budget reports that are due.
struct Meter { tap: crate::accounts::TokenTap, door: Arc<crate::accounts::SlotDoor>, job: String }
impl Drop for Meter {
    fn drop(&mut self) {
        let n = self.tap.total();
        if n == 0 { return; }
        for m in crate::accounts::count(&self.door, n) { crate::live::report(&self.job, m); }
    }
}

/// What a hosted role's broker adds: its tools at the Gate, the lease epoch they're called with, its model grant (it
/// changes with the epoch), and a local model's address.
pub struct RoleDoor {
    /// `/node/mcp/steward` or `/node/mcp/orchestrator/<project>` (`/node/mcp/lead/<project>` from an older Gate:
    /// compatibility window), as the Gate gave it.
    pub mcp: String,
    pub epoch: std::sync::atomic::AtomicU64,
    pub grants: std::sync::RwLock<HashMap<String, Grant>>,
    /// e.g. http://127.0.0.1:11434 (Ollama) when an orchestrator runs on a local model.
    pub local: std::sync::RwLock<Option<String>>,
}

/// MCP messages are small JSON; a megabyte is plenty.
const MCP_MAX: usize = 1024 * 1024;

type Body = BoxBody<Bytes, std::io::Error>;
fn json_res(status: StatusCode, v: serde_json::Value) -> Response<Body> {
    Response::builder().status(status).header("content-type", "application/json").body(BodyExt::boxed(Full::new(Bytes::from(v.to_string())).map_err(|e| match e {}))).unwrap()
}
fn text(status: StatusCode, s: String) -> Response<Body> {
    Response::builder().status(status).header("content-type", "text/plain; charset=utf-8").header("x-pavilion-node", "blocked")
        .body(Full::new(Bytes::from(s)).map_err(|never| match never {}).boxed()).unwrap()
}

pub fn parse_subnet(cidr: &str) -> Option<(u32, u32)> {
    let (ip, bits) = cidr.split_once('/')?;
    let ip: std::net::Ipv4Addr = ip.parse().ok()?;
    let bits: u32 = bits.parse().ok()?;
    let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
    Some((u32::from(ip) & mask, mask))
}
fn in_subnet(ip: IpAddr, (net, mask): (u32, u32)) -> bool { matches!(ip, IpAddr::V4(v4) if u32::from(v4) & mask == net) }

/// Media door bodies hold images and audio, so they may be larger than egress bodies (the Gate's limit too).
const DOOR_MAX: usize = 32 * 1024 * 1024;

/// A door path: `/v1/` and plain segments only. No dot segments or escapes, so it can't become another Gate route.
pub fn door_path(path: &str) -> bool {
    path.starts_with("/v1/") && path.len() <= 200
        && path[1..].split('/').all(|s| !s.is_empty() && s != "." && s != ".." && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.'))
}
/// What the sandbox called this broker, for links it can fetch back (`http://<host>/v1/files/…`).
fn door_base(host: Option<&str>) -> Option<String> {
    let h = host?;
    let (name, port) = h.rsplit_once(':').map_or((h, None), |(n, p)| (n, Some(p)));
    let ok = !name.is_empty() && name.len() <= 253 && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        && port.map_or(true, |p| !p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit()));
    ok.then(|| format!("http://{h}"))
}

pub fn host_matches(pattern: &str, host: &str) -> bool {
    match pattern.strip_prefix("*.") { Some(base) => host.len() > base.len() + 1 && host.ends_with(&format!(".{base}")), None => host == pattern }
}

/* ---------- SSH from the sandbox (docs/SECRETS.md §7b) ---------- */

/// A CONNECT that was answered 200: what to run on that connection once hyper hands it over.
type Tunnel = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;
type Slot = Arc<std::sync::Mutex<Option<Tunnel>>>;
type GateSocket = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// `host:port` from a CONNECT: a lower-case host name with a dot (the Gate refuses IP addresses and local names) and a
/// port. Nothing that could change the Gate path.
pub fn ssh_target(authority: &str) -> Option<(String, u16)> {
    let (host, port) = authority.rsplit_once(':')?;
    let host = host.to_ascii_lowercase();
    let label = |l: &str| !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-') && l.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    let ok_host = host.len() <= 253 && host.contains('.') && host.split('.').all(label);
    let port: u16 = if !port.is_empty() && port.len() <= 5 && port.bytes().all(|b| b.is_ascii_digit()) { port.parse().ok()? } else { return None };
    (ok_host && port > 0).then_some((host, port))
}

/// The sandbox's throwaway key, `ssh-ed25519 <base64> [comment]`: its 51-byte public key blob, or None.
pub fn ssh_client_key(line: &str) -> Option<Vec<u8>> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let mut f = line.split_whitespace();
    if f.next()? != "ssh-ed25519" { return None; }
    let blob = STANDARD.decode(f.next()?).ok()?;
    let mut want = vec![0, 0, 0, 11]; want.extend_from_slice(b"ssh-ed25519"); want.extend_from_slice(&[0, 0, 0, 32]);
    (blob.len() == 51 && blob.starts_with(&want)).then_some(blob)
}

/// A key name, as the Gate takes it (`PAVILION_SSH_KEY` picks one when several fit).
pub fn ssh_key_name(k: &str) -> bool {
    !k.is_empty() && k.len() <= 40 && k.as_bytes()[0] != b'.' && k.as_bytes()[0] != b'-' && k.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
}

/// A refusal the ProxyCommand prints as "pavilion: …". The connection closes after it.
fn ssh_refused(status: StatusCode, why: &str) -> Response<Body> {
    let mut r = text(status, format!("{why}\n"));
    r.headers_mut().insert("connection", hyper::header::HeaderValue::from_static("close"));
    r
}

/// SSH bytes both ways between the sandbox's connection and the Gate's WebSocket, starting with the proxy's first bytes.
async fn pipe<T: tokio::io::AsyncRead + tokio::io::AsyncWrite>(io: T, ws: GateSocket, first: Vec<u8>) {
    use futures_util::{SinkExt, StreamExt};
    let (mut rd, mut wr) = tokio::io::split(io);
    let (mut tx, mut rx) = ws.split();
    if wr.write_all(&first).await.is_err() { return; }
    let down = async {
        while let Some(Ok(m)) = rx.next().await {
            match m { Message::Binary(b) => if wr.write_all(&b).await.is_err() { break }, Message::Close(_) => break, _ => {} }
        }
        let _ = wr.shutdown().await;
    };
    let up = async {
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            match rd.read(&mut buf).await { Ok(0) | Err(_) => break, Ok(n) => if tx.send(Message::binary(buf[..n].to_vec())).await.is_err() { break } }
        }
        let _ = tx.send(Message::Close(None)).await;
    };
    tokio::pin!(down);
    // The sandbox may stop sending before the last bytes from the server have arrived: give those a moment.
    tokio::select! { _ = &mut down => {}, _ = up => { let _ = tokio::time::timeout(Duration::from_secs(10), &mut down).await; } }
}

/// Run before every job's command, quietly, and only when the image has ssh: a throwaway key made inside the sandbox
/// for this job (its public half reaches the Gate with the first connection and is pinned to the job), an ssh config
/// that sends every connection through this job's broker, and the ProxyCommand. The Include goes first in ~/.ssh/config
/// so plain `ssh` and `git` use it; where that can't be written, GIT_SSH_COMMAND points git at it instead.
const SSH_SETUP: &str = r#"if [ -n "${PAVILION_BROKER:-}" ] && command -v ssh >/dev/null 2>&1 && command -v ssh-keygen >/dev/null 2>&1; then
( umask 077; d=${PAVILION_SSH_DIR:-/tmp/.pavilion-ssh}
  rm -rf "$d" && mkdir -p "$d" || exit 1
  ssh-keygen -q -t ed25519 -N '' -C pavilion-job -f "$d/id" </dev/null || exit 1
  b=${PAVILION_BROKER#http://}; printf '%s %s\n' "${b%:*}" "${b##*:}" > "$d/broker"; : > "$d/known_hosts"
  cat > "$d/connect" <<'PAVILION_SSH'
@CONNECT@PAVILION_SSH
  cat > "$d/config" <<PAVILION_SSH
@CONFIG@PAVILION_SSH
  h=${HOME:-/root}
  grep -qs "^Include $d/config" "$h/.ssh/config" && exit 0
  mkdir -p "$h/.ssh" && { echo "Include $d/config"; cat "$h/.ssh/config" 2>/dev/null || true; } > "$d/user-config" && cat "$d/user-config" > "$h/.ssh/config"
) >/dev/null 2>&1
grep -qs "^Include ${PAVILION_SSH_DIR:-/tmp/.pavilion-ssh}/config" "${HOME:-/root}/.ssh/config" || { [ -f "${PAVILION_SSH_DIR:-/tmp/.pavilion-ssh}/config" ] && export GIT_SSH_COMMAND="ssh -F ${PAVILION_SSH_DIR:-/tmp/.pavilion-ssh}/config"; }
:
fi
"#;

/// The ProxyCommand (`sh <dir>/connect %h %p`): one HTTP CONNECT to this job's broker with `nc`, or bash's /dev/tcp. A
/// refusal is printed as "pavilion: …"; on 200 the proxy's host key the broker names is pinned before any SSH byte is
/// passed on, so ssh checks the proxy against it.
const SSH_CONNECT: &str = r#"# ProxyCommand for SSH from this job's sandbox (written by pavilion-node). The real keys stay in the pavilion's Gate.
d=${0%/*}
read -r bh bp < "$d/broker" || exit 255
cr=$(printf '\r') f="$d/answer.$$"
tcp() {
  if command -v nc >/dev/null 2>&1; then exec nc "$bh" "$bp"; fi
  if command -v bash >/dev/null 2>&1; then exec bash -c 'exec 3<>"/dev/tcp/$0/$1" || exit 255; cat <&3 & exec cat >&3' "$bh" "$bp"; fi
  echo "pavilion: SSH from this sandbox needs nc or bash" >&2; exit 255
}
# The connection runs in the background and answers through a FIFO, so this shell holds nothing of ssh's but what it
# reads and writes itself: when it ends (a refusal), ssh sees the end at once.
rm -f "$f"; mkfifo "$f" || exit 255
exec 3<&0
{ printf 'CONNECT %s:%s HTTP/1.1\r\nHost: %s:%s\r\nX-Pavilion-Ssh-Client: %s\r\nX-Pavilion-Ssh-Key: %s\r\n\r\n' "$1" "$2" "$1" "$2" "$(cat "$d/id.pub")" "${PAVILION_SSH_KEY:-}"; exec cat <&3; } | tcp > "$f" &
exec 3<&- < "$f"
rm -f "$f"
IFS= read -r status || { echo "pavilion: this job's broker closed the connection" >&2; exit 255; }
key=
while IFS= read -r l; do
  l=${l%"$cr"}
  [ -z "$l" ] && break
  case $l in x-pavilion-ssh-proxy-key:*) key=${l#*: } ;; esac
done
case $status in
  "HTTP/1.1 200"*) [ -n "$key" ] && printf 'pavilion-proxy %s\n' "$key" > "$d/known_hosts.$$" && mv -f "$d/known_hosts.$$" "$d/known_hosts"; exec cat ;;
esac
IFS= read -r why
printf 'pavilion: %s\n' "${why:-the broker answered ${status%"$cr"}}" >&2
exit 255
"#;

/// Every connection goes through the broker; only the proxy's host key (pinned per connection) is trusted.
const SSH_CONFIG: &str = r#"# Written by pavilion-node for this job. Every SSH connection goes through this job's broker to the pavilion's SSH
# proxy, which holds the real keys, pins each server's host key and checks every command.
Host *
  ProxyCommand sh $d/connect %h %p
  IdentityFile $d/id
  IdentitiesOnly yes
  IdentityAgent none
  UserKnownHostsFile $d/known_hosts
  GlobalKnownHostsFile /dev/null
  HostKeyAlias pavilion-proxy
  StrictHostKeyChecking yes
  HostKeyAlgorithms ssh-ed25519
  UpdateHostKeys no
  ForwardAgent no
  ServerAliveInterval 30
"#;

/// The job's command, after the SSH setup. The command itself is unchanged and runs in the same shell.
pub fn with_ssh_setup(cmd: &str) -> String {
    format!("{}{cmd}", SSH_SETUP.replace("@CONNECT@", SSH_CONNECT).replace("@CONFIG@", SSH_CONFIG))
}

impl Broker {
    /// Listens on all addresses (the job's bridge only exists once its VM runs) and answers only the job's subnet.
    /// Ports 47100-47199 only; the packet filter lets job VMs reach those and nothing else on this Mac.
    pub async fn serve(self: Arc<Self>) -> anyhow::Result<(u16, tokio::task::JoinHandle<()>)> {
        // A fixed range, so the packet filter can allow exactly these ports from job VMs (node/pf/pavilion.conf).
        let mut listener = None;
        for port in 47100..=47199u16 { if let Ok(l) = TcpListener::bind(("0.0.0.0", port)).await { listener = Some(l); break; } }
        let listener = listener.ok_or_else(|| anyhow::anyhow!("all broker ports 47100-47199 are busy"))?;
        let port = listener.local_addr()?.port();
        let h = tokio::spawn(async move {
            // Every connection, SSH tunnels included, lives in this set: when the job ends and this task is aborted, they all go.
            let mut conns = tokio::task::JoinSet::new();
            loop {
                let Ok((stream, peer)) = listener.accept().await else { continue };
                while conns.try_join_next().is_some() {}
                if !in_subnet(peer.ip(), self.subnet) { drop(stream); continue; }
                let me = self.clone();
                conns.spawn(async move {
                    let slot: Slot = Default::default();
                    let s2 = slot.clone();
                    let svc = hyper::service::service_fn(move |req| { let me = me.clone(); let s = s2.clone(); async move { Ok::<_, std::convert::Infallible>(me.handle(req, peer, &s).await) } });
                    // Half-closes are fine: `nc` shuts its sending side when its input ends, and still wants the answer.
                    let _ = hyper::server::conn::http1::Builder::new().half_close(true).serve_connection(hyper_util::rt::TokioIo::new(stream), svc).with_upgrades().await;
                    // A CONNECT that was answered 200: the same connection now carries SSH bytes.
                    let tunnel = slot.lock().unwrap().take();
                    if let Some(t) = tunnel { t.await; }
                });
            }
        });
        Ok((port, h))
    }

    async fn handle(&self, req: Request<Incoming>, _peer: SocketAddr, slot: &Slot) -> Response<Body> {
        let path = req.uri().path().to_string();
        let query = req.uri().query().map(|q| format!("?{q}")).unwrap_or_default();
        if let Some(r) = &self.role {
            if path == "/mcp" { return self.mcp(req, r).await; }
            if path.starts_with("/local/") { return self.local(req, r, &path).await; }
            if req.method() == hyper::Method::CONNECT || path == "/v1" || path.starts_with("/v1/") {
                return text(StatusCode::FORBIDDEN, "Blocked by the node: a hosted role has its pavilion tools (/mcp) and its model, nothing else.\n".into());
            }
        }
        if req.method() == hyper::Method::CONNECT { return self.ssh(req, slot).await; }
        if path == "/v1" || path.starts_with("/v1/") { return self.door(req, &path).await; }
        let parts: Vec<&str> = path.trim_start_matches('/').splitn(3, '/').collect();
        if parts.len() < 2 || parts[0].is_empty() {
            let list: Vec<String> = self.grants.iter().map(|(s, g)| format!("{s} → {}", g.hosts.join(", "))).collect();
            return text(StatusCode::OK, format!("pavilion-node broker. Call http://<this address>/<SECRET>/<host>/<path>; the Gate adds the secret.\nThis job may use: {}\nMedia (OpenAI-compatible): OPENAI_BASE_URL=http://<this address>/v1\n", if list.is_empty() { "nothing".into() } else { list.join("; ") }));
        }
        let (secret, host, rest) = (parts[0], parts[1].to_lowercase(), format!("/{}", parts.get(2).unwrap_or(&"")));
        if let Some(p) = crate::slot_auth::by_secret(secret) { return self.slot_call(req, p, &host, &rest, &query).await; }
        let role_grant = self.role.as_ref().and_then(|r| r.grants.read().unwrap().get(secret).cloned());
        let Some(grant) = self.grants.get(secret).or(role_grant.as_ref()) else { return text(StatusCode::FORBIDDEN, format!("Blocked by the node: this job has no grant for {secret}.\n")) };
        if !grant.hosts.iter().any(|h| host_matches(h, &host)) { return text(StatusCode::FORBIDDEN, format!("Blocked by the node: {secret} isn't granted for {host}.\n")); }

        let method = req.method().clone();
        let mut headers = vec![];
        for (k, v) in req.headers() {
            let k = k.as_str().to_lowercase();
            if ["host", "connection", "content-length", "transfer-encoding", "authorization", "proxy-authorization", "cookie", "x-api-key"].contains(&k.as_str()) || k.starts_with("x-pavilion-") { continue; }
            if let Ok(v) = v.to_str() { headers.push((k, v.to_string())); }
        }
        // Bodies are signed, so they're read whole (8 MB at most, like the Gate).
        let body = match Limited::new(req.into_body(), 8 * 1024 * 1024).collect().await { Ok(b) => b.to_bytes(), Err(_) => return text(StatusCode::PAYLOAD_TOO_LARGE, "Blocked by the node: request over 8 MB.\n".into()) };

        let gate_url = reqwest::Url::parse(&self.gate).unwrap();
        let gate_host = gate_url.host_str().unwrap_or_default().to_string() + &gate_url.port().map(|p| format!(":{p}")).unwrap_or_default();
        let gate_path = format!("/p/{}/node/egress/{}/{}{}{}", self.pavilion, grant.id, host, rest, query);
        let mut rb = self.http.request(method.clone(), format!("{}{}", self.gate.trim_end_matches('/'), gate_path));
        for (k, v) in headers { rb = rb.header(k, v); }
        for (k, v) in crate::signing::signed_headers(&self.key, &gate_host, method.as_str(), &gate_path, &body) { rb = rb.header(k, v); }
        let res = match rb.body(body).send().await { Ok(r) => r, Err(e) => return text(StatusCode::BAD_GATEWAY, format!("Blocked by the node: the Gate didn't answer: {e}\n")) };
        // A model limit, from the provider's status and its own rate-limit headers: the pavilion pauses the work
        // instead of failing it (docs/WORK-ROUTING.md §8). Nothing else is read; never a credential.
        if let Some(l) = crate::live::limit_from(res.status().as_u16(), res.headers().iter().filter_map(|(k, v)| v.to_str().ok().map(|v| (k.as_str(), v)))) {
            crate::live::report_limit(&self.job, &host, l);
        }

        let mut out = Response::builder().status(res.status().as_u16());
        for (k, v) in res.headers() { if !["connection", "transfer-encoding", "content-length"].contains(&k.as_str()) { out = out.header(k, v); } }
        let stream = res.bytes_stream().map_ok(Frame::data).map_err(std::io::Error::other);
        out.body(BodyExt::boxed(StreamBody::new(stream))).unwrap()
    }

    /// `http://<broker>/<CLAUDE_SLOT|CODEX_SLOT|GEMINI_SLOT>/<host>/<path>` from an agent job on one of this machine's
    /// slots: the sandbox's credential headers dropped, the slot's current credential added (a Codex or Gemini one
    /// refreshed here first when it is near its end), straight to the provider. Only that provider's exact model calls
    /// (slot_auth.rs `allowed`), on its one host: never a token, profile, usage or history endpoint, and never another
    /// provider's. The reply's status, the provider's own rate-limit headers and a 429's own error say whether the slot
    /// is now limited or signed out (accounts.rs); nothing else is read.
    async fn slot_call(&self, req: Request<Incoming>, p: &'static crate::slot_auth::Provider, host: &str, rest: &str, query: &str) -> Response<Body> {
        use crate::slot_auth::{allowed, allowed_words, credential, AuthErr};
        let Some(door) = self.slot.as_ref() else { return text(StatusCode::FORBIDDEN, "Blocked by the node: this job has no account slot.\n".into()) };
        if door.harness != p.harness { return text(StatusCode::FORBIDDEN, format!("Blocked by the node: this job's slot is a {} slot, not {}.\n", door.harness, p.name)); }
        // Codex's own token refresh, pointed here from the VM (CODEX_REFRESH_TOKEN_URL_OVERRIDE): the real token is
        // refreshed on this machine, and the VM is answered with placeholders. Nothing reaches OpenAI from the VM.
        if p.harness == "codex" && host == crate::slot_auth::CODEX_AUTH_HOST {
            if req.method() != hyper::Method::POST || rest != crate::slot_auth::CODEX_TOKEN_PATH { return text(StatusCode::FORBIDDEN, format!("Blocked by the node: a Codex slot reaches {} for its refresh only.\n", crate::slot_auth::CODEX_AUTH_HOST)); }
            return match credential(&door.harness, &door.home, true).await {
                Ok(_) => json_res(StatusCode::OK, crate::slot_auth::codex_placeholder_refresh()),
                Err(AuthErr::SignedOut(why)) => { crate::accounts::signed_out(&door.slot); json_res(StatusCode::UNAUTHORIZED, serde_json::json!({ "error": "invalid_grant", "error_description": why })) }
                Err(AuthErr::Other(why)) => text(StatusCode::BAD_GATEWAY, format!("Blocked by the node: {why}\n")),
            };
        }
        if host != p.host { return text(StatusCode::FORBIDDEN, format!("Blocked by the node: a {} slot reaches {} only.\n", p.name, p.host)); }
        // Codex opens a WebSocket first; a 426 sends it to plain HTTP at once (codex-rs core/src/client.rs), which this
        // broker can read for limits and count. No credential is added to an upgrade.
        if p.harness == "codex" && req.headers().get("upgrade").and_then(|v| v.to_str().ok()).is_some_and(|v| v.eq_ignore_ascii_case("websocket")) {
            return text(StatusCode::UPGRADE_REQUIRED, "pavilion-node broker: plain HTTP only\n".into());
        }
        let method = req.method().clone();
        if !allowed(p.harness, method.as_str(), rest) {
            // A Gemini account that never finished its first-run setup asks for it here; that is done once on the host,
            // with the person (decided 21 Nov 2026), so the refusal says how.
            if p.harness == "gemini-cli" && rest == "/v1internal:onboardUser" {
                return text(StatusCode::FORBIDDEN, "Blocked by the node: this Gemini account hasn't finished setting up. On this machine run pavilion-node accounts add gemini <its label> again, ask the Gemini CLI one question, then /quit.\n".into());
            }
            return text(StatusCode::FORBIDDEN, format!("Blocked by the node: a slot carries {}.\n", allowed_words(p.harness)));
        }
        // The slot's token budgets (WORK-ROUTING §12): a spent turn or day gets no further call. Not a 429: the provider
        // didn't refuse anything, so nothing here may read as a model limit.
        if let Some((scope, used, limit)) = crate::accounts::over_budget(door) {
            let bit = if scope == "turn" { 2 } else { 8 };
            if door.told.fetch_or(bit, std::sync::atomic::Ordering::Relaxed) & bit == 0 {
                if scope == "day" { crate::accounts::limited(&door.slot, Some(crate::accounts::next_day(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)))); }
                crate::live::report(&self.job, serde_json::json!({ "t": "budget", "slot": door.slot, "scope": scope, "used": used, "limit": limit }));
            }
            return text(StatusCode::FORBIDDEN, format!("Blocked by the node: this slot's {} token budget is used ({used} of {limit}).\n", if scope == "turn" { "per-turn" } else { "daily" }));
        }
        let mut headers = vec![];
        let mut beta = None;
        for (k, v) in req.headers() {
            let k = k.as_str().to_lowercase();
            if ["host", "connection", "content-length", "transfer-encoding", "authorization", "proxy-authorization", "cookie", "x-api-key", "chatgpt-account-id", "x-openai-fedramp", "x-goog-api-key", "upgrade"].contains(&k.as_str())
                || k.starts_with("x-pavilion-") { continue; }
            let Ok(v) = v.to_str() else { continue };
            if k == "anthropic-beta" && p.harness == "claude-code" { beta = Some(v.to_string()); continue; }
            headers.push((k, v.to_string()));
        }
        // The credential: a Claude slot's token as kept; a Codex or Gemini one read now, refreshed here when near its end.
        let cred = if p.harness == "claude-code" {
            crate::slot_auth::Cred { bearer: zeroize::Zeroizing::new(door.token.as_str().to_string()), account: None }
        } else {
            match credential(&door.harness, &door.home, false).await {
                Ok(c) => c,
                Err(AuthErr::SignedOut(why)) => { crate::accounts::signed_out(&door.slot); return text(StatusCode::UNAUTHORIZED, format!("Blocked by the node: {why}.\n")); }
                Err(AuthErr::Other(why)) => return text(StatusCode::BAD_GATEWAY, format!("Blocked by the node: {why}.\n")),
            }
        };
        let body = match Limited::new(req.into_body(), 32 * 1024 * 1024).collect().await { Ok(b) => b.to_bytes(), Err(_) => return text(StatusCode::PAYLOAD_TOO_LARGE, "Blocked by the node: request over 32 MB.\n".into()) };
        let mut rb = self.http.request(method.clone(), format!("{}{rest}{query}", door.upstream.trim_end_matches('/')));
        for (k, v) in headers { rb = rb.header(k, v); }
        if p.harness == "claude-code" {
            // A subscription token works only with the OAuth beta, which Claude Code sends; added when it is missing.
            let beta = match beta { Some(b) if b.split(',').any(|x| x.trim() == "oauth-2025-04-20") => b, Some(b) => format!("{b},oauth-2025-04-20"), None => "oauth-2025-04-20".into() };
            rb = rb.header("anthropic-beta", beta);
        }
        rb = rb.header("authorization", format!("Bearer {}", cred.bearer.as_str()));
        if let Some(a) = &cred.account { rb = rb.header("chatgpt-account-id", a.as_str()); }
        drop(cred);
        if method == hyper::Method::POST { rb = rb.body(body); }
        let res = match rb.send().await { Ok(r) => r, Err(e) => return text(StatusCode::BAD_GATEWAY, format!("Blocked by the node: {host} didn't answer: {}\n", e.without_url())) };
        let status = res.status().as_u16();
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);
        let mut out = Response::builder().status(status);
        for (k, v) in res.headers() { if !["connection", "transfer-encoding", "content-length", "set-cookie"].contains(&k.as_str()) { out = out.header(k, v); } }
        if let Some(l) = crate::live::limit_from(status, res.headers().iter().filter_map(|(k, v)| v.to_str().ok().map(|v| (k.as_str(), v)))) {
            // A Codex or Gemini 429 says its reset in its own error: read that (64 KB at most), and pass it on unchanged.
            let mut err = Vec::new();
            let mut res = res;
            if status == 429 && p.harness != "claude-code" {
                while let Ok(Some(c)) = res.chunk().await { if err.len() + c.len() > 64 * 1024 { break; } err.extend_from_slice(&c); }
            }
            let until = crate::slot_auth::limit_until(p.harness, &err, now)
                .or_else(|| l["retry_after_s"].as_u64().map(|s| now + s * 1000)).or_else(|| l["reset_at_s"].as_u64().map(|s| s * 1000));
            crate::accounts::limited(&door.slot, until);
            let mut l = l; l["slot"] = serde_json::json!(door.slot);
            if let Some(u) = until { l["until_ms"] = serde_json::json!(u); }
            crate::live::report_limit(&self.job, host, l);
            if !err.is_empty() || p.harness != "claude-code" { return out.body(BodyExt::boxed(Full::new(Bytes::from(err)).map_err(|e| match e {}))).unwrap(); }
            let stream = res.bytes_stream().map_ok(Frame::data).map_err(std::io::Error::other);
            return out.body(BodyExt::boxed(StreamBody::new(stream))).unwrap();
        } else if status == 401 {
            // A Claude token can't be renewed here: signed out. A Codex or Gemini one is refreshed once; only a refused
            // refresh signs the slot out (the harness in the VM retries, and Codex asks this broker for its refresh).
            if p.harness == "claude-code" { crate::accounts::signed_out(&door.slot); }
            else if let Err(AuthErr::SignedOut(_)) = credential(&door.harness, &door.home, true).await { crate::accounts::signed_out(&door.slot); }
        } else if status < 400 {
            crate::accounts::used(&door.slot);
        }
        // The tokens are counted from the answer's own usage as it passes, and added up when it ends (or is dropped).
        let mut meter = Meter { tap: crate::accounts::TokenTap::default(), door: door.clone(), job: self.job.clone() };
        let stream = futures_util::StreamExt::map(res.bytes_stream(), move |r| { if let Ok(b) = &r { meter.tap.feed(b); } r }).map_ok(Frame::data).map_err(std::io::Error::other);
        out.body(BodyExt::boxed(StreamBody::new(stream))).unwrap()
    }

    /// `/mcp` from a hosted role's sandbox → the Gate's MCP route for that role, with the current lease epoch, signed by
    /// this machine. Only the JSON body goes; the sandbox can't name another role, project or epoch.
    async fn mcp(&self, req: Request<Incoming>, r: &RoleDoor) -> Response<Body> {
        if req.method() != hyper::Method::POST { return text(StatusCode::METHOD_NOT_ALLOWED, "POST JSON-RPC here\n".into()); }
        let body = match Limited::new(req.into_body(), MCP_MAX).collect().await { Ok(b) => b.to_bytes(), Err(_) => return text(StatusCode::PAYLOAD_TOO_LARGE, "Blocked by the node: MCP message over 1 MB.\n".into()) };
        let epoch = r.epoch.load(std::sync::atomic::Ordering::SeqCst);
        if epoch == 0 { return text(StatusCode::SERVICE_UNAVAILABLE, "Blocked by the node: this machine doesn't hold the role right now.\n".into()); }
        let gate_url = reqwest::Url::parse(&self.gate).unwrap();
        let gate_host = gate_url.host_str().unwrap_or_default().to_string() + &gate_url.port().map(|p| format!(":{p}")).unwrap_or_default();
        let gate_path = format!("/p/{}{}?epoch={epoch}", self.pavilion, r.mcp);
        let mut rb = self.http.post(format!("{}{}", self.gate.trim_end_matches('/'), gate_path)).header("content-type", "application/json");
        for (k, v) in crate::signing::signed_headers(&self.key, &gate_host, "POST", &gate_path, &body) { rb = rb.header(k, v); }
        let res = match rb.body(body).send().await { Ok(r) => r, Err(e) => return text(StatusCode::BAD_GATEWAY, format!("Blocked by the node: the Gate didn't answer: {e}\n")) };
        let mut out = Response::builder().status(res.status().as_u16());
        if let Some(ct) = res.headers().get("content-type") { out = out.header("content-type", ct); }
        let stream = res.bytes_stream().map_ok(Frame::data).map_err(std::io::Error::other);
        out.body(BodyExt::boxed(StreamBody::new(stream))).unwrap()
    }

    /// `/local/v1/messages` from an orchestrator's sandbox → the local model server on this machine (Ollama's
    /// Anthropic-compatible API). Only that path, only the body and its type; nothing from the sandbox reaches any other local service.
    async fn local(&self, req: Request<Incoming>, r: &RoleDoor, path: &str) -> Response<Body> {
        let Some(base) = r.local.read().unwrap().clone() else { return text(StatusCode::NOT_FOUND, "Blocked by the node: no local model for this role.\n".into()) };
        let sub = &path["/local".len()..];
        if req.method() != hyper::Method::POST || !(sub == "/v1/messages" || sub == "/v1/messages/count_tokens") {
            return text(StatusCode::NOT_FOUND, "Blocked by the node: only POST /local/v1/messages.\n".into());
        }
        let version = req.headers().get("anthropic-version").and_then(|v| v.to_str().ok()).map(str::to_string);
        let body = match Limited::new(req.into_body(), 8 * 1024 * 1024).collect().await { Ok(b) => b.to_bytes(), Err(_) => return text(StatusCode::PAYLOAD_TOO_LARGE, "Blocked by the node: request over 8 MB.\n".into()) };
        let mut rb = self.http.post(format!("{}{sub}", base.trim_end_matches('/'))).header("content-type", "application/json");
        if let Some(v) = version { rb = rb.header("anthropic-version", v); }
        let res = match rb.body(body).send().await { Ok(r) => r, Err(e) => return text(StatusCode::BAD_GATEWAY, format!("Blocked by the node: the local model didn't answer: {e}\n")) };
        let mut out = Response::builder().status(res.status().as_u16());
        if let Some(ct) = res.headers().get("content-type") { out = out.header("content-type", ct); }
        let stream = res.bytes_stream().map_ok(Frame::data).map_err(std::io::Error::other);
        out.body(BodyExt::boxed(StreamBody::new(stream))).unwrap()
    }

    /// `/v1/…` from the sandbox → the Gate's `/p/<pavilion>/node/jobs/<job>/v1/…`, signed by this machine. Only the body,
    /// its type and where the sandbox reached us are passed on; the SDK's (dummy) API key and anything else stay here.
    async fn door(&self, req: Request<Incoming>, path: &str) -> Response<Body> {
        if !door_path(path) { return text(StatusCode::NOT_FOUND, "Blocked by the node: not a media door. Try /v1/images/generations, /v1/audio/speech, /v1/audio/transcriptions or /v1/models.\n".into()); }
        let method = req.method().clone();
        let ct = req.headers().get("content-type").and_then(|v| v.to_str().ok()).map(str::to_string);
        let base = door_base(req.headers().get("host").and_then(|v| v.to_str().ok()));
        let body = match Limited::new(req.into_body(), DOOR_MAX).collect().await { Ok(b) => b.to_bytes(), Err(_) => return text(StatusCode::PAYLOAD_TOO_LARGE, "Blocked by the node: request over 32 MB.\n".into()) };

        let gate_url = reqwest::Url::parse(&self.gate).unwrap();
        let gate_host = gate_url.host_str().unwrap_or_default().to_string() + &gate_url.port().map(|p| format!(":{p}")).unwrap_or_default();
        let gate_path = format!("/p/{}/node/jobs/{}{}", self.pavilion, self.job, path);
        let mut rb = self.http.request(method.clone(), format!("{}{}", self.gate.trim_end_matches('/'), gate_path));
        if let Some(ct) = ct { rb = rb.header("content-type", ct); }
        if let Some(b) = base { rb = rb.header("x-pavilion-door-base", b); }
        for (k, v) in crate::signing::signed_headers(&self.key, &gate_host, method.as_str(), &gate_path, &body) { rb = rb.header(k, v); }
        let res = match rb.body(body).send().await { Ok(r) => r, Err(e) => return text(StatusCode::BAD_GATEWAY, format!("Blocked by the node: the Gate didn't answer: {e}\n")) };

        let mut out = Response::builder().status(res.status().as_u16());
        for (k, v) in res.headers() { if !["connection", "transfer-encoding", "content-length"].contains(&k.as_str()) { out = out.header(k, v); } }
        let stream = res.bytes_stream().map_ok(Frame::data).map_err(std::io::Error::other);
        out.body(BodyExt::boxed(StreamBody::new(stream))).unwrap()
    }

    /// `CONNECT <host>:<port>` from the sandbox's ProxyCommand → a WebSocket to the Gate for this job, signed by this
    /// machine. The answer waits for the proxy's first bytes (its SSH banner) or the Gate's reason, so a refusal reaches
    /// the sandbox as text ("pavilion: …"), not as a dropped connection. On 200 it names the proxy's host key to pin.
    async fn ssh(&self, mut req: Request<Incoming>, slot: &Slot) -> Response<Body> {
        let Some((host, port)) = req.uri().authority().and_then(|a| ssh_target(a.as_str())) else {
            return ssh_refused(StatusCode::BAD_REQUEST, "this broker only opens SSH connections: CONNECT <host>:<port>, with a host name");
        };
        let Some(client) = req.headers().get("x-pavilion-ssh-client").and_then(|v| v.to_str().ok()).and_then(ssh_client_key) else {
            return ssh_refused(StatusCode::BAD_REQUEST, "no SSH key from the sandbox (x-pavilion-ssh-client: ssh-ed25519 …)");
        };
        let key = req.headers().get("x-pavilion-ssh-key").and_then(|v| v.to_str().ok()).map(str::trim).filter(|k| !k.is_empty()).map(str::to_string);
        if key.as_deref().is_some_and(|k| !ssh_key_name(k)) { return ssh_refused(StatusCode::BAD_REQUEST, "bad key name in PAVILION_SSH_KEY"); }

        let gate_url = reqwest::Url::parse(&self.gate).unwrap();
        let gate_host = gate_url.host_str().unwrap_or_default().to_string() + &gate_url.port().map(|p| format!(":{p}")).unwrap_or_default();
        let path = format!("/p/{}/node/jobs/{}/ssh/{}/{}?client={}{}", self.pavilion, self.job, host, port, crate::signing::b64(&client),
            key.map(|k| format!("&key={k}")).unwrap_or_default());
        let ws_url = format!("{}{}", self.gate.replacen("https://", "wss://", 1).replacen("http://", "ws://", 1).trim_end_matches('/'), path);
        let Ok(mut wreq) = ws_url.into_client_request() else { return ssh_refused(StatusCode::BAD_GATEWAY, "bad Gate address") };
        for (k, v) in crate::signing::signed_headers(&self.key, &gate_host, "GET", &path, b"") { if let Ok(v) = v.parse() { wreq.headers_mut().insert(k, v); } }
        let (mut ws, res) = match tokio::time::timeout(Duration::from_secs(30), tokio_tungstenite::connect_async(wreq)).await {
            Ok(Ok(x)) => x,
            Ok(Err(tungstenite::Error::Http(r))) => {
                let why = r.body().as_deref().and_then(|b| serde_json::from_slice::<serde_json::Value>(b).ok()).and_then(|j| j["error"].as_str().map(str::to_string))
                    .unwrap_or_else(|| format!("the Gate answered {}", r.status()));
                eprintln!("ssh: {} → {host}:{port} refused: {why}", self.job);
                return ssh_refused(StatusCode::FORBIDDEN, &why);
            }
            Ok(Err(e)) => return ssh_refused(StatusCode::BAD_GATEWAY, &format!("couldn't reach the Gate: {e}")),
            Err(_) => return ssh_refused(StatusCode::GATEWAY_TIMEOUT, "the Gate didn't answer in time"),
        };
        let Some(proxy_key) = res.headers().get("x-pavilion-ssh-proxy-key").and_then(|v| v.to_str().ok()).and_then(|v| ssh_client_key(v).map(|_| v.to_string())) else {
            return ssh_refused(StatusCode::BAD_GATEWAY, "the Gate didn't name the SSH proxy's host key");
        };
        // The proxy speaks first (its version line); a Gate that closes instead says why.
        let first = loop {
            match tokio::time::timeout(Duration::from_secs(90), futures_util::StreamExt::next(&mut ws)).await {
                Ok(Some(Ok(Message::Binary(b)))) => break b,
                Ok(Some(Ok(Message::Close(f)))) => {
                    let why = f.map(|f| f.reason.to_string()).filter(|r| !r.is_empty()).unwrap_or_else(|| "the Gate closed the connection".into());
                    eprintln!("ssh: {} → {host}:{port} ended: {why}", self.job);
                    return ssh_refused(StatusCode::BAD_GATEWAY, &why);
                }
                Ok(Some(Ok(_))) => continue,
                Ok(Some(Err(e))) => return ssh_refused(StatusCode::BAD_GATEWAY, &format!("the connection to the Gate failed: {e}")),
                Ok(None) => return ssh_refused(StatusCode::BAD_GATEWAY, "the Gate closed the connection"),
                Err(_) => return ssh_refused(StatusCode::GATEWAY_TIMEOUT, "the SSH proxy didn't start in time"),
            }
        };
        eprintln!("ssh: {} → {host}:{port} open", self.job);
        let upgrade = hyper::upgrade::on(&mut req);
        *slot.lock().unwrap() = Some(Box::pin(async move {
            if let Ok(up) = upgrade.await { pipe(hyper_util::rt::TokioIo::new(up), ws, first.to_vec()).await; }
        }));
        Response::builder().status(StatusCode::OK).header("x-pavilion-ssh-proxy-key", proxy_key)
            .body(Full::new(Bytes::new()).map_err(|never| match never {}).boxed()).unwrap()
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn subnets() {
        let s = parse_subnet("192.168.128.0/24").unwrap();
        assert!(in_subnet("192.168.128.2".parse().unwrap(), s));
        assert!(!in_subnet("192.168.129.2".parse().unwrap(), s));
        assert!(!in_subnet("10.0.0.5".parse().unwrap(), s));
    }
    #[test]
    fn doors() {
        assert!(door_path("/v1/images/generations"));
        assert!(door_path("/v1/files/ast_0123456789abcdef01234567"));
        assert!(!door_path("/v1"));
        assert!(!door_path("/v1/../egress/grt_x/example.com"));
        assert!(!door_path("/v1/images/./x"));
        assert!(!door_path("/v1/%2e%2e/media/next"));
        assert!(!door_path("/v1//models"));
        assert_eq!(door_base(Some("10.89.0.1:47100")).as_deref(), Some("http://10.89.0.1:47100"));
        assert_eq!(door_base(Some("evil.example/x")), None);
        assert_eq!(door_base(Some("h:")), None);
        assert_eq!(door_base(None), None);
    }
    /// A sandbox's OpenAI call goes to the Gate's door for this job, signed, without the SDK's key; tricks stay here.
    #[tokio::test]
    async fn doors_forward_to_the_gate() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        // A stand-in Gate that answers once per connection with what it was sent.
        let gate = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gate_port = gate.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = gate.accept().await else { break };
                tokio::spawn(async move {
                    let svc = hyper::service::service_fn(|req: Request<Incoming>| async move {
                        let mut seen = vec![format!("{} {}", req.method(), req.uri().path())];
                        let mut names: Vec<String> = req.headers().iter().map(|(k, v)| format!("{k}={}", v.to_str().unwrap_or(""))).collect();
                        names.sort();
                        seen.extend(names);
                        let body = req.into_body().collect().await.unwrap().to_bytes();
                        seen.push(String::from_utf8_lossy(&body).into_owned());
                        Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from(seen.join("\n")))))
                    });
                    let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(stream), svc).await;
                });
            }
        });
        let broker = Arc::new(Broker { gate: format!("http://127.0.0.1:{gate_port}"), pavilion: "pv".into(), job: "job_abc".into(),
            key: SigningKey::from_bytes(&[7u8; 32]), grants: HashMap::new(), subnet: parse_subnet("127.0.0.0/8").unwrap(), http: reqwest::Client::new(), role: None, slot: None });
        let (port, task) = broker.serve().await.unwrap();
        let r = reqwest::Client::new().post(format!("http://127.0.0.1:{port}/v1/images/generations")).bearer_auth("sk-dummy")
            .header("x-pavilion-door-base", "http://evil.example").header("cookie", "a=b").header("content-type", "application/json")
            .body(r#"{"prompt":"a cat"}"#).send().await.unwrap();
        assert_eq!(r.status(), 200);
        let seen = r.text().await.unwrap();
        assert!(seen.starts_with("POST /p/pv/node/jobs/job_abc/v1/images/generations\n"), "{seen}");
        assert!(seen.contains(&format!("x-pavilion-door-base=http://127.0.0.1:{port}")), "{seen}");
        assert!(seen.contains("x-pavilion-signature=") && seen.contains("content-type=application/json") && seen.ends_with(r#"{"prompt":"a cat"}"#), "{seen}");
        assert!(!seen.contains("authorization") && !seen.contains("sk-dummy") && !seen.contains("cookie") && !seen.contains("evil.example"), "{seen}");
        // A dot segment never leaves the broker (sent raw: an HTTP client would tidy it up first).
        let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        s.write_all(b"GET /v1/../node/media/next HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n").await.unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).await.unwrap();
        assert!(out.starts_with("HTTP/1.1 404") && out.contains("not a media door"), "{out}");
        task.abort();
    }
    #[test]
    fn ssh_targets_and_keys() {
        assert_eq!(ssh_target("github.com:22"), Some(("github.com".into(), 22)));
        assert_eq!(ssh_target("Git.Example.COM:2222"), Some(("git.example.com".into(), 2222)));
        for bad in ["github.com", "github.com:", "github.com:0", "github.com:65536", "github.com:+22", "localhost:22",
            "a..b:22", "-a.b:22", "a-.b:22", "a.b/../c:22", "a.b%2f:22", "[::1]:22", "a.b:22 ", "user@a.b:22", "a_b.c:22"] {
            assert_eq!(ssh_target(bad), None, "{bad}");
        }
        // An IP address passes here as a name with digits; the Gate refuses it (only names, never local ones).
        let pk = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
        assert_eq!(ssh_client_key(pk).map(|b| b.len()), Some(51));
        assert!(ssh_client_key(&format!("{pk} pavilion-job")).is_some());
        assert!(ssh_client_key(&pk.replace("ssh-ed25519", "ssh-rsa")).is_none());
        assert!(ssh_client_key("ssh-ed25519 AAAAB3NzaC1yc2EAAAADAQABAAABAQ").is_none());
        assert!(ssh_client_key("ssh-ed25519 not*base64").is_none());
        assert!(ssh_client_key("").is_none());
        assert!(ssh_key_name("deploy.staging") && ssh_key_name("acme-push"));
        assert!(!ssh_key_name("") && !ssh_key_name("Acme") && !ssh_key_name("a&b=c") && !ssh_key_name("-x") && !ssh_key_name(&"a".repeat(41)));
    }

    /// A stand-in for the Gate's SSH route: refuses one host before the upgrade, closes with a reason for another, and
    /// for the rest names a proxy host key, sends a banner and echoes. Returns its port and the paths it was asked for.
    async fn standin_ssh_gate() -> (u16, Arc<std::sync::Mutex<Vec<String>>>) {
        use futures_util::{SinkExt, StreamExt};
        use tungstenite::handshake::server::{ErrorResponse, Request as WsReq, Response as WsRes};
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let seen = Arc::new(std::sync::Mutex::new(vec![]));
        let seen2 = seen.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = l.accept().await else { break };
                let seen = seen2.clone();
                tokio::spawn(async move {
                    let path = Arc::new(std::sync::Mutex::new(String::new()));
                    let p2 = path.clone();
                    let cb = move |req: &WsReq, mut res: WsRes| -> Result<WsRes, ErrorResponse> {
                        let pq = req.uri().path_and_query().map(|x| x.to_string()).unwrap_or_default();
                        let signed = ["x-pavilion-key", "x-pavilion-time", "x-pavilion-nonce", "x-pavilion-signature"].iter().all(|h| req.headers().contains_key(*h));
                        *p2.lock().unwrap() = format!("{pq} signed={signed}");
                        if pq.contains("/refused.example/") {
                            return Err(tungstenite::http::Response::builder().status(403).body(Some(r#"{"error":"no SSH key lets project acme on this machine reach refused.example:22"}"#.into())).unwrap());
                        }
                        res.headers_mut().insert("x-pavilion-ssh-proxy-key", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl".parse().unwrap());
                        Ok(res)
                    };
                    let ws = tokio_tungstenite::accept_hdr_async(stream, cb).await;
                    seen.lock().unwrap().push(path.lock().unwrap().clone());
                    let Ok(mut ws) = ws else { return };
                    if path.lock().unwrap().contains("/closing.example/") {
                        let _ = ws.send(Message::Close(Some(tungstenite::protocol::CloseFrame { code: 4003.into(), reason: "budget reached: machine x".into() }))).await;
                        return;
                    }
                    let _ = ws.send(Message::binary(b"SSH-2.0-standin\r\n".to_vec())).await;
                    while let Some(Ok(m)) = ws.next().await {
                        match m { Message::Binary(b) => { let mut e = b"echo:".to_vec(); e.extend_from_slice(&b); let _ = ws.send(Message::binary(e)).await; } Message::Close(_) => break, _ => {} }
                    }
                });
            }
        });
        (port, seen)
    }

    fn test_broker(gate_port: u16) -> Arc<Broker> {
        Arc::new(Broker { gate: format!("http://127.0.0.1:{gate_port}"), pavilion: "pv".into(), job: "job_abc".into(),
            key: SigningKey::from_bytes(&[7u8; 32]), grants: HashMap::new(), subnet: parse_subnet("127.0.0.0/8").unwrap(), http: reqwest::Client::new(), role: None, slot: None })
    }

    /// CONNECT from a sandbox → a signed WebSocket to the Gate's route for this job; bytes both ways; refusals as text.
    #[tokio::test]
    async fn ssh_forwards_to_the_gate() {
        let (gate_port, seen) = standin_ssh_gate().await;
        let (port, task) = test_broker(gate_port).serve().await.unwrap();
        let pk = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl pavilion-job";
        let connect = |target: &str, extra: &str| format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nX-Pavilion-Ssh-Client: {pk}\r\n{extra}\r\n");
        async fn send(port: u16, req: String) -> tokio::net::TcpStream {
            let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            s.write_all(req.as_bytes()).await.unwrap();
            s
        }
        async fn read_all(mut s: tokio::net::TcpStream) -> String { let mut out = String::new(); let _ = s.read_to_string(&mut out).await; out }

        // Allowed: 200 naming the proxy's host key, then the proxy's banner, then bytes both ways.
        let mut s = send(port, connect("git.example.com:2222", "X-Pavilion-Ssh-Key: deploy\r\n")).await;
        let mut buf = vec![0u8; 4096];
        let mut got = String::new();
        while !got.contains("SSH-2.0-standin\r\n") { let n = s.read(&mut buf).await.unwrap(); assert!(n > 0, "{got}"); got.push_str(&String::from_utf8_lossy(&buf[..n])); }
        assert!(got.starts_with("HTTP/1.1 200 OK\r\n") && got.contains("x-pavilion-ssh-proxy-key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\r\n"), "{got}");
        s.write_all(b"SSH-2.0-client\r\n").await.unwrap();
        let n = s.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"echo:SSH-2.0-client\r\n");
        drop(s);
        let p = seen.lock().unwrap()[0].clone();
        assert_eq!(p, format!("/p/pv/node/jobs/job_abc/ssh/git.example.com/2222?client={}&key=deploy signed=true",
            crate::signing::b64(&ssh_client_key(pk).unwrap())));

        // Refused by the Gate before the upgrade: its reason, and the connection closes.
        let out = read_all(send(port, connect("refused.example:22", "")).await).await;
        assert!(out.starts_with("HTTP/1.1 403") && out.ends_with("no SSH key lets project acme on this machine reach refused.example:22\n"), "{out}");
        // Closed by the Gate with a reason (a budget, the job ended): that reason.
        let out = read_all(send(port, connect("closing.example:22", "")).await).await;
        assert!(out.starts_with("HTTP/1.1 502") && out.ends_with("budget reached: machine x\n"), "{out}");
        // Never reaches the Gate: an IP or local name, no key, a bad key name, a path in the target.
        let before = seen.lock().unwrap().len();
        for (target, extra) in [("127.0.0.1:22x", ""), ("localhost:22", ""), ("a.b:22/../x", ""), ("git.example.com:22", "X-Pavilion-Ssh-Key: a&b\r\n")] {
            let out = read_all(send(port, connect(target, extra)).await).await;
            assert!(out.starts_with("HTTP/1.1 400"), "{target}: {out}");
        }
        let out = read_all(send(port, "CONNECT git.example.com:22 HTTP/1.1\r\nHost: x\r\n\r\n".into()).await).await;
        assert!(out.starts_with("HTTP/1.1 400") && out.contains("no SSH key from the sandbox"), "{out}");
        assert_eq!(seen.lock().unwrap().len(), before);

        // When the job ends (its broker task is aborted), open tunnels end with it.
        let mut s = send(port, connect("git.example.com:22", "")).await;
        let mut got = String::new();
        while !got.contains("SSH-2.0-standin\r\n") { let n = s.read(&mut buf).await.unwrap(); assert!(n > 0); got.push_str(&String::from_utf8_lossy(&buf[..n])); }
        task.abort();
        let _ = task.await;
        let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf)).await.expect("the tunnel should close").unwrap_or(0);
        assert_eq!(n, 0, "the tunnel is still open");
    }

    /// The setup and ProxyCommand that go into every sandbox, run by this machine's own `sh` (and nc or bash) against
    /// the broker: the key and config are made, refusals print as "pavilion: …", and the proxy's host key is pinned.
    #[tokio::test]
    async fn ssh_setup_and_proxycommand_work_with_plain_sh() {
        if std::process::Command::new("ssh-keygen").arg("-?").output().is_err() { eprintln!("no ssh-keygen here; skipped"); return; }
        let (gate_port, _) = standin_ssh_gate().await;
        let (port, task) = test_broker(gate_port).serve().await.unwrap();
        let tmp = std::env::temp_dir().join(format!("pav-ssh-test-{}", rand::random::<u32>()));
        let (dir, home) = (tmp.join("ssh"), tmp.join("home"));
        std::fs::create_dir_all(&home).unwrap();
        let out = tokio::process::Command::new("sh").arg("-c").arg(with_ssh_setup("echo job-ran; echo \"git=${GIT_SSH_COMMAND:-}\""))
            .env("PAVILION_BROKER", format!("http://127.0.0.1:{port}")).env("PAVILION_SSH_DIR", &dir).env("HOME", &home).output().await.unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(out.status.success() && stdout == "job-ran\ngit=\n", "{stdout} {}", String::from_utf8_lossy(&out.stderr));
        assert!(out.stderr.is_empty(), "the setup is quiet: {}", String::from_utf8_lossy(&out.stderr));
        let conf = std::fs::read_to_string(dir.join("config")).unwrap();
        assert!(conf.contains(&format!("ProxyCommand sh {}/connect %h %p", dir.display())) && conf.contains("StrictHostKeyChecking yes"), "{conf}");
        assert_eq!(std::fs::read_to_string(home.join(".ssh/config")).unwrap(), format!("Include {}/config\n", dir.display()));
        assert!(std::fs::read_to_string(dir.join("id.pub")).unwrap().starts_with("ssh-ed25519 "));
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(dir.join("id")).unwrap().permissions().mode() & 0o077, 0, "the key is private");
        // Run again (a warm sandbox's next step): a new key, and the Include isn't added twice.
        let old = std::fs::read_to_string(dir.join("id.pub")).unwrap();
        let _ = tokio::process::Command::new("sh").arg("-c").arg(with_ssh_setup("true")).env("PAVILION_BROKER", format!("http://127.0.0.1:{port}"))
            .env("PAVILION_SSH_DIR", &dir).env("HOME", &home).output().await.unwrap();
        assert_ne!(std::fs::read_to_string(dir.join("id.pub")).unwrap(), old);
        assert_eq!(std::fs::read_to_string(home.join(".ssh/config")).unwrap().matches("Include").count(), 1);

        // The ProxyCommand: allowed → the proxy's bytes on stdout, its key pinned; refused → the reason on stderr.
        let run = |host: &str| { let mut c = tokio::process::Command::new("sh"); c.arg(dir.join("connect")).arg(host).arg("22").stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()); c };
        let mut child = run("git.example.com").spawn().unwrap();
        let mut stdin = child.stdin.take().unwrap();
        let mut stdout = child.stdout.take().unwrap();
        let mut got = vec![];
        let mut b = vec![0u8; 256];
        while !String::from_utf8_lossy(&got).contains("SSH-2.0-standin\r\n") { let n = stdout.read(&mut b).await.unwrap(); assert!(n > 0); got.extend_from_slice(&b[..n]); }
        assert_eq!(String::from_utf8_lossy(&got), "SSH-2.0-standin\r\n", "nothing of the HTTP answer reaches ssh");
        assert_eq!(std::fs::read_to_string(dir.join("known_hosts")).unwrap(), "pavilion-proxy ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n");
        stdin.write_all(b"SSH-2.0-client\r\n").await.unwrap();
        let n = stdout.read(&mut b).await.unwrap();
        assert_eq!(&b[..n], b"echo:SSH-2.0-client\r\n");
        drop(stdin);
        let _ = child.kill().await;
        // Refused: the reason on stderr, and it ends at once, though its input (ssh's side) stays open.
        let mut child = run("refused.example").spawn().unwrap();
        let _held = child.stdin.take();
        let status = tokio::time::timeout(Duration::from_secs(5), child.wait()).await.expect("a refusal ends the ProxyCommand at once").unwrap();
        drop(_held); // ssh's side closes; what's left in the background goes with it
        let mut err = String::new();
        child.stderr.take().unwrap().read_to_string(&mut err).await.unwrap();
        let mut out = vec![];
        child.stdout.take().unwrap().read_to_end(&mut out).await.unwrap();
        assert!(!status.success() && err.contains("pavilion: no SSH key lets project acme"), "{err}");
        assert!(out.is_empty());
        task.abort();
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// By hand, with a real sandbox (Apple container or Podman), a local Gate and a job open on this machine: the job's
    /// command runs through `sandbox::run` exactly as `pavilion-node run` would, minus the resource guard.
    ///   PAVILION_NODE_HOME=… PAVILION_SSH_E2E='{"gate":…,"pavilion":…,"job":…,"project":…,"image":…,"cmd":…}' \
    ///   cargo test real_sandbox_ssh -- --ignored --nocapture
    #[tokio::test]
    #[ignore]
    async fn real_sandbox_ssh() {
        let Ok(spec) = std::env::var("PAVILION_SSH_E2E") else { return };
        let v: serde_json::Value = serde_json::from_str(&spec).unwrap();
        let s = |k: &str| v[k].as_str().unwrap().to_string();
        let spec = crate::sandbox::JobSpec { job: s("job"), project: s("project"), image: s("image"), cmd: s("cmd"), cpus: 1, memory_mib: 384, timeout_s: 240,
            grants: HashMap::new(), env: vec![], warm: None, slot: None };
        let out = crate::sandbox::run(spec, &s("gate"), &s("pavilion"), crate::state::key().unwrap()).await.unwrap();
        println!("<<<OUT\n{}\nOUT>>> exit={} note={}", out.output, out.exit_code, out.note);
    }

    #[test]
    fn hosts() {
        assert!(host_matches("api.github.com", "api.github.com"));
        assert!(!host_matches("api.github.com", "api.github.com.evil.example"));
        assert!(host_matches("*.github.com", "api.github.com"));
        assert!(!host_matches("*.github.com", "github.com"));
    }

    /// An agent job on one of this machine's slots: the broker adds the slot's token itself, to the model API only, and
    /// reads the provider's answer for the slot's state (WORK-ROUTING §9). A stand-in provider, never the real one.
    #[test]
    fn a_slot_adds_its_token_to_the_model_api_only() {
        use crate::accounts::tests::{with_home, FAKE};
        with_home(|| tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
            let up = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let up_port = up.local_addr().unwrap().port();
            tokio::spawn(async move {
                loop {
                    let Ok((stream, _)) = up.accept().await else { break };
                    tokio::spawn(async move {
                        let svc = hyper::service::service_fn(|req: Request<Incoming>| async move {
                            let mut seen = vec![format!("{} {}", req.method(), req.uri())];
                            let mut names: Vec<String> = req.headers().iter().map(|(k, v)| format!("{k}={}", v.to_str().unwrap_or(""))).collect();
                            names.sort();
                            seen.extend(names);
                            let body = String::from_utf8_lossy(&req.into_body().collect().await.unwrap().to_bytes()).into_owned();
                            let r = Response::builder();
                            let r = if body.contains("spent") { r.status(429).header("retry-after", "120") } else if body.contains("expired") { r.status(401) } else { r.status(200) };
                            Ok::<_, std::convert::Infallible>(r.body(Full::new(Bytes::from(seen.join("\n")))).unwrap())
                        });
                        let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(stream), svc).await;
                    });
                }
            });
            let id = crate::accounts::put("claude-code", "work", FAKE).unwrap();
            let mut door = crate::accounts::door(&id).unwrap();
            door.upstream = format!("http://127.0.0.1:{up_port}");
            let broker = Arc::new(Broker { gate: "http://127.0.0.1:9".into(), pavilion: "pv".into(), job: "job_abc".into(), key: SigningKey::from_bytes(&[7u8; 32]),
                grants: HashMap::new(), subnet: parse_subnet("127.0.0.0/8").unwrap(), http: reqwest::Client::new(), role: None, slot: Some(Arc::new(door)) });
            let (port, task) = broker.serve().await.unwrap();
            let c = reqwest::Client::new();
            let base = format!("http://127.0.0.1:{port}/CLAUDE_SLOT/api.anthropic.com");
            let r = c.post(format!("{base}/v1/messages?beta=true")).bearer_auth("sk-ant-oat01-pavilion-placeholder").header("anthropic-beta", "claude-code-20250219")
                .header("cookie", "a=b").body(r#"{"model":"opus"}"#).send().await.unwrap();
            assert_eq!(r.status(), 200);
            let seen = r.text().await.unwrap();
            assert!(seen.starts_with("POST /v1/messages?beta=true\n"), "{seen}");
            assert!(seen.contains(&format!("authorization=Bearer {FAKE}")) && !seen.contains("placeholder") && !seen.contains("cookie"), "{seen}");
            assert!(seen.contains("anthropic-beta=claude-code-20250219,oauth-2025-04-20"), "{seen}");
            assert_eq!(crate::accounts::current()[0]["state"], "ready");
            assert!(crate::accounts::current()[0]["last_used_at"].as_u64().is_some());
            // Never another path, method or host with the slot's token.
            for (m, url) in [("GET", format!("{base}/v1/messages")), ("POST", format!("{base}/api/oauth/profile")), ("POST", format!("http://127.0.0.1:{port}/CLAUDE_SLOT/chatgpt.com/v1/messages"))] {
                let r = c.request(m.parse().unwrap(), url.clone()).body("{}").send().await.unwrap();
                assert_eq!(r.status(), 403, "{m} {url}");
                assert!(r.text().await.unwrap().starts_with("Blocked by the node"));
            }
            // The provider says the plan is spent: the slot is parked until the reset it stated.
            let r = c.post(format!("{base}/v1/messages")).body(r#"{"spent":1}"#).send().await.unwrap();
            assert_eq!(r.status(), 429);
            let now = crate::accounts::current();
            assert_eq!(now[0]["state"], "limited");
            assert!(now[0]["limited_until"].as_u64().unwrap() > std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64 + 100_000);
            // The provider refuses the token: signed out, until the person signs in again on this machine.
            let r = c.post(format!("{base}/v1/messages")).body(r#"{"expired":1}"#).send().await.unwrap();
            assert_eq!(r.status(), 401);
            assert_eq!(crate::accounts::current()[0]["state"], "signed-out");
            // A job without a slot has no such door.
            task.abort();
            let plain = Arc::new(Broker { gate: "http://127.0.0.1:9".into(), pavilion: "pv".into(), job: "job_abc".into(), key: SigningKey::from_bytes(&[7u8; 32]),
                grants: HashMap::new(), subnet: parse_subnet("127.0.0.0/8").unwrap(), http: reqwest::Client::new(), role: None, slot: None });
            let (port, task) = plain.serve().await.unwrap();
            let r = c.post(format!("http://127.0.0.1:{port}/CLAUDE_SLOT/api.anthropic.com/v1/messages")).body("{}").send().await.unwrap();
            assert_eq!(r.status(), 403);
            task.abort();
        }));
    }
    /// A slot's token budgets (WORK-ROUTING §12): counted from the provider's own usage on the way back, a warning at 80%,
    /// the turn's budget reported once spent and its next call refused with a 403 that never reads as a model limit.
    #[test]
    fn a_slot_counts_its_tokens_and_keeps_its_budget() {
        use crate::accounts::tests::{with_home, FAKE};
        with_home(|| tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
            let up = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let up_port = up.local_addr().unwrap().port();
            tokio::spawn(async move {
                loop {
                    let Ok((stream, _)) = up.accept().await else { break };
                    tokio::spawn(async move {
                        let svc = hyper::service::service_fn(|_req: Request<Incoming>| async move {
                            Ok::<_, std::convert::Infallible>(Response::builder().status(200).header("content-type", "application/json")
                                .body(Full::new(Bytes::from(r#"{"type":"message","content":[],"usage":{"input_tokens":500,"output_tokens":100,"cache_read_input_tokens":300}}"#))).unwrap())
                        });
                        let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(stream), svc).await;
                    });
                }
            });
            // What it reports is accounts.rs's `count` (tested there); the socket is shared by tests running at once.
            let id = crate::accounts::put("claude-code", "work", FAKE).unwrap();
            crate::accounts::set_budget("job_budget", crate::accounts::Budget { turn: Some(1000), day: None });
            let mut door = crate::accounts::door_for(&id, "job_budget").unwrap();
            door.upstream = format!("http://127.0.0.1:{up_port}");
            let broker = Arc::new(Broker { gate: "http://127.0.0.1:9".into(), pavilion: "pv".into(), job: "job_budget".into(), key: SigningKey::from_bytes(&[7u8; 32]),
                grants: HashMap::new(), subnet: parse_subnet("127.0.0.0/8").unwrap(), http: reqwest::Client::new(), role: None, slot: Some(Arc::new(door)) });
            let (port, task) = broker.serve().await.unwrap();
            let c = reqwest::Client::new();
            let url = format!("http://127.0.0.1:{port}/CLAUDE_SLOT/api.anthropic.com/v1/messages");
            let mut seen = vec![];
            for _ in 0..3 {
                let r = c.post(&url).body("{}").send().await.unwrap();
                seen.push((r.status().as_u16(), r.text().await.unwrap()));
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            // 900 tokens a call: the first passes and warns (90%), the second passes and spends the turn, the third is refused.
            assert_eq!((seen[0].0, seen[1].0, seen[2].0), (200, 200, 403), "{seen:?}");
            assert!(seen[2].1.contains("per-turn token budget is used (1800 of 1000)") && !seen[2].1.contains("429") && !seen[2].1.to_lowercase().contains("rate"), "{seen:?}");
            assert_eq!(crate::accounts::current()[0]["used_today"], 1800);
            assert_eq!(crate::accounts::current()[0]["state"], "ready", "a spent turn is the turn's, not the slot's");
            task.abort();
            crate::accounts::clear_budget("job_budget");
        }));
    }

    /// A stand-in provider (and token endpoint) for the Codex and Gemini tests: it answers with what it saw, and says
    /// "spent" or "expired" when the body asks it to. Never the real providers.
    async fn standin(kind: &'static str) -> (u16, Arc<std::sync::Mutex<Vec<String>>>) {
        let up = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = up.local_addr().unwrap().port();
        let seen: Arc<std::sync::Mutex<Vec<String>>> = Default::default();
        let s2 = seen.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = up.accept().await else { break };
                let seen = s2.clone();
                tokio::spawn(async move {
                    let svc = hyper::service::service_fn(move |req: Request<Incoming>| { let seen = seen.clone(); async move {
                        let mut lines = vec![format!("{} {}", req.method(), req.uri())];
                        let mut hs: Vec<String> = req.headers().iter().map(|(k, v)| format!("{k}={}", v.to_str().unwrap_or(""))).collect();
                        hs.sort(); lines.extend(hs);
                        let path = req.uri().path().to_string();
                        let body = String::from_utf8_lossy(&req.into_body().collect().await.unwrap().to_bytes()).into_owned();
                        lines.push(format!("body={body}"));
                        seen.lock().unwrap().push(lines.join("\n"));
                        let r = Response::builder();
                        let (r, out) = if path.contains("refuse") { (r.status(400).header("content-type", "application/json"), r#"{"error":"invalid_grant"}"#.to_string()) }
                        else if path == "/oauth/token" || path == "/token" {
                            (r.status(200).header("content-type", "application/json"), if kind == "codex" {
                                serde_json::json!({ "access_token": crate::slot_auth::tests_jwt(4_102_444_801), "refresh_token": "rt-refreshed", "id_token": crate::slot_auth::tests_jwt(4_102_444_801) }).to_string()
                            } else { serde_json::json!({ "access_token": "ya29.refreshed", "expires_in": 3599, "token_type": "Bearer" }).to_string() })
                        } else if body.contains("spent") {
                            (r.status(429).header("content-type", "application/json"), if kind == "codex" { r#"{"error":{"type":"usage_limit_reached","plan_type":"plus","resets_at":4102444800}}"#.to_string() }
                                else { r#"[{"error":{"code":429,"status":"RESOURCE_EXHAUSTED","details":[{"@type":"type.googleapis.com/google.rpc.RetryInfo","retryDelay":"120s"}]}}]"#.to_string() })
                        } else if body.contains("expired") { (r.status(401), String::new()) }
                        else if kind == "codex" { (r.status(200).header("content-type", "text/event-stream"), "data: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":700,\"output_tokens\":50}}}\n\n".into()) }
                        else { (r.status(200), "data: {\"response\":{\"usageMetadata\":{\"promptTokenCount\":300,\"candidatesTokenCount\":20,\"thoughtsTokenCount\":5}}}\n\n".into()) };
                        Ok::<_, std::convert::Infallible>(r.body(Full::new(Bytes::from(out))).unwrap())
                    } });
                    let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(stream), svc).await;
                });
            }
        });
        (port, seen)
    }
    fn slot_broker(door: crate::accounts::SlotDoor, job: &str) -> Arc<Broker> {
        Arc::new(Broker { gate: "http://127.0.0.1:9".into(), pavilion: "pv".into(), job: job.into(), key: SigningKey::from_bytes(&[7u8; 32]),
            grants: HashMap::new(), subnet: parse_subnet("127.0.0.0/8").unwrap(), http: reqwest::Client::new(), role: None, slot: Some(Arc::new(door)) })
    }

    /// A Codex slot (WORK-ROUTING §9): the access token refreshed on the host when near its end, added with the account
    /// id to Codex's own calls only; the VM's own refresh answered with placeholders; a 429's reset parks the slot.
    #[test]
    fn a_codex_slot_refreshes_on_the_host_and_swaps_its_token_in() {
        use crate::accounts::tests::with_home;
        with_home(|| tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
            let (up, seen) = standin("codex").await;
            *crate::slot_auth::TEST_TOKEN_URL.lock().unwrap() = Some(format!("http://127.0.0.1:{up}/oauth/token"));
            let fresh = std::env::temp_dir().join(format!("pavilion-codex-fresh-{}", std::process::id()));
            crate::slot_auth::make_private_dir(&fresh).unwrap();
            let soon = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + 60;
            std::fs::write(fresh.join("auth.json"), serde_json::json!({ "OPENAI_API_KEY": null, "tokens": { "id_token": crate::slot_auth::tests_jwt(soon),
                "access_token": crate::slot_auth::tests_jwt(soon), "refresh_token": "rt-fake-original", "account_id": "acc-fake-real" }, "last_refresh": "2026-11-20T10:00:00Z" }).to_string()).unwrap();
            let id = crate::accounts::put_folder("codex", "personal", &fresh).unwrap();
            let mut door = crate::accounts::door(&id).unwrap();
            door.upstream = format!("http://127.0.0.1:{up}");
            let (port, task) = slot_broker(door, "job_codex").serve().await.unwrap();
            let c = reqwest::Client::new();
            let base = format!("http://127.0.0.1:{port}/CODEX_SLOT/chatgpt.com/backend-api/codex");
            // A turn: near its end, the token is refreshed here first, then the real one goes out with the account id.
            let r = c.post(format!("{base}/responses")).bearer_auth("placeholder-jwt").header("chatgpt-account-id", "pavilion-placeholder").header("originator", "codex_exec")
                .body(r#"{"model":"gpt-5-codex","input":[]}"#).send().await.unwrap();
            assert_eq!(r.status(), 200);
            let _ = r.text().await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            let log = seen.lock().unwrap().clone();
            assert!(log[0].starts_with("POST /oauth/token") && log[0].contains("rt-fake-original") && log[0].contains("app_EMoamEEZ73f0CkXaXp7hrann"), "{log:?}");
            let fresh_jwt = crate::slot_auth::tests_jwt(4_102_444_801);
            assert!(log[1].starts_with("POST /backend-api/codex/responses") && log[1].contains(&format!("authorization=Bearer {fresh_jwt}"))
                && log[1].contains("chatgpt-account-id=acc-fake-real") && !log[1].contains("placeholder") && log[1].contains("originator=codex_exec"), "{log:?}");
            let kept = std::fs::read_to_string(crate::slot_auth::codex_auth(&crate::accounts::home_of(&id))).unwrap();
            assert!(kept.contains("rt-refreshed") && !kept.contains("rt-fake-original"), "the refreshed sign-in is kept on the host");
            assert_eq!(crate::accounts::current()[0]["used_today"], 750, "Codex's own usage counted");
            // Fresh now: the next call doesn't refresh again.
            let r = c.get(format!("{base}/models?client_version=0.153.4")).send().await.unwrap();
            assert_eq!(r.status(), 200);
            assert_eq!(seen.lock().unwrap().iter().filter(|l| l.starts_with("POST /oauth/token")).count(), 1);
            // A WebSocket first: refused with 426, so Codex goes to HTTP. No credential on it.
            let r = c.get(format!("{base}/responses")).header("upgrade", "websocket").header("connection", "Upgrade").send().await.unwrap();
            assert_eq!(r.status(), 426);
            // The VM's own refresh: refreshed here, answered with placeholders only.
            let r = c.post(format!("http://127.0.0.1:{port}/CODEX_SLOT/auth.openai.com/oauth/token")).json(&serde_json::json!({ "refresh_token": "pavilion-placeholder" })).send().await.unwrap();
            assert_eq!(r.status(), 200);
            let t = r.text().await.unwrap();
            assert!(t.contains("pavilion-placeholder") && !t.contains("rt-refreshed") && !t.contains(&fresh_jwt), "{t}");
            assert_eq!(seen.lock().unwrap().iter().filter(|l| l.starts_with("POST /oauth/token")).count(), 2);
            // Never anywhere else with it: another path, method, host, or another provider's door.
            for (m, url) in [("POST", format!("http://127.0.0.1:{port}/CODEX_SLOT/chatgpt.com/backend-api/wham/usage")), ("GET", format!("{base}/responses")),
                ("POST", format!("http://127.0.0.1:{port}/CODEX_SLOT/api.openai.com/v1/responses")), ("POST", format!("http://127.0.0.1:{port}/CODEX_SLOT/evil.example/backend-api/codex/responses")),
                ("POST", format!("http://127.0.0.1:{port}/CLAUDE_SLOT/api.anthropic.com/v1/messages")), ("POST", format!("http://127.0.0.1:{port}/GEMINI_SLOT/cloudcode-pa.googleapis.com/v1internal:generateContent")),
                ("GET", format!("http://127.0.0.1:{port}/CODEX_SLOT/auth.openai.com/oauth/token"))] {
                let r = c.request(m.parse().unwrap(), url.clone()).body("{}").send().await.unwrap();
                assert_eq!(r.status(), 403, "{m} {url}");
            }
            let n = seen.lock().unwrap().len();
            assert_eq!(n, 4, "nothing refused reached the provider");
            // Spent: the 429's own resets_at parks the slot, and the error passes to Codex unchanged.
            let r = c.post(format!("{base}/responses")).body(r#"{"spent":1}"#).send().await.unwrap();
            assert_eq!(r.status(), 429);
            assert!(r.text().await.unwrap().contains("usage_limit_reached"));
            let now = crate::accounts::current();
            assert_eq!((now[0]["state"].as_str(), now[0]["limited_until"].as_u64()), (Some("limited"), Some(4_102_444_800_000)));
            assert!(!now.to_string().contains("rt-") && !now.to_string().contains("acc-fake"));
            task.abort();
            *crate::slot_auth::TEST_TOKEN_URL.lock().unwrap() = None;
        }));
    }

    /// A Gemini slot: Google's installed-app refresh on the host, the Code Assist calls the CLI needs and no others, a
    /// RESOURCE_EXHAUSTED's retry delay parks the slot, and a refused refresh signs it out.
    #[test]
    fn a_gemini_slot_refreshes_on_the_host_and_carries_code_assist_only() {
        use crate::accounts::tests::with_home;
        with_home(|| tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
            let (up, seen) = standin("gemini").await;
            *crate::slot_auth::TEST_TOKEN_URL.lock().unwrap() = Some(format!("http://127.0.0.1:{up}/token"));
            let fresh = std::env::temp_dir().join(format!("pavilion-gemini-fresh-{}", std::process::id()));
            crate::slot_auth::make_private_dir(&fresh.join(".gemini")).unwrap();
            std::fs::write(fresh.join(".gemini/oauth_creds.json"), r#"{"access_token":"ya29.stale","refresh_token":"1//fake-refresh","expiry_date":1}"#).unwrap();
            std::fs::write(crate::slot_auth::gemini_client(&fresh), r#"{"client_id":"fake-id.apps.googleusercontent.com","client_secret":"fake-secret"}"#).unwrap();
            let id = crate::accounts::put_folder("gemini-cli", "personal", &fresh).unwrap();
            let mut door = crate::accounts::door(&id).unwrap();
            door.upstream = format!("http://127.0.0.1:{up}");
            let (port, task) = slot_broker(door, "job_gemini").serve().await.unwrap();
            let c = reqwest::Client::new();
            let base = format!("http://127.0.0.1:{port}/GEMINI_SLOT/cloudcode-pa.googleapis.com");
            let r = c.post(format!("{base}/v1internal:streamGenerateContent?alt=sse")).bearer_auth("ya29.pavilion-placeholder").body(r#"{"model":"gemini-2.5-pro"}"#).send().await.unwrap();
            assert_eq!(r.status(), 200);
            let _ = r.text().await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            let log = seen.lock().unwrap().clone();
            assert!(log[0].starts_with("POST /token") && log[0].contains("grant_type=refresh_token") && log[0].contains("client_secret=fake-secret") && log[0].contains("refresh_token=1%2F%2Ffake-refresh"), "{log:?}");
            assert!(log[1].starts_with("POST /v1internal:streamGenerateContent?alt=sse") && log[1].contains("authorization=Bearer ya29.refreshed") && !log[1].contains("placeholder"), "{log:?}");
            assert_eq!(crate::accounts::current()[0]["used_today"], 325);
            for (m, path) in [("POST", "/v1internal:onboardUser"), ("POST", "/v1internal:recordCodeAssistMetrics"), ("GET", "/v1internal:generateContent"), ("POST", "/v1beta/models/gemini-2.5-pro:generateContent")] {
                let r = c.request(m.parse().unwrap(), format!("{base}{path}")).body("{}").send().await.unwrap();
                assert_eq!(r.status(), 403, "{m} {path}");
            }
            assert_eq!(seen.lock().unwrap().len(), 2);
            let r = c.post(format!("{base}/v1internal:generateContent")).body(r#"{"spent":1}"#).send().await.unwrap();
            assert_eq!(r.status(), 429);
            let st = crate::accounts::current();
            let until = st[0]["limited_until"].as_u64().unwrap();
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
            assert!(st[0]["state"] == "limited" && until > now + 110_000 && until < now + 130_000, "{st}");
            // Google refuses the refresh: signed out, until the person signs in again on this machine.
            *crate::slot_auth::TEST_TOKEN_URL.lock().unwrap() = Some(format!("http://127.0.0.1:{up}/refused"));
            assert!(matches!(crate::slot_auth::credential("gemini-cli", &crate::accounts::home_of(&id), true).await, Err(crate::slot_auth::AuthErr::SignedOut(_))));
            let r = c.post(format!("{base}/v1internal:generateContent")).body(r#"{"expired":1}"#).send().await.unwrap();
            assert_eq!(r.status(), 401);
            assert_eq!(crate::accounts::current()[0]["state"], "signed-out", "a 401 and a refused refresh: sign in again on this machine");
            task.abort();
            *crate::slot_auth::TEST_TOKEN_URL.lock().unwrap() = None;
        }));
    }
}
