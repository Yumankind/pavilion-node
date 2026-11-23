//! The three kinds of account slot (accounts.rs; docs/WORK-ROUTING.md §9, docs/MACHINES.md §6 Tier 3): which provider
//! each reaches, the exact calls a job's broker may carry for it, how its sign-in is kept and refreshed on this machine,
//! and what the job's VM is given in its place.
//!
//! | harness      | the person types        | kept on this machine                        | the broker reaches, and only this            |
//! |--------------|-------------------------|---------------------------------------------|----------------------------------------------|
//! | `claude-code`| `accounts add claude`   | the `claude setup-token` token (accounts.json) | api.anthropic.com: POST /v1/messages (+ count_tokens) |
//! | `codex`      | `accounts add codex`    | `codex login`'s auth.json, in the slot's own CODEX_HOME | chatgpt.com: POST /backend-api/codex/responses, POST …/responses/compact, GET …/models |
//! | `gemini-cli` | `accounts add gemini`   | the Gemini CLI's Google login (oauth_creds.json), in the slot's own GEMINI_CLI_HOME | cloudcode-pa.googleapis.com: POST /v1internal:{loadCodeAssist, listExperiments, generateContent, streamGenerateContent, countTokens, retrieveUserQuota, fetchAdminControls} |
//!
//! Where the endpoints come from (checked 21 Nov 2026, not guessed):
//! - **Codex** (openai/codex at `rust-v0.153.4`, the version installed here): with a ChatGPT login the model client's
//!   base is `https://chatgpt.com/backend-api/codex` (`model-provider-info/src/lib.rs` CHATGPT_CODEX_BASE_URL); a turn
//!   opens a WebSocket to `{base}/responses` first and falls back to HTTP at once on a 426 (`core/src/client.rs`), then
//!   `POST {base}/responses`, `POST {base}/responses/compact` and `GET {base}/models?client_version=…`
//!   (`codex-api/src/endpoint/`). Auth is `Authorization: Bearer <tokens.access_token>` and `ChatGPT-Account-ID:
//!   <tokens.account_id>` (`model-provider/src/bearer_auth_provider.rs`). The base is moved with the config key
//!   `openai_base_url` (not `OPENAI_BASE_URL`, which this version does not read). Refresh: `POST
//!   https://auth.openai.com/oauth/token` JSON `{client_id, grant_type: "refresh_token", refresh_token}`, client id
//!   `app_EMoamEEZ73f0CkXaXp7hrann`, when the access token's `exp` is within 5 minutes (or `last_refresh` is 8 days old)
//!   and on a 401 (`login/src/auth/manager.rs`); `CODEX_REFRESH_TOKEN_URL_OVERRIDE` moves it. Limits: HTTP 429 with
//!   `{"error":{"type":"usage_limit_reached","resets_at":<epoch s>}}`, and `x-codex-primary-reset-at` (epoch s)
//!   headers (`codex-api/src/rate_limits.rs`, `api_bridge.rs`).
//! - **Gemini CLI** (the bundle of @google/gemini-cli 0.54.4 installed here): with "Login with Google" it calls
//!   `${CODE_ASSIST_ENDPOINT ?? "https://cloudcode-pa.googleapis.com"}/${CODE_ASSIST_API_VERSION || "v1internal"}:<method>`
//!   (`CodeAssistServer.getMethodUrl`); `GOOGLE_GENAI_USE_GCA=true` with `GOOGLE_CLOUD_ACCESS_TOKEN` gives it an access
//!   token and no refresh token, so it never refreshes; credentials live in `$GEMINI_CLI_HOME/.gemini/oauth_creds.json`
//!   (`Storage.getOAuthCredsPath`). `listExperiments` failing is not caught at start-up, so it is allowed;
//!   `recordCodeAssistMetrics` failing is caught, so it is refused, as are `onboardUser` and the user-setting calls.
//!   An account's first-run setup (`onboardUser`) stays refused in jobs (decided 21 Nov 2026): it happens once, when the
//!   person signs in with `accounts add gemini` on the host and the CLI runs in full.
//!   Refresh is Google's installed-app flow: `POST https://oauth2.googleapis.com/token` (form: client_id, client_secret,
//!   refresh_token, grant_type) with the CLI's own client, read from the installed CLI when the slot is added.
//!   Limits: HTTP 429 `RESOURCE_EXHAUSTED`, with a `google.rpc.RetryInfo` `retryDelay` when Google says one.
//!
//! The VM never holds a credential: placeholders only. Refreshing happens here, on the host, in this module — never in
//! the VM. A Codex job's VM is pointed at the broker for its token refresh too, and the broker answers it with
//! placeholders after refreshing the real token here.
use anyhow::{anyhow, bail, Result};
use base64::{engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}, Engine};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// One provider a slot reaches: the harness the pavilion routes on, the name in the broker's egress form, the one host.
#[derive(Debug, PartialEq)]
pub struct Provider { pub harness: &'static str, pub secret: &'static str, pub host: &'static str, pub upstream: &'static str, pub name: &'static str, pub cli: &'static str }
pub const CLAUDE: Provider = Provider { harness: "claude-code", secret: "CLAUDE_SLOT", host: "api.anthropic.com", upstream: "https://api.anthropic.com", name: "Claude", cli: "claude" };
pub const CODEX: Provider = Provider { harness: "codex", secret: "CODEX_SLOT", host: "chatgpt.com", upstream: "https://chatgpt.com", name: "Codex", cli: "codex" };
pub const GEMINI: Provider = Provider { harness: "gemini-cli", secret: "GEMINI_SLOT", host: "cloudcode-pa.googleapis.com", upstream: "https://cloudcode-pa.googleapis.com", name: "Gemini", cli: "gemini" };
pub const PROVIDERS: [&Provider; 3] = [&CLAUDE, &CODEX, &GEMINI];
pub fn by_secret(s: &str) -> Option<&'static Provider> { PROVIDERS.into_iter().find(|p| p.secret == s) }
pub fn by_harness(h: &str) -> Option<&'static Provider> { PROVIDERS.into_iter().find(|p| p.harness == h) }

/// Codex's own token endpoint, which a Codex job's VM is pointed at through the broker (`CODEX_REFRESH_TOKEN_URL_OVERRIDE`):
/// the broker refreshes here, on the host, and answers with placeholders.
pub const CODEX_AUTH_HOST: &str = "auth.openai.com";
pub const CODEX_TOKEN_PATH: &str = "/oauth/token";
const CODEX_TOKEN_URL: &str = "https://auth.openai.com/oauth/token";
const CODEX_CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
/// Refresh when the access token has less than this left (Codex's own rule; Google's tokens last an hour).
pub const REFRESH_BEFORE_MS: u64 = 5 * 60_000;
const CODEX_STALE_MS: u64 = 8 * 86_400_000;

/// The calls a slot's token may go on: these and nothing else. `path` has no query.
pub fn allowed(harness: &str, method: &str, path: &str) -> bool {
    match harness {
        "claude-code" => method == "POST" && ["/v1/messages", "/v1/messages/count_tokens"].contains(&path),
        "codex" => (method == "POST" && ["/backend-api/codex/responses", "/backend-api/codex/responses/compact"].contains(&path))
            || (method == "GET" && path == "/backend-api/codex/models"),
        "gemini-cli" => method == "POST" && path.strip_prefix("/v1internal:").is_some_and(|m|
            ["loadCodeAssist", "listExperiments", "generateContent", "streamGenerateContent", "countTokens", "retrieveUserQuota", "fetchAdminControls"].contains(&m)),
        _ => false,
    }
}
/// What the refusal says each provider carries.
pub fn allowed_words(harness: &str) -> &'static str {
    match harness {
        "codex" => "the Codex model API only (POST /backend-api/codex/responses, …/responses/compact, GET …/models)",
        "gemini-cli" => "the Gemini CLI's model calls only (POST /v1internal:generateContent and the few calls it needs to start)",
        _ => "the model API only (POST /v1/messages)",
    }
}

/* ---------------------------------------------------------------- the slot's own folder */

/// A slot's private folder (0700): CODEX_HOME for a Codex slot, GEMINI_CLI_HOME for a Gemini one. Never the person's own
/// ~/.codex or ~/.gemini.
pub fn home(base: &Path, slot: &str) -> PathBuf { base.join("slots").join(slot) }
pub fn codex_auth(home: &Path) -> PathBuf { home.join("auth.json") }
pub fn gemini_creds(home: &Path) -> PathBuf { home.join(".gemini").join("oauth_creds.json") }
pub fn gemini_client(home: &Path) -> PathBuf { home.join("client.json") }
/// Whether the sign-in's files are there.
pub fn signed_in(harness: &str, home: &Path) -> bool {
    match harness { "codex" => codex_auth(home).is_file(), "gemini-cli" => gemini_creds(home).is_file() && gemini_client(home).is_file(), _ => false }
}
pub fn make_private_dir(d: &Path) -> Result<()> {
    #[cfg(unix)]
    { use std::os::unix::fs::DirBuilderExt; std::fs::DirBuilder::new().recursive(true).mode(0o700).create(d)?; use std::os::unix::fs::PermissionsExt; std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700))?; }
    #[cfg(not(unix))]
    std::fs::create_dir_all(d)?;
    Ok(())
}
/// Removes a slot's folder, each file overwritten first.
pub fn scrub(d: &Path) {
    fn walk(p: &Path) {
        let Ok(rd) = std::fs::read_dir(p) else { return };
        for e in rd.flatten() {
            let q = e.path();
            if q.is_dir() { walk(&q); } else if let Ok(m) = std::fs::metadata(&q) { let _ = std::fs::write(&q, vec![0u8; m.len() as usize]); }
        }
    }
    walk(d);
    let _ = std::fs::remove_dir_all(d);
}

/// What a sign-in left: checked before the slot is kept. A Codex slot is a ChatGPT plan login (an API key belongs in the
/// pavilion's vault); a Gemini slot is a Google login with a refresh token.
pub fn check_signed_in(harness: &str, home: &Path) -> Result<()> {
    match harness {
        "codex" => {
            let v = read_json(&codex_auth(home)).map_err(|_| anyhow!("`codex login` finished without writing auth.json here; nothing was kept"))?;
            if v["OPENAI_API_KEY"].as_str().is_some_and(|k| !k.is_empty()) || v["auth_mode"].as_str().is_some_and(|m| m.eq_ignore_ascii_case("apikey")) {
                bail!("that was an API-key login: a slot is your ChatGPT plan's own sign-in. An API key goes in the pavilion's vault instead (Settings › Model accounts); nothing was kept");
            }
            if v["tokens"]["refresh_token"].as_str().unwrap_or("").is_empty() || v["tokens"]["access_token"].as_str().unwrap_or("").is_empty() {
                bail!("`codex login` left no ChatGPT sign-in here; nothing was kept");
            }
            Ok(())
        }
        "gemini-cli" => {
            let v = read_json(&gemini_creds(home)).map_err(|_| anyhow!("the Gemini CLI finished without a Google sign-in here (no oauth_creds.json); choose \"Login with Google\" and sign in, then /quit. Nothing was kept"))?;
            if v["refresh_token"].as_str().unwrap_or("").is_empty() { bail!("the Gemini CLI's sign-in has no refresh token; nothing was kept"); }
            if !gemini_client(home).is_file() { bail!("the Gemini CLI's sign-in client wasn't read; nothing was kept"); }
            Ok(())
        }
        _ => bail!("{harness} keeps its token in accounts.json"),
    }
}

/// The Gemini CLI's own OAuth client (an installed-app client: Google's flow needs it to refresh), read from the CLI
/// installed on this machine, so it is the same one that signed in. Kept in the slot's folder.
pub fn find_gemini_client() -> Result<(String, String)> {
    if let (Ok(i), Ok(s)) = (std::env::var("PAVILION_GEMINI_CLIENT_ID"), std::env::var("PAVILION_GEMINI_CLIENT_SECRET")) { return Ok((i, s)); }
    let exe = std::env::var("PATH").unwrap_or_default().split(':').map(|d| Path::new(d).join("gemini")).find(|p| p.exists())
        .ok_or_else(|| anyhow!("the Gemini CLI isn't installed on this machine (npm install -g @google/gemini-cli)"))?;
    let real = std::fs::canonicalize(&exe)?;
    let bundle = real.parent().ok_or_else(|| anyhow!("can't find the Gemini CLI's files"))?;
    for e in std::fs::read_dir(bundle)?.flatten() {
        let p = e.path();
        if p.extension().and_then(|x| x.to_str()) != Some("js") { continue; }
        let Ok(text) = std::fs::read_to_string(&p) else { continue };
        let pick = |k: &str| text.find(k).and_then(|i| { let r = &text[i + k.len()..]; r.find('"').map(|j| r[..j].to_string()) });
        if let (Some(id), Some(secret)) = (pick("OAUTH_CLIENT_ID = \""), pick("OAUTH_CLIENT_SECRET = \"")) {
            if id.ends_with(".apps.googleusercontent.com") && !secret.is_empty() { return Ok((id, secret)); }
        }
    }
    bail!("couldn't read the Gemini CLI's sign-in client from {}; update the Gemini CLI and try again", bundle.display())
}

fn read_json(p: &Path) -> Result<Value> { Ok(serde_json::from_slice(&Zeroizing::new(std::fs::read(p)?))?) }
fn write_json(p: &Path, v: &Value) -> Result<()> {
    if let Some(d) = p.parent() { make_private_dir(d)?; }
    crate::state::write_private(&p.to_path_buf(), &Zeroizing::new(serde_json::to_vec_pretty(v)?))
}

/* ---------------------------------------------------------------- the current token, refreshed here */

/// What the broker adds to a call: the bearer token and, for Codex, the account id header.
pub struct Cred { pub bearer: Zeroizing<String>, pub account: Option<String> }
#[derive(Debug)]
pub enum AuthErr { SignedOut(String), Other(String) }

/// A JWT's `exp`, in ms (the signature is not ours to check: it is our own token, read from our own file).
pub fn jwt_exp_ms(jwt: &str) -> Option<u64> {
    let p = jwt.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(p.trim_end_matches('=')).ok()?;
    serde_json::from_slice::<Value>(&bytes).ok()?["exp"].as_u64().map(|s| s * 1000)
}
/// ISO 8601 / RFC 3339 in UTC to the second, as Codex writes `last_refresh`.
pub fn rfc3339(ms: u64) -> String { format!("{}:{:02}Z", crate::accounts::iso(ms), ms / 1000 % 60) }
fn rfc3339_ms(s: &str) -> Option<u64> {
    // 2026-11-21T10:00:00.123Z or …+00:00: enough to tell whether it is 8 days old.
    let b = s.as_bytes(); if b.len() < 19 { return None; }
    let n = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let (y, mo, d, h, mi, se) = (n(0..4)?, n(5..7)?, n(8..10)?, n(11..13)?, n(14..16)?, n(17..19)?);
    let (y2, m2) = if mo <= 2 { (y - 1, mo + 9) } else { (y, mo - 3) };
    let era = y2.div_euclid(400); let yoe = y2 - era * 400; let doy = (153 * m2 + 2) / 5 + d - 1; let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    u64::try_from(((days * 86_400) + h * 3600 + mi * 60 + se) * 1000).ok()
}

/// Test-only: where the refresh calls go (a stand-in), never the real endpoints.
#[cfg(test)]
pub(crate) static TEST_TOKEN_URL: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);
fn token_url(real: &str) -> String {
    #[cfg(test)]
    if let Some(u) = TEST_TOKEN_URL.lock().unwrap_or_else(|e| e.into_inner()).clone() { return u; }
    real.to_string()
}
/// One refresh at a time on this machine: two jobs' brokers never spend one refresh token twice.
static REFRESH: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn now_ms() -> u64 { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0) }

/// The slot's current credential, refreshed here first when it is near its end (or `force`, after a 401). A refused
/// refresh (400/401: the sign-in was revoked or expired) is `SignedOut`: the person signs in again on this machine.
pub async fn credential(harness: &str, home: &Path, force: bool) -> Result<Cred, AuthErr> {
    let _one = REFRESH.lock().await;
    let http = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).timeout(std::time::Duration::from_secs(30)).build().map_err(|e| AuthErr::Other(e.to_string()))?;
    let now = now_ms();
    match harness {
        "codex" => {
            let p = codex_auth(home);
            let mut v = read_json(&p).map_err(|_| AuthErr::SignedOut("this Codex slot's sign-in isn't on this machine".into()))?;
            let access = v["tokens"]["access_token"].as_str().unwrap_or("").to_string();
            let due = force || match jwt_exp_ms(&access) {
                Some(exp) => exp <= now + REFRESH_BEFORE_MS,
                None => v["last_refresh"].as_str().and_then(rfc3339_ms).map_or(true, |t| now.saturating_sub(t) > CODEX_STALE_MS),
            };
            if due {
                let rt = Zeroizing::new(v["tokens"]["refresh_token"].as_str().unwrap_or("").to_string());
                if rt.is_empty() { return Err(AuthErr::SignedOut("this Codex slot has no refresh token".into())); }
                let r = http.post(token_url(CODEX_TOKEN_URL)).json(&json!({ "client_id": CODEX_CLIENT_ID, "grant_type": "refresh_token", "refresh_token": rt.as_str() }))
                    .send().await.map_err(|e| AuthErr::Other(format!("couldn't reach OpenAI to refresh: {}", e.without_url())))?;
                let st = r.status().as_u16();
                if st == 400 || st == 401 { return Err(AuthErr::SignedOut(format!("OpenAI refused this Codex slot's refresh ({st}): sign in again on this machine"))); }
                if st != 200 { return Err(AuthErr::Other(format!("OpenAI's refresh answered {st}"))); }
                let n: Value = r.json().await.map_err(|_| AuthErr::Other("OpenAI's refresh answer wasn't JSON".into()))?;
                for k in ["id_token", "access_token", "refresh_token"] { if let Some(t) = n[k].as_str().filter(|t| !t.is_empty()) { v["tokens"][k] = json!(t); } }
                v["last_refresh"] = json!(rfc3339(now));
                write_json(&p, &v).map_err(|e| AuthErr::Other(e.to_string()))?;
            }
            let bearer = Zeroizing::new(v["tokens"]["access_token"].as_str().unwrap_or("").to_string());
            if bearer.is_empty() { return Err(AuthErr::SignedOut("this Codex slot has no access token".into())); }
            Ok(Cred { bearer, account: v["tokens"]["account_id"].as_str().map(String::from) })
        }
        "gemini-cli" => {
            let p = gemini_creds(home);
            let mut v = read_json(&p).map_err(|_| AuthErr::SignedOut("this Gemini slot's sign-in isn't on this machine".into()))?;
            let due = force || v["access_token"].as_str().unwrap_or("").is_empty() || v["expiry_date"].as_u64().map_or(true, |e| e <= now + REFRESH_BEFORE_MS);
            if due {
                let c = read_json(&gemini_client(home)).map_err(|_| AuthErr::SignedOut("this Gemini slot has no sign-in client; add it again".into()))?;
                let rt = Zeroizing::new(v["refresh_token"].as_str().unwrap_or("").to_string());
                if rt.is_empty() { return Err(AuthErr::SignedOut("this Gemini slot has no refresh token".into())); }
                let form = [("client_id", c["client_id"].as_str().unwrap_or("")), ("client_secret", c["client_secret"].as_str().unwrap_or("")), ("refresh_token", rt.as_str()), ("grant_type", "refresh_token")];
                let body = form.iter().map(|(k, v)| format!("{k}={}", urlenc(v))).collect::<Vec<_>>().join("&");
                let r = http.post(token_url(GOOGLE_TOKEN_URL)).header("content-type", "application/x-www-form-urlencoded").body(body)
                    .send().await.map_err(|e| AuthErr::Other(format!("couldn't reach Google to refresh: {}", e.without_url())))?;
                let st = r.status().as_u16();
                if st == 400 || st == 401 { return Err(AuthErr::SignedOut(format!("Google refused this Gemini slot's refresh ({st}): sign in again on this machine"))); }
                if st != 200 { return Err(AuthErr::Other(format!("Google's refresh answered {st}"))); }
                let n: Value = r.json().await.map_err(|_| AuthErr::Other("Google's refresh answer wasn't JSON".into()))?;
                let Some(at) = n["access_token"].as_str().filter(|t| !t.is_empty()) else { return Err(AuthErr::Other("Google's refresh gave no access token".into())) };
                v["access_token"] = json!(at);
                v["expiry_date"] = json!(now + n["expires_in"].as_u64().unwrap_or(3600) * 1000);
                for k in ["id_token", "scope", "token_type"] { if let Some(t) = n[k].as_str() { v[k] = json!(t); } }
                if let Some(t) = n["refresh_token"].as_str().filter(|t| !t.is_empty()) { v["refresh_token"] = json!(t); }
                write_json(&p, &v).map_err(|e| AuthErr::Other(e.to_string()))?;
            }
            Ok(Cred { bearer: Zeroizing::new(v["access_token"].as_str().unwrap_or("").to_string()), account: None })
        }
        h => Err(AuthErr::Other(format!("{h} slots keep a token, not a sign-in folder"))),
    }
}
fn urlenc(s: &str) -> String {
    s.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
}

/* ---------------------------------------------------------------- what the VM gets instead */

/// The same placeholder for every Codex job: not a credential, never accepted anywhere.
pub const CODEX_PLACEHOLDER: &str = "pavilion-placeholder";
/// An unsigned stand-in token with the claims Codex reads (it decodes, never verifies): a `pro` plan, so Codex asks for
/// no business config, and an `exp` far away, so it never tries to refresh by itself.
fn fake_jwt(payload: Value) -> String {
    format!("{}.{}.cGxhY2Vob2xkZXI", URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#), URL_SAFE_NO_PAD.encode(payload.to_string()))
}
pub fn codex_placeholder_tokens() -> Value {
    json!({
        "id_token": fake_jwt(json!({ "email": "agent@cloudpavilion.invalid", "https://api.openai.com/auth": { "chatgpt_plan_type": "pro", "chatgpt_account_id": CODEX_PLACEHOLDER } })),
        "access_token": fake_jwt(json!({ "exp": 4_102_444_800u64 })),
        "refresh_token": CODEX_PLACEHOLDER,
    })
}
/// The VM's `$CODEX_HOME/auth.json`: a ChatGPT login made of placeholders. Base64 for the job's environment.
pub fn codex_placeholder_auth_b64(now: u64) -> String {
    let mut t = codex_placeholder_tokens();
    t["account_id"] = json!(CODEX_PLACEHOLDER);
    STANDARD.encode(json!({ "auth_mode": "chatgpt", "OPENAI_API_KEY": null, "tokens": t, "last_refresh": rfc3339(now) }).to_string())
}
/// What the broker answers a Codex VM's refresh with, after refreshing the real token here.
pub fn codex_placeholder_refresh() -> Value { codex_placeholder_tokens() }
/// The Gemini CLI's access token in the VM.
pub const GEMINI_PLACEHOLDER: &str = "ya29.pavilion-placeholder";

/* ---------------------------------------------------------------- limits the provider stated in its answer */

/// When a 429's own body says the account comes back (ms since 1970): Codex's `usage_limit_reached` `resets_at`, or
/// Google's `RetryInfo` `retryDelay`. Only the error is read; a model's answer is never a 429.
pub fn limit_until(harness: &str, body: &[u8], now: u64) -> Option<u64> {
    let v: Value = serde_json::from_slice(body).ok()?;
    let v = if v.is_array() { v[0].clone() } else { v };
    match harness {
        "codex" => {
            let e = &v["error"];
            e["resets_at"].as_u64().map(|s| s * 1000).or_else(|| e["resets_in_seconds"].as_u64().map(|s| now + s * 1000))
        }
        "gemini-cli" => v["error"]["details"].as_array()?.iter()
            .find(|d| d["@type"].as_str().is_some_and(|t| t.ends_with("google.rpc.RetryInfo")))
            .and_then(|d| d["retryDelay"].as_str()).and_then(|s| s.trim().trim_end_matches('s').parse::<f64>().ok())
            .map(|s| now + (s * 1000.0).ceil() as u64),
        _ => None,
    }
}

/// A stand-in token with this `exp`, for tests.
#[cfg(test)]
pub(crate) fn tests_jwt(exp_s: u64) -> String { fake_jwt(json!({ "exp": exp_s })) }

#[cfg(test)]
mod tests {
    use super::*;

    /// The swap's allowlists: each provider's exact calls; nothing else, and never another provider's.
    #[test]
    fn each_slot_reaches_its_own_calls_only() {
        assert!(allowed("claude-code", "POST", "/v1/messages") && allowed("claude-code", "POST", "/v1/messages/count_tokens"));
        assert!(!allowed("claude-code", "GET", "/v1/messages") && !allowed("claude-code", "POST", "/api/oauth/profile"));
        assert!(allowed("codex", "POST", "/backend-api/codex/responses") && allowed("codex", "POST", "/backend-api/codex/responses/compact") && allowed("codex", "GET", "/backend-api/codex/models"));
        for (m, p) in [("GET", "/backend-api/codex/responses"), ("POST", "/backend-api/wham/usage"), ("GET", "/backend-api/wham/config/bundle"), ("POST", "/backend-api/codex/models"),
            ("POST", "/v1/messages"), ("POST", "/backend-api/codex/responses/../../accounts"), ("POST", "/oauth/token")] {
            assert!(!allowed("codex", m, p), "{m} {p}");
        }
        assert!(allowed("gemini-cli", "POST", "/v1internal:streamGenerateContent") && allowed("gemini-cli", "POST", "/v1internal:loadCodeAssist"));
        for (m, p) in [("POST", "/v1internal:onboardUser"), ("POST", "/v1internal:recordCodeAssistMetrics"), ("POST", "/v1internal:setCodeAssistGlobalUserSetting"),
            ("GET", "/v1internal:generateContent"), ("POST", "/v1/models/gemini:generateContent"), ("POST", "/v1internal/operations/x")] {
            assert!(!allowed("gemini-cli", m, p), "{m} {p}");
        }
        assert!(!allowed("other", "POST", "/v1/messages"));
        assert_eq!(by_secret("CODEX_SLOT").map(|p| p.host), Some("chatgpt.com"));
        assert_eq!(by_harness("gemini-cli").map(|p| p.secret), Some("GEMINI_SLOT"));
        assert!(by_secret("ANTHROPIC_API_KEY").is_none());
    }

    #[test]
    fn placeholders_load_as_codex_reads_them_and_hold_nothing() {
        let a: Value = serde_json::from_slice(&STANDARD.decode(codex_placeholder_auth_b64(1_763_208_000_000)).unwrap()).unwrap();
        assert_eq!(a["auth_mode"], "chatgpt"); assert!(a["OPENAI_API_KEY"].is_null());
        assert_eq!(a["last_refresh"], "2025-11-15T12:00:00Z");
        let id = a["tokens"]["id_token"].as_str().unwrap();
        assert_eq!(id.split('.').filter(|p| !p.is_empty()).count(), 3, "three non-empty parts, as Codex wants");
        let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(id.split('.').nth(1).unwrap()).unwrap()).unwrap();
        assert_eq!(claims["https://api.openai.com/auth"]["chatgpt_plan_type"], "pro");
        assert_eq!(jwt_exp_ms(a["tokens"]["access_token"].as_str().unwrap()), Some(4_102_444_800_000), "far away: Codex never refreshes by itself");
    }

    #[test]
    fn limits_from_the_bodies_providers_send() {
        let now = 1_000_000;
        assert_eq!(limit_until("codex", br#"{"error":{"type":"usage_limit_reached","plan_type":"plus","resets_at":1763208000}}"#, now), Some(1_763_208_000_000));
        assert_eq!(limit_until("codex", br#"{"error":{"type":"usage_limit_reached","resets_in_seconds":60}}"#, now), Some(now + 60_000));
        let g = br#"[{"error":{"code":429,"status":"RESOURCE_EXHAUSTED","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"QUOTA_EXHAUSTED"},{"@type":"type.googleapis.com/google.rpc.RetryInfo","retryDelay":"34.2s"}]}}]"#;
        assert_eq!(limit_until("gemini-cli", g, now), Some(now + 34_200));
        assert_eq!(limit_until("gemini-cli", br#"{"error":{"status":"RESOURCE_EXHAUSTED"}}"#, now), None, "no stated reset: the back-off decides");
        assert_eq!(limit_until("codex", b"not json", now), None);
    }

    #[test]
    fn times() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339_ms("2025-11-15T12:00:00.5Z"), Some(1_763_208_000_000));
        assert_eq!(rfc3339_ms(&rfc3339(1_763_208_042_000)), Some(1_763_208_042_000));
        assert_eq!(urlenc("a b/+="), "a%20b%2F%2B%3D");
    }
}
