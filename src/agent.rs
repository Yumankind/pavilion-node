//! Agent jobs (docs/MACHINES.md §5c): Claude Code — or, on a member's own Codex or Gemini slot, the Codex CLI or the
//! Gemini CLI (`harness`, docs/WORK-ROUTING.md §9) — in a sandbox on this machine, working on a repository's `task/*`
//! branch. The pavilion sends `kind: "agent"` with a prompt, an SSH repository, the branch and its base, a time limit,
//! which model account to use, and who asked. The node starts (or reuses, per branch) a VM from the worker image
//! (node/images/dev), and a fixed script inside it clones or fetches over SSH through the job's broker, checks out the
//! branch, runs `claude -p` with tools on and permissions bypassed (the VM is the sandbox), commits what changed, pushes
//! the branch and prints the result lines: Claude's short summary, `branch: task/…`, and
//! `git diff --stat origin/<base>...HEAD`.
//!
//! Model calls go to `http://<broker>/<SECRET>/api.anthropic.com`, the broker's ordinary egress form, so the Gate picks
//! the real account, adds its token and rotates on 429. The VM holds only a placeholder; this machine never holds a
//! token and never talks to api.anthropic.com itself — except on one of this machine's own account slots
//! (`account: "slot"`, accounts.rs, docs/WORK-ROUTING.md §9): then the broker adds that slot's token, kept here, and
//! calls the provider itself. The VM still holds only the placeholder, and the pavilion never sees the token. Git goes over the broker's SSH CONNECT to the Gate's SSH proxy,
//! which holds the deploy key.
//!
//! A resumed item (docs/WORK-ROUTING.md §12) carries the heads it was paused on (`expect: {base, branch}`): right after
//! its fetch the script compares them with the remote's and, if either moved, stops before Claude Code runs (exit 78),
//! printing the new heads, so the pavilion's orchestrator decides instead of the agent carrying on in a changed world.
//! Every run prints `pavilion: heads <base> <branch>` once it has fetched; the pavilion keeps them.
//!
//! Nothing from the job is ever put into a shell command line: the script is the same text for every job, and the
//! prompt, repository and names reach it as environment variables (the prompt as base64), read with quotes, and the
//! prompt reaches Claude Code on its standard input.
use crate::broker::{host_matches, Grant};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use std::collections::HashMap;

/// The worker image the node runs agent jobs in, unless `agent_image` in config.json names another. Built locally
/// (node/images/dev/build.sh); the pavilion never picks the image. `:2` has Claude Code, the Codex CLI and the Gemini
/// CLI; an older `:1` (Claude Code only) is still used for Claude work until `:2` is built.
pub const DEFAULT_IMAGE: &str = "pavilion-dev:2";
pub const CLAUDE_ONLY_IMAGE: &str = "pavilion-dev:1";
/// The harnesses an agent job may run: what the pavilion's envelope says (`harness`), default Claude Code.
pub const HARNESSES: [&str; 3] = ["claude-code", "codex", "gemini-cli"];
pub const MAX_TIMEOUT_S: u64 = 3600;
pub const DEFAULT_TIMEOUT_S: u64 = 1800;
pub const MIN_TIMEOUT_S: u64 = 60;
/// 64 KiB: well under Linux's 128 KiB limit for one environment string once base64 makes it 4/3 larger.
pub const MAX_PROMPT: usize = 64 * 1024;
pub const MODEL_HOST: &str = "api.anthropic.com";
/// What Claude Code is given in place of a token. The broker drops `authorization` and `x-api-key`, and the Gate adds
/// the real one.
pub const OAUTH_PLACEHOLDER: &str = "sk-ant-oat01-pavilion-placeholder";
pub const API_KEY_PLACEHOLDER: &str = "sk-ant-pavilion-placeholder";
/// The script's exit code when the repository moved while the work was paused (WORK-ROUTING §12): the `exit 78` in
/// SCRIPT, which the Gate reads (gate/src/work-store.ts `WORLD_MOVED_EXIT`). Named here for the tests.
#[cfg_attr(not(test), allow(dead_code))]
pub const WORLD_MOVED_EXIT: i32 = 78;
/// After Claude Code's own time limit: fetch, commit and push.
pub const GIT_MARGIN_S: u64 = 300;
/// A task's sandbox is kept this long after its last job, then removed (link.rs reaps warm sandboxes every 30 s).
pub const WARM_KEEP_S: u64 = 1200;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Account { Subscription, ApiKey, Slot }
impl Account {
    /// The secret name in the broker's egress form; the Gate maps it to a real account. A slot's is the broker's own.
    pub fn secret(self) -> &'static str { match self { Account::Subscription => "CLAUDE_SUBSCRIPTION", Account::ApiKey => "ANTHROPIC_API_KEY", Account::Slot => crate::accounts::SLOT_SECRET } }
}

#[derive(Clone, Debug)]
pub struct AgentJob {
    pub job: String,
    pub project: String,
    pub prompt: String,
    pub repo: String,
    pub branch: String,
    pub base: String,
    pub timeout_s: u64,
    pub account: Account,
    /// `claude-code`, `codex` or `gemini-cli`: which CLI runs in the VM. Codex and Gemini run on a slot only.
    pub harness: &'static str,
    /// The slot, when `account` is `Slot`: one of this machine's (accounts.rs).
    pub slot: Option<String>,
    pub requested_by: (String, String),
    pub model: Option<String>,
    pub memory_mib: u64,
    pub cpus: u32,
    pub grants: HashMap<String, Grant>,
    /// A resumed item's heads (base, branch; `None` for one that was not there): checked after the fetch.
    pub expect: Option<(Option<String>, Option<String>)>,
    /// On a slot: its token budgets per turn and per day (UTC), counted by the broker (accounts.rs).
    pub budget: crate::accounts::Budget,
}

/// A commit id: SHA-1 or SHA-256, lower-case hex.
fn sha_ok(s: &str) -> bool { (s.len() == 40 || s.len() == 64) && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) }

/// A host name as SSH takes it: lower-case labels with a dot.
fn host_ok(h: &str) -> bool {
    let label = |l: &str| !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-') && l.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    h.len() <= 253 && h.contains('.') && h.split('.').all(label)
}
/// `owner/name.git`: plain segments, none starting with a dot or a dash.
fn repo_path_ok(p: &str) -> bool {
    !p.is_empty() && p.len() <= 200 && p.split('/').all(|s| !s.is_empty() && !s.starts_with('.') && !s.starts_with('-')
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-'))
}
/// An SSH repository: `git@host:owner/name.git` or `ssh://git@host[:port]/owner/name.git`. Nothing that git could read
/// as an option, another transport or a local path; the VM has no route for HTTPS anyway.
pub fn repo_ok(r: &str) -> bool {
    if let Some(rest) = r.strip_prefix("ssh://git@") {
        let Some((authority, path)) = rest.split_once('/') else { return false };
        let (host, port) = authority.split_once(':').map_or((authority, None), |(h, p)| (h, Some(p)));
        return host_ok(host) && port.map_or(true, |p| !p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit())) && repo_path_ok(path);
    }
    let Some(rest) = r.strip_prefix("git@") else { return false };
    let Some((host, path)) = rest.split_once(':') else { return false };
    host_ok(host) && repo_path_ok(path)
}
/// A branch name git accepts and no shell or git option could misread (a subset of `git check-ref-format --branch`).
pub fn ref_ok(r: &str) -> bool {
    !r.is_empty() && r.len() <= 200 && r.bytes().all(|b| b.is_ascii_alphanumeric() || b"._/-".contains(&b))
        && !r.starts_with('-') && !r.ends_with(".lock") && !r.contains("..") && !r.ends_with('.')
        && r.split('/').all(|s| !s.is_empty() && !s.starts_with('.') && !s.starts_with('-'))
}
fn job_id_ok(j: &str) -> bool { !j.is_empty() && j.len() <= 64 && j.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-') }
/// A model name Claude Code is given: Anthropic's (`claude-opus-5-5`, `opus`), or a local model reached through the
/// machine relay (`ollama:qwen3:8b`, `lmstudio:qwen/qwen3-vl-8b`, docs/MODEL-ACCOUNTS.md §7). It travels in an
/// environment variable read with quotes, never as shell code; it may not start like an option.
fn model_ok(m: &str) -> bool { !m.is_empty() && m.len() <= 128 && !m.starts_with('-') && m.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-.[]:/_".contains(&b)) }

/// The grants in an envelope: secret name → grant (as for command jobs).
pub fn grants_of(env: &Value) -> HashMap<String, Grant> {
    env["grants"].as_array().cloned().unwrap_or_default().into_iter().filter_map(|g| Some((
        g["secret"].as_str()?.to_string(),
        Grant { id: g["id"].as_str()?.to_string(), hosts: g["hosts"].as_array()?.iter().filter_map(|h| h.as_str().map(String::from)).collect() },
    ))).collect()
}

/// Checks an agent envelope (its signature, machine and sequence were checked by link.rs). The reason is shown to
/// whoever sent the job.
pub fn validate(env: &Value, now_ms: u64) -> Result<AgentJob, String> {
    if env["kind"] != "agent" { return Err("not an agent job".into()); }
    if now_ms > env["expiresAt"].as_u64().unwrap_or(0) { return Err("the job expired before it arrived".into()); }
    let s = |k: &str| env[k].as_str().map(str::trim).filter(|v| !v.is_empty());
    let job = s("job").filter(|j| job_id_ok(j)).ok_or("an agent job needs a job id (letters, digits, _ and -)")?;
    let prompt = env["prompt"].as_str().filter(|p| !p.trim().is_empty()).ok_or("an agent job needs a prompt")?;
    if prompt.len() > MAX_PROMPT { return Err(format!("the prompt is over {} KiB", MAX_PROMPT / 1024)); }
    if prompt.contains('\0') { return Err("the prompt holds a NUL byte".into()); }
    let repo = s("repo").ok_or("an agent job needs a repo")?;
    if !repo_ok(repo) { return Err(format!("the repo must be an SSH address like git@github.com:owner/name.git, not {repo:?}")); }
    let branch = s("branch").ok_or("an agent job needs a branch")?;
    if !branch.starts_with("task/") || branch.len() <= 5 || !ref_ok(branch) { return Err(format!("the branch must be a plain task/… name, not {branch:?}")); }
    let base = s("base").ok_or("an agent job needs a base branch")?;
    if !ref_ok(base) || base == branch { return Err(format!("bad base branch {base:?}")); }
    let timeout_s = match &env["timeoutS"] {
        Value::Null => DEFAULT_TIMEOUT_S,
        v => v.as_u64().filter(|t| *t > 0).ok_or("timeoutS must be a positive number of seconds")?.clamp(MIN_TIMEOUT_S, MAX_TIMEOUT_S),
    };
    let account = match s("account") {
        Some("subscription") => Account::Subscription,
        Some("api-key") => Account::ApiKey,
        Some("slot") => Account::Slot,
        Some(a) => return Err(format!("unknown account {a:?}: subscription, api-key or slot")),
        None => return Err("an agent job needs an account (subscription, api-key or slot)".into()),
    };
    let slot = match (account, s("slot")) {
        (Account::Slot, Some(id)) if crate::accounts::slot_id_ok(id) => Some(id.to_string()),
        (Account::Slot, _) => return Err("an agent job on a slot names it: slot is slt_…".into()),
        (_, Some(_)) => return Err("slot goes with account \"slot\" only".into()),
        _ => None,
    };
    let harness = match s("harness") {
        None => "claude-code",
        Some(h) => HARNESSES.into_iter().find(|x| *x == h).ok_or_else(|| format!("unknown harness {h:?}: claude-code, codex or gemini-cli"))?,
    };
    // A Codex or Gemini job runs on one of this machine's own slots: there is no vault path for those plans.
    if harness != "claude-code" && account != Account::Slot { return Err(format!("a {harness} job runs on a slot of this machine only")); }
    let by = &env["requestedBy"];
    let field = |k: &str| by[k].as_str().map(str::trim).filter(|v| !v.is_empty() && v.len() <= 200 && !v.contains(['\0', '\n', '\r'])).map(String::from);
    let requested_by = match (field("name"), field("key")) { (Some(n), Some(k)) => (n, k), _ => return Err("an agent job needs requestedBy { name, key }".into()) };
    let model = match &env["model"] { Value::Null => None, v => Some(v.as_str().filter(|m| model_ok(m)).ok_or("bad model name")?.to_string()) };
    let grants = grants_of(env);
    let expect = match &env["expect"] {
        Value::Null => None,
        e => {
            let one = |k: &str| match &e[k] { Value::Null => Ok(None), v => v.as_str().filter(|s| sha_ok(s)).map(|s| Some(s.to_string())).ok_or("expect holds commit ids") };
            let (b, t) = (one("base")?, one("branch")?);
            if b.is_none() && t.is_none() { return Err("expect names at least one head".into()); }
            Some((b, t))
        }
    };
    let budget = match &env["slot_budget"] {
        Value::Null => crate::accounts::Budget::default(),
        b if account == Account::Slot => {
            let n = |k: &str| match &b[k] { Value::Null => Ok(None), v => v.as_u64().filter(|x| (1000..=10_000_000_000).contains(x)).map(Some).ok_or("slot_budget holds whole numbers of tokens") };
            crate::accounts::Budget { turn: n("turn_tokens")?, day: n("day_tokens")? }
        }
        _ => return Err("slot_budget goes with account \"slot\" only".into()),
    };
    // The model is reached through the broker's egress form, which needs the Gate's grant for the account's secret; a
    // slot's call is the broker's own and needs none.
    if account != Account::Slot && !grants.get(account.secret()).is_some_and(|g| g.hosts.iter().any(|h| host_matches(h, MODEL_HOST))) {
        return Err(format!("the pavilion sent no grant for {} on {MODEL_HOST}", account.secret()));
    }
    Ok(AgentJob {
        job: job.into(), project: s("project").unwrap_or("default").into(), prompt: prompt.into(), repo: repo.into(), branch: branch.into(), base: base.into(),
        timeout_s, account, harness, slot, requested_by, model,
        memory_mib: env["memoryMiB"].as_u64().unwrap_or(4096).clamp(2048, 8192), cpus: env["cpus"].as_u64().unwrap_or(4).clamp(1, 8) as u32, grants, expect, budget,
    })
}

/// The job's environment inside the VM. `{broker}` is the job broker's address (sandbox.rs fills it in). Only
/// placeholders, never a token: the broker drops the auth headers and the Gate adds the real ones.
pub fn env(a: &AgentJob) -> Vec<(String, String)> {
    let mut e: Vec<(String, String)> = vec![
        ("PAVILION_PROMPT_B64".into(), STANDARD.encode(&a.prompt)),
        ("PAVILION_REPO".into(), a.repo.clone()),
        ("PAVILION_BRANCH".into(), a.branch.clone()),
        ("PAVILION_BASE".into(), a.base.clone()),
        ("PAVILION_TIMEOUT_S".into(), a.timeout_s.to_string()),
        ("PAVILION_REQUESTED_BY".into(), a.requested_by.0.clone()),
        ("PAVILION_HARNESS".into(), a.harness.into()),
    ];
    match a.harness {
        // Codex with a ChatGPT login (slot_auth.rs): a placeholder auth.json, the model base and the backend base moved
        // to the broker (config keys `openai_base_url` and `chatgpt_base_url`, given with -c by the script), and its
        // own refresh pointed at the broker too, which refreshes on the host and answers with placeholders.
        "codex" => {
            let slot = crate::slot_auth::CODEX.secret;
            e.push(("PAVILION_MODEL".into(), a.model.clone().unwrap_or_default()));
            e.push(("PAVILION_CODEX_AUTH_B64".into(), crate::slot_auth::codex_placeholder_auth_b64(now_ms())));
            e.push(("PAVILION_CODEX_BASE".into(), format!("{{broker}}/{slot}/chatgpt.com/backend-api/codex")));
            e.push(("PAVILION_CODEX_CHATGPT_BASE".into(), format!("{{broker}}/{slot}/chatgpt.com/backend-api/")));
            e.push(("CODEX_REFRESH_TOKEN_URL_OVERRIDE".into(), format!("{{broker}}/{slot}/{}{}", crate::slot_auth::CODEX_AUTH_HOST, crate::slot_auth::CODEX_TOKEN_PATH)));
        }
        // The Gemini CLI's "Login with Google" with an access token only (so it never refreshes in the VM), its Code
        // Assist endpoint moved to the broker.
        "gemini-cli" => {
            e.push(("PAVILION_MODEL".into(), a.model.clone().unwrap_or_default()));
            e.push(("GOOGLE_GENAI_USE_GCA".into(), "true".into()));
            e.push(("GOOGLE_CLOUD_ACCESS_TOKEN".into(), crate::slot_auth::GEMINI_PLACEHOLDER.into()));
            e.push(("CODE_ASSIST_ENDPOINT".into(), format!("{{broker}}/{}/{}", crate::slot_auth::GEMINI.secret, crate::slot_auth::GEMINI.host)));
            e.push(("GEMINI_TELEMETRY_ENABLED".into(), "false".into()));
        }
        _ => {
            e.push(("PAVILION_MODEL".into(), a.model.clone().unwrap_or_else(|| "opus".into())));
            e.push(("ANTHROPIC_BASE_URL".into(), format!("{{broker}}/{}/{MODEL_HOST}", a.account.secret())));
            // Without this Claude Code also calls api.anthropic.com directly (seen: 6 connections a run), past the base URL.
            e.push(("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC".into(), "1".into()));
            e.push(("DISABLE_AUTOUPDATER".into(), "1".into()));
            e.push(("IS_SANDBOX".into(), "1".into()));
            match a.account {
                Account::Subscription | Account::Slot => e.push(("CLAUDE_CODE_OAUTH_TOKEN".into(), OAUTH_PLACEHOLDER.into())),
                Account::ApiKey => e.push(("ANTHROPIC_API_KEY".into(), API_KEY_PLACEHOLDER.into())),
            }
        }
    }
    // A resumed item's heads: empty for one not checked, `none` for a branch that was not there yet.
    if let Some((b, t)) = &a.expect {
        e.push(("PAVILION_EXPECT_BASE".into(), b.clone().unwrap_or_default()));
        e.push(("PAVILION_EXPECT_BRANCH".into(), t.clone().unwrap_or_else(|| "none".into())));
    }
    e
}
fn now_ms() -> u64 { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0) }

/// The script every agent job runs, after the broker's SSH setup (broker.rs). The same text for every job: what the job
/// says arrives in environment variables. Exit codes: Claude Code's own (124 for its time limit), 70 setup, 75 the
/// repository or a branch, 76 the push, 77 Claude Code left another branch checked out.
pub const SCRIPT: &str = r#"exec 2>&1
set -u
say() { printf 'pavilion: %s\n' "$*"; }
W=${PAVILION_WORK:-/work} D=${HOME:-/tmp}/.pavilion
R=$W/repo B=${PAVILION_BRANCH:-} BASE=${PAVILION_BASE:-}
mkdir -p "$D" "$W" || { say "couldn't make the work folders"; exit 70; }
printf %s "${PAVILION_PROMPT_B64:-}" | base64 -d > "$D/prompt" || { say "the prompt didn't decode"; exit 70; }
unset PAVILION_PROMPT_B64
git check-ref-format --branch "$B" >/dev/null 2>&1 && git check-ref-format --branch "$BASE" >/dev/null 2>&1 || { say "bad branch names"; exit 70; }
export GIT_TERMINAL_PROMPT=0
# 1. The repository: cloned the first time, fetched when this task's sandbox is reused.
if [ -d "$R/.git" ]; then
  say "fetching $PAVILION_REPO"
  git -C "$R" remote set-url origin "$PAVILION_REPO" && git -C "$R" fetch --prune --quiet origin || { say "couldn't fetch $PAVILION_REPO"; exit 75; }
else
  say "cloning $PAVILION_REPO"
  rm -rf "$R" && git clone --quiet --no-checkout -- "$PAVILION_REPO" "$R" || { say "couldn't clone $PAVILION_REPO"; exit 75; }
fi
cd "$R" || exit 70
git config user.name "${PAVILION_GIT_NAME:-Claude Code (Cloud Pavilion)}" && git config user.email "${PAVILION_GIT_EMAIL:-agent@cloudpavilion.invalid}" || exit 70
# The heads as fetched: the pavilion keeps them, and a resumed item stops here if either moved while it was paused.
bh=$(git rev-parse --verify --quiet "refs/remotes/origin/$BASE^{commit}") || bh=none
th=$(git rev-parse --verify --quiet "refs/remotes/origin/$B^{commit}") || th=none
say "heads $bh $th"
if [ -n "${PAVILION_EXPECT_BASE:-}${PAVILION_EXPECT_BRANCH:-}" ]; then
  if { [ -n "${PAVILION_EXPECT_BASE:-}" ] && [ "$PAVILION_EXPECT_BASE" != "$bh" ]; } || { [ -n "${PAVILION_EXPECT_BRANCH:-}" ] && [ "$PAVILION_EXPECT_BRANCH" != "$th" ]; }; then
    say "the repository moved while this work was paused ($BASE ${PAVILION_EXPECT_BASE:-?} -> $bh, $B ${PAVILION_EXPECT_BRANCH:-?} -> $th); not run, the pavilion decides"
    exit 78
  fi
fi
# 2. The task branch: this sandbox's copy, else the remote's, else a new one from the base.
git rev-parse --verify --quiet "refs/remotes/origin/$BASE" >/dev/null || { say "the base branch $BASE isn't on the remote"; exit 75; }
if git rev-parse --verify --quiet "refs/heads/$B" >/dev/null; then
  git checkout --quiet "$B" -- || { say "couldn't check out $B"; exit 75; }
  if git rev-parse --verify --quiet "refs/remotes/origin/$B" >/dev/null; then
    git merge --ff-only --quiet "refs/remotes/origin/$B" || say "the remote $B moved on and can't be fast-forwarded here; working on this sandbox's copy"
  fi
elif git rev-parse --verify --quiet "refs/remotes/origin/$B" >/dev/null; then
  git checkout --quiet -b "$B" "refs/remotes/origin/$B" || { say "couldn't check out $B"; exit 75; }
else
  git checkout --quiet -b "$B" "refs/remotes/origin/$BASE" || { say "couldn't make $B from $BASE"; exit 75; }
  say "new branch $B from $BASE"
fi
# 3. Dependencies come from the image (there is no registry from here): the Gate's, when the lock files match.
deps=/opt/pavilion/gate-deps note=""
if [ -f gate/pnpm-lock.yaml ] && [ -d "$deps/node_modules" ] && [ ! -e gate/node_modules ]; then
  if [ "$(sha256sum gate/pnpm-lock.yaml | cut -d' ' -f1)" = "$(cat "$deps/lock.sha256" 2>/dev/null)" ]; then
    ln -s "$deps/node_modules" gate/node_modules && note="gate/node_modules is linked from the image, so npx vitest run and npx tsc work in gate/."
  else
    note="gate/pnpm-lock.yaml differs from the one baked into this image, so gate/node_modules isn't there and can't be installed."
  fi
fi
{
  printf '%s\n' "You are working in a Cloud Pavilion sandbox: a Linux VM holding a clone of the repository below."
  printf 'Repository: %s\nBranch: %s (made from %s)\n' "$PAVILION_REPO" "$B" "$BASE"
  printf '%s\n' "- Stay on this branch. Don't push and don't switch branches: when you finish, the pavilion commits what changed and pushes the branch."
  printf '%s\n' "- There is no internet and no package registry here. Use only what is installed; don't try to install anything."
  printf '%s\n' "- End with a short summary, a few lines, of what you changed and what you checked."
  [ -n "$note" ] && printf '%s\n' "- $note"
} > "$D/system.md"
# 4. The agent, with its tools and no permission prompts: this VM is the sandbox. The prompt arrives on stdin, from a
# file. Claude Code by default; Codex or the Gemini CLI on a member's own slot of theirs (PAVILION_HARNESS).
T=${PAVILION_TIMEOUT_S:-1800} H=${PAVILION_HARNESS:-claude-code}
: > "$D/summary"
set --
[ -n "${PAVILION_MODEL:-}" ] && set -- -m "$PAVILION_MODEL"
case "$H" in
  codex)
    C=${CODEX_HOME:-$HOME/.codex}
    mkdir -p "$C" && chmod 700 "$C" && printf %s "${PAVILION_CODEX_AUTH_B64:-}" | base64 -d > "$C/auth.json" && chmod 600 "$C/auth.json" || { say "the Codex sign-in placeholder didn't decode"; exit 70; }
    unset PAVILION_CODEX_AUTH_B64
    { cat "$D/system.md"; printf '\n'; cat "$D/prompt"; } > "$D/prompt.full"
    say "Codex starts (up to $T s)"
    timeout "$T" codex exec --dangerously-bypass-approvals-and-sandbox --skip-git-repo-check \
      -c "openai_base_url=\"$PAVILION_CODEX_BASE\"" -c "chatgpt_base_url=\"$PAVILION_CODEX_CHATGPT_BASE\"" \
      -o "$D/summary" "$@" - < "$D/prompt.full" > "$D/agent.log" 2>&1
    code=$? name=Codex ;;
  gemini-cli)
    { cat "$D/system.md"; printf '\n'; cat "$D/prompt"; } > "$D/prompt.full"
    say "Gemini CLI starts (up to $T s)"
    timeout "$T" gemini --yolo --skip-trust -o text "$@" -p "Do the task above." < "$D/prompt.full" > "$D/summary" 2> "$D/agent.log"
    code=$? name="Gemini CLI" ;;
  *)
    say "Claude Code starts (up to $T s)"
    timeout "$T" claude -p --dangerously-skip-permissions --output-format text --model "${PAVILION_MODEL:-opus}" \
      --append-system-prompt-file "$D/system.md" < "$D/prompt" > "$D/summary"
    code=$? name="Claude Code" ;;
esac
# A CLI that stopped before saying anything: the end of its log stands in for the summary.
[ -s "$D/summary" ] || { [ -f "$D/agent.log" ] && tail -c 4000 "$D/agent.log" > "$D/summary"; }
[ "$code" -eq 124 ] && say "$name was stopped at its time limit; committing what it had done"
say "$name exited $code"
# 5. Commit what changed, naming the task, and push the branch.
pcode=0 pushed=no
if [ "$(git symbolic-ref --short -q HEAD)" != "$B" ]; then
  say "Claude Code left another branch checked out; nothing was committed or pushed"; pcode=77
else
  git add -A
  if ! git diff --cached --quiet; then
    { printf '%s: %s\n\n' "$B" "$(head -n 1 "$D/prompt" | cut -c1-72)"
      printf 'Done by %s in a Cloud Pavilion sandbox (job %s).\nRequested by %s.\n' "$name" "${PAVILION_JOB:-?}" "${PAVILION_REQUESTED_BY:-?}"; } > "$D/message"
    git commit --quiet --no-verify -F "$D/message" || say "the commit failed"
  fi
  head=$(git rev-parse HEAD)
  say "head $head"
  if [ "$head" = "$(git rev-parse -q --verify "refs/remotes/origin/$B")" ]; then pushed=already
  elif [ "$head" = "$(git rev-parse "refs/remotes/origin/$BASE")" ]; then pushed=nothing
  elif git push --quiet origin "HEAD:refs/heads/$B"; then pushed=yes
  else say "the push failed"; pcode=76
  fi
fi
say "pushed: $pushed"
# 6. The result: Claude Code's summary, the branch, and what differs from the base.
printf '%s\n' "$(tail -c 8000 "$D/summary")"
printf 'branch: %s\n' "$B"
git diff --stat "refs/remotes/origin/$BASE...HEAD"
[ "$code" -ne 0 ] && exit "$code"
exit "$pcode"
"#;

/// The warm sandbox's key: one per project, repository and branch, so a task's next job carries on where it stopped.
pub fn warm_key(a: &AgentJob) -> String { format!("agent|{}|{}|{}", a.project, a.repo, a.branch) }

/// The image this node runs agent jobs in (as configured, else the default).
pub fn image() -> String { configured_image().unwrap_or_else(|| DEFAULT_IMAGE.to_string()) }
fn configured_image() -> Option<String> {
    crate::state::config()["agent_image"].as_str().filter(|i| (3..=200).contains(&i.len()) && i.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"./_:@-".contains(&b))).map(String::from)
}
/// The image here and the harnesses it has: a configured image (its harnesses from `agent_harnesses` in config.json,
/// else Claude Code only), else `:2` (all three), else `:1` (Claude Code only). None: no image here.
pub async fn resolved() -> Option<(String, Vec<&'static str>)> {
    let rt = crate::sandbox::detect().ok()?;
    if let Some(i) = configured_image() {
        if !crate::sandbox::image_present(&rt, &i).await { return None; }
        let cfg = crate::state::config();
        let said: Vec<&'static str> = cfg["agent_harnesses"].as_array().map(|a| HARNESSES.into_iter().filter(|h| a.iter().any(|x| x == h)).collect()).unwrap_or_default();
        return Some((i, if said.is_empty() { vec!["claude-code"] } else { said }));
    }
    if crate::sandbox::image_present(&rt, DEFAULT_IMAGE).await { return Some((DEFAULT_IMAGE.into(), HARNESSES.to_vec())); }
    if crate::sandbox::image_present(&rt, CLAUDE_ONLY_IMAGE).await { return Some((CLAUDE_ONLY_IMAGE.into(), vec!["claude-code"])); }
    None
}
/// The image to run a harness in, when this machine has one with it.
pub async fn image_for(harness: &str) -> Option<String> { resolved().await.filter(|(_, hs)| hs.contains(&harness)).map(|(i, _)| i) }

/// Whether this node can run agent jobs: a strong sandbox runtime, and the worker image already here.
pub async fn ready() -> bool { resolved().await.is_some() }

/// What the job's output says, parsed: the summary, the branch line and the diff stat (contract: the output ends with
/// those), and whether the branch was pushed. The Gate gets these beside the raw output.
#[derive(Debug, Default, PartialEq)]
pub struct AgentResult { pub summary: String, pub branch: Option<String>, pub diff_stat: String, pub pushed: Option<String>,
    /// The base's and the branch's heads as fetched (`pavilion: heads <base> <branch|none>`), and the head after the commit.
    pub heads: Option<(String, Option<String>)>, pub head: Option<String> }
pub fn parse_result(output: &str) -> AgentResult {
    let lines: Vec<&str> = output.lines().collect();
    // The heads come early, so a job stopped half-way (a pause) still says them.
    let heads = lines.iter().rev().find_map(|l| l.strip_prefix("pavilion: heads ")).and_then(|h| {
        let (b, t) = h.trim().split_once(' ')?;
        sha_ok(b).then(|| (b.to_string(), sha_ok(t).then(|| t.to_string())))
    });
    let head = lines.iter().rev().find_map(|l| l.strip_prefix("pavilion: head ")).map(str::trim).filter(|h| sha_ok(h)).map(String::from);
    let Some(b) = lines.iter().rposition(|l| l.starts_with("branch: ")) else { return AgentResult { heads, head, ..AgentResult::default() } };
    let start = lines[..b].iter().rposition(|l| l.starts_with("pavilion: ")).map_or(0, |i| i + 1);
    let pushed = lines[..b].iter().rev().find_map(|l| l.strip_prefix("pavilion: pushed: ")).map(|s| s.trim().to_string());
    AgentResult {
        summary: lines[start..b].join("\n").trim().to_string(),
        branch: Some(lines[b]["branch: ".len()..].trim().to_string()),
        diff_stat: lines[b + 1..].join("\n").trim_end().to_string(),
        pushed, heads, head,
    }
}
impl AgentResult {
    pub fn to_json(&self) -> Value {
        let mut v = json!({ "summary": self.summary, "branch": self.branch, "diffStat": self.diff_stat, "pushed": self.pushed });
        if let Some((b, t)) = &self.heads { v["heads"] = json!({ "base": b, "branch": t }); }
        if let Some(h) = &self.head { v["head"] = json!(h); }
        v
    }
}

/// The sandbox for one agent job: the worker image, this task's warm VM, the fixed script, the job's environment.
pub fn spec(a: &AgentJob, image: &str) -> crate::sandbox::JobSpec {
    crate::sandbox::JobSpec {
        job: a.job.clone(), project: a.project.clone(), image: image.into(), cmd: SCRIPT.into(), cpus: a.cpus, memory_mib: a.memory_mib,
        timeout_s: a.timeout_s + GIT_MARGIN_S, grants: a.grants.clone(), env: env(a),
        warm: Some(crate::sandbox::Warm { key: warm_key(a), keep_s: WARM_KEEP_S }),
        slot: a.slot.clone(),
    }
}

/// Runs an agent job; the outcome as for any job, and the parsed result lines.
pub async fn run(a: AgentJob, gate: &str, pavilion: &str, key: ed25519_dalek::SigningKey) -> anyhow::Result<(crate::sandbox::Outcome, AgentResult)> {
    // A slot's budgets for this job, where its broker (built from the job's spec) finds them.
    if a.slot.is_some() { crate::accounts::set_budget(&a.job, a.budget); }
    let img = image_for(a.harness).await.unwrap_or_else(image);
    let o = crate::sandbox::run(spec(&a, &img), gate, pavilion, key).await;
    crate::accounts::clear_budget(&a.job);
    let o = o?;
    let r = parse_result(&o.output);
    Ok((o, r))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> u64 { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64 }
    fn good() -> Value {
        json!({ "v": 1, "kind": "agent", "job": "job_a1", "project": "cloudpavilion", "machine": "mch_1", "seq": 9, "expiresAt": now() + 60_000,
            "prompt": "Fix the flaky test in gate/test/x.test.ts", "repo": "git@github.com:youfoundbruno/cloudpavilion.git",
            "branch": "task/fix-flaky", "base": "main", "timeoutS": 900, "account": "subscription",
            "requestedBy": { "name": "Bruno", "key": "mk_123" },
            "grants": [{ "id": "grt_1", "secret": "CLAUDE_SUBSCRIPTION", "hosts": ["api.anthropic.com"] }] })
    }
    fn with(k: &str, v: Value) -> Value { let mut e = good(); e[k] = v; e }
    fn without(k: &str) -> Value { let mut e = good(); e.as_object_mut().unwrap().remove(k); e }

    #[test]
    fn a_good_envelope() {
        let a = validate(&good(), now()).unwrap();
        assert_eq!((a.job.as_str(), a.project.as_str(), a.branch.as_str(), a.base.as_str(), a.timeout_s, a.account), ("job_a1", "cloudpavilion", "task/fix-flaky", "main", 900, Account::Subscription));
        assert_eq!(a.requested_by, ("Bruno".into(), "mk_123".into()));
        assert_eq!(a.grants["CLAUDE_SUBSCRIPTION"].id, "grt_1");
        assert_eq!((a.memory_mib, a.cpus, a.model.as_deref()), (4096, 4, None));
        // ssh:// with a port works too; the time limit is capped at an hour and defaults to half of one.
        let a = validate(&with("repo", json!("ssh://git@git.example.com:2222/team/app.git")), now()).unwrap();
        assert_eq!(a.repo, "ssh://git@git.example.com:2222/team/app.git");
        assert_eq!(validate(&with("timeoutS", json!(99_999)), now()).unwrap().timeout_s, MAX_TIMEOUT_S);
        assert_eq!(validate(&without("timeoutS"), now()).unwrap().timeout_s, DEFAULT_TIMEOUT_S);
        let mut k = with("account", json!("api-key"));
        k["grants"] = json!([{ "id": "grt_2", "secret": "ANTHROPIC_API_KEY", "hosts": ["api.anthropic.com"] }]);
        assert_eq!(validate(&k, now()).unwrap().account, Account::ApiKey);
    }

    #[test]
    fn missing_fields_are_refused_by_name() {
        for (k, why) in [("prompt", "prompt"), ("repo", "repo"), ("branch", "branch"), ("base", "base"), ("account", "account"), ("requestedBy", "requestedBy"), ("job", "job id")] {
            let e = validate(&without(k), now()).unwrap_err();
            assert!(e.contains(why), "{k}: {e}");
        }
        assert!(validate(&with("prompt", json!("   ")), now()).unwrap_err().contains("prompt"));
        assert!(validate(&with("requestedBy", json!({ "name": "Bruno" })), now()).unwrap_err().contains("requestedBy"));
        assert!(validate(&with("grants", json!([])), now()).unwrap_err().contains("no grant for CLAUDE_SUBSCRIPTION"));
        // A grant for the other account, or for another host, isn't the model grant.
        assert!(validate(&with("grants", json!([{ "id": "g", "secret": "ANTHROPIC_API_KEY", "hosts": ["api.anthropic.com"] }])), now()).is_err());
        assert!(validate(&with("grants", json!([{ "id": "g", "secret": "CLAUDE_SUBSCRIPTION", "hosts": ["api.github.com"] }])), now()).is_err());
    }

    #[test]
    fn wrong_kind_and_expired_are_refused() {
        assert_eq!(validate(&with("kind", json!("command")), now()).unwrap_err(), "not an agent job");
        assert_eq!(validate(&without("kind"), now()).unwrap_err(), "not an agent job");
        assert!(validate(&with("expiresAt", json!(now() - 1)), now()).unwrap_err().contains("expired"));
        assert!(validate(&without("expiresAt"), now()).unwrap_err().contains("expired"));
    }

    #[test]
    fn names_that_could_mislead_git_or_a_shell_are_refused() {
        for r in ["https://github.com/a/b.git", "git@github.com:-oProxyCommand=x/b", "git@github.com:a/../b", "git@localhost:a/b", "ext::sh -c x",
            "git@github.com:a/b;id", "git@github.com:a/$(id)", "/tmp/repo", "file:///tmp/r", "git@github.com:", "ssh://git@github.com:22a/a/b", "git@github.com:a/.git"] {
            assert!(validate(&with("repo", json!(r)), now()).is_err(), "{r}");
        }
        for b in ["main", "task/", "task/-x", "task/a..b", "task/a b", "task/$(id)", "task/a.lock", "task//a", "task/.a", "task/a;b", "task/`id`", "task/a\nb"] {
            assert!(validate(&with("branch", json!(b)), now()).is_err(), "{b:?}");
        }
        for b in ["-main", "a..b", "task/fix-flaky", "$(id)"] { assert!(validate(&with("base", json!(b)), now()).is_err(), "{b}"); }
        for t in [json!(0), json!(-5), json!("600"), json!(1.5)] { assert!(validate(&with("timeoutS", t.clone()), now()).is_err(), "{t}"); }
        assert!(validate(&with("account", json!("someone-elses")), now()).is_err());
        assert!(validate(&with("model", json!("opus; id")), now()).is_err());
        assert_eq!(validate(&with("model", json!("claude-opus-5-5")), now()).unwrap().model.as_deref(), Some("claude-opus-5-5"));
        // A local model through the machine relay; never one that reads as an option.
        assert_eq!(validate(&with("model", json!("ollama:qwen3:8b")), now()).unwrap().model.as_deref(), Some("ollama:qwen3:8b"));
        assert!(validate(&with("model", json!("--dangerously-x")), now()).is_err());
        assert!(validate(&with("job", json!("job 1; id")), now()).is_err());
        assert!(validate(&with("prompt", json!("x".repeat(MAX_PROMPT + 1))), now()).unwrap_err().contains("KiB"));
    }

    /// One of this machine's account slots (WORK-ROUTING §9): named by id, no grant, the broker's own door, a placeholder.
    #[test]
    fn a_job_on_a_slot() {
        let mut k = with("account", json!("slot"));
        k["slot"] = json!("slt_ab12cd34ef");
        k["grants"] = json!([]);
        let a = validate(&k, now()).unwrap();
        assert_eq!((a.account, a.slot.as_deref()), (Account::Slot, Some("slt_ab12cd34ef")));
        let e: HashMap<String, String> = env(&a).into_iter().collect();
        assert_eq!(e["ANTHROPIC_BASE_URL"], "{broker}/CLAUDE_SLOT/api.anthropic.com");
        assert_eq!(e["CLAUDE_CODE_OAUTH_TOKEN"], OAUTH_PLACEHOLDER);
        assert_eq!(spec(&a, "img").slot.as_deref(), Some("slt_ab12cd34ef"));
        assert!(validate(&with("account", json!("slot")), now()).unwrap_err().contains("names it"));
        k["slot"] = json!("slt_../x");
        assert!(validate(&k, now()).is_err());
        assert!(validate(&with("slot", json!("slt_ab12cd34ef")), now()).unwrap_err().contains("account \"slot\" only"));
        assert_eq!(validate(&good(), now()).unwrap().slot, None);
        // Its token budgets (WORK-ROUTING §12) ride on a slot job only, as whole numbers of tokens.
        k["slot"] = json!("slt_ab12cd34ef");
        k["slot_budget"] = json!({ "turn_tokens": 200_000, "day_tokens": null });
        assert_eq!(validate(&k, now()).unwrap().budget, crate::accounts::Budget { turn: Some(200_000), day: None });
        k["slot_budget"] = json!({ "turn_tokens": 5, "day_tokens": null });
        assert!(validate(&k, now()).is_err());
        assert!(validate(&with("slot_budget", json!({ "turn_tokens": 200_000 })), now()).unwrap_err().contains("slot"));
    }

    /// Codex and Gemini on a member's own slot (WORK-ROUTING §9): their CLIs pointed at the broker, placeholders only.
    #[test]
    fn codex_and_gemini_jobs_get_placeholders_and_the_broker() {
        let mut k = with("account", json!("slot"));
        k["slot"] = json!("slt_ab12cd34ef"); k["grants"] = json!([]); k["harness"] = json!("codex");
        let a = validate(&k, now()).unwrap();
        assert_eq!(a.harness, "codex");
        let e: HashMap<String, String> = env(&a).into_iter().collect();
        assert_eq!(e["PAVILION_HARNESS"], "codex");
        assert_eq!(e["PAVILION_CODEX_BASE"], "{broker}/CODEX_SLOT/chatgpt.com/backend-api/codex");
        assert_eq!(e["PAVILION_CODEX_CHATGPT_BASE"], "{broker}/CODEX_SLOT/chatgpt.com/backend-api/");
        assert_eq!(e["CODEX_REFRESH_TOKEN_URL_OVERRIDE"], "{broker}/CODEX_SLOT/auth.openai.com/oauth/token", "its own refresh goes to the broker too");
        let auth = String::from_utf8(STANDARD.decode(&e["PAVILION_CODEX_AUTH_B64"]).unwrap()).unwrap();
        assert!(auth.contains("pavilion-placeholder") && auth.contains("\"OPENAI_API_KEY\":null"));
        assert_eq!(e["PAVILION_MODEL"], "", "Codex's own default model unless the pavilion names one");
        assert!(!e.contains_key("ANTHROPIC_BASE_URL") && !e.contains_key("CLAUDE_CODE_OAUTH_TOKEN"));
        let filled: HashMap<String, String> = crate::sandbox::with_broker(&env(&a), "http://10.89.7.1:47101").into_iter().collect();
        assert_eq!(filled["CODEX_REFRESH_TOKEN_URL_OVERRIDE"], "http://10.89.7.1:47101/CODEX_SLOT/auth.openai.com/oauth/token");
        k["harness"] = json!("gemini-cli");
        let e: HashMap<String, String> = env(&validate(&k, now()).unwrap()).into_iter().collect();
        assert_eq!((e["GOOGLE_GENAI_USE_GCA"].as_str(), e["GOOGLE_CLOUD_ACCESS_TOKEN"].as_str()), ("true", "ya29.pavilion-placeholder"));
        assert_eq!(e["CODE_ASSIST_ENDPOINT"], "{broker}/GEMINI_SLOT/cloudcode-pa.googleapis.com");
        // Codex and Gemini only on a slot; no other harness.
        k["harness"] = json!("aider");
        assert!(validate(&k, now()).unwrap_err().contains("unknown harness"));
        let mut v = good(); v["harness"] = json!("codex");
        assert!(validate(&v, now()).unwrap_err().contains("on a slot of this machine only"));
        assert_eq!(validate(&good(), now()).unwrap().harness, "claude-code");
        // Each CLI reads the prompt from a file on its standard input; none of them as an argument.
        for line in ["codex exec", "gemini --yolo", "claude -p"] {
            let l = SCRIPT.lines().find(|x| x.contains(line)).unwrap();
            assert!(!l.contains("$(") && !l.contains('`'), "{l}");
        }
        assert!(SCRIPT.contains(r#"- < "$D/prompt.full""#) && SCRIPT.contains(r#"-p "Do the task above." < "$D/prompt.full""#));
    }

    /// A resumed item's heads (WORK-ROUTING §12): commit ids only, at least one; they reach the script as plain values.
    #[test]
    fn an_expected_world() {
        let sha = "a".repeat(40);
        let a = validate(&with("expect", json!({ "base": sha, "branch": null })), now()).unwrap();
        assert_eq!(a.expect, Some((Some(sha.clone()), None)));
        let e: HashMap<String, String> = env(&a).into_iter().collect();
        assert_eq!((e["PAVILION_EXPECT_BASE"].as_str(), e["PAVILION_EXPECT_BRANCH"].as_str()), (sha.as_str(), "none"));
        for bad in [json!({ "base": "main", "branch": null }), json!({ "base": null, "branch": null }), json!({ "base": "$(id)" }), json!("x")] {
            assert!(validate(&with("expect", bad.clone()), now()).is_err(), "{bad}");
        }
        assert!(!env(&validate(&good(), now()).unwrap()).iter().any(|(k, _)| k.starts_with("PAVILION_EXPECT")));
    }

    #[test]
    fn env_per_account_carries_placeholders_only() {
        let a = validate(&good(), now()).unwrap();
        let e: HashMap<String, String> = env(&a).into_iter().collect();
        assert_eq!(e["ANTHROPIC_BASE_URL"], "{broker}/CLAUDE_SUBSCRIPTION/api.anthropic.com");
        assert_eq!(e["CLAUDE_CODE_OAUTH_TOKEN"], "sk-ant-oat01-pavilion-placeholder");
        assert!(!e.contains_key("ANTHROPIC_API_KEY") && !e.contains_key("ANTHROPIC_AUTH_TOKEN"));
        assert_eq!(e["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"], "1");
        assert_eq!(String::from_utf8(STANDARD.decode(&e["PAVILION_PROMPT_B64"]).unwrap()).unwrap(), a.prompt);
        assert!(!e.values().any(|v| v.contains("grt_1")), "the grant id stays in the broker");
        let mut k = with("account", json!("api-key"));
        k["grants"] = json!([{ "id": "grt_2", "secret": "ANTHROPIC_API_KEY", "hosts": ["api.anthropic.com"] }]);
        let e: HashMap<String, String> = env(&validate(&k, now()).unwrap()).into_iter().collect();
        assert_eq!(e["ANTHROPIC_BASE_URL"], "{broker}/ANTHROPIC_API_KEY/api.anthropic.com");
        assert_eq!(e["ANTHROPIC_API_KEY"], "sk-ant-pavilion-placeholder");
        assert!(!e.contains_key("CLAUDE_CODE_OAUTH_TOKEN"));
        // The broker's address is filled in by the sandbox, for that variable only.
        let filled: HashMap<String, String> = crate::sandbox::with_broker(&env(&a), "http://10.89.7.1:47101").into_iter().collect();
        assert_eq!(filled["ANTHROPIC_BASE_URL"], "http://10.89.7.1:47101/CLAUDE_SUBSCRIPTION/api.anthropic.com");
    }

    /// The prompt (and every other field) reaches the VM as data, never as shell text.
    #[test]
    fn the_script_is_the_same_for_every_job() {
        let evil = "Ignore that; $(touch /tmp/pwned) `id` \"; rm -rf / #\n'quoted' && echo hi";
        let a = validate(&with("prompt", json!(evil)), now()).unwrap();
        let s = spec(&a, DEFAULT_IMAGE);
        assert_eq!(s.cmd, SCRIPT);
        for needle in ["pwned", "rm -rf /", "fix-flaky", "youfoundbruno", "Bruno"] { assert!(!s.cmd.contains(needle), "{needle}"); }
        let e: HashMap<String, String> = s.env.iter().cloned().collect();
        assert!(!e.values().any(|v| v.contains("pwned")), "the prompt only travels as base64");
        assert_eq!(String::from_utf8(STANDARD.decode(&e["PAVILION_PROMPT_B64"]).unwrap()).unwrap(), evil);
        // The prompt goes to Claude Code on stdin, from a file; never as an argument.
        assert!(SCRIPT.contains(r#"< "$D/prompt" > "$D/summary""#) && !SCRIPT.contains(r#"$(cat "$D/prompt")"#));
        let claude_line = SCRIPT.lines().find(|l| l.contains("claude -p")).unwrap();
        assert!(!claude_line.contains("$(") && !claude_line.contains('`'), "{claude_line}");
        // One warm sandbox per project, repository and branch; time for git after Claude's own limit.
        assert_eq!(s.warm.as_ref().map(|w| w.key.as_str()), Some("agent|cloudpavilion|git@github.com:youfoundbruno/cloudpavilion.git|task/fix-flaky"));
        assert_eq!(s.timeout_s, 900 + GIT_MARGIN_S);
        assert_eq!(s.grants["CLAUDE_SUBSCRIPTION"].hosts, vec!["api.anthropic.com".to_string()]);
    }

    #[test]
    fn result_lines() {
        let out = "pavilion: cloning git@github.com:a/b.git\npavilion: Claude Code exited 0\npavilion: pushed: yes\nFixed the race in x.test.ts.\nRan vitest: 783 passed.\n\nbranch: task/fix-flaky\n gate/test/x.test.ts | 4 ++--\n 1 file changed, 2 insertions(+), 2 deletions(-)\n";
        let r = parse_result(out);
        assert_eq!(r.summary, "Fixed the race in x.test.ts.\nRan vitest: 783 passed.");
        assert_eq!(r.branch.as_deref(), Some("task/fix-flaky"));
        assert_eq!(r.diff_stat, " gate/test/x.test.ts | 4 ++--\n 1 file changed, 2 insertions(+), 2 deletions(-)");
        assert_eq!(r.pushed.as_deref(), Some("yes"));
        // A summary that itself says "branch: …" doesn't confuse it: the last one wins.
        let r = parse_result("pavilion: pushed: nothing\nbranch: main is fine\nbranch: task/x\n");
        assert_eq!((r.summary.as_str(), r.branch.as_deref(), r.diff_stat.as_str()), ("branch: main is fine", Some("task/x"), ""));
        assert_eq!(parse_result("pavilion: couldn't clone\n"), AgentResult::default());
        // The heads come early, so a stopped job still says them; `none` for a branch not there yet.
        let (b, h) = ("b".repeat(40), "c".repeat(40));
        let r = parse_result(&format!("pavilion: fetching x\npavilion: heads {b} none\npavilion: Claude Code starts\n"));
        assert_eq!((r.heads, r.branch), (Some((b.clone(), None)), None));
        let r = parse_result(&format!("pavilion: heads {b} {h}\npavilion: head {h}\npavilion: pushed: already\nDone.\nbranch: task/x\n"));
        assert_eq!((r.heads.clone(), r.head.as_deref()), (Some((b.clone(), Some(h.clone()))), Some(h.as_str())));
        assert_eq!(r.to_json()["heads"], json!({ "base": b, "branch": h }));
        assert_eq!(parse_result("pavilion: heads main none\n").heads, None);
    }

    /// The script itself, run with plain sh against a real git repository, with stand-ins for `claude` and `timeout`
    /// (the runtime here is this machine's shell, not a VM): clone, a new branch from the base, the prompt on stdin and
    /// never run, commit, push, the result lines; then a second job reusing the same folder (a warm sandbox).
    #[cfg(unix)]
    #[test]
    fn the_script_runs_end_to_end_with_stand_ins() {
        if std::process::Command::new("git").arg("--version").output().is_err() { return; }
        // Debian's sh is dash, which is what the VM runs; this Mac's sh is bash in POSIX mode. Both, where present.
        for shell in ["/bin/sh", "/bin/dash"] { if std::path::Path::new(shell).exists() { script_scenario(shell); } }
    }
    #[cfg(unix)]
    fn script_scenario(shell: &str) {
        use std::process::Command;
        let t = std::env::temp_dir().join(format!("pav-agent-{}-{}", std::process::id(), rand::random::<u32>()));
        let (origin, seed, bin, home, work) = (t.join("origin.git"), t.join("seed"), t.join("bin"), t.join("home"), t.join("work"));
        for d in [&seed, &bin, &home, &work] { std::fs::create_dir_all(d).unwrap(); }
        let git = |dir: &std::path::Path, args: &[&str]| {
            let o = Command::new("git").current_dir(dir).args(args).env("GIT_CONFIG_GLOBAL", "/dev/null").env("GIT_CONFIG_NOSYSTEM", "1").output().unwrap();
            assert!(o.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&o.stderr));
            String::from_utf8_lossy(&o.stdout).to_string()
        };
        git(&t, &["init", "-q", "--bare", "-b", "main", origin.to_str().unwrap()]);
        git(&seed, &["init", "-q", "-b", "main"]);
        std::fs::write(seed.join("README.md"), "hello\n").unwrap();
        git(&seed, &["add", "."]);
        git(&seed, &["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "first"]);
        git(&seed, &["push", "-q", origin.to_str().unwrap(), "main"]);
        // Stand-ins: `timeout` runs the rest; `claude` records its arguments and stdin and edits a file.
        let write_exec = |p: std::path::PathBuf, s: &str| { std::fs::write(&p, s).unwrap(); Command::new("chmod").arg("+x").arg(&p).status().unwrap(); };
        write_exec(bin.join("timeout"), "#!/bin/sh\nshift\nexec \"$@\"\n");
        write_exec(bin.join("claude"), "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done > \"$HOME/claude-args\"\ncat > \"$HOME/claude-stdin\"\necho \"edit $(date +%s%N)\" >> NOTES.md\necho 'Added a note.'\necho 'Checked nothing else.'\n");
        let evil = format!("Add a note. $(touch {0}/pwned) `touch {0}/pwned2`\n\"; touch {0}/pwned3; #", t.display());
        let mut env = good();
        env["prompt"] = json!(evil);
        let a = validate(&env, now()).unwrap();
        let run_job = |a: &AgentJob| {
            let mut c = Command::new(shell);
            c.arg("-c").arg(crate::broker::with_ssh_setup(SCRIPT)).env_clear()
                .env("PATH", format!("{}:/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin", bin.display())).env("HOME", &home).env("PAVILION_WORK", &work)
                .env("GIT_CONFIG_GLOBAL", "/dev/null").env("GIT_CONFIG_NOSYSTEM", "1").env("PAVILION_JOB", &a.job);
            for (k, v) in crate::sandbox::with_broker(&super::env(a), "http://127.0.0.1:1") { c.env(k, v); }
            c.env("PAVILION_REPO", &origin); // a local path stands in for the SSH address
            let o = c.output().unwrap();
            (o.status.code().unwrap_or(-1), String::from_utf8_lossy(&o.stdout).to_string())
        };
        let run = || run_job(&a);
        let (code, out) = run();
        assert_eq!(code, 0, "{out}");
        for p in ["pwned", "pwned2", "pwned3"] { assert!(!t.join(p).exists(), "the prompt was run by a shell: {p}\n{out}"); }
        assert_eq!(std::fs::read_to_string(home.join("claude-stdin")).unwrap(), evil);
        let args = std::fs::read_to_string(home.join("claude-args")).unwrap();
        assert!(args.starts_with("-p\n--dangerously-skip-permissions\n") && args.contains("--model\nopus\n") && !args.contains("pwned"), "{args}");
        assert!(out.contains("pavilion: new branch task/fix-flaky from main") && out.contains("pavilion: pushed: yes"), "{out}");
        let r = parse_result(&out);
        assert_eq!((r.summary.as_str(), r.branch.as_deref(), r.pushed.as_deref()), ("Added a note.\nChecked nothing else.", Some("task/fix-flaky"), Some("yes")), "{out}");
        assert!(r.diff_stat.contains("NOTES.md") && r.diff_stat.contains("1 file changed"), "{out}");
        // Pushed to the task branch, with a message naming the task and who asked; the base is untouched.
        let log = git(&origin, &["log", "-1", "--format=%s%n%b", "task/fix-flaky"]);
        assert!(log.starts_with("task/fix-flaky: Add a note. $(touch") && log.contains("Requested by Bruno."), "{log}");
        assert_eq!(git(&origin, &["rev-list", "--count", "main"]).trim(), "1");
        // The same task again, in the same (warm) folder: fetched, carried on, a second commit on the branch.
        let (code, out) = run();
        assert_eq!(code, 0, "{out}");
        assert!(out.contains("pavilion: fetching") && !out.contains("new branch"), "{out}");
        assert_eq!(git(&origin, &["rev-list", "--count", "task/fix-flaky"]).trim(), "3");
        // The heads it fetched, and the head it pushed (WORK-ROUTING §12).
        let (main1, task1) = (git(&origin, &["rev-parse", "main"]).trim().to_string(), git(&origin, &["rev-parse", "task/fix-flaky"]).trim().to_string());
        let r = parse_result(&out);
        assert_eq!(r.head.as_deref(), Some(task1.as_str()), "{out}");
        assert_eq!(r.heads.as_ref().map(|h| h.0.as_str()), Some(main1.as_str()), "{out}");
        // Resumed with the heads it was paused on, unchanged: it runs.
        let mut resumed = a.clone();
        resumed.expect = Some((Some(main1.clone()), Some(task1.clone())));
        let (code, out) = run_job(&resumed);
        assert_eq!(code, 0, "{out}");
        let task2 = git(&origin, &["rev-parse", "task/fix-flaky"]).trim().to_string();
        // Someone pushes to main meanwhile: a resume that expected the old main stops before Claude Code, and says why.
        std::fs::write(seed.join("README.md"), "hello again\n").unwrap();
        git(&seed, &["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-am", "second"]);
        git(&seed, &["push", "-q", origin.to_str().unwrap(), "main"]);
        let _ = std::fs::remove_file(home.join("claude-stdin"));
        resumed.expect = Some((Some(main1.clone()), Some(task2.clone())));
        let (code, out) = run_job(&resumed);
        assert_eq!(code, WORLD_MOVED_EXIT, "{out}");
        assert!(out.contains("the repository moved while this work was paused") && !home.join("claude-stdin").exists(), "{out}");
        let main2 = git(&origin, &["rev-parse", "main"]).trim().to_string();
        assert_eq!(parse_result(&out).heads, Some((main2, Some(task2.clone()))), "{out}");
        assert_eq!(git(&origin, &["rev-parse", "task/fix-flaky"]).trim(), task2, "nothing pushed");
        let _ = std::fs::remove_dir_all(&t);
    }
}
