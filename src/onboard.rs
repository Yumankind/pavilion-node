//! Onboarding on the machine (docs/ONBOARDING.md §5, §6):
//!
//!   pavilion-node join <CODE> [--gate <url>]   the eight characters from the console (or its QR); the code is exchanged
//!                                              for a one-time machine link, then the existing join runs (main.rs join_with)
//!   pavilion-node join <link>                  the link from Machines › Add a machine (`https://<gate>/m/<pavilion>/…`),
//!                                              straight to the join; with no argument either one is read from the terminal
//!   pavilion-node login claude|codex [label]    the same as `pavilion-node accounts add` (it says so): plan logins stay
//!                                              on your machine, and the pavilion's vault holds API keys only. Until
//!                                              21 Nov 2026 this sent the plan's token to the vault; that path is retired
//!                                              (docs/ONBOARDING.md §6, docs/SECRETS.md)
//!
//! The plan token is never printed and never copied by hand. `claude setup-token` prints it, wrapped across lines in a
//! terminal; the lines that hold it are replaced on screen and joined here (Redactor), and accounts.rs keeps it.
use anyhow::{anyhow, bail, Result};
use serde_json::{json, Value};
use zeroize::Zeroizing;

pub const DEFAULT_GATE: &str = "https://cloudpavilion.net";
/// What stands where the token was on screen: a slot's token never leaves this machine (21 Nov 2026: the slot's sign-in
/// said "sent to the vault", which was not true; the vault path itself is retired since).
pub(crate) const SLOT_PLACEHOLDER: &str = "[the token — kept on this machine only, not shown here]";

/* ---------------------------------------------------------------- pairing codes */

/// The eight characters of a typed or scanned code (gate/src/onboarding.ts normPairCode): any case, spaces and dashes
/// dropped, O read as 0 and I or L as 1 (Crockford's base32), a pasted `…/pair/<code>` link read too.
pub fn norm_code(raw: &str) -> Option<String> {
    let mut t = raw.trim().to_string();
    if let Some(i) = t.rfind("/pair/").or_else(|| t.rfind("/pair#")) { t = t[i + 6..].to_string(); }
    let t: String = t.chars().filter(|c| !c.is_whitespace() && *c != '-').map(|c| match c.to_ascii_uppercase() { 'O' => '0', 'I' | 'L' => '1', c => c }).collect();
    let ok = t.len() == 8 && t.chars().all(|c| c.is_ascii_digit() || (c.is_ascii_uppercase() && !matches!(c, 'I' | 'L' | 'O' | 'U')));
    ok.then_some(t)
}

/// `--gate <url>`, else PAVILION_GATE, else production; a pasted `https://<gate>/pair/<code>` link names its own Gate.
pub fn gate_for(args: &[String], code_arg: &str) -> String {
    if let Some(i) = args.iter().position(|a| a == "--gate") { if let Some(g) = args.get(i + 1) { return g.trim_end_matches('/').to_string(); } }
    if let Some(i) = code_arg.find("/pair") { if code_arg.starts_with("http") { return code_arg[..i].trim_end_matches('/').to_string(); } }
    std::env::var("PAVILION_GATE").ok().filter(|g| !g.is_empty()).map(|g| g.trim_end_matches('/').to_string()).unwrap_or_else(|| DEFAULT_GATE.into())
}

/// The contract's refusals, in words for the person at the machine.
fn pair_refusal(status: u16, v: &Value) -> String {
    match v["error"].as_str().unwrap_or("") {
        "invalid_code" => "that code doesn't exist. Get a code in the console (Machines › Pair a machine) and type it again".into(),
        "code_expired" => "that code has ended or was already used: a code works once, for ten minutes. Get a new one in the console".into(),
        "too_many_attempts" => format!("too many tries from here; wait {} seconds", v["retryAfterS"].as_u64().unwrap_or(600)),
        e if !e.is_empty() => e.to_string(),
        _ => format!("the Gate answered {status}"),
    }
}

/* ---------------------------------------------------------------- what `join` was given */

/// What `pavilion-node join` was given: a pairing code (Machines › Pair a machine, or its `…/pair/<CODE>` link), or the
/// one-time machine link from Machines › Add a machine (`https://<gate>/m/<pavilion>/<token>`). 21 Nov 2026: the link
/// as an argument was refused as "not a pairing code"; only the pasted form took it.
#[derive(Debug, PartialEq)]
pub enum JoinWith {
    Code(String),
    Link { gate: String, pavilion: String, token: String },
}

/// Anything else, naming both forms.
pub const NOT_JOINABLE: &str = "that isn't a pairing code or a machine link. Give either the code from Machines › Pair a \
machine (eight letters and digits, like K7QM-2XPA) or the link from Machines › Add a machine (https://…/m/<pavilion>/…)";
const LINK_CUT: &str = "that machine link is cut short or has extra characters in it. Copy it again from Machines › Add a \
machine: it ends in a 43-character code after the pavilion's name";

fn unwrap_paste(raw: &str) -> &str { raw.trim().trim_matches(|c| matches!(c, '"' | '\'' | '<' | '>')).trim() }

/// Reads a code or a machine link, with or without the quotes or angle brackets a paste can bring.
pub fn join_target(raw: &str) -> Result<JoinWith, &'static str> {
    let t = unwrap_paste(raw);
    if let Ok(u) = reqwest::Url::parse(t).map_err(|_| ()).and_then(|u| if matches!(u.scheme(), "http" | "https") && u.host_str().is_some() { Ok(u) } else { Err(()) }) {
        // `/m/<pavilion>/<token>` in the path, or after `#` (a console that routes by fragment).
        let segs: Vec<&str> = u.path_segments().map(|s| s.filter(|x| !x.is_empty()).collect()).unwrap_or_default();
        let frag: Vec<&str> = u.fragment().unwrap_or("").split('/').filter(|x| !x.is_empty()).collect();
        let parts = if segs.first() == Some(&"m") { segs } else if frag.first() == Some(&"m") { frag } else { vec![] };
        if !parts.is_empty() {
            let pav_ok = |p: &str| { let b = p.as_bytes(); !b.is_empty() && b.len() <= 63 && b[0].is_ascii_alphanumeric() && p.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') };
            let token_ok = |s: &str| s.len() == 43 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
            if parts.len() != 3 || !pav_ok(parts[1]) || !token_ok(parts[2]) { return Err(LINK_CUT); }
            let origin = format!("{}://{}{}", u.scheme(), u.host_str().unwrap_or_default(), u.port().map(|p| format!(":{p}")).unwrap_or_default());
            return Ok(JoinWith::Link { gate: origin, pavilion: parts[1].into(), token: parts[2].into() });
        }
        // Any other link: only `…/pair/<CODE>` is something to join with.
        if !t.contains("/pair") { return Err(NOT_JOINABLE); }
    }
    norm_code(t).map(JoinWith::Code).ok_or(NOT_JOINABLE)
}

/// `pavilion-node join [<CODE>|<link>] [--gate <url>]`. With nothing, the code or link is read from the terminal (so it
/// lands in neither `ps` nor the shell's history); a link is spent at its first use either way.
pub async fn join(args: &[String]) -> Result<()> {
    let raw = match args.first().filter(|a| *a != "--gate") {
        Some(a) => a.clone(),
        None => {
            eprint!("Paste the link from Machines › Add a machine, or type the pairing code (it isn't shown or saved): ");
            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;
            line
        }
    };
    match join_target(&raw).map_err(|e| anyhow!(e))? {
        JoinWith::Code(code) => join_with_code(args, unwrap_paste(&raw), &code).await,
        JoinWith::Link { gate, pavilion, token } => {
            // The link names its own Gate; a different --gate would join somewhere the person didn't mean.
            if let Some(g) = args.iter().position(|a| a == "--gate").and_then(|i| args.get(i + 1)) {
                if g.trim_end_matches('/') != gate { bail!("the link is for {gate}, but --gate says {}. Leave out --gate: a machine link names its own Gate", g.trim_end_matches('/')); }
            }
            crate::join_with(&gate, &pavilion, &token, "machine").await
        }
    }
}

/// A pairing code, exchanged at the Gate for a one-time machine link, then the existing join.
async fn join_with_code(args: &[String], raw: &str, code: &str) -> Result<()> {
    let gate = gate_for(args, raw);
    let http = reqwest::Client::new();
    let r = http.post(format!("{gate}/pair")).json(&json!({ "code": code })).send().await.map_err(|e| anyhow!("couldn't reach {gate}: {e}"))?;
    let status = r.status().as_u16();
    let v: Value = r.json().await.unwrap_or(json!({}));
    if status != 200 || v.get("error").is_some() { bail!("{}", pair_refusal(status, &v)); }
    let (pavilion, token) = (v["pavilion"].as_str().unwrap_or_default().to_string(), v["token"].as_str().unwrap_or_default().to_string());
    if pavilion.is_empty() || token.len() != 43 { bail!("the Gate's answer had no machine link; nothing was joined"); }
    eprintln!("The code is good: joining {pavilion} as \"{}\".", v["name"].as_str().unwrap_or("machine"));
    // The Gate we asked, never one the answer names: the link is for this Gate.
    crate::join_with(&gate, &pavilion, &token, v["name"].as_str().unwrap_or("machine")).await
}

/* ---------------------------------------------------------------- the token on screen */

/// Removes terminal escapes (CSI `ESC [ … final`, OSC `ESC ] … BEL|ST`, and two-byte `ESC x`).
pub fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c != '\u{1b}' { if c != '\r' { out.push(c); } continue; }
        match it.next() {
            Some('[') => { for d in it.by_ref() { if ('\u{40}'..='\u{7e}').contains(&d) { break; } } }
            Some(']') => { while let Some(d) = it.next() { if d == '\u{7}' { break; } if d == '\u{1b}' { it.next(); break; } } }
            _ => {}
        }
    }
    out
}

const TOKEN_START: &str = "sk-ant-";
fn token_char(c: char) -> bool { c.is_ascii_alphanumeric() || c == '-' || c == '_' }

/// Reads a CLI's output as it streams: what may be shown, with every line holding the token replaced; the token's
/// pieces joined (setup-token wraps it across lines, docs/SPIKE.md L11).
#[derive(Default)]
pub struct Redactor {
    line: String,
    shown: usize,
    in_token: bool,
    said: bool,
    token: Zeroizing<String>,
    found: bool,
    /// What replaces the token's first line: SLOT_PLACEHOLDER unless a caller names its own (None: the default).
    placeholder: Option<&'static str>,
}

impl Redactor {
    /// Feeds output; returns what can be shown now.
    pub fn feed(&mut self, chunk: &str) -> String {
        let mut out = String::new();
        for c in chunk.chars() {
            if c == '\n' { let l = std::mem::take(&mut self.line); out.push_str(&self.complete(&l)); self.shown = 0; } else { self.line.push(c); }
        }
        // A line still being written (a prompt, a URL to open) is shown as far as it can't be the start of a token.
        if !self.in_token {
            let clean = strip_ansi(&self.line);
            if !clean.contains(TOKEN_START) {
                let hold = (1..=TOKEN_START.len().min(clean.len())).rev().find(|n| clean.ends_with(&TOKEN_START[..*n])).unwrap_or(0);
                let upto = clean.len() - hold;
                if upto > self.shown { out.push_str(&clean[self.shown..upto]); self.shown = upto; }
            }
        }
        out
    }
    pub fn finish(&mut self) -> String { let l = std::mem::take(&mut self.line); let o = self.complete(&l); o.trim_end_matches('\n').to_string() }
    fn complete(&mut self, raw: &str) -> String {
        let clean = strip_ansi(raw);
        let rest = |s: &str, n: usize| -> String { if n < s.len() { s[n..].to_string() } else { String::new() } };
        if let Some(pos) = clean.find(TOKEN_START) {
            let run: String = clean[pos..].chars().take_while(|c| token_char(*c)).collect();
            if !self.found { self.token.push_str(&run); }
            // The token reaching the end of the line may go on on the next one.
            self.in_token = !self.found && pos + run.len() == clean.trim_end().len();
            if !self.in_token { self.found = true; }
            let before = if self.shown <= pos { clean[self.shown..pos].to_string() } else { String::new() };
            let after = clean[pos + run.len()..].to_string();
            let place = if self.said { "[the token]" } else { self.said = true; self.placeholder.unwrap_or(SLOT_PLACEHOLDER) };
            return format!("{before}{place}{after}\n");
        }
        if self.in_token {
            let t = clean.trim();
            if !t.is_empty() && t.chars().all(token_char) { self.token.push_str(t); return String::new(); }
            self.in_token = false;
            self.found = true;
        }
        format!("{}\n", rest(&clean, self.shown))
    }
    /// The token, once seen whole: `sk-ant-oat01-…` with nothing else in it.
    pub fn token(&self) -> Option<Zeroizing<String>> {
        let t = self.token.as_str();
        (t.starts_with("sk-ant-oat01-") && t.len() > 33 && t.chars().all(token_char)).then(|| Zeroizing::new(t.to_string()))
    }
}

/* ---------------------------------------------------------------- the providers' own logins */

/// `claude setup-token`, saying `placeholder` where the token was.
pub(crate) async fn run_claude_saying(placeholder: &'static str) -> Result<Zeroizing<String>> {
    use tokio::io::AsyncReadExt;
    use std::io::Write;
    let mut child = tokio::process::Command::new("claude").arg("setup-token")
        .stdin(std::process::Stdio::inherit()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::inherit())
        .spawn().map_err(|e| anyhow!("couldn't run `claude setup-token` ({e}). Install Claude Code on this machine first"))?;
    let mut out = child.stdout.take().ok_or_else(|| anyhow!("no output from claude"))?;
    let (mut red, mut carry, mut buf) = (Redactor { placeholder: Some(placeholder), ..Redactor::default() }, Vec::<u8>::new(), vec![0u8; 4096]);
    loop {
        let n = out.read(&mut buf).await?;
        if n == 0 { break; }
        carry.extend_from_slice(&buf[..n]);
        let valid = match std::str::from_utf8(&carry) { Ok(s) => s.len(), Err(e) => e.valid_up_to() };
        let text = String::from_utf8_lossy(&carry[..valid]).to_string();
        carry.drain(..valid);
        let show = red.feed(&text);
        eprint!("{show}");
        let _ = std::io::stderr().flush();
    }
    carry.iter_mut().for_each(|b| *b = 0);
    eprintln!("{}", red.finish());
    let status = child.wait().await?;
    if !status.success() { bail!("`claude setup-token` stopped ({status}); nothing was kept"); }
    red.token().ok_or_else(|| anyhow!("`claude setup-token` finished without printing a token this program could read; nothing was kept"))
}

/* ---------------------------------------------------------------- pavilion-node login */

/// What `pavilion-node login` says now, before it does what `accounts add` does.
pub const LOGIN_IS_ACCOUNTS_ADD: &str = "pavilion-node login is now the same as pavilion-node accounts add: plan logins stay on your machine, \
and the pavilion's vault holds API keys only. Signing in here as an account slot.";

/// `pavilion-node login claude|codex [label]`: the same as `accounts add`, and says so. The label defaults to `personal`.
pub fn login_args(args: &[String]) -> Result<Vec<String>> {
    let provider = match args.first().map(String::as_str) { Some(p @ ("claude" | "codex" | "gemini")) => p.to_string(),
        _ => bail!("usage: pavilion-node login claude|codex|gemini [label]   (the same as pavilion-node accounts add)") };
    Ok(vec!["add".into(), provider, args.get(1).cloned().unwrap_or_else(|| "personal".into())])
}
pub async fn login(args: &[String]) -> Result<()> {
    let add = login_args(args)?;
    eprintln!("\n  {LOGIN_IS_ACCOUNTS_ADD}");
    crate::accounts::cli(&add).await
}

#[cfg(test)]
mod tests {
    use super::*;
    const FAKE: &str = "sk-ant-oat01-Ab3_dE-fGhAb3_dE-fGhAb3_dE-fGhAb3_dE-fGhAb3_dE-fGhAb3_dE-fGh"; // made up here, never real

    #[test]
    fn codes_read_as_the_gate_reads_them() {
        assert_eq!(norm_code("K7QM-2XPA").as_deref(), Some("K7QM2XPA"));
        assert_eq!(norm_code(" k7qm 2xpa ").as_deref(), Some("K7QM2XPA"));
        assert_eq!(norm_code("O1IL-ABCD").as_deref(), Some("0111ABCD"));
        assert_eq!(norm_code("https://gate.example/pair/K7QM-2XPA").as_deref(), Some("K7QM2XPA"));
        assert_eq!(norm_code("K7QM-2XPU"), None);
        assert_eq!(norm_code("K7QM-2XP"), None);
        assert_eq!(norm_code(""), None);
    }

    #[test]
    fn the_gate_is_the_flag_then_the_link_then_production() {
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(gate_for(&a(&["K7QM-2XPA", "--gate", "http://localhost:9020/"]), "K7QM-2XPA"), "http://localhost:9020");
        assert_eq!(gate_for(&a(&["https://g.example/pair/K7QM-2XPA"]), "https://g.example/pair/K7QM-2XPA"), "https://g.example");
        if std::env::var("PAVILION_GATE").is_err() { assert_eq!(gate_for(&a(&["K7QM-2XPA"]), "K7QM-2XPA"), DEFAULT_GATE); }
    }

    /// 21 Nov 2026: `pavilion-node join 'https://staging…/m/teste/…'` was refused as "not a pairing code".
    #[test]
    fn join_takes_a_code_or_a_machine_link_and_names_both_otherwise() {
        let token = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_abcde"; // 43 characters, made up here
        assert_eq!(token.len(), 43);
        let link = |gate: &str, pav: &str| JoinWith::Link { gate: gate.into(), pavilion: pav.into(), token: token.into() };
        // Codes: with or without the dash, any case, and the console's `/pair/<CODE>` link.
        assert_eq!(join_target("K7QM-2XPA"), Ok(JoinWith::Code("K7QM2XPA".into())));
        assert_eq!(join_target("k7qm2xpa\n"), Ok(JoinWith::Code("K7QM2XPA".into())));
        assert_eq!(join_target("https://staging.cloudpavilion.net/pair/K7QM-2XPA"), Ok(JoinWith::Code("K7QM2XPA".into())));
        // Machine links: the path form, a port, the fragment form, a trailing slash, quotes and angle brackets from a paste.
        assert_eq!(join_target(&format!("https://staging.cloudpavilion.net/m/teste/{token}")), Ok(link("https://staging.cloudpavilion.net", "teste")));
        assert_eq!(join_target(&format!("http://localhost:9133/m/my-pav/{token}/")), Ok(link("http://localhost:9133", "my-pav")));
        assert_eq!(join_target(&format!("https://g.example/#/m/teste/{token}")), Ok(link("https://g.example", "teste")));
        assert_eq!(join_target(&format!("  '<https://g.example/m/teste/{token}>'\n")), Ok(link("https://g.example", "teste")));
        // A link cut short, or with something added, says so rather than "not a code".
        assert_eq!(join_target(&format!("https://g.example/m/teste/{}", &token[..40])), Err(LINK_CUT));
        assert_eq!(join_target("https://g.example/m/teste"), Err(LINK_CUT));
        assert_eq!(join_target(&format!("https://g.example/m/teste/{token}/extra")), Err(LINK_CUT));
        assert_eq!(join_target(&format!("https://g.example/m/Teste!/{token}")), Err(LINK_CUT));
        // Anything else names both forms.
        for bad in ["", "hello", "K7QM-2XP", "https://g.example/", "https://g.example/p/teste", "ftp://g.example/m/teste/x", "mailto:a@b.c"] {
            assert_eq!(join_target(bad), Err(NOT_JOINABLE), "{bad:?}");
        }
        assert!(NOT_JOINABLE.contains("K7QM-2XPA") && NOT_JOINABLE.contains("/m/<pavilion>/"));
    }

    /// 21 Nov 2026: the vault path for plan logins is retired; `login` is `accounts add`, and says so.
    #[test]
    fn login_is_accounts_add() {
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(login_args(&a(&["claude"])).unwrap(), a(&["add", "claude", "personal"]));
        assert_eq!(login_args(&a(&["codex", "work"])).unwrap(), a(&["add", "codex", "work"]));
        assert!(login_args(&a(&["gpt"])).is_err() && login_args(&[]).is_err());
        assert!(LOGIN_IS_ACCOUNTS_ADD.contains("accounts add") && LOGIN_IS_ACCOUNTS_ADD.contains("vault holds API keys only"));
    }

    #[test]
    fn refusals_are_said_in_words() {
        assert!(pair_refusal(410, &json!({"error": "code_expired"})).contains("works once"));
        assert!(pair_refusal(429, &json!({"error": "too_many_attempts", "retryAfterS": 42})).contains("42 seconds"));
        assert!(pair_refusal(400, &json!({"error": "invalid_code"})).contains("doesn't exist"));
    }

    fn run(chunks: &[&str]) -> (String, Option<String>) {
        let mut r = Redactor::default();
        let mut shown = String::new();
        for c in chunks { shown.push_str(&r.feed(c)); }
        shown.push_str(&r.finish());
        (shown, r.token().map(|t| t.to_string()))
    }

    #[test]
    fn a_token_wrapped_across_lines_is_joined_and_never_shown() {
        let out = format!("\u{1b}[32m✓ Long-lived authentication token created successfully!\u{1b}[0m\n\nYour OAuth token (valid for 1 year):\n\n{}\n{}\n{}\n\nStore this token securely.\n",
            &FAKE[..30], &FAKE[30..55], &FAKE[55..]);
        let (shown, token) = run(&[&out]);
        assert_eq!(token.as_deref(), Some(FAKE));
        assert!(!shown.contains(&FAKE[13..30]) && !shown.contains(&FAKE[30..55]) && !shown.contains(&FAKE[55..]), "{shown}");
        assert!(shown.contains(SLOT_PLACEHOLDER) && shown.contains("Store this token securely.") && shown.contains("created successfully"));
        // A slot's sign-in says the token stays here, not that it went to the vault.
        let mut slot = Redactor { placeholder: Some(SLOT_PLACEHOLDER), ..Redactor::default() };
        let fake = format!("sk-ant-oat01-{}", "Zz9_yY-xXw".repeat(10)); // made up here; never a real token
        let mut shown2 = slot.feed(&format!(" Your OAuth token (valid for 1 year):\n\n {fake}\n\n"));
        shown2.push_str(&slot.finish());
        assert!(shown2.contains(SLOT_PLACEHOLDER) && !shown2.contains("vault") && !shown2.contains(&fake), "{shown2}");
        assert_eq!(slot.token().map(|t| t.to_string()), Some(fake));
        assert!(!shown.contains('\u{1b}'));
    }

    #[test]
    fn a_token_split_across_reads_and_said_twice_is_still_hidden() {
        let out = format!("Visit https://claude.ai/oauth to sign in\nPaste code here if prompted > \n{FAKE}\n\nexport CLAUDE_CODE_OAUTH_TOKEN={FAKE}\n");
        let pieces: Vec<String> = out.as_bytes().chunks(7).map(|c| String::from_utf8_lossy(c).to_string()).collect();
        let refs: Vec<&str> = pieces.iter().map(String::as_str).collect();
        let (shown, token) = run(&refs);
        assert_eq!(token.as_deref(), Some(FAKE));
        assert!(!shown.contains(&FAKE[12..]), "{shown}");
        assert!(shown.contains("Paste code here if prompted >"), "a prompt without a newline is shown: {shown}");
        assert!(shown.contains("export CLAUDE_CODE_OAUTH_TOKEN=[the token]"));
    }

    #[test]
    fn no_token_means_nothing_to_send() {
        let (shown, token) = run(&["Error: not signed in\n"]);
        assert!(token.is_none());
        assert!(shown.contains("not signed in"));
        let (_, token) = run(&["sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789\n"]);
        assert!(token.is_none(), "an API key is not a plan token");
    }

    #[test]
    fn escapes_are_removed() {
        assert_eq!(strip_ansi("\u{1b}[1;32mok\u{1b}[0m\r"), "ok");
        assert_eq!(strip_ansi("a\u{1b}]8;;https://x\u{7}link\u{1b}]8;;\u{7}b"), "alinkb");
    }

    /// `pavilion-node login` is `accounts add` now (21 Nov 2026): against a fake `claude` and a fake `codex` on PATH,
    /// the sign-ins become slots kept on this machine — Codex's in the slot's own CODEX_HOME — and nothing goes anywhere:
    /// there is no Gate in this test, and the vault is never asked. Nothing real is ever run.
    #[cfg(unix)]
    #[test]
    fn login_keeps_the_plan_on_this_machine() {
        use std::os::unix::fs::PermissionsExt;
        let _g = crate::onboard::tests::ENV.lock().unwrap_or_else(|e| e.into_inner());
        let bin = std::env::temp_dir().join(format!("pn-login-bin-{}", std::process::id()));
        std::fs::create_dir_all(&bin).unwrap();
        // A fake claude: prints the token wrapped over three lines, as a terminal shows it.
        std::fs::write(bin.join("claude"), format!("#!/bin/sh\n[ \"$1\" = setup-token ] || exit 3\necho 'Your OAuth token (valid for 1 year):'\necho\necho '{}'\necho '{}'\necho '{}'\necho\necho 'Store this token securely.'\n", &FAKE[..30], &FAKE[30..60], &FAKE[60..])).unwrap();
        // A fake codex: writes auth.json where CODEX_HOME says, and nowhere else.
        std::fs::write(bin.join("codex"), "#!/bin/sh\n[ \"$1\" = login ] || exit 3\n[ -n \"$CODEX_HOME\" ] || exit 4\nprintf '{\"tokens\":{\"access_token\":\"a.b.c\",\"refresh_token\":\"r-fake\",\"account_id\":\"acct\"}}' > \"$CODEX_HOME/auth.json\"\necho \"$CODEX_HOME\" > \"$(dirname \"$0\")/codex-home-was\"\n").unwrap();
        for f in ["claude", "codex"] { std::fs::set_permissions(bin.join(f), std::fs::Permissions::from_mode(0o755)).unwrap(); }
        let path = std::env::var("PATH").unwrap_or_default();
        std::env::set_var("PATH", format!("{}:{path}", bin.display()));
        crate::accounts::tests::with_home(|| tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
            login(&["claude".to_string()]).await.unwrap();
            login(&["codex".to_string(), "work".to_string()]).await.unwrap();
            let r = crate::accounts::current();
            let got: Vec<(String, String, String)> = r.as_array().unwrap().iter().map(|s| (s["harness"].as_str().unwrap().into(), s["label"].as_str().unwrap().into(), s["state"].as_str().unwrap().into())).collect();
            assert_eq!(got, vec![("claude-code".into(), "personal".into(), "ready".into()), ("codex".into(), "work".into(), "ready".into())]);
            assert!(!r.to_string().contains("sk-ant") && !r.to_string().contains("r-fake"));
            let d = crate::accounts::door(r[0]["slot"].as_str().unwrap()).unwrap();
            assert_eq!(d.token.as_str(), FAKE, "the token kept here, joined, exactly as printed");
            let codex = r[1]["slot"].as_str().unwrap();
            let was = std::fs::read_to_string(bin.join("codex-home-was")).unwrap();
            assert!(was.contains("/slots/.new-") && !std::path::Path::new(was.trim()).exists(), "codex signed in into a fresh private folder of the slot's, never ~/.codex: {was}");
            assert!(crate::slot_auth::codex_auth(&crate::accounts::home_of(codex)).is_file());
        }));
        std::env::set_var("PATH", path);
        let _ = std::fs::remove_dir_all(&bin);
    }

    /// Tests that change the process's environment take turns.
    pub static ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());
}
