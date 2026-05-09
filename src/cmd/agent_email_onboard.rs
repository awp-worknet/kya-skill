// Agent-email "onboard" flow (left card).
//
// KYA-side proxies the agentmail signUp → verify-OTP dance so a user without
// an existing `*@agentmail.to` inbox can get one in one shot. The resulting
// attestation lands as `agent_email_claim` with `proof_strength=signup_only`.
// To upgrade to `inbox_control`, run `agent-email-inbox-otp` afterwards.
//
// Two signs sandwich the OTP:
//   1. agent_email_onboard_prepare — hands human_email + username to KYA,
//      which calls agentmail signUp on the agent's behalf.
//   2. agent_email_onboard_confirm — hands the OTP that landed in the human
//      email plus the api_key KYA received back from agentmail.
//
// Keep the returned api_key only in memory long enough to confirm the OTP.

use super::{poll_attestation, resolve_agent, sign_action, signed, stdin_is_tty, Ctx};
use crate::client;
use crate::error::{ErrorKind, KyaError, Result};
use crate::output;
use clap::Parser;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fs;
use std::io::{stdout, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// std-only home-dir resolver. Mirrors what `dirs::home_dir` does on the two
/// platforms we care about. Falls back to None if neither var is set so that
/// persist_org_key() degrades to a warning instead of panicking.
fn home_dir() -> Option<PathBuf> {
    if let Some(h) = std::env::var_os("HOME") {
        if !h.is_empty() {
            return Some(PathBuf::from(h));
        }
    }
    if let Some(h) = std::env::var_os("USERPROFILE") {
        if !h.is_empty() {
            return Some(PathBuf::from(h));
        }
    }
    None
}

/// Persist the AgentMail organization-level api_key returned by signUp into
/// `~/.kya/agentmail-org-key` (chmod 600 on Unix). Re-running onboard will
/// rotate the upstream key, so we always overwrite. Best-effort: any IO error
/// is downgraded to a warning step so the verify flow itself still finishes.
fn persist_org_key(api_key: &str) -> Option<PathBuf> {
    let home = home_dir()?;
    let dir = home.join(".kya");
    if let Err(e) = fs::create_dir_all(&dir) {
        output::step(
            "agent_email_onboard.org_key_persist.warn",
            json!({ "error": format!("mkdir {}: {e}", dir.display()) }),
        );
        return None;
    }
    let path = dir.join("agentmail-org-key");
    let body = format!(
        "# AgentMail organization API key — KYA agent-email onboard\n\
         # Created by kya-agent at {}.\n\
         # Treat this file like a password; deleting an inbox in console.agentmail.to\n\
         # never invalidates this key, but re-running `kya-agent agent-email-onboard`\n\
         # will rotate it.\n\
         {}\n",
        chrono_like_iso8601(crate::eip712::now_unix_seconds()),
        api_key,
    );
    if let Err(e) = overwrite_secret_file(&path, body.as_bytes()) {
        output::step(
            "agent_email_onboard.org_key_persist.warn",
            json!({ "error": format!("write {}: {e}", path.display()) }),
        );
        return None;
    }
    Some(path)
}

#[cfg(unix)]
fn overwrite_secret_file(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    if path.exists() {
        let _ = fs::remove_file(path);
    }
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    Ok(())
}

#[cfg(not(unix))]
fn overwrite_secret_file(path: &Path, bytes: &[u8]) -> Result<()> {
    if path.exists() {
        let _ = fs::remove_file(path);
    }
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)?;
    file.write_all(bytes)?;
    Ok(())
}

/// 不引 chrono crate;手搓一个能展示秒级 UTC 的 ISO8601。only used in
/// the persisted-key file header for human inspection, never parsed back.
fn chrono_like_iso8601(unix_seconds: u64) -> String {
    let days_from_epoch = unix_seconds / 86_400;
    let seconds_in_day = unix_seconds % 86_400;
    let h = seconds_in_day / 3600;
    let m = (seconds_in_day % 3600) / 60;
    let s = seconds_in_day % 60;
    let (year, month, day) = civil_from_days(days_from_epoch as i64);
    format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}Z")
}

/// days from 1970-01-01 → (year, month, day). Hinnant's algorithm.
fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = (y + if m <= 2 { 1 } else { 0 }) as i32;
    (year, m as u32, d as u32)
}

static EMAIL_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[^\s@]+@[^\s@]+\.[^\s@]+$").expect("email regex"));
static USERNAME_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-z0-9][a-z0-9\-]{1,30}[a-z0-9]$").expect("username regex"));
static CODE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[0-9]{6}$").expect("code regex"));

#[derive(Parser, Debug)]
pub struct Args {
    #[arg(long, default_value = "")]
    pub agent: String,
    /// Human email that will receive the agentmail OTP. Required when piped.
    #[arg(long, default_value = "")]
    pub human_email: String,
    /// agentmail username — becomes `<username>@agentmail.to`. Required when piped.
    #[arg(long, default_value = "")]
    pub username: String,
    /// 6-digit OTP that agentmail delivered to --human-email. Required when piped.
    #[arg(long, default_value = "")]
    pub code: String,
    /// Stop after prepare and write a local state file for a later confirm.
    #[arg(long)]
    pub prepare_only: bool,
    /// Resume a prepared onboard flow from a local state file and confirm with --code.
    #[arg(long, default_value = "")]
    pub state: String,
    /// Skip the post-confirm attestation poll.
    #[arg(long)]
    pub no_poll: bool,
    #[arg(long, default_value_t = 60)]
    pub poll_timeout: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct OnboardState {
    agent_address: String,
    human_email: String,
    username: String,
    inbox_email: String,
    api_key: String,
    api_base: String,
    chain_id: u64,
    prepared_at: u64,
}

pub fn run(ctx: &Ctx, args: Args) -> Result<()> {
    if !args.state.trim().is_empty() {
        return run_confirm_from_state(ctx, &args);
    }

    let agent = resolve_agent(ctx, &args.agent)?;
    let human_email = resolve_human_email(&args)?;
    let username = resolve_username(&args)?;
    output::info(
        "agent resolved",
        json!({
            "agent": &agent,
            "chain_id": ctx.chain_id,
            "human_email": &human_email,
            "agent_email": format!("{username}@agentmail.to"),
        }),
    );

    // Stage 1 — onboard/prepare (KYA calls agentmail signUp).
    let (sig1, ts1, n1) = sign_action(ctx, "agent_email_onboard_prepare", &agent)?;
    let prepared = client::agent_email_onboard_prepare(
        &ctx.api_base,
        &agent,
        &human_email,
        &username,
        signed(&sig1, ts1, &n1),
    )?;
    let inbox_email = prepared
        .get("inbox_email")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let api_key = prepared
        .get("api_key")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    if inbox_email.is_empty() || api_key.is_empty() {
        return Err(KyaError::new(
            ErrorKind::KyaError,
            "unexpected onboard/prepare response: missing inbox_email or api_key",
        ));
    }
    output::step(
        "prepare.ok",
        json!({
            "inbox_email": &inbox_email,
            "expires_at": prepared.get("expires_at"),
            "otp_channel": "human_email",
        }),
    );

    if args.prepare_only {
        let state = OnboardState {
            agent_address: agent.clone(),
            human_email: human_email.clone(),
            username: username.clone(),
            inbox_email: inbox_email.clone(),
            api_key,
            api_base: ctx.api_base.clone(),
            chain_id: ctx.chain_id,
            prepared_at: crate::eip712::now_unix_seconds(),
        };
        let path = write_state_file(&state)?;
        let next_command = format!(
            "kya-agent agent-email-onboard --state {} --code <6-digit-otp>",
            shell_quote(&path),
        );
        output::ok(
            json!({
                "agent_address": &agent,
                "human_email": &human_email,
                "inbox_email": &inbox_email,
                "state_path": path.to_string_lossy(),
                "note": "OTP sent to the human email. The local state file contains a short-lived AgentMail api_key and will be deleted after confirm.",
            }),
            "wait_for_otp",
            Some(&next_command),
        );
        return Ok(());
    }

    // Stage 2 — read OTP from human_email.
    let code = resolve_code(&args)?;

    // Stage 3 — onboard/confirm (KYA calls agentmail verify, writes attestation).
    let (sig2, ts2, n2) = sign_action(ctx, "agent_email_onboard_confirm", &agent)?;
    let confirmed = client::agent_email_onboard_confirm(
        &ctx.api_base,
        &agent,
        &inbox_email,
        &api_key,
        &code,
        signed(&sig2, ts2, &n2),
    )?;
    let attestation_id = confirmed
        .get("attestation_id")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    if attestation_id.is_empty() {
        return Err(KyaError::new(
            ErrorKind::KyaError,
            format!("unexpected onboard/confirm response: {confirmed}"),
        ));
    }
    output::step(
        "confirm.ok",
        json!({
            "attestation_id": &attestation_id,
            "proof_strength": "signup_only",
            "status": confirmed.get("status"),
        }),
    );

    let (final_status, timed_out) = if !args.no_poll {
        let final_att = poll_attestation(
            &ctx.api_base,
            &agent,
            &attestation_id,
            "agent_email_claim",
            Duration::from_secs(3),
            Duration::from_secs(args.poll_timeout),
        )?;
        match final_att {
            Some(att) => (
                att.get("status")
                    .and_then(|x| x.as_str())
                    .unwrap_or("pending")
                    .to_string(),
                false,
            ),
            None => (
                confirmed
                    .get("status")
                    .and_then(|x| x.as_str())
                    .unwrap_or("pending")
                    .to_string(),
                true,
            ),
        }
    } else {
        (
            confirmed
                .get("status")
                .and_then(|x| x.as_str())
                .unwrap_or("pending")
                .to_string(),
            false,
        )
    };

    let key_path = persist_org_key(&api_key);
    let body = json!({
        "agent_address": &agent,
        "attestation_id": &attestation_id,
        "status": final_status,
        "proof_strength": "signup_only",
        "inbox_email": &inbox_email,
        "agentmail_org_key": &api_key,
        "agentmail_org_key_path": key_path.as_ref().map(|p| p.to_string_lossy().to_string()),
        "save_org_key_hint": "Save this AgentMail organization API key — needed to add more inboxes or re-verify later. KYA does not store it.",
        "upgrade_hint": "run `kya-agent agent-email-inbox-otp` after wiring an AgentMail API key to your agent",
        "timed_out": timed_out,
    });
    output::ok(body, "ready", None);
    Ok(())
}

fn run_confirm_from_state(ctx: &Ctx, args: &Args) -> Result<()> {
    let path = PathBuf::from(args.state.trim());
    let state = read_state_file(&path)?;
    if ctx.chain_id != state.chain_id {
        return Err(KyaError::new(
            ErrorKind::InputRequired,
            format!(
                "state was prepared for chain_id {}, but current --chain-id is {}",
                state.chain_id, ctx.chain_id
            ),
        ));
    }
    let code = resolve_code(args)?;
    output::info(
        "resuming prepared agent-email onboard flow",
        json!({
            "agent": &state.agent_address,
            "inbox_email": &state.inbox_email,
            "prepared_at": state.prepared_at,
        }),
    );

    let (sig, ts, nonce) = sign_action(ctx, "agent_email_onboard_confirm", &state.agent_address)?;
    let confirmed = client::agent_email_onboard_confirm(
        &state.api_base,
        &state.agent_address,
        &state.inbox_email,
        &state.api_key,
        &code,
        signed(&sig, ts, &nonce),
    )?;
    let attestation_id = confirmed
        .get("attestation_id")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    if attestation_id.is_empty() {
        return Err(KyaError::new(
            ErrorKind::KyaError,
            format!("unexpected onboard/confirm response: {confirmed}"),
        ));
    }
    let _ = fs::remove_file(&path);
    output::step(
        "confirm.ok",
        json!({
            "attestation_id": &attestation_id,
            "proof_strength": "signup_only",
            "status": confirmed.get("status"),
            "state_deleted": true,
        }),
    );

    let (final_status, timed_out) = if !args.no_poll {
        let final_att = poll_attestation(
            &state.api_base,
            &state.agent_address,
            &attestation_id,
            "agent_email_claim",
            Duration::from_secs(3),
            Duration::from_secs(args.poll_timeout),
        )?;
        match final_att {
            Some(att) => (
                att.get("status")
                    .and_then(|x| x.as_str())
                    .unwrap_or("pending")
                    .to_string(),
                false,
            ),
            None => (
                confirmed
                    .get("status")
                    .and_then(|x| x.as_str())
                    .unwrap_or("pending")
                    .to_string(),
                true,
            ),
        }
    } else {
        (
            confirmed
                .get("status")
                .and_then(|x| x.as_str())
                .unwrap_or("pending")
                .to_string(),
            false,
        )
    };

    let key_path = persist_org_key(&state.api_key);
    output::ok(
        json!({
            "agent_address": &state.agent_address,
            "attestation_id": &attestation_id,
            "status": final_status,
            "proof_strength": "signup_only",
            "inbox_email": &state.inbox_email,
            "agentmail_org_key": &state.api_key,
            "agentmail_org_key_path": key_path.as_ref().map(|p| p.to_string_lossy().to_string()),
            "save_org_key_hint": "Save this AgentMail organization API key — needed to add more inboxes or re-verify later. KYA does not store it.",
            "upgrade_hint": "run `kya-agent agent-email-inbox-otp` after wiring an AgentMail API key to your agent",
            "timed_out": timed_out,
        }),
        "ready",
        None,
    );
    Ok(())
}

fn write_state_file(state: &OnboardState) -> Result<PathBuf> {
    let mut dir = std::env::temp_dir();
    dir.push("kya-agent");
    fs::create_dir_all(&dir)?;
    let filename = format!(
        "agent-email-onboard-{}-{}-{}.json",
        state.agent_address.to_lowercase(),
        state.username,
        state.prepared_at
    );
    let path = dir.join(filename);
    let bytes = serde_json::to_vec_pretty(state)?;
    write_secret_file(&path, &bytes)?;
    Ok(path)
}

#[cfg(unix)]
fn write_secret_file(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_secret_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)?;
    file.write_all(bytes)?;
    Ok(())
}

fn read_state_file(path: &Path) -> Result<OnboardState> {
    let raw = fs::read(path)?;
    serde_json::from_slice(&raw).map_err(KyaError::from)
}

fn shell_quote(path: &Path) -> String {
    let raw = path.to_string_lossy();
    if raw
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "/._:-".contains(c))
    {
        raw.to_string()
    } else {
        format!("'{}'", raw.replace('\'', "'\\''"))
    }
}

fn resolve_human_email(args: &Args) -> Result<String> {
    let raw = args.human_email.trim().to_string();
    let raw = if raw.is_empty() {
        if !stdin_is_tty() {
            return Err(KyaError::new(
                ErrorKind::InputRequired,
                "human_email required (pass --human-email <addr> in non-interactive mode)",
            ));
        }
        let _ = write!(
            stdout(),
            "Your personal email (receives the agentmail OTP): "
        );
        let _ = stdout().flush();
        let mut buf = String::new();
        std::io::stdin()
            .read_line(&mut buf)
            .map_err(|e| KyaError::new(ErrorKind::Internal, format!("stdin: {e}")))?;
        buf.trim().to_string()
    } else {
        raw
    };
    if !EMAIL_RE.is_match(&raw) {
        return Err(KyaError::new(
            ErrorKind::EmailInvalid,
            format!("invalid human_email format: {raw:?}"),
        ));
    }
    Ok(raw)
}

fn resolve_username(args: &Args) -> Result<String> {
    let raw = args.username.trim().to_lowercase();
    let raw = if raw.is_empty() {
        if !stdin_is_tty() {
            return Err(KyaError::new(
                ErrorKind::InputRequired,
                "username required (pass --username <name> in non-interactive mode)",
            ));
        }
        let _ = write!(
            stdout(),
            "Choose agentmail username (<name>@agentmail.to): "
        );
        let _ = stdout().flush();
        let mut buf = String::new();
        std::io::stdin()
            .read_line(&mut buf)
            .map_err(|e| KyaError::new(ErrorKind::Internal, format!("stdin: {e}")))?;
        buf.trim().to_lowercase()
    } else {
        raw
    };
    if !USERNAME_RE.is_match(&raw) {
        return Err(KyaError::new(
            ErrorKind::AgentmailSignupInvalidUsername,
            format!(
                "username must be 3-32 chars of [a-z0-9-], not starting/ending with '-', got {raw:?}"
            ),
        ));
    }
    Ok(raw)
}

fn resolve_code(args: &Args) -> Result<String> {
    let raw = args.code.trim().to_string();
    let raw = if raw.is_empty() {
        if !stdin_is_tty() {
            return Err(KyaError::new(
                ErrorKind::InputRequired,
                "code required in non-interactive mode (pass --code <6 digits>)",
            ));
        }
        output::info(
            "check your inbox (and spam) for a 6-digit OTP from agentmail",
            json!({
                "note": "OTP expires in ~10 minutes; re-running onboard may rotate your api_key",
            }),
        );
        let _ = write!(stdout(), "agentmail OTP (6 digits): ");
        let _ = stdout().flush();
        let mut buf = String::new();
        std::io::stdin()
            .read_line(&mut buf)
            .map_err(|e| KyaError::new(ErrorKind::Internal, format!("stdin: {e}")))?;
        buf.trim().to_string()
    } else {
        raw
    };
    if !CODE_RE.is_match(&raw) {
        return Err(KyaError::new(
            ErrorKind::EmailCodeInvalid,
            format!("code must be exactly 6 digits, got {raw:?}"),
        ));
    }
    Ok(raw)
}
