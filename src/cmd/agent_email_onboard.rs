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
// AgentMail api_key 是后续读取 inbox OTP 的唯一凭据。不要打印它，但注册成功后
// 要保存到本地受限权限文件，避免用户完成 signup_only 后无法升级 inbox_control。

use super::{poll_attestation, resolve_agent, sign_action, signed, stdin_is_tty, Ctx};
use crate::agentmail;
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
    #[serde(default)]
    inbox_id: String,
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
    let inbox_id = prepared
        .get("inbox_id")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    if inbox_email.is_empty() || inbox_id.is_empty() || api_key.is_empty() {
        return Err(KyaError::new(
            ErrorKind::KyaError,
            "unexpected onboard/prepare response: missing inbox_email, inbox_id, or api_key",
        ));
    }
    output::step(
        "prepare.ok",
        json!({
            "inbox_email": &inbox_email,
            "inbox_id": &inbox_id,
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
            inbox_id,
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
                "note": "OTP sent to the human email. The local state file contains the AgentMail api_key; confirm will save it to the local key store before deleting the state file.",
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
    let key_path =
        agentmail::save_key(&agent, &inbox_email, &inbox_id, &api_key, "", ctx.chain_id)?;
    emit_key_saved_notice(&inbox_email, &key_path);
    output::step(
        "confirm.ok",
        json!({
            "attestation_id": &attestation_id,
            "proof_strength": "signup_only",
            "status": confirmed.get("status"),
            "agentmail_key_path": key_path.to_string_lossy(),
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

    let body = json!({
        "agent_address": &agent,
        "attestation_id": &attestation_id,
        "status": final_status,
        "proof_strength": "signup_only",
        "inbox_email": &inbox_email,
        "inbox_id": &inbox_id,
        "agentmail_key_path": key_path.to_string_lossy(),
        "credential_warning": agentmail::key_warning(&inbox_email),
        "upgrade_hint": "keep the saved AgentMail key; it is required to read future inbox OTPs and upgrade to inbox_control",
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
    let key_path = agentmail::save_key(
        &state.agent_address,
        &state.inbox_email,
        &state.inbox_id,
        &state.api_key,
        "",
        state.chain_id,
    )?;
    emit_key_saved_notice(&state.inbox_email, &key_path);
    let _ = fs::remove_file(&path);
    output::step(
        "confirm.ok",
        json!({
            "attestation_id": &attestation_id,
            "proof_strength": "signup_only",
            "status": confirmed.get("status"),
            "state_deleted": true,
            "agentmail_key_path": key_path.to_string_lossy(),
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

    output::ok(
        json!({
            "agent_address": &state.agent_address,
            "attestation_id": &attestation_id,
            "status": final_status,
            "proof_strength": "signup_only",
            "inbox_email": &state.inbox_email,
            "inbox_id": &state.inbox_id,
            "agentmail_key_path": key_path.to_string_lossy(),
            "credential_warning": agentmail::key_warning(&state.inbox_email),
            "upgrade_hint": "keep the saved AgentMail key; it is required to read future inbox OTPs and upgrade to inbox_control",
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

fn emit_key_saved_notice(inbox_email: &str, path: &Path) {
    output::info(
        "IMPORTANT: AgentMail inbox key saved locally",
        json!({
            "inbox_email": inbox_email,
            "agentmail_key_path": path.to_string_lossy(),
            "warning": agentmail::key_warning(inbox_email),
        }),
    );
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
