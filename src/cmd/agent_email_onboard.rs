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
use serde_json::json;
use std::io::{stdout, Write};
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
    /// Skip the post-confirm attestation poll.
    #[arg(long)]
    pub no_poll: bool,
    #[arg(long, default_value_t = 60)]
    pub poll_timeout: u64,
}

pub fn run(ctx: &Ctx, args: Args) -> Result<()> {
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

    let body = json!({
        "agent_address": &agent,
        "attestation_id": &attestation_id,
        "status": final_status,
        "proof_strength": "signup_only",
        "inbox_email": &inbox_email,
        "upgrade_hint": "run `kya-agent agent-email-inbox-otp` after wiring an AgentMail API key to your agent",
        "timed_out": timed_out,
    });
    output::ok(body, "ready", None);
    Ok(())
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
