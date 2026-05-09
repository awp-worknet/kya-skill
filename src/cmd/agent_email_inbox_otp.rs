// Agent-email "inbox-OTP" flow (right card).
//
// Upgrades an existing agent_email_claim from `signup_only` to
// `inbox_control`, or creates one fresh for a user who already owns an
// `*@agentmail.to` inbox out-of-band. KYA sends a 6-digit code to the inbox;
// the agent (holding the agentmail API key) must read it and return it.
//
// Two signs sandwich the OTP:
//   1. agent_email_inbox_otp_prepare — KYA generates code, delivers to inbox.
//   2. agent_email_inbox_otp_confirm — agent posts the code back. KYA writes
//      or upserts the attestation with proof_strength=inbox_control.

use super::{poll_attestation, resolve_agent, sign_action, signed, stdin_is_tty, Ctx};
use crate::agentmail;
use crate::client;
use crate::error::{ErrorKind, KyaError, Result};
use crate::output;
use clap::Parser;
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::json;
use std::io::{stdout, Write};
use std::time::Duration;

static AGENTMAIL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[a-z0-9][a-z0-9\-]{1,30}[a-z0-9]@agentmail\.to$").expect("agentmail regex")
});
static CODE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[0-9]{6}$").expect("code regex"));

#[derive(Parser, Debug)]
pub struct Args {
    #[arg(long, default_value = "")]
    pub agent: String,
    /// The `*@agentmail.to` inbox the agent controls. Required when piped.
    #[arg(long, default_value = "")]
    pub inbox_email: String,
    /// 6-digit code KYA delivered to the inbox. Required when piped.
    #[arg(long, default_value = "")]
    pub code: String,
    /// Local AgentMail key JSON saved by `agent-email-onboard`.
    #[arg(long, default_value = "")]
    pub key_file: String,
    /// AgentMail API key. Prefer AGENTMAIL_API_KEY over passing secrets in argv.
    #[arg(long, env = "AGENTMAIL_API_KEY", default_value = "")]
    pub api_key: String,
    /// AgentMail inbox_id. Optional when the key can list inboxes.
    #[arg(long, env = "AGENTMAIL_INBOX_ID", default_value = "")]
    pub inbox_id: String,
    /// AgentMail API base URL.
    #[arg(long, env = "AGENTMAIL_API_BASE", default_value = "")]
    pub agentmail_api_base: String,
    /// Disable automatic AgentMail inbox polling and prompt/pass --code instead.
    #[arg(long)]
    pub no_auto_read: bool,
    /// How long to wait for the KYA OTP to appear in AgentMail.
    #[arg(long, default_value_t = 60)]
    pub mail_poll_timeout: u64,
    /// Skip the post-confirm attestation poll.
    #[arg(long)]
    pub no_poll: bool,
    #[arg(long, default_value_t = 60)]
    pub poll_timeout: u64,
}

pub fn run(ctx: &Ctx, args: Args) -> Result<()> {
    let agent = resolve_agent(ctx, &args.agent)?;
    let inbox_email = resolve_inbox_email(&args)?;
    output::info(
        "agent resolved",
        json!({
            "agent": &agent,
            "chain_id": ctx.chain_id,
            "inbox_email": &inbox_email,
        }),
    );

    // Stage 1 — inbox-otp/prepare: KYA emails the code.
    let (sig1, ts1, n1) = sign_action(ctx, "agent_email_inbox_otp_prepare", &agent)?;
    let prepared = client::agent_email_inbox_otp_prepare(
        &ctx.api_base,
        &agent,
        &inbox_email,
        signed(&sig1, ts1, &n1),
    )?;
    output::step(
        "prepare.ok",
        json!({
            "inbox_email": &inbox_email,
            "expires_at": prepared.get("expires_at"),
            "resend_available_at": prepared.get("resend_available_at"),
        }),
    );

    // Stage 2 — read code from the inbox. Prefer AgentMail API credentials;
    // keep --code/TTY input as the fallback for operators without a saved key.
    let code = resolve_code(&agent, &inbox_email, &args)?;

    // Stage 3 — inbox-otp/confirm: agent returns the code.
    let (sig2, ts2, n2) = sign_action(ctx, "agent_email_inbox_otp_confirm", &agent)?;
    let confirmed = client::agent_email_inbox_otp_confirm(
        &ctx.api_base,
        &agent,
        &inbox_email,
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
            format!("unexpected inbox-otp/confirm response: {confirmed}"),
        ));
    }
    output::step(
        "confirm.ok",
        json!({
            "attestation_id": &attestation_id,
            "proof_strength": "inbox_control",
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
        "proof_strength": "inbox_control",
        "inbox_email": &inbox_email,
        "otp_source": if args.code.trim().is_empty() && !args.no_auto_read {
            "agentmail_or_prompt"
        } else {
            "manual"
        },
        "timed_out": timed_out,
    });
    output::ok(body, "ready", None);
    Ok(())
}

fn resolve_inbox_email(args: &Args) -> Result<String> {
    let raw = args.inbox_email.trim().to_lowercase();
    let raw = if raw.is_empty() {
        if !stdin_is_tty() {
            return Err(KyaError::new(
                ErrorKind::InputRequired,
                "inbox_email required (pass --inbox-email <addr>@agentmail.to)",
            ));
        }
        let _ = write!(stdout(), "Your agentmail inbox (*@agentmail.to): ");
        let _ = stdout().flush();
        let mut buf = String::new();
        std::io::stdin()
            .read_line(&mut buf)
            .map_err(|e| KyaError::new(ErrorKind::Internal, format!("stdin: {e}")))?;
        buf.trim().to_lowercase()
    } else {
        raw
    };
    if !AGENTMAIL_RE.is_match(&raw) {
        return Err(KyaError::new(
            ErrorKind::EmailInvalid,
            format!("inbox_email must be a valid *@agentmail.to address, got {raw:?}"),
        ));
    }
    Ok(raw)
}

fn resolve_code(agent: &str, inbox_email: &str, args: &Args) -> Result<String> {
    let raw = args.code.trim().to_string();
    if !raw.is_empty() {
        return validate_code(raw);
    }

    if !args.no_auto_read {
        if let Some(creds) = agentmail::resolve_credentials(
            agent,
            inbox_email,
            &args.key_file,
            &args.api_key,
            &args.inbox_id,
            &args.agentmail_api_base,
        )? {
            output::info(
                "reading KYA OTP from AgentMail inbox",
                json!({
                    "inbox_email": inbox_email,
                    "inbox_id": &creds.inbox_id,
                    "credential_source": &creds.source,
                }),
            );
            match agentmail::read_latest_kya_otp(
                &creds,
                Duration::from_secs(args.mail_poll_timeout),
                Duration::from_secs(3),
            ) {
                Ok(code) => return validate_code(code),
                Err(err) if stdin_is_tty() => {
                    output::info(
                        "AgentMail auto-read failed; falling back to manual OTP input",
                        json!({ "error": err.to_string() }),
                    );
                }
                Err(err) => return Err(err),
            }
        }
    }

    if !stdin_is_tty() {
        return Err(KyaError::new(
            ErrorKind::InputRequired,
            "code required in non-interactive mode unless AgentMail credentials are available (pass --code, --key-file, or AGENTMAIL_API_KEY)",
        ));
    }
    output::info(
        "read the latest KYA OTP from your agentmail inbox",
        json!({ "note": "codes expire in ~10 minutes; 5 wrong attempts invalidate the code" }),
    );
    let _ = write!(stdout(), "Inbox OTP (6 digits): ");
    let _ = stdout().flush();
    let mut buf = String::new();
    std::io::stdin()
        .read_line(&mut buf)
        .map_err(|e| KyaError::new(ErrorKind::Internal, format!("stdin: {e}")))?;
    validate_code(buf.trim().to_string())
}

fn validate_code(raw: String) -> Result<String> {
    if !CODE_RE.is_match(&raw) {
        return Err(KyaError::new(
            ErrorKind::EmailCodeInvalid,
            format!("code must be exactly 6 digits, got {raw:?}"),
        ));
    }
    Ok(raw)
}
