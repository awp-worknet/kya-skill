// Agent-email "inbox-OTP" flow (right card).
//
// Upgrades an existing agent_email_claim from `signup_only` to
// `inbox_control`, or creates one fresh for a user who already owns an
// `*@agentmail.to` inbox out-of-band. KYA sends a 6-digit code to the inbox;
// the user reads that inbox and gives the code back to the agent.
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
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fs;
use std::io::{stdout, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

static AGENTMAIL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[a-z0-9][a-z0-9._-]{0,62}@agentmail\.to$").expect("agentmail regex")
});
static CODE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[0-9]{6}$").expect("code regex"));

#[derive(Parser, Debug)]
pub struct Args {
    #[arg(long, default_value = "")]
    pub agent: String,
    /// The `*@agentmail.to` inbox the agent controls. Required when piped.
    #[arg(long, default_value = "")]
    pub inbox_email: String,
    /// 6-digit code KYA delivered to the inbox. Prompted in TTY; required when piped.
    #[arg(long, default_value = "")]
    pub code: String,
    /// Stop after prepare and write a local state file for a later confirm.
    #[arg(long)]
    pub prepare_only: bool,
    /// Resume a prepared inbox-OTP flow from a local state file and confirm with --code.
    #[arg(long, default_value = "")]
    pub state: String,
    /// Advanced: local AgentMail key JSON saved by `agent-email-onboard`, used only with --auto-read.
    #[arg(long, default_value = "")]
    pub key_file: String,
    /// Advanced: AgentMail API key, used only with --auto-read.
    #[arg(long, env = "AGENTMAIL_API_KEY", default_value = "")]
    pub api_key: String,
    /// Advanced: AgentMail inbox_id for --auto-read. Optional when the key can list inboxes.
    #[arg(long, env = "AGENTMAIL_INBOX_ID", default_value = "")]
    pub inbox_id: String,
    /// Advanced: AgentMail API base URL for --auto-read.
    #[arg(long, env = "AGENTMAIL_API_BASE", default_value = "")]
    pub agentmail_api_base: String,
    /// Advanced: try reading the OTP with a saved AgentMail key/API key.
    #[arg(long)]
    pub auto_read: bool,
    /// Deprecated alias: keep manual OTP entry even if credentials are configured.
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

#[derive(Debug, Serialize, Deserialize)]
struct InboxOtpState {
    agent_address: String,
    inbox_email: String,
    api_base: String,
    chain_id: u64,
    prepared_at: u64,
}

pub fn run(ctx: &Ctx, args: Args) -> Result<()> {
    if !args.state.trim().is_empty() {
        return run_confirm_from_state(ctx, &args);
    }

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

    // If the caller supplies a code, it must belong to an already prepared
    // challenge. Do not prepare again: that would send a fresh OTP and make
    // the supplied code stale.
    let supplied_code = args.code.trim();
    if !supplied_code.is_empty() && !args.prepare_only {
        let code = validate_code(supplied_code.to_string())?;
        return confirm_inbox_otp(
            ctx,
            &ctx.api_base,
            &agent,
            &inbox_email,
            &code,
            args.no_poll,
            args.poll_timeout,
            "manual_existing_challenge",
        );
    }

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

    if args.prepare_only || (!args.auto_read && !stdin_is_tty()) {
        let state = InboxOtpState {
            agent_address: agent.clone(),
            inbox_email: inbox_email.clone(),
            api_base: ctx.api_base.clone(),
            chain_id: ctx.chain_id,
            prepared_at: crate::eip712::now_unix_seconds(),
        };
        let path = write_state_file(&state)?;
        let next_command = format!(
            "kya-agent agent-email-inbox-otp --state {} --code <6-digit-otp>",
            shell_quote(&path),
        );
        output::ok(
            json!({
                "agent_address": &agent,
                "inbox_email": &inbox_email,
                "state_path": path.to_string_lossy(),
                "expires_at": prepared.get("expires_at"),
                "resend_available_at": prepared.get("resend_available_at"),
                "note": "OTP sent to the AgentMail inbox. Re-run the returned next_command with the code; do not start a fresh prepare.",
            }),
            "wait_for_otp",
            Some(&next_command),
        );
        return Ok(());
    }

    // Stage 2 — read code from the inbox. Manual OTP entry is the default
    // because the web flow asks users to open the AgentMail inbox themselves.
    // --auto-read remains an advanced local-only convenience for saved keys.
    let code = resolve_code(&agent, &inbox_email, &args)?;

    confirm_inbox_otp(
        ctx,
        &ctx.api_base,
        &agent,
        &inbox_email,
        &code,
        args.no_poll,
        args.poll_timeout,
        if args.auto_read && !args.no_auto_read {
            "agentmail_or_prompt"
        } else {
            "manual"
        },
    )
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
    let code = validate_code(args.code.trim().to_string())?;
    output::info(
        "resuming prepared agent-email inbox-OTP flow",
        json!({
            "agent": &state.agent_address,
            "inbox_email": &state.inbox_email,
            "prepared_at": state.prepared_at,
        }),
    );

    let result = confirm_inbox_otp(
        ctx,
        &state.api_base,
        &state.agent_address,
        &state.inbox_email,
        &code,
        args.no_poll,
        args.poll_timeout,
        "manual_state",
    );
    if result.is_ok() {
        let _ = fs::remove_file(&path);
    }
    result
}

fn confirm_inbox_otp(
    ctx: &Ctx,
    api_base: &str,
    agent: &str,
    inbox_email: &str,
    code: &str,
    no_poll: bool,
    poll_timeout: u64,
    otp_source: &str,
) -> Result<()> {
    // Stage 3 — inbox-otp/confirm: agent returns the code.
    let (sig2, ts2, n2) = sign_action(ctx, "agent_email_inbox_otp_confirm", agent)?;
    let confirmed = client::agent_email_inbox_otp_confirm(
        api_base,
        agent,
        inbox_email,
        code,
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

    let (final_status, timed_out) = if !no_poll {
        let final_att = poll_attestation(
            api_base,
            agent,
            &attestation_id,
            "agent_email_claim",
            Duration::from_secs(3),
            Duration::from_secs(poll_timeout),
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
        "agent_address": agent,
        "attestation_id": &attestation_id,
        "status": final_status,
        "proof_strength": "inbox_control",
        "inbox_email": inbox_email,
        "otp_source": otp_source,
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

    if args.auto_read && !args.no_auto_read {
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
            "code required in non-interactive mode (pass --code <6 digits>; optional auto-read requires --auto-read plus saved AgentMail credentials)",
        ));
    }
    output::info(
        "open your AgentMail inbox and paste the latest KYA OTP",
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

fn write_state_file(state: &InboxOtpState) -> Result<PathBuf> {
    let mut dir = std::env::temp_dir();
    dir.push("kya-agent");
    fs::create_dir_all(&dir)?;
    let filename = format!(
        "agent-email-inbox-otp-{}-{}.json",
        state.agent_address.to_lowercase(),
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

fn read_state_file(path: &Path) -> Result<InboxOtpState> {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn args(inbox_email: &str) -> Args {
        Args {
            agent: String::new(),
            inbox_email: inbox_email.to_string(),
            code: String::new(),
            prepare_only: false,
            state: String::new(),
            key_file: String::new(),
            api_key: String::new(),
            inbox_id: String::new(),
            agentmail_api_base: String::new(),
            auto_read: false,
            no_auto_read: false,
            mail_poll_timeout: 60,
            no_poll: false,
            poll_timeout: 60,
        }
    }

    #[test]
    fn accepts_web_agentmail_username_charset() {
        let got = resolve_inbox_email(&args("xin.agent_kya-001@agentmail.to")).unwrap();
        assert_eq!(got, "xin.agent_kya-001@agentmail.to");
    }

    #[test]
    fn rejects_non_agentmail_domain() {
        assert!(resolve_inbox_email(&args("xin.agent@example.com")).is_err());
    }
}
