// Agent-email existing-organization flow.
//
// Use this when the human email already has an AgentMail organization. The
// caller supplies an org-level AgentMail API key once; KYA creates a new inbox,
// returns an inbox-scoped read key, sends a KYA OTP to the inbox, then the agent
// confirms that OTP to write `agent_email_claim` with proof_strength=inbox_control.

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

static USERNAME_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-z0-9][a-z0-9._-]{0,62}$").expect("username regex"));
static CODE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[0-9]{6}$").expect("code regex"));

#[derive(Parser, Debug)]
pub struct Args {
    #[arg(long, default_value = "")]
    pub agent: String,
    /// New AgentMail username — becomes `<username>@agentmail.to`.
    #[arg(long, default_value = "")]
    pub username: String,
    /// Existing AgentMail organization API key. Reads AGENTMAIL_API_KEY when omitted.
    #[arg(long, env = "AGENTMAIL_API_KEY", default_value = "")]
    pub agentmail_api_key: String,
    /// 6-digit KYA OTP delivered to the newly created AgentMail inbox.
    #[arg(long, default_value = "")]
    pub code: String,
    /// Stop after creating the inbox and write a local state file for later confirm.
    #[arg(long)]
    pub prepare_only: bool,
    /// Resume a prepared existing-org flow from a local state file and confirm with --code.
    #[arg(long, default_value = "")]
    pub state: String,
    /// Skip the post-confirm attestation poll.
    #[arg(long)]
    pub no_poll: bool,
    #[arg(long, default_value_t = 60)]
    pub poll_timeout: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct ExistingOrgState {
    agent_address: String,
    username: String,
    inbox_email: String,
    inbox_id: String,
    inbox_api_key: String,
    api_base: String,
    chain_id: u64,
    prepared_at: u64,
}

pub fn run(ctx: &Ctx, args: Args) -> Result<()> {
    if !args.state.trim().is_empty() {
        return run_confirm_from_state(ctx, &args);
    }

    let agent = resolve_agent(ctx, &args.agent)?;
    let username = resolve_username(&args)?;
    let org_key = resolve_agentmail_api_key(&args)?;
    output::info(
        "agent resolved",
        json!({
            "agent": &agent,
            "chain_id": ctx.chain_id,
            "agent_email": format!("{username}@agentmail.to"),
        }),
    );

    let (sig1, ts1, n1) = sign_action(ctx, "agent_email_existing_org_prepare", &agent)?;
    let prepared = client::agent_email_existing_org_prepare(
        &ctx.api_base,
        &agent,
        &username,
        &org_key,
        signed(&sig1, ts1, &n1),
    )?;
    let inbox_email = required_str(&prepared, "inbox_email")?;
    let inbox_id = required_str(&prepared, "inbox_id")?;
    let inbox_api_key = required_str(&prepared, "inbox_api_key")?;
    output::step(
        "prepare.ok",
        json!({
            "inbox_email": &inbox_email,
            "inbox_id": &inbox_id,
            "expires_at": prepared.get("expires_at"),
            "resend_available_at": prepared.get("resend_available_at"),
            "otp_channel": "agentmail_inbox",
            "note": "KYA returned an inbox-scoped AgentMail key; keep it only long enough to read the OTP.",
        }),
    );

    if args.prepare_only {
        let state = ExistingOrgState {
            agent_address: agent.clone(),
            username: username.clone(),
            inbox_email: inbox_email.clone(),
            inbox_id: inbox_id.clone(),
            inbox_api_key,
            api_base: ctx.api_base.clone(),
            chain_id: ctx.chain_id,
            prepared_at: crate::eip712::now_unix_seconds(),
        };
        let path = write_state_file(&state)?;
        let next_command = format!(
            "kya-agent agent-email-existing-org --state {} --code <6-digit-otp>",
            shell_quote(&path),
        );
        output::ok(
            json!({
                "agent_address": &agent,
                "inbox_email": &inbox_email,
                "inbox_id": &inbox_id,
                "state_path": path.to_string_lossy(),
                "note": "OTP sent to the new AgentMail inbox. The local state file contains an inbox-scoped AgentMail key and will be deleted after confirm.",
            }),
            "wait_for_otp",
            Some(&next_command),
        );
        return Ok(());
    }

    let code = resolve_code(&args)?;
    confirm_inbox_otp(ctx, &agent, &inbox_email, &code, args.no_poll, args.poll_timeout)
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
        "resuming prepared existing-org agent-email flow",
        json!({
            "agent": &state.agent_address,
            "inbox_email": &state.inbox_email,
            "prepared_at": state.prepared_at,
        }),
    );
    let res = confirm_inbox_otp(
        ctx,
        &state.agent_address,
        &state.inbox_email,
        &code,
        args.no_poll,
        args.poll_timeout,
    );
    if res.is_ok() {
        let _ = fs::remove_file(&path);
    }
    res
}

fn confirm_inbox_otp(
    ctx: &Ctx,
    agent: &str,
    inbox_email: &str,
    code: &str,
    no_poll: bool,
    poll_timeout: u64,
) -> Result<()> {
    let (sig2, ts2, n2) = sign_action(ctx, "agent_email_inbox_otp_confirm", agent)?;
    let confirmed = client::agent_email_inbox_otp_confirm(
        &ctx.api_base,
        agent,
        inbox_email,
        code,
        signed(&sig2, ts2, &n2),
    )?;
    let attestation_id = required_str(&confirmed, "attestation_id")?;
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
            &ctx.api_base,
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

    output::ok(
        json!({
            "agent_address": agent,
            "attestation_id": &attestation_id,
            "status": final_status,
            "proof_strength": "inbox_control",
            "inbox_email": inbox_email,
            "timed_out": timed_out,
        }),
        "ready",
        None,
    );
    Ok(())
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
        let _ = write!(stdout(), "New agentmail username (<name>@agentmail.to): ");
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
            format!("username must be 1-63 chars of [a-z0-9._-] starting with alnum, got {raw:?}"),
        ));
    }
    Ok(raw)
}

fn resolve_agentmail_api_key(args: &Args) -> Result<String> {
    let raw = args.agentmail_api_key.trim().to_string();
    if !raw.is_empty() {
        return Ok(raw);
    }
    if !stdin_is_tty() {
        return Err(KyaError::new(
            ErrorKind::InputRequired,
            "agentmail API key required (pass --agentmail-api-key or set AGENTMAIL_API_KEY)",
        ));
    }
    let _ = write!(stdout(), "AgentMail organization API key: ");
    let _ = stdout().flush();
    let mut buf = String::new();
    std::io::stdin()
        .read_line(&mut buf)
        .map_err(|e| KyaError::new(ErrorKind::Internal, format!("stdin: {e}")))?;
    let key = buf.trim().to_string();
    if key.is_empty() {
        return Err(KyaError::new(
            ErrorKind::InputRequired,
            "agentmail API key cannot be empty",
        ));
    }
    Ok(key)
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
            "read the latest KYA OTP from the new AgentMail inbox",
            json!({ "note": "Use the inbox-scoped key from prepare output/state or your AgentMail console." }),
        );
        let _ = write!(stdout(), "Inbox OTP (6 digits): ");
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

fn required_str(v: &serde_json::Value, key: &str) -> Result<String> {
    v.get(key)
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .ok_or_else(|| KyaError::new(ErrorKind::KyaError, format!("response missing {key}: {v}")))
}

fn write_state_file(state: &ExistingOrgState) -> Result<PathBuf> {
    let mut dir = std::env::temp_dir();
    dir.push("kya-agent");
    fs::create_dir_all(&dir)?;
    let filename = format!(
        "agent-email-existing-org-{}-{}-{}.json",
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

fn read_state_file(path: &Path) -> Result<ExistingOrgState> {
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
