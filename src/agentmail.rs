use crate::error::{ErrorKind, KyaError, Result};
use crate::output;
use once_cell::sync::Lazy;
use regex::Regex;
use reqwest::blocking::Client;
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const DEFAULT_AGENTMAIL_API_BASE: &str = "https://api.agentmail.to";

static HTTP: Lazy<Client> = Lazy::new(|| {
    Client::builder()
        .user_agent(crate::version::USER_AGENT)
        .timeout(Duration::from_secs(20))
        .build()
        .expect("agentmail reqwest client builds")
});

static OTP_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b([0-9]{6})\b").expect("otp regex"));

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentmailKeyFile {
    pub schema_version: u8,
    pub agent_address: String,
    pub inbox_email: String,
    #[serde(default)]
    pub inbox_id: String,
    pub api_key: String,
    pub api_base: String,
    pub chain_id: u64,
    pub saved_at: u64,
    pub usage: String,
}

#[derive(Debug, Clone)]
pub struct AgentmailCredentials {
    pub api_key: String,
    pub inbox_id: String,
    pub api_base: String,
    pub source: String,
}

pub fn save_key(
    agent: &str,
    inbox_email: &str,
    inbox_id: &str,
    api_key: &str,
    api_base: &str,
    chain_id: u64,
) -> Result<PathBuf> {
    let key = AgentmailKeyFile {
        schema_version: 1,
        agent_address: agent.to_string(),
        inbox_email: inbox_email.to_string(),
        inbox_id: inbox_id.to_string(),
        api_key: api_key.to_string(),
        api_base: resolve_agentmail_api_base(api_base),
        chain_id,
        saved_at: crate::eip712::now_unix_seconds(),
        usage: "Used by kya-agent to read KYA OTP messages from this AgentMail inbox. Do not paste in chat or commit."
            .to_string(),
    };
    let dir = key_dir()?;
    fs::create_dir_all(&dir)?;
    let filename = format!(
        "agentmail-key-{}-{}.json",
        safe_filename_part(&agent.to_lowercase()),
        safe_filename_part(&inbox_email.to_lowercase())
    );
    let path = dir.join(filename);
    let bytes = serde_json::to_vec_pretty(&key)?;
    write_secret_file_replace(&path, &bytes)?;
    Ok(path)
}

pub fn load_saved_key(
    agent: &str,
    inbox_email: &str,
    explicit_path: &str,
) -> Result<Option<AgentmailKeyFile>> {
    if !explicit_path.trim().is_empty() {
        return read_key_file(Path::new(explicit_path.trim())).map(Some);
    }
    if let Ok(path) = std::env::var("KYA_AGENTMAIL_KEY_FILE") {
        let trimmed = path.trim();
        if !trimmed.is_empty() {
            return read_key_file(Path::new(trimmed)).map(Some);
        }
    }

    let path = key_dir()?.join(format!(
        "agentmail-key-{}-{}.json",
        safe_filename_part(&agent.to_lowercase()),
        safe_filename_part(&inbox_email.to_lowercase())
    ));
    if path.exists() {
        return read_key_file(&path).map(Some);
    }
    Ok(None)
}

pub fn resolve_credentials(
    agent: &str,
    inbox_email: &str,
    key_file: &str,
    api_key_arg: &str,
    inbox_id_arg: &str,
    api_base_arg: &str,
) -> Result<Option<AgentmailCredentials>> {
    if let Some(saved) = load_saved_key(agent, inbox_email, key_file)? {
        if saved.api_key.trim().is_empty() {
            return Err(KyaError::new(
                ErrorKind::InputRequired,
                "AgentMail key file is missing api_key",
            ));
        }
        let api_base = resolve_agentmail_api_base(&saved.api_base);
        let inbox_id = if saved.inbox_id.trim().is_empty() {
            find_inbox_id(&api_base, &saved.api_key, inbox_email)?
        } else {
            saved.inbox_id
        };
        return Ok(Some(AgentmailCredentials {
            api_key: saved.api_key,
            inbox_id,
            api_base,
            source: "key_file".to_string(),
        }));
    }

    let api_key = first_non_empty(&[
        api_key_arg,
        &std::env::var("AGENTMAIL_API_KEY").unwrap_or_default(),
    ]);
    if api_key.is_empty() {
        return Ok(None);
    }
    let api_base = resolve_agentmail_api_base(api_base_arg);
    let inbox_id = first_non_empty(&[
        inbox_id_arg,
        &std::env::var("AGENTMAIL_INBOX_ID").unwrap_or_default(),
    ]);
    let inbox_id = if inbox_id.is_empty() {
        find_inbox_id(&api_base, &api_key, inbox_email)?
    } else {
        inbox_id
    };
    Ok(Some(AgentmailCredentials {
        api_key,
        inbox_id,
        api_base,
        source: "env_or_args".to_string(),
    }))
}

pub fn read_latest_kya_otp(
    creds: &AgentmailCredentials,
    timeout: Duration,
    interval: Duration,
) -> Result<String> {
    let started = Instant::now();
    while started.elapsed() <= timeout {
        let messages = list_messages(creds, 10)?;
        for item in messages {
            if let Some(code) = extract_otp_from_value(&item) {
                output::step(
                    "agentmail.otp.found",
                    json!({
                        "inbox_id": &creds.inbox_id,
                        "message_id": item.get("message_id"),
                        "source": &creds.source,
                    }),
                );
                return Ok(code);
            }
            let message_id = item
                .get("message_id")
                .and_then(|x| x.as_str())
                .unwrap_or("");
            if message_id.is_empty() || !looks_like_kya_message(&item) {
                continue;
            }
            let full = get_message(creds, message_id)?;
            if let Some(code) = extract_otp_from_value(&full) {
                output::step(
                    "agentmail.otp.found",
                    json!({
                        "inbox_id": &creds.inbox_id,
                        "message_id": message_id,
                        "source": &creds.source,
                    }),
                );
                return Ok(code);
            }
        }
        std::thread::sleep(interval);
    }
    Err(KyaError::new(
        ErrorKind::InputRequired,
        "timed out waiting for KYA OTP in AgentMail inbox; pass --code <6 digits> to confirm manually",
    ))
}

pub fn key_warning(inbox_email: &str) -> String {
    format!(
        "IMPORTANT: save this local AgentMail key file. Without it, the agent cannot read OTPs sent to {inbox_email} and cannot automate inbox_control upgrades. Never paste the key in chat or commit it."
    )
}

pub fn resolve_agentmail_api_base(flag: &str) -> String {
    let raw = if !flag.trim().is_empty() {
        flag.trim().to_string()
    } else {
        std::env::var("AGENTMAIL_API_BASE").unwrap_or_default()
    };
    let trimmed = raw.trim_end_matches('/').to_string();
    if trimmed.is_empty() {
        DEFAULT_AGENTMAIL_API_BASE.to_string()
    } else {
        trimmed
    }
}

fn list_messages(creds: &AgentmailCredentials, limit: usize) -> Result<Vec<Value>> {
    let payload = agentmail_get_json(
        &creds.api_base,
        &format!("/v0/inboxes/{}/messages?limit={limit}", creds.inbox_id),
        &creds.api_key,
        "agentmail.list_messages",
    )?;
    Ok(payload
        .get("messages")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default())
}

fn get_message(creds: &AgentmailCredentials, message_id: &str) -> Result<Value> {
    agentmail_get_json(
        &creds.api_base,
        &format!("/v0/inboxes/{}/messages/{message_id}", creds.inbox_id),
        &creds.api_key,
        "agentmail.get_message",
    )
}

fn find_inbox_id(api_base: &str, api_key: &str, inbox_email: &str) -> Result<String> {
    let payload = agentmail_get_json(
        api_base,
        "/v0/inboxes?limit=100",
        api_key,
        "agentmail.list_inboxes",
    )?;
    let inboxes = payload
        .get("inboxes")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    for inbox in inboxes {
        let email = inbox
            .get("email")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .trim()
            .to_lowercase();
        if email == inbox_email.trim().to_lowercase() {
            if let Some(id) = inbox.get("inbox_id").and_then(|x| x.as_str()) {
                if !id.trim().is_empty() {
                    return Ok(id.to_string());
                }
            }
        }
    }
    Err(KyaError::new(
        ErrorKind::InputRequired,
        format!("AgentMail key cannot find inbox_id for {inbox_email}; pass --inbox-id <id>"),
    ))
}

fn agentmail_get_json(api_base: &str, path: &str, api_key: &str, op: &str) -> Result<Value> {
    let url = format!("{}{}", api_base.trim_end_matches('/'), path);
    let resp = HTTP
        .get(&url)
        .header(ACCEPT, "application/json")
        .header(CONTENT_TYPE, "application/json")
        .bearer_auth(api_key)
        .send()
        .map_err(|e| {
            KyaError::new(
                ErrorKind::AgentmailProviderUnavailable,
                format!("{op}: AgentMail API unreachable: {e}"),
            )
        })?;
    let status = resp.status();
    let body = resp.text().map_err(KyaError::from)?;
    if !status.is_success() {
        return Err(KyaError::new(
            ErrorKind::AgentmailProviderUnavailable,
            format!(
                "{op}: AgentMail HTTP {}: {}",
                status.as_u16(),
                body.chars().take(200).collect::<String>()
            ),
        ));
    }
    if body.trim().is_empty() {
        Ok(json!({}))
    } else {
        serde_json::from_str(&body).map_err(KyaError::from)
    }
}

fn read_key_file(path: &Path) -> Result<AgentmailKeyFile> {
    let raw = fs::read(path)?;
    serde_json::from_slice(&raw).map_err(KyaError::from)
}

fn key_dir() -> Result<PathBuf> {
    if let Ok(raw) = std::env::var("KYA_AGENTMAIL_KEY_DIR") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return Ok(PathBuf::from(trimmed));
        }
    }

    #[cfg(windows)]
    {
        if let Ok(raw) = std::env::var("APPDATA") {
            let trimmed = raw.trim();
            if !trimmed.is_empty() {
                return Ok(PathBuf::from(trimmed)
                    .join("kya-agent")
                    .join("agentmail-keys"));
            }
        }
    }

    if let Ok(raw) = std::env::var("XDG_CONFIG_HOME") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return Ok(PathBuf::from(trimmed)
                .join("kya-agent")
                .join("agentmail-keys"));
        }
    }
    if let Ok(raw) = std::env::var("HOME") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return Ok(PathBuf::from(trimmed)
                .join(".config")
                .join("kya-agent")
                .join("agentmail-keys"));
        }
    }

    Err(KyaError::new(
        ErrorKind::Internal,
        "cannot resolve a safe directory for the AgentMail key; set KYA_AGENTMAIL_KEY_DIR",
    ))
}

#[cfg(unix)]
fn write_secret_file_replace(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_secret_file_replace(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)?;
    file.write_all(bytes)?;
    Ok(())
}

fn safe_filename_part(raw: &str) -> String {
    raw.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn first_non_empty(values: &[&str]) -> String {
    for value in values {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    String::new()
}

fn extract_otp_from_value(value: &Value) -> Option<String> {
    if !looks_like_kya_message(value) {
        return None;
    }
    for field in [
        "subject",
        "preview",
        "text",
        "html",
        "extracted_text",
        "extracted_html",
    ] {
        if let Some(text) = value.get(field).and_then(|x| x.as_str()) {
            if let Some(code) = extract_otp(text) {
                return Some(code);
            }
        }
    }
    None
}

fn looks_like_kya_message(value: &Value) -> bool {
    let mut haystack = String::new();
    for field in [
        "from",
        "subject",
        "preview",
        "text",
        "html",
        "extracted_text",
        "extracted_html",
    ] {
        if let Some(text) = value.get(field).and_then(|x| x.as_str()) {
            haystack.push_str(text);
            haystack.push('\n');
        }
    }
    let h = haystack.to_lowercase();
    h.contains("kya") || h.contains("kya.link") || h.contains("verification code")
}

fn extract_otp(text: &str) -> Option<String> {
    OTP_RE
        .captures(text)
        .and_then(|caps| caps.get(1).map(|m| m.as_str().to_string()))
}

#[cfg(test)]
mod tests {
    use super::{extract_otp, extract_otp_from_value};
    use serde_json::json;

    #[test]
    fn extracts_code_from_kya_subject() {
        let msg = json!({
            "subject": "Your KYA verification code is 123456",
            "preview": "Ignore if you did not initiate this"
        });
        assert_eq!(extract_otp_from_value(&msg).as_deref(), Some("123456"));
    }

    #[test]
    fn ignores_non_kya_six_digit_text() {
        let msg = json!({
            "subject": "Invoice 123456",
            "preview": "No verification context"
        });
        assert_eq!(extract_otp_from_value(&msg), None);
    }

    #[test]
    fn extracts_plain_six_digit_code() {
        assert_eq!(extract_otp("code: 000042").as_deref(), Some("000042"));
    }
}
