use super::{resolve_agent, sign_action, signed, Ctx};
use crate::client;
use crate::error::{ErrorKind, KyaError, Result};
use crate::output;
use clap::Parser;
use serde_json::json;

#[derive(Parser, Debug)]
pub struct Args {
    #[arg(long, default_value = "")]
    pub agent: String,
}

/// Telegram public-channel claim — handoff-only.
///
/// Same shape as `claim-twitter`: sign `telegram_prepare` +
/// `telegram_claim`, embed both signatures in a KYA web handoff URL,
/// the owner clicks it and KYA web takes the published message URL
/// + POSTs the claim itself. The agent re-runs `kya-agent attestations`
///   after the owner reports done.
///
/// There is intentionally no agent-driven `--message-url` path; same
/// reasoning as `claim-twitter` — the web-handoff design keeps the
/// calling LLM out of URL collection.
pub fn run(ctx: &Ctx, args: Args) -> Result<()> {
    let agent = resolve_agent(ctx, &args.agent)?;
    output::info(
        "agent resolved",
        json!({ "agent": &agent, "chain_id": ctx.chain_id }),
    );

    let (sig1, ts1, n1) = sign_action(ctx, "telegram_prepare", &agent)?;
    let prepared = client::prepare_telegram(&ctx.api_base, &agent, signed(&sig1, ts1, &n1))?;
    let claim_text = prepared
        .get("claim_text")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let claim_nonce = prepared
        .get("nonce")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    if claim_text.is_empty() || claim_nonce.is_empty() {
        return Err(KyaError::new(
            ErrorKind::KyaError,
            format!("unexpected prepare response: {prepared}"),
        ));
    }
    output::step(
        "prepare.ok",
        json!({
            "nonce": &claim_nonce,
            "expires_at": prepared.get("expires_at"),
            "claim_text_chars": claim_text.len(),
        }),
    );

    let (sig2, ts2, n2) = sign_action(ctx, "telegram_claim", &agent)?;
    let ts2_str = ts2.to_string();
    // 与 claim_twitter 同一落地页 `/verify/social/claim`，靠 fragment 里
    // `platform=telegram` 切到 Telegram tab。
    // 兼容性：web 侧还保留了一个 `/verify/social/telegram` 的 client-side
    // redirect 兜底（透传 fragment + 强制 platform=telegram），用于之前
    // 已经签发但还没用完的旧版 handoff URL，本仓库版本不再生成该 path。
    let url = build_handoff_url(
        &ctx.web_base,
        "/verify/social/claim",
        &[
            ("platform", "telegram"),
            ("agent", &agent),
            ("nonce", &claim_nonce),
            ("claim_text", &claim_text),
            (
                "expires_at",
                prepared
                    .get("expires_at")
                    .and_then(|x| x.as_str())
                    .unwrap_or_default(),
            ),
            ("sig", &sig2),
            ("ts", &ts2_str),
            ("msg_nonce", &n2),
        ],
    );
    // See claim_twitter.rs — stdout intentionally exposes ONLY handoff_url
    // so the calling LLM can't drift back to "ask owner to post + paste URL".
    let body = json!({
        "mode": "handoff",
        "agent_address": &agent,
        "handoff_url": &url,
        "instructions_for_agent": "Relay handoff_url verbatim to the owner. Do NOT ask the owner to publish a Telegram message or paste any URL back. KYA web walks them through it. After they say done, run `kya-agent attestations`.",
    });
    output::ok(
        body,
        "browser_handoff_then_verify",
        Some("kya-agent attestations"),
    );
    Ok(())
}

fn build_handoff_url(web_base: &str, path: &str, params: &[(&str, &str)]) -> String {
    let frag: Vec<String> = params
        .iter()
        .map(|(k, v)| format!("{}={}", percent_encode(k), percent_encode(v)))
        .collect();
    format!(
        "{}{}#{}",
        web_base.trim_end_matches('/'),
        path,
        frag.join("&")
    )
}

fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}
