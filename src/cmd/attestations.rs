// `kya-agent attestations` — list active KYA attestations for an agent and
// classify them so the calling agent can decide where to go next in the
// canonical journey (verify → delegated staking).
//
// This endpoint is PUBLIC — no signing, no nonce. PII fields are masked
// per server policy (e.g. email shows up as `email_masked`); the owner can
// run `kya-agent reveal` to see plaintext.

use super::{resolve_agent, Ctx};
use crate::client;
use crate::error::Result;
use crate::output;
use clap::Parser;
use serde_json::{json, Value};

#[derive(Parser, Debug)]
pub struct Args {
    /// Agent EOA. Default: read from awp-wallet.
    #[arg(long, default_value = "")]
    pub agent: String,
    /// Narrow to one attestation type. Empty = all kinds.
    #[arg(long, default_value = "")]
    pub r#type: String,
}

const KNOWN_TYPES: &[&str] = &[
    "twitter_claim",
    "telegram_claim",
    "email_claim",
    "kyc",
    "staking",
];

pub fn run(ctx: &Ctx, args: Args) -> Result<()> {
    let agent = resolve_agent(ctx, &args.agent)?;

    let type_filter = if args.r#type.is_empty() {
        None
    } else {
        Some(args.r#type.as_str())
    };

    let resp = client::list_attestations(&ctx.api_base, &agent, type_filter)?;
    let items: Vec<Value> = resp
        .get("attestations")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();

    // KYA delegated staking currently only accepts active X/Twitter verification.
    // Other attestations still appear in the response, but they do not unlock this flow.
    let mut active: Vec<Value> = Vec::new();
    let mut active_kinds: Vec<&'static str> = Vec::new();
    let mut by_type: std::collections::BTreeMap<String, usize> = Default::default();

    for att in &items {
        if att.get("status").and_then(|s| s.as_str()) != Some("active") {
            continue;
        }
        active.push(att.clone());
        let t = att.get("type").and_then(|x| x.as_str()).unwrap_or("");
        *by_type.entry(t.to_string()).or_insert(0) += 1;
        match t {
            "twitter_claim" => {
                if !active_kinds.contains(&"twitter") {
                    active_kinds.push("twitter");
                }
            }
            _ => {}
        }
    }

    let qualifies = active_kinds.contains(&"twitter");

    // next_action drives the calling agent's branch:
    // - qualifies → tell user they can proceed to delegated staking now
    // - empty     → list verification options so user picks one
    let (next_action, extras) = if qualifies {
        (
            "ready_for_delegated_staking",
            json!({
                "qualifies_for_delegated_staking": true,
                "active_kinds": active_kinds,
            }),
        )
    } else {
        (
            "choose_verification",
            json!({
                "qualifies_for_delegated_staking": false,
                "active_kinds": active_kinds,
                "options": verification_options(),
            }),
        )
    };

    let body = json!({
        "ok": true,
        "agent_address": agent,
        "active": active,
        "active_kinds": active_kinds,
        "qualifies_for_delegated_staking": qualifies,
        "by_type": by_type,
        "type_filter": type_filter,
        "known_types": KNOWN_TYPES,
    });
    let _ = extras; // packaged below
    let extras_obj = if qualifies {
        json!({
            "qualifies_for_delegated_staking": true,
            "active_kinds": active_kinds,
            "next_command_hint": "kya-agent set-recipient --worknet <ID> --amount <AWP>"
        })
    } else {
        json!({
            "qualifies_for_delegated_staking": false,
            "active_kinds": active_kinds,
            "options": verification_options(),
        })
    };
    output::ok_extra(body, next_action, None, Some(extras_obj));
    Ok(())
}

/// Canonical verification option for delegated staking eligibility.
fn verification_options() -> Value {
    json!([
        {
            "kind": "social",
            "method": "twitter",
            "label": "Twitter (X) — public tweet",
            "command": "kya-agent claim-twitter"
        }
    ])
}
