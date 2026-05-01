# kya-skill

Sign and submit [KYA (Know Your Agent)](https://kya.link) attestations
from your IDE or terminal. A single static Rust binary (`kya-agent`)
that drives the KYA identity and matchmaking flow — Twitter / Telegram /
Email claims, KYC initiation, AWP-relayer matchmaking actions
(`setRecipient` / `grantDelegate`), generic EIP-712 signing — by
delegating signatures to the official `awp-wallet` CLI.

[![license](https://img.shields.io/badge/license-MIT-blue)](./LICENSE)

## What this is — and what it is NOT

| ✅ | ❌ |
|---|---|
| EIP-712 signatures only — never raw `eth_sendRawTransaction` from the user's machine | No transaction is ever broadcast by this skill itself. |
| Two domain shapes, both hard-coded in `src/eip712.rs`: `KYA` (identity) and `AWPRegistry` (matchmaking) | Cannot be tricked into signing a payload for an unknown contract. |
| The AWP relayer (`https://api.awp.sh`, override via `AWP_RELAY_BASE`) pays gas for KYA matchmaking actions | The agent EOA never needs ETH. |
| `awp-wallet sign-typed-data` keeps the key inside the wallet process | Skill never reads the seed phrase, password, or raw private key. |
| Public, MIT, single static binary, deps listed in `Cargo.toml` | No third-party install steps to vet beyond `awp-wallet`. |

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/awp-worknet/kya-skill/main/install.sh | sh
```

The script downloads a prebuilt `kya-agent` binary from the latest
GitHub Release and drops it in `~/.local/bin/`. On minimal sandboxes
that lack `curl` and `wget`, it falls back to `python3` then `node` —
all four follow HTTPS 302 redirects.

Verify:

```sh
kya-agent --version
kya-agent preflight
```

## Prerequisites

KYA is a subnet of the AWP network. Before any KYA flow, the agent EOA
must already be registered on AWPRegistry. If
[`awp-skill`](https://github.com/awp-core/awp-skill) onboarding hasn't
been run yet, do that first; `kya-agent preflight` will surface
`AWP_NOT_REGISTERED` with a handoff hint when the prerequisite is
missing.

You also need [`awp-wallet`](https://github.com/awp-core/awp-wallet) on
your `PATH`.

## Subcommands

| Command | Purpose |
|---|---|
| `preflight` | Self-check: `awp-wallet`, KYA reachable, RPC reachable, AWP registration. |
| `bootstrap` | First-run alias of `preflight` plus an onboarding hint. |
| `smoke-test` | Non-destructive probe — never signs, never POSTs. |
| `open <url>` | Parse a `kya-sign://...` magic link and dispatch. Use `--dry-run` to preview. |
| `attestations` | List active attestations + delegated-staking eligibility. |
| `claim-twitter` | Sign locally, emit a `kya.link/verify/social/claim#…` handoff URL. **Web-driven only.** |
| `claim-telegram` | Same shape as `claim-twitter`, public-channel only. |
| `claim-email` | Bind an email — two signs sandwich a 6-digit code. |
| `kyc` | Sign `KycInit`, create a Didit session, return verification URL. |
| `reveal` | Off-chain. Sign `Action(attestation_reveal)`, get unredacted metadata. |
| `set-recipient` | Stage 1: gasless `AWPRegistry.setRecipient` via relayer. Stage 2 (with `--amount`): KYA `delegated_staking_request`. |
| `staking-status` | Re-check a delegated-staking request's status. |
| `grant-delegate` | Provider side: authorize `KyaAllocatorProxy` to allocate on your behalf, gasless via relayer. |
| `sign` / `sign-action` | Generic / single-shot EIP-712 signers. |

Read [SKILL.md](./SKILL.md) for the full agent-facing contract — rules,
canonical journey, error-code recovery table, and the OpenClaw / Hermes
runtime adaptations.

## Build from source

```sh
cargo build --release
# binary at target/release/kya-agent
```

Static Linux musl build:

```sh
cargo install cross --locked
cross build --release --target x86_64-unknown-linux-musl
```

## License

MIT — see [LICENSE](./LICENSE).
