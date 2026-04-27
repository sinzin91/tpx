# tpx — Claude Code instructions

This repo dogfoods its own binary. While working in this directory, follow the
boundary tpx is meant to enforce.

## API access via tpx

When you need to talk to **Vercel** (`api.vercel.com`) or **Langfuse**
(`cloud.langfuse.com`, `us.cloud.langfuse.com`), use the `tpx` CLI rather than
curl/wget/SDKs:

```bash
tpx vercel GET /v9/projects
tpx vercel GET /v6/deployments --query limit=10
tpx langfuse GET /api/public/traces
tpx --list-providers   # see what's available
tpx check vercel GET /v9/projects/abc   # dry-run policy probe (no network call)
```

`tpx` enforces a deny-closed allowlist (`src/rules/*.yaml`) and pulls the real
credential from `~/.tpx/credentials.json` at exec time, so the API token never
appears in your tool calls or environment.

For everything else (other domains, docs lookups, package mirrors, webhooks
you're testing, etc.) `curl`, `wget`, and `WebFetch` are all fine — this isn't
a curl ban, just a routing convention for the two providers tpx brokers.

**Don't read `~/.tpx/credentials.json`** — directly or via shell. The file is
mode-0600 and out-of-scope per the spec's threat model; if a task seems to
require reading it, that's a sign to use `tpx` instead. The Read tool is
denied on that exact path to make accidents harder, but the real contract is
*don't try*.

You **can** (and often should) read the other files under `~/.tpx/`:

- `~/.tpx/rules/<provider>.yaml` — runtime override rules; check before proposing changes.
- `~/.tpx/log/decisions.jsonl` — audit log; useful for debugging "why did this deny?"

### Adding a rule (when tpx denies an endpoint you legitimately need)

Don't route around tpx with a script. Instead:

1. Reproduce: `tpx explain <provider> <method> <path>` — confirms which rule
   matched (or didn't) and why.
2. Decide where the rule should live:
   - **Runtime override** (default for one-off / personal needs): edit
     `~/.tpx/rules/<provider>.yaml`. tpx prefers this path over the bundled
     rules at runtime — no rebuild needed.
   - **Canonical / shipped** (rule should be the new default for everyone):
     edit `src/rules/<provider>.yaml` and rebuild (`cargo install --path . --locked`).
3. Show me the proposed YAML diff *before* writing it. The deny-closed
   contract is load-bearing — auto-applying allow rules turns tpx into a
   yes-machine. I want to approve each new rule.
4. After write, verify with `tpx explain` and re-run the original request.

If the request is one-off and not worth a rule (e.g. a weird PATCH on a
single resource), surface the deny and ask whether to add a rule or back off
— don't quietly add an `action: allow` to make the failure go away.

## Useful invocations

```bash
tpx --list-providers
tpx check vercel GET /v9/projects        # dry-run policy probe (no network)
tpx explain vercel GET /v9/projects/abc  # which rule matched and why
tpx vercel GET /v9/projects              # live call (uses ~/.tpx/credentials.json)
tpx tail-log -n 10                       # JSONL audit trail
```

## Working in this repo

- Tests must pass: `cargo test --locked --all-features`.
- Lints clean: `cargo fmt --all -- --check` and `cargo clippy --locked --all-targets --all-features -- -D warnings`.
- Spec lives in the user's Obsidian vault: *2026-04-26 tpx CLI - Dumb Proxy Spec*.
  When in doubt about scope, that's the source of truth.
