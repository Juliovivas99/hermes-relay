# hermes-relay

Self-hosted **Streamable-HTTP MCP gateway** that lets **Grok Bot** (and other OAuth MCP clients) call a **local Hermes Agent** on the operator's machine.

```
Grok Bot
  -- HTTPS + OAuth 2.1 (discovery, DCR, PKCE) -->
reverse proxy / tunnel
  -- localhost only -->
hermes-relay (ASGI)
  -- bounded subprocess, fixed argv, minimal env -->
local `hermes` CLI  +  ~/.hermes
```

This is an original MIT-licensed project by **Julio Vivas**. It is a clean-room implementation. Do not confuse it with other public bridges.

**Direction:** Grok Bot → Hermes. Hermes cannot call Grok Bot built-ins through this gateway.

## Threat model (short)

hermes-relay is a **single-owner** bridge. Anyone who completes OAuth (owner-secret approval) can make Hermes run on your machine with your Hermes config, tools, and credentials. Treat the public HTTPS URL as a privileged control plane.

- Bind defaults to `127.0.0.1` only. Put TLS and the public hostname on Cloudflare Tunnel or Caddy.
- The owner secret unlocks the approval page. **It is not a Bearer token** and is rejected if sent as one.
- No generic shell tool. No arbitrary Hermes subcommand runner.
- Child processes get a fixed argv and a minimal environment. Timeouts and cancel send SIGTERM to the process group, then SIGKILL.
- Job payloads stay in memory. Completed jobs expire.

Read [SECURITY.md](SECURITY.md) before exposing a tunnel.

## Requirements

- Python 3.11+
- A working [Hermes Agent](https://hermes-agent.nousresearch.com/) install (`hermes` on `PATH` or `HERMES_BIN`)
- A public HTTPS URL pointed at this process (Cloudflare Tunnel, Caddy + DNS, etc.)

Tests and `doctor` do **not** need a real Hermes binary.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

hermes-relay init          # writes mode-0600 .env with a generated owner secret
hermes-relay doctor        # green/red checks; secrets are not printed
hermes-relay serve         # http://127.0.0.1:8099
```

`serve` refuses to start unless all of these are valid:

1. `HERMES_RELAY_OWNER_SECRET` (length ≥ 16, not a placeholder)
2. `HERMES_RELAY_PUBLIC_BASE_URL` (https, unless the host is loopback)
3. An executable Hermes binary (`HERMES_BIN` or `PATH`)

### Tunnel, then set the public URL

```bash
hermes-relay tunnel --print-only
hermes-relay tunnel
```

`tunnel` runs `cloudflared tunnel --url http://127.0.0.1:8099` and prints the command. After cloudflared shows the `https://*.trycloudflare.com` origin:

1. Put that origin (no `/mcp`) in `HERMES_RELAY_PUBLIC_BASE_URL`
2. Restart `hermes-relay serve` so OAuth discovery advertises the real issuer

A Caddy example lives in [`deploy/Caddyfile.example`](deploy/Caddyfile.example).

### Add the connector in Grok Bot

1. Create a **custom MCP connector**.
2. URL: `https://<your-public-host>/mcp`
3. Auth: **OAuth** (not a static `Authorization` header, not the owner secret).
4. Grok Bot will discover `/.well-known/oauth-protected-resource`, register a public client (DCR), and open the approval page.
5. On the approval page, enter the **owner secret** from your `.env`.
6. After redirect, Grok Bot stores the access token and can call tools.

Usage rules for the bot: [`skills/hermes-relay/SKILL.md`](skills/hermes-relay/SKILL.md).

## MCP tools

| Tool | Behavior |
| --- | --- |
| `hermes_ask(prompt, session_id?, profile?, max_turns?, async_mode?)` | Default `async_mode=true` enqueues a job and returns `{job_id, status}`. `async_mode=false` waits up to the sync timeout. |
| `hermes_poll(job_id)` | Status plus answer when finished. |
| `hermes_cancel(job_id)` | Cancel queued/running jobs; kill the child process group. |
| `hermes_status()` | Filtered health. No home paths, tokens, or secret-bearing URLs. |

Job states: `queued` · `running` · `succeeded` · `failed` · `cancelled` · `timed_out`.

## Hermes CLI adapter

Official Hermes docs define two one-shot shapes. hermes-relay implements both:

| `HERMES_RELAY_INVOKE_MODE` | Argv | Session | Profile | Max turns |
| --- | --- | --- | --- | --- |
| `chat_oneshot` (default) | `hermes chat --oneshot --source hermes-relay -q PROMPT` | `--resume` when `session_id` is a safe token | `--profile` | `--max-turns` (clamped) |
| `top_level_z` | `hermes -z PROMPT` | **not applied** (parameter kept for schema compatibility) | `--profile` if provided | **not applied** |

The prompt is always a single argv element. `shell=True` is never used.

Child environment is constructed from scratch: `PATH` (binary dir + system bins), `HERMES_HOME` when configured, `HERMES_SESSION_SOURCE=hermes-relay`, and locale/`TERM`. Parent secrets are not inherited.

If you pass `session_id` while using `top_level_z`, the tool still succeeds and reports `session_applied: false`.

## CLI

```text
hermes-relay serve [--env-file .env] [--host 127.0.0.1] [--port 8099]
hermes-relay doctor
hermes-relay init [--path .env] [--force]
hermes-relay tunnel [--port 8099] [--print-only]
python -m hermes_relay serve
```

## Development

```bash
pip install -e ".[dev]"
pytest
```

`pytest` uses a fake Hermes binary and does not need a real Hermes install.

## License

MIT © Julio Vivas / hermes-relay. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
