# Architecture

hermes-relay is a single ASGI process. Official `mcp` 2.x (`MCPServer`, formerly
FastMCP) serves Streamable HTTP at `/mcp`. A small original OAuth 2.1 layer sits
in front of that endpoint.

```
                    HTTPS
Grok Bot  ----->  tunnel / Caddy  ----->  127.0.0.1:8099
                       |                       |
                  TLS + Host              hermes-relay
                                              |
                         +--------------------+--------------------+
                         |                    |                    |
                   OAuth routes          MCP /mcp            operator UI
                   /oauth/*              (Bearer JWT)        GET /
                   /.well-known/*
                         |                    |
                    owner approval      JobStore (memory)
                                              |
                                        HermesRunner
                                              |
                                      argv + minimal env
                                              |
                                         hermes CLI
```

## Modules

| Module | Role |
| --- | --- |
| `config` | Fail-closed settings from the environment |
| `security` | Host/Origin, body cap, redaction, sanitization |
| `limits` | Rate limit + concurrency gate |
| `oauth` | Discovery, DCR, PKCE, tokens, revoke, approval page |
| `agent` | Argv builder + bounded subprocess |
| `jobs` | In-memory queue, TTL, cancel |
| `gateway` | MCP tools |
| `server` | Starlette app + middleware |
| `cli` | `serve`, `doctor`, `init`, `tunnel` |

## OAuth (single owner)

1. Client `POST /mcp` without a token → `401` + `WWW-Authenticate` pointing at protected-resource metadata.
2. Client reads `/.well-known/oauth-protected-resource` then `/.well-known/oauth-authorization-server`.
3. Client `POST /oauth/register` (RFC 7591). Public client, PKCE-only.
4. Browser hits `/oauth/authorize`. Operator enters the owner secret.
5. Redirect returns an authorization code. Token endpoint verifies PKCE S256.
6. Access token `aud` is `{PUBLIC_BASE_URL}/mcp`. Refresh tokens rotate.

Fallback if a client cannot do DCR: register is the supported path. There is no
static client-id file. Pre-seeding a client is intentionally omitted so the
operator always approves the redirect URI they see.

## Hermes invocation

Default argv (official CLI: answer-and-exit):

```text
hermes chat --oneshot [--profile NAME] [--resume SESSION] --max-turns N --source hermes-relay -q PROMPT
```

Alternate scripted mode (`HERMES_RELAY_INVOKE_MODE=top_level_z`):

```text
hermes [--profile NAME] -z PROMPT
```

`--resume` / `--max-turns` are not applied in `-z` mode. The MCP schema still
accepts `session_id` so clients do not break; the result includes
`session_applied: false`.

## Jobs

- Default `hermes_ask` is async: enqueue, return `{job_id, status}`.
- A background worker respects `max_concurrent` and `max_queue`.
- Completed jobs drop the prompt and expire after TTL.
- Cancel sets an `asyncio.Event`; the runner signals the process group.

## Why not copy an existing bridge

The public grokbot-hermes-bridge repository is architecture inspiration only.
This tree is written from MCP / OAuth RFCs and the published Hermes CLI
reference. No code was copied from that project.
