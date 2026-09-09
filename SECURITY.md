# Security

hermes-relay is a privileged single-owner gateway. A successful OAuth approval
lets a cloud MCP client run Hermes on the operator machine.

## What this project assumes

- You are the only person who should approve clients.
- Hermes itself is already installed and configured (`~/.hermes`, model keys).
- TLS terminates on a tunnel or reverse proxy you control.
- The process binds to loopback. It is not an Internet-facing multi-tenant IdP.

## Fail-closed startup

`hermes-relay serve` exits without listening when any of these are invalid:

- `HERMES_RELAY_OWNER_SECRET` missing, shorter than 16 characters, or a placeholder
- `HERMES_RELAY_PUBLIC_BASE_URL` missing, containing credentials, or non-HTTPS for a non-loopback host
- Hermes binary missing or not executable
- Bind host is not loopback

## Owner secret

The owner secret is only for the local approval form. It is compared with
constant-time equality. If a client sends it as `Authorization: Bearer …`, the
gateway **rejects** the request. Rotating the secret does not, by itself, revoke
already-issued JWTs unless you also rely on an ephemeral signing key. Use
`POST /oauth/revoke` or restart without `HERMES_RELAY_TOKEN_KEY` to drop tokens.

## Tokens

- Authorization code + PKCE (S256 only)
- Dynamic client registration for public clients (`token_endpoint_auth_method=none`)
- HMAC-signed access and refresh tokens bound to the MCP resource URL
- Refresh tokens rotate; the previous refresh `jti` is denylisted
- `POST /oauth/revoke` denylists access or refresh tokens by `jti`

Tokens are not written to disk. The in-memory denylist resets on process exit.

## Network controls

- Default bind: `127.0.0.1`
- Host and Origin allowlists (DNS-rebinding protection)
- Per-IP sliding-window rate limits on `/mcp` and `/oauth/*`
- Hard request body cap
- CORS is limited to the configured public origin

Do not put hermes-relay on `0.0.0.0`. Do not disable the Host check.

## Hermes subprocess

- Fixed argv list; prompt is one argument
- No `shell=True`
- Minimal child environment (no parent secret inheritance)
- Byte-capped stdout/stderr, ANSI stripped, answer length bounded
- Hard timeout; cancel kills the process group (`SIGTERM`, then `SIGKILL`)
- Errors are sanitized (absolute paths and secret-looking strings removed)

There is no exec/shell MCP tool and no generic `hermes <subcommand>` runner.

## Logging

Logs are structured JSON and pass through a redactor. Prompts are logged by
length only. Tokens, owner secrets, and home directories must not appear in
status tool output.

## What we will not do

- Accept the owner secret as an API key
- Persist job prompts to disk
- Forward Grok / MCP bearer tokens into Hermes
- Trust `X-Forwarded-For` from non-loopback peers by default

## Reporting

This is a private operator tool. If you find a vulnerability in a deployment you
do not own, contact the operator. If you find a defect in this repository,
open an issue without including secrets or hostnames.
