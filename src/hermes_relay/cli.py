"""Console script for hermes-relay."""

from __future__ import annotations

import argparse
import os
import secrets
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from hermes_relay import __version__
from hermes_relay.config import (
    ConfigError,
    load_env_file,
    load_settings,
    resolve_hermes_binary,
    validate_owner_secret,
    validate_public_base_url,
)
from hermes_relay.security import configure_logging

EXAMPLE_ENV = """# hermes-relay operator configuration
# chmod 600 this file. Never commit it.

# Required to serve. Generate with: hermes-relay init
HERMES_RELAY_OWNER_SECRET={owner_secret}

# Public HTTPS origin that Grok Bot will use (no trailing slash, no /mcp).
# Set this AFTER your tunnel or reverse proxy is up.
HERMES_RELAY_PUBLIC_BASE_URL=https://your-tunnel.example

# Optional: persist token signatures across restarts. If unset, tokens die on restart.
# HERMES_RELAY_TOKEN_KEY=

# Loopback bind only. TLS terminates at Caddy / cloudflared.
HERMES_RELAY_BIND_HOST=127.0.0.1
HERMES_RELAY_BIND_PORT=8099

# Hermes binary. Leave unset to use PATH.
# HERMES_BIN=
# Optional Hermes home (usually ~/.hermes). Do not publish this path.
# HERMES_HOME=

# chat_oneshot  -> hermes chat --oneshot -q PROMPT  (supports --resume / --profile / --max-turns)
# top_level_z   -> hermes -z PROMPT                 (final answer only; session_id not applied)
HERMES_RELAY_INVOKE_MODE=chat_oneshot

HERMES_RELAY_SYNC_TIMEOUT=180
HERMES_RELAY_ASYNC_TIMEOUT=600
HERMES_RELAY_ASYNC_TIMEOUT_MAX=1800
HERMES_RELAY_MAX_CONCURRENT=2
HERMES_RELAY_MAX_QUEUE=8
HERMES_RELAY_JOB_TTL=3600
HERMES_RELAY_MAX_ANSWER_CHARS=32000
HERMES_RELAY_MAX_TURNS_DEFAULT=16
HERMES_RELAY_MAX_TURNS_CAP=64
"""


@dataclass
class Check:
    name: str
    ok: bool
    detail: str


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="hermes-relay",
        description="Self-hosted Streamable-HTTP MCP gateway from Grok Bot to local Hermes.",
    )
    parser.add_argument("--version", action="version", version=f"hermes-relay {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="run the gateway on loopback")
    serve.add_argument("--env-file", default=None)
    serve.add_argument("--host", default=None)
    serve.add_argument("--port", type=int, default=None)
    serve.add_argument("--log-level", default="INFO")

    doctor = sub.add_parser("doctor", help="validate Hermes, env, and bind settings")
    doctor.add_argument("--env-file", default=None)

    init = sub.add_parser("init", help="write a mode-0600 .env with a generated owner secret")
    init.add_argument("--path", default=".env")
    init.add_argument("--force", action="store_true")

    tunnel = sub.add_parser("tunnel", help="print or run a cloudflared quick tunnel")
    tunnel.add_argument("--port", type=int, default=None)
    tunnel.add_argument("--print-only", action="store_true")

    args = parser.parse_args(argv)
    if args.command == "serve":
        return cmd_serve(args)
    if args.command == "doctor":
        return cmd_doctor(args)
    if args.command == "init":
        return cmd_init(args)
    if args.command == "tunnel":
        return cmd_tunnel(args)
    parser.error("unknown command")
    return 2


def cmd_serve(args: argparse.Namespace) -> int:
    try:
        load_env_file(args.env_file)
        settings = load_settings(require_serve=True)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.host:
        if args.host not in {"127.0.0.1", "localhost", "::1"}:
            print("error: --host must be a loopback address", file=sys.stderr)
            return 2
        object.__setattr__(settings, "bind_host", args.host)
    if args.port:
        object.__setattr__(settings, "bind_port", args.port)

    configure_logging(args.log_level)
    from hermes_relay.server import create_app

    app = create_app(settings)
    import uvicorn

    print(
        f"hermes-relay {__version__} listening on http://{settings.bind_host}:{settings.bind_port}/mcp",
        file=sys.stderr,
    )
    uvicorn.run(
        app,
        host=settings.bind_host,
        port=settings.bind_port,
        log_level=args.log_level.lower(),
        access_log=False,
    )
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    try:
        if args.env_file:
            load_env_file(args.env_file)
        elif Path(".env").is_file():
            load_env_file(".env")
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    checks = collect_doctor_checks()
    worst = 0
    for check in checks:
        mark = "OK " if check.ok else "ERR"
        color = "\033[32m" if check.ok else "\033[31m"
        reset = "\033[0m"
        if not sys.stdout.isatty():
            color = reset = ""
        print(f"{color}{mark}{reset}  {check.name}: {check.detail}")
        if not check.ok:
            worst = 1
    return worst


def collect_doctor_checks() -> list[Check]:
    checks: list[Check] = []
    checks.append(Check("python", True, f"{sys.version.split()[0]}"))

    hermes_ok = False
    hermes_detail = "not found on PATH and HERMES_BIN is unset"
    try:
        path = resolve_hermes_binary()
        hermes_ok = True
        hermes_detail = f"executable named {path.name} is available"
    except ConfigError as exc:
        hermes_detail = str(exc)
    checks.append(Check("hermes_binary", hermes_ok, hermes_detail))

    default_home = Path.home() / ".hermes"
    configured = os.environ.get("HERMES_HOME") or os.environ.get("HERMES_RELAY_HERMES_HOME")
    if configured:
        home_path = Path(configured).expanduser()
        checks.append(
            Check(
                "hermes_home",
                home_path.is_dir(),
                "configured HERMES_HOME exists" if home_path.is_dir() else "configured HERMES_HOME is missing",
            )
        )
    else:
        checks.append(
            Check(
                "hermes_home",
                True,
                "~/.hermes is present" if default_home.is_dir() else "~/.hermes not found (Hermes will use its default on first run)",
            )
        )

    secret = os.environ.get("HERMES_RELAY_OWNER_SECRET") or os.environ.get("OWNER_SECRET")
    secret_ok = False
    secret_detail = "HERMES_RELAY_OWNER_SECRET is not set"
    if secret:
        try:
            validate_owner_secret(secret)
            secret_ok = True
            secret_detail = f"set ({len(secret)} chars, value hidden)"
        except ConfigError as exc:
            secret_detail = str(exc)
    checks.append(Check("owner_secret", secret_ok, secret_detail))

    url = os.environ.get("HERMES_RELAY_PUBLIC_BASE_URL") or os.environ.get("PUBLIC_BASE_URL")
    url_ok = False
    url_detail = "HERMES_RELAY_PUBLIC_BASE_URL is not set"
    if url:
        try:
            validate_public_base_url(url, require_https=os.environ.get("HERMES_RELAY_REQUIRE_HTTPS", "1") != "0")
            parsed_ok = True
            url_ok = parsed_ok
            host = url.split("://", 1)[-1].split("/", 1)[0]
            url_detail = f"configured host {host} (full URL hidden from logs)"
        except ConfigError as exc:
            url_detail = str(exc)
    checks.append(Check("public_base_url", url_ok, url_detail))

    bind = os.environ.get("HERMES_RELAY_BIND_HOST", "127.0.0.1")
    checks.append(
        Check(
            "bind_host",
            bind in {"127.0.0.1", "localhost", "::1"},
            "loopback" if bind in {"127.0.0.1", "localhost", "::1"} else "refusing non-loopback bind",
        )
    )

    token_key = os.environ.get("HERMES_RELAY_TOKEN_KEY") or os.environ.get("TOKEN_SIGNING_KEY")
    checks.append(
        Check(
            "token_key",
            True,
            "persistent signing key is set (value hidden)"
            if token_key
            else "ephemeral signing key will be derived (tokens die on restart)",
        )
    )

    cloudflared = shutil.which("cloudflared")
    checks.append(
        Check(
            "cloudflared",
            True,
            "available for `hermes-relay tunnel`"
            if cloudflared
            else "not on PATH (optional; you can use Caddy or another tunnel)",
        )
    )
    return checks


def cmd_init(args: argparse.Namespace) -> int:
    path = Path(args.path)
    if path.exists() and not args.force:
        print(f"error: {path.name} already exists (pass --force to overwrite)", file=sys.stderr)
        return 2
    secret = secrets.token_urlsafe(32)
    path.write_text(EXAMPLE_ENV.format(owner_secret=secret), encoding="utf-8")
    path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    print(f"wrote {path} (mode 0600). Owner secret generated; value not printed.")
    print("Set HERMES_RELAY_PUBLIC_BASE_URL after your tunnel is running, then: hermes-relay serve")
    return 0


def cmd_tunnel(args: argparse.Namespace) -> int:
    port = args.port
    if port is None:
        raw = os.environ.get("HERMES_RELAY_BIND_PORT") or os.environ.get("BIND_PORT") or "8099"
        port = int(raw)
    command = ["cloudflared", "tunnel", "--url", f"http://127.0.0.1:{port}"]
    print("Public URL must be copied into HERMES_RELAY_PUBLIC_BASE_URL after the tunnel starts.")
    print("Then restart `hermes-relay serve` so OAuth discovery advertises that origin.")
    print("Command:")
    print(" ".join(command))
    if args.print_only:
        return 0
    cloudflared = shutil.which("cloudflared")
    if cloudflared is None:
        print("error: cloudflared is not on PATH", file=sys.stderr)
        return 2
    try:
        return subprocess.call(command)
    except OSError as exc:
        print(f"error: failed to start cloudflared ({type(exc).__name__})", file=sys.stderr)
        return 2
