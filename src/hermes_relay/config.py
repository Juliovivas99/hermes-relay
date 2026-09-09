"""Fail-closed configuration for hermes-relay."""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from urllib.parse import urlparse

from dotenv import load_dotenv

PLACEHOLDER_SECRETS = frozenset(
    {
        "changeme",
        "change-me",
        "secret",
        "password",
        "owner-secret",
        "your-owner-secret",
        "replace-me",
        "todo",
        "example",
    }
)


class ConfigError(ValueError):
    """Raised when required configuration is missing or invalid."""


class InvokeMode(str, Enum):
    """How to invoke the local Hermes CLI.

    Official Hermes CLI (Nous Research docs):
    - ``chat --oneshot -q`` answers one prompt and exits (supports resume/profile/max-turns).
    - top-level ``-z`` prints only the final answer (scripted one-shot; fewer flags).
    """

    CHAT_ONESHOT = "chat_oneshot"
    TOP_LEVEL_Z = "top_level_z"


def _env(*names: str, default: str | None = None) -> str | None:
    for name in names:
        value = os.environ.get(name)
        if value is not None and value.strip() != "":
            return value.strip()
    return default


def _env_int(*names: str, default: int) -> int:
    raw = _env(*names)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        joined = ", ".join(names)
        raise ConfigError(f"{joined} must be an integer") from exc


def _env_bool(*names: str, default: bool) -> bool:
    raw = _env(*names)
    if raw is None:
        return default
    return raw.lower() in {"1", "true", "yes", "on"}


def is_loopback_host(host: str) -> bool:
    lowered = host.strip("[]").lower()
    return lowered in {"127.0.0.1", "localhost", "::1"}


@dataclass(frozen=True)
class Settings:
    owner_secret: str
    public_base_url: str
    hermes_bin: Path
    hermes_home: Path | None
    bind_host: str = "127.0.0.1"
    bind_port: int = 8099
    token_signing_key: str | None = None
    invoke_mode: InvokeMode = InvokeMode.CHAT_ONESHOT
    sync_timeout_seconds: int = 180
    async_timeout_seconds: int = 600
    async_timeout_max_seconds: int = 1800
    kill_grace_seconds: float = 5.0
    max_concurrent_jobs: int = 2
    max_queue_depth: int = 8
    job_ttl_seconds: int = 3600
    max_answer_chars: int = 32_000
    max_stdout_bytes: int = 1_048_576
    max_stderr_bytes: int = 65_536
    max_prompt_chars: int = 16_384
    max_turns_default: int = 16
    max_turns_cap: int = 64
    max_request_body_bytes: int = 262_144
    extra_allowed_hosts: tuple[str, ...] = field(default_factory=tuple)
    extra_allowed_origins: tuple[str, ...] = field(default_factory=tuple)
    rate_limit_mcp_per_minute: int = 60
    rate_limit_oauth_per_minute: int = 30
    access_token_ttl_seconds: int = 3600
    refresh_token_ttl_seconds: int = 7 * 24 * 3600
    auth_code_ttl_seconds: int = 120
    require_https_public_url: bool = True

    @property
    def issuer(self) -> str:
        return self.public_base_url.rstrip("/")

    @property
    def resource(self) -> str:
        return f"{self.issuer}/mcp"

    @property
    def public_host(self) -> str:
        return urlparse(self.public_base_url).hostname or ""

    @property
    def public_origin(self) -> str:
        parsed = urlparse(self.public_base_url)
        if not parsed.scheme or not parsed.netloc:
            return ""
        return f"{parsed.scheme}://{parsed.netloc}"

    def allowed_hosts(self) -> list[str]:
        hosts = {
            "127.0.0.1",
            "localhost",
            "[::1]",
            "127.0.0.1:*",
            "localhost:*",
            "[::1]:*",
        }
        if self.public_host:
            hosts.add(self.public_host)
            hosts.add(f"{self.public_host}:*")
        hosts.update(self.extra_allowed_hosts)
        return sorted(hosts)

    def allowed_origins(self) -> list[str]:
        origins = {
            "http://127.0.0.1",
            "http://localhost",
            "http://[::1]",
            "http://127.0.0.1:*",
            "http://localhost:*",
            "http://[::1]:*",
        }
        if self.public_origin:
            origins.add(self.public_origin)
        origins.update(self.extra_allowed_origins)
        return sorted(origins)

    def signing_key_bytes(self) -> bytes:
        if self.token_signing_key:
            return self.token_signing_key.encode("utf-8")
        # Ephemeral-derived key: tokens die on restart unless TOKEN_KEY is set.
        material = f"hermes-relay-v1|{self.owner_secret}|{self.issuer}"
        return material.encode("utf-8")


def load_env_file(path: str | Path | None = None) -> Path | None:
    """Load a dotenv file if present. Returns the path loaded, if any."""
    if path is not None:
        candidate = Path(path)
        if not candidate.is_file():
            raise ConfigError(f"env file not found: {candidate.name}")
        load_dotenv(candidate, override=False)
        return candidate
    for name in (".env", "examples/env.example"):
        candidate = Path(name)
        if candidate.is_file() and name == ".env":
            load_dotenv(candidate, override=False)
            return candidate
    return None


def resolve_hermes_binary(explicit: str | None = None) -> Path:
    raw = explicit or _env("HERMES_RELAY_HERMES_BIN", "HERMES_BIN")
    if raw:
        path = Path(raw).expanduser()
        if not path.is_file():
            raise ConfigError("Hermes binary path is set but the file does not exist")
        if not os.access(path, os.X_OK):
            raise ConfigError("Hermes binary exists but is not executable")
        return path.resolve()
    found = shutil.which("hermes")
    if not found:
        raise ConfigError("Hermes binary not found on PATH and HERMES_BIN is unset")
    path = Path(found)
    if not os.access(path, os.X_OK):
        raise ConfigError("Hermes binary on PATH is not executable")
    return path.resolve()


def validate_owner_secret(secret: str | None) -> str:
    if not secret:
        raise ConfigError("HERMES_RELAY_OWNER_SECRET is required")
    if len(secret) < 16:
        raise ConfigError("HERMES_RELAY_OWNER_SECRET must be at least 16 characters")
    if secret.strip().lower() in PLACEHOLDER_SECRETS:
        raise ConfigError("HERMES_RELAY_OWNER_SECRET looks like a placeholder")
    return secret


def validate_public_base_url(url: str | None, *, require_https: bool = True) -> str:
    if not url:
        raise ConfigError("HERMES_RELAY_PUBLIC_BASE_URL is required")
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ConfigError("HERMES_RELAY_PUBLIC_BASE_URL must be http or https")
    if not parsed.netloc or parsed.username or parsed.password:
        raise ConfigError("HERMES_RELAY_PUBLIC_BASE_URL must be a host URL without credentials")
    if parsed.query or parsed.fragment:
        raise ConfigError("HERMES_RELAY_PUBLIC_BASE_URL must not include a query or fragment")
    host = parsed.hostname or ""
    if require_https and parsed.scheme != "https" and not is_loopback_host(host):
        raise ConfigError("HERMES_RELAY_PUBLIC_BASE_URL must use https unless the host is loopback")
    return url.rstrip("/")


def parse_invoke_mode(raw: str | None) -> InvokeMode:
    if raw is None or raw == "":
        return InvokeMode.CHAT_ONESHOT
    try:
        return InvokeMode(raw)
    except ValueError as exc:
        raise ConfigError(
            "HERMES_RELAY_INVOKE_MODE must be 'chat_oneshot' or 'top_level_z'"
        ) from exc


def load_settings(*, require_serve: bool = True) -> Settings:
    """Load settings from the environment.

    When ``require_serve`` is true (the `serve` command), owner secret, public
    URL, and Hermes binary are mandatory. Doctor/init may call with
    ``require_serve=False`` to inspect a partial environment.
    """
    require_https = _env_bool("HERMES_RELAY_REQUIRE_HTTPS", default=True)
    owner_secret = _env("HERMES_RELAY_OWNER_SECRET", "OWNER_SECRET")
    public_base_url = _env("HERMES_RELAY_PUBLIC_BASE_URL", "PUBLIC_BASE_URL")
    hermes_home_raw = _env("HERMES_RELAY_HERMES_HOME", "HERMES_HOME")
    extra_hosts = tuple(
        h.strip()
        for h in (_env("HERMES_RELAY_ALLOWED_HOSTS") or "").split(",")
        if h.strip()
    )
    extra_origins = tuple(
        o.strip()
        for o in (_env("HERMES_RELAY_ALLOWED_ORIGINS") or "").split(",")
        if o.strip()
    )

    hermes_bin: Path | None = None
    hermes_home: Path | None = None
    if require_serve:
        owner_secret = validate_owner_secret(owner_secret)
        public_base_url = validate_public_base_url(public_base_url, require_https=require_https)
        hermes_bin = resolve_hermes_binary()
        if hermes_home_raw:
            hermes_home = Path(hermes_home_raw).expanduser()
            if not hermes_home.is_dir():
                raise ConfigError("HERMES_HOME is set but is not a directory")
    else:
        if owner_secret:
            try:
                owner_secret = validate_owner_secret(owner_secret)
            except ConfigError:
                owner_secret = owner_secret  # keep raw for doctor to flag
        if public_base_url:
            try:
                public_base_url = validate_public_base_url(
                    public_base_url, require_https=require_https
                )
            except ConfigError:
                pass
        try:
            hermes_bin = resolve_hermes_binary()
        except ConfigError:
            hermes_bin = None
        if hermes_home_raw:
            hermes_home = Path(hermes_home_raw).expanduser()

    bind_host = _env("HERMES_RELAY_BIND_HOST", "BIND_HOST", default="127.0.0.1") or "127.0.0.1"
    if require_serve and not is_loopback_host(bind_host):
        raise ConfigError("HERMES_RELAY_BIND_HOST must be a loopback address (127.0.0.1 / localhost / ::1)")

    if not require_serve:
        # Provide inert placeholders so dataclass construction succeeds for doctor.
        owner_secret = owner_secret or ""
        public_base_url = public_base_url or "http://127.0.0.1"
        hermes_bin = hermes_bin or Path("/nonexistent/hermes")

    assert hermes_bin is not None
    assert owner_secret is not None
    assert public_base_url is not None

    sync_timeout = _env_int("HERMES_RELAY_SYNC_TIMEOUT", default=180)
    async_timeout = _env_int("HERMES_RELAY_ASYNC_TIMEOUT", default=600)
    async_timeout_max = _env_int("HERMES_RELAY_ASYNC_TIMEOUT_MAX", default=1800)
    if sync_timeout < 5 or async_timeout < 5:
        raise ConfigError("timeouts must be at least 5 seconds")
    if async_timeout > async_timeout_max:
        async_timeout = async_timeout_max

    return Settings(
        owner_secret=owner_secret,
        public_base_url=public_base_url,
        hermes_bin=hermes_bin,
        hermes_home=hermes_home,
        bind_host=bind_host,
        bind_port=_env_int("HERMES_RELAY_BIND_PORT", "BIND_PORT", default=8099),
        token_signing_key=_env("HERMES_RELAY_TOKEN_KEY", "TOKEN_SIGNING_KEY"),
        invoke_mode=parse_invoke_mode(_env("HERMES_RELAY_INVOKE_MODE")),
        sync_timeout_seconds=sync_timeout,
        async_timeout_seconds=async_timeout,
        async_timeout_max_seconds=async_timeout_max,
        kill_grace_seconds=float(_env("HERMES_RELAY_KILL_GRACE", default="5") or "5"),
        max_concurrent_jobs=_env_int("HERMES_RELAY_MAX_CONCURRENT", default=2),
        max_queue_depth=_env_int("HERMES_RELAY_MAX_QUEUE", default=8),
        job_ttl_seconds=_env_int("HERMES_RELAY_JOB_TTL", default=3600),
        max_answer_chars=_env_int("HERMES_RELAY_MAX_ANSWER_CHARS", default=32_000),
        max_stdout_bytes=_env_int("HERMES_RELAY_MAX_STDOUT_BYTES", default=1_048_576),
        max_stderr_bytes=_env_int("HERMES_RELAY_MAX_STDERR_BYTES", default=65_536),
        max_prompt_chars=_env_int("HERMES_RELAY_MAX_PROMPT_CHARS", default=16_384),
        max_turns_default=_env_int("HERMES_RELAY_MAX_TURNS_DEFAULT", default=16),
        max_turns_cap=_env_int("HERMES_RELAY_MAX_TURNS_CAP", default=64),
        max_request_body_bytes=_env_int("HERMES_RELAY_MAX_REQUEST_BODY", default=262_144),
        extra_allowed_hosts=extra_hosts,
        extra_allowed_origins=extra_origins,
        rate_limit_mcp_per_minute=_env_int("HERMES_RELAY_RATE_LIMIT_MCP", default=60),
        rate_limit_oauth_per_minute=_env_int("HERMES_RELAY_RATE_LIMIT_OAUTH", default=30),
        access_token_ttl_seconds=_env_int("HERMES_RELAY_ACCESS_TTL", default=3600),
        refresh_token_ttl_seconds=_env_int("HERMES_RELAY_REFRESH_TTL", default=7 * 24 * 3600),
        auth_code_ttl_seconds=_env_int("HERMES_RELAY_AUTH_CODE_TTL", default=120),
        require_https_public_url=require_https,
    )
