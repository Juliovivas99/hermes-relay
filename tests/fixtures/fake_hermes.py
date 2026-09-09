#!/usr/bin/env python3
"""Fake Hermes CLI used by hermes-relay tests. Not a copy of any real CLI."""

from __future__ import annotations

import argparse
import os
import signal
import sys
import time


def _parse(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="hermes")
    parser.add_argument("-z", "--oneshot-prompt", dest="z_prompt", default=None)
    parser.add_argument("--profile", "-p", default=None)
    sub = parser.add_subparsers(dest="command")
    chat = sub.add_parser("chat")
    chat.add_argument("--oneshot", action="store_true")
    chat.add_argument("-q", "--query", default=None)
    chat.add_argument("--resume", "-r", default=None)
    chat.add_argument("--profile", "-p", default=None)
    chat.add_argument("--max-turns", type=int, default=None)
    chat.add_argument("--source", default=None)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse(argv if argv is not None else sys.argv[1:])
    prompt = args.z_prompt
    profile = args.profile
    session = None
    if args.command == "chat":
        prompt = args.query
        profile = args.profile or profile
        session = args.resume
        if not args.oneshot:
            print("fake hermes: chat without --oneshot", file=sys.stderr)
            return 2
    if not prompt:
        print("fake hermes: missing prompt", file=sys.stderr)
        return 2

    if prompt.startswith("SLEEP:"):
        seconds = float(prompt.split(":", 1)[1])
        time.sleep(seconds)
        print("slept")
        return 0
    if prompt.startswith("FAIL:"):
        print(prompt.split(":", 1)[1], file=sys.stderr)
        return 3
    if prompt == "ECHO_ARGV":
        print("ARGV:" + "\x1f".join(sys.argv[1:]))
        return 0
    if prompt == "ECHO_ENV":
        keys = sorted(
            k
            for k in os.environ
            if k.startswith("HERMES_") or k in {"PATH", "HOME", "OWNER_SECRET", "AWS_SECRET_ACCESS_KEY"}
        )
        print("ENV:" + ",".join(keys))
        return 0
    if prompt == "PATH_LEAK":
        print("see /home/secret-user/.hermes/config.yaml and Bearer super-secret-token")
        return 0
    if prompt == "ANSI":
        sys.stdout.write("\x1b[31mred\x1b[0m answer\n")
        return 0
    if prompt.startswith("BIG:"):
        size = int(prompt.split(":", 1)[1])
        sys.stdout.write("X" * size)
        return 0
    if prompt == "TRAP":
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        time.sleep(30)
        return 0

    bits = [f"answer:{prompt}"]
    if profile:
        bits.append(f"profile:{profile}")
    if session:
        bits.append(f"session:{session}")
    print(" ".join(bits))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
