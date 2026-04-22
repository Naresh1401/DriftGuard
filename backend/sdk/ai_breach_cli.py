"""
DriftGuard AI breach CLI
========================
Tiny command-line wrapper around `AIBreachClient`. Stdlib only.

Usage:
    python -m sdk.ai_breach_cli patterns --base https://driftguard-api-mbdj.onrender.com
    python -m sdk.ai_breach_cli demo     --base https://driftguard-api-mbdj.onrender.com
    python -m sdk.ai_breach_cli forecast --base https://driftguard-api-mbdj.onrender.com
    python -m sdk.ai_breach_cli playbook --pattern Prompt_Injection
    python -m sdk.ai_breach_cli scan --signals signals.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from sdk.ai_breach_client import AIBreachClient


def _print(payload) -> None:
    print(json.dumps(payload, indent=2, default=str))


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="driftguard-ai-breach", description=__doc__)
    p.add_argument("command", choices=["patterns", "scan", "risk", "playbooks", "playbook", "forecast", "correlate", "demo"])
    p.add_argument("--base", default="http://localhost:8000", help="DriftGuard base URL")
    p.add_argument("--prefix", default="/api/v1")
    p.add_argument("--api-key", default=None)
    p.add_argument("--pattern", default=None, help="Pattern enum value for `playbook`")
    p.add_argument("--signals", default=None, help="Path to JSON file: list of AI signals")
    p.add_argument("--human-events", default=None, help="Path to JSON file: list of human-drift events (for correlate)")
    p.add_argument("--window-minutes", type=int, default=60)
    args = p.parse_args(argv)

    client = AIBreachClient(base_url=args.base, api_prefix=args.prefix, api_key=args.api_key)

    def _load(path):
        if not path:
            return []
        return json.loads(Path(path).read_text())

    if args.command == "patterns":
        _print(client.patterns())
    elif args.command == "playbooks":
        _print(client.playbooks())
    elif args.command == "playbook":
        if not args.pattern:
            p.error("--pattern is required for `playbook`")
        _print(client.playbook(args.pattern))
    elif args.command == "forecast":
        _print(client.forecast())
    elif args.command == "demo":
        _print(client.demo())
    elif args.command == "scan":
        _print(client.scan(_load(args.signals)))
    elif args.command == "risk":
        _print(client.risk(_load(args.signals)))
    elif args.command == "correlate":
        _print(client.correlate(_load(args.signals), _load(args.human_events), args.window_minutes))

    return 0


if __name__ == "__main__":
    sys.exit(main())
