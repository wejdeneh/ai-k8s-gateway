#!/usr/bin/env python3
"""
Utility script: mint test JWTs for local development and the demo.

Run from the project root:
    python -m app.auth.mint_tokens
    python -m app.auth.mint_tokens --agent agent-deploy

Tokens are printed to stdout so they can be copy-pasted into curl / httpie
or captured by a shell script:
    TOKEN=$(python -m app.auth.mint_tokens --agent agent-readonly --bare)
"""

import argparse
import sys

from app.auth.jwt_handler import AGENT_IDENTITIES, create_token
from app.config import settings


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Mint short-lived JWTs for AI Gateway agent identities.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="\n".join(
            f"  {k:20s} role={v['role']}" for k, v in AGENT_IDENTITIES.items()
        ),
    )
    parser.add_argument(
        "--agent",
        default=None,
        metavar="AGENT_ID",
        help="Agent ID to mint a token for. Omit to mint tokens for all identities.",
    )
    parser.add_argument(
        "--bare",
        action="store_true",
        help="Print only the raw JWT string (useful for shell variable capture).",
    )
    args = parser.parse_args()

    agents = [args.agent] if args.agent else list(AGENT_IDENTITIES.keys())

    for agent_id in agents:
        try:
            token = create_token(agent_id)
        except ValueError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            sys.exit(1)

        if args.bare:
            # Only print the token — no decoration — for shell capture.
            print(token)
        else:
            role = AGENT_IDENTITIES[agent_id]["role"]
            print(f"\n{'─' * 64}")
            print(f"  Agent     : {agent_id}")
            print(f"  Role      : {role}")
            print(f"  Algorithm : {settings.jwt_algorithm}")
            print(f"  TTL       : {settings.jwt_ttl_minutes} minutes")
            print(f"  Token     : {token}")

    if not args.bare:
        print(f"\n{'─' * 64}")
        print(
            "\nUsage example:\n"
            "  curl -X POST http://localhost:8000/agent-action \\\n"
            '       -H "Authorization: Bearer <token>" \\\n'
            "       -H 'Content-Type: application/json' \\\n"
            '       -d \'{"action": "list", "resource": "pods",'
            ' "namespace": "default", "params": {}}\''
        )


if __name__ == "__main__":
    main()
