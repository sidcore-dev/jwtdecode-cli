"""Command-line entry point for jwtdecode-cli."""
from __future__ import annotations

import argparse
import json
import sys

from .core import InvalidTokenError, decode_jwt, describe_time_claims

WARNING = (
    "WARNING: this only decodes the token -- it does NOT verify the signature.\n"
    "Never treat this output as proof the token is authentic or untampered."
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="jwtdecode-cli",
        description="Decode (never verify) a JWT's header and payload for inspection and debugging.",
    )
    parser.add_argument(
        "token",
        nargs="?",
        default=None,
        help="The JWT to decode. If omitted, the token is read from stdin.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit only {\"header\": ..., \"payload\": ...} as JSON, no banner or claim notes",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    token = args.token
    if token is None:
        token = sys.stdin.read()
    token = token.strip()

    if not token:
        print("jwtdecode-cli: error: no token provided (pass it as an argument or via stdin)", file=sys.stderr)
        return 1

    try:
        header, payload, _signature = decode_jwt(token)
    except InvalidTokenError as exc:
        print(f"jwtdecode-cli: error: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps({"header": header, "payload": payload}, indent=2))
        return 0

    print(WARNING)
    print()
    print("=== Header ===")
    print(json.dumps(header, indent=2))
    print()
    print("=== Payload ===")
    print(json.dumps(payload, indent=2))

    notes = describe_time_claims(payload)
    if notes:
        print()
        print("=== Claim notes ===")
        for note in notes:
            print(note)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
