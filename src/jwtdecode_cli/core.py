"""Core JWT decoding logic.

This module only ever decodes. It never checks a signature, never contacts
a JWKS endpoint, and never validates expiry as a security control. Nothing
decoded here should be treated as authenticated or trustworthy.
"""
from __future__ import annotations

import base64
import binascii
import json
from datetime import datetime, timezone

TIME_CLAIMS = ("exp", "iat", "nbf")


class InvalidTokenError(ValueError):
    """Raised when a string doesn't look like a decodable JWT."""


def _b64url_decode(segment: str) -> bytes:
    padded = segment + "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except (binascii.Error, ValueError) as exc:
        raise InvalidTokenError(f"could not base64url-decode segment: {exc}") from exc


def _decode_json_segment(segment: str, name: str) -> dict:
    raw = _b64url_decode(segment)
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InvalidTokenError(f"{name} segment is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise InvalidTokenError(f"{name} segment did not decode to a JSON object")
    return data


def decode_jwt(token: str) -> tuple[dict, dict, str]:
    """Split and decode `token` into (header, payload, signature_b64).

    Performs no verification whatsoever — this is a pure decode. Raises
    InvalidTokenError if the token isn't a well-formed JWT (three
    dot-separated segments, first two of which are base64url JSON objects).
    """
    token = token.strip()
    parts = token.split(".")
    if len(parts) != 3:
        raise InvalidTokenError(f"expected 3 dot-separated segments (header.payload.signature), got {len(parts)}")

    header_b64, payload_b64, signature_b64 = parts
    if not header_b64 or not payload_b64:
        raise InvalidTokenError("header and payload segments must not be empty")

    header = _decode_json_segment(header_b64, "header")
    payload = _decode_json_segment(payload_b64, "payload")
    return header, payload, signature_b64


def format_timestamp(value) -> str:
    """Format a numeric epoch-seconds claim value as an ISO-8601 UTC string.

    Raises ValueError if `value` isn't numeric.
    """
    seconds = float(value)
    dt = datetime.fromtimestamp(seconds, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def describe_time_claims(payload: dict) -> list[str]:
    """Return human-readable 'name: raw (UTC date)' lines for exp/iat/nbf, if present."""
    notes = []
    now = datetime.now(tz=timezone.utc).timestamp()
    for claim in TIME_CLAIMS:
        if claim not in payload:
            continue
        raw = payload[claim]
        try:
            formatted = format_timestamp(raw)
        except (TypeError, ValueError, OSError):
            notes.append(f"{claim}: {raw!r} (not a valid numeric timestamp)")
            continue
        line = f"{claim}: {raw} ({formatted})"
        if claim == "exp":
            line += " -- already passed" if float(raw) < now else " -- in the future"
        if claim == "nbf":
            line += " -- already valid" if float(raw) < now else " -- not yet valid"
        notes.append(line)
    return notes
