import base64
import json
import unittest

from jwtdecode_cli.core import InvalidTokenError, decode_jwt, describe_time_claims, format_timestamp


def _b64url(data: dict) -> str:
    raw = json.dumps(data, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def make_token(header: dict, payload: dict, signature: str = "sig") -> str:
    return f"{_b64url(header)}.{_b64url(payload)}.{signature}"


class TestDecodeJwt(unittest.TestCase):
    def test_decodes_header_and_payload(self) -> None:
        token = make_token({"alg": "HS256", "typ": "JWT"}, {"sub": "123", "name": "Ada"})
        header, payload, signature = decode_jwt(token)
        self.assertEqual(header, {"alg": "HS256", "typ": "JWT"})
        self.assertEqual(payload, {"sub": "123", "name": "Ada"})
        self.assertEqual(signature, "sig")

    def test_handles_missing_base64_padding(self) -> None:
        # Real-world JWTs frequently need padding restored; segment lengths vary.
        token = make_token({"alg": "none"}, {"a": 1, "b": 2, "c": 3, "d": 4})
        header, payload, _sig = decode_jwt(token)
        self.assertEqual(header["alg"], "none")
        self.assertEqual(payload["d"], 4)

    def test_rejects_wrong_segment_count(self) -> None:
        with self.assertRaises(InvalidTokenError):
            decode_jwt("only.two")

    def test_rejects_non_base64_segment(self) -> None:
        with self.assertRaises(InvalidTokenError):
            decode_jwt("not-base64-!!!.also-not-base64-!!!.sig")

    def test_rejects_non_json_payload(self) -> None:
        not_json = base64.urlsafe_b64encode(b"hello world").rstrip(b"=").decode()
        header_ok = _b64url({"alg": "none"})
        with self.assertRaises(InvalidTokenError):
            decode_jwt(f"{header_ok}.{not_json}.sig")

    def test_rejects_empty_segments(self) -> None:
        with self.assertRaises(InvalidTokenError):
            decode_jwt("..sig")


class TestFormatTimestamp(unittest.TestCase):
    def test_formats_known_epoch(self) -> None:
        self.assertEqual(format_timestamp(0), "1970-01-01T00:00:00Z")

    def test_rejects_non_numeric(self) -> None:
        with self.assertRaises(ValueError):
            format_timestamp("not-a-number")


class TestDescribeTimeClaims(unittest.TestCase):
    def test_reports_exp_and_iat(self) -> None:
        notes = describe_time_claims({"exp": 0, "iat": 0})
        joined = "\n".join(notes)
        self.assertIn("exp: 0 (1970-01-01T00:00:00Z)", joined)
        self.assertIn("iat: 0 (1970-01-01T00:00:00Z)", joined)
        self.assertIn("already passed", joined)

    def test_no_notes_when_no_time_claims(self) -> None:
        self.assertEqual(describe_time_claims({"sub": "123"}), [])

    def test_handles_non_numeric_time_claim_gracefully(self) -> None:
        notes = describe_time_claims({"exp": "soon"})
        self.assertIn("not a valid numeric timestamp", notes[0])


if __name__ == "__main__":
    unittest.main()
