import base64
import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout

from jwtdecode_cli.cli import main


def _b64url(data: dict) -> str:
    raw = json.dumps(data, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def make_token(header: dict, payload: dict) -> str:
    return f"{_b64url(header)}.{_b64url(payload)}.sig"


class TestCli(unittest.TestCase):
    def test_decodes_and_prints_warning(self) -> None:
        token = make_token({"alg": "HS256"}, {"sub": "abc"})
        out = io.StringIO()
        with redirect_stdout(out):
            code = main([token])
        self.assertEqual(code, 0)
        text = out.getvalue()
        self.assertIn("does NOT verify", text)
        self.assertIn('"alg": "HS256"', text)
        self.assertIn('"sub": "abc"', text)

    def test_json_flag_emits_clean_json_only(self) -> None:
        token = make_token({"alg": "none"}, {"sub": "abc"})
        out = io.StringIO()
        with redirect_stdout(out):
            code = main([token, "--json"])
        self.assertEqual(code, 0)
        parsed = json.loads(out.getvalue())
        self.assertEqual(parsed, {"header": {"alg": "none"}, "payload": {"sub": "abc"}})

    def test_reads_token_from_stdin_when_omitted(self) -> None:
        token = make_token({"alg": "none"}, {"sub": "xyz"})
        out = io.StringIO()
        import unittest.mock as mock

        with mock.patch("sys.stdin", io.StringIO(token)):
            with redirect_stdout(out):
                code = main([])
        self.assertEqual(code, 0)
        self.assertIn('"sub": "xyz"', out.getvalue())

    def test_invalid_token_errors(self) -> None:
        err = io.StringIO()
        with redirect_stderr(err):
            code = main(["not.a.jwt.token"])
        self.assertEqual(code, 1)
        self.assertIn("error", err.getvalue())

    def test_empty_token_errors(self) -> None:
        err = io.StringIO()
        with redirect_stderr(err):
            code = main([""])
        self.assertEqual(code, 1)
        self.assertIn("no token provided", err.getvalue())

    def test_claim_notes_shown_for_exp(self) -> None:
        token = make_token({"alg": "none"}, {"exp": 0})
        out = io.StringIO()
        with redirect_stdout(out):
            code = main([token])
        self.assertEqual(code, 0)
        self.assertIn("Claim notes", out.getvalue())
        self.assertIn("exp: 0", out.getvalue())


if __name__ == "__main__":
    unittest.main()
