# jwtdecode-cli

[![CI](https://github.com/sidcore-dev/jwtdecode-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/sidcore-dev/jwtdecode-cli/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/sidcore-dev/jwtdecode-cli)](https://github.com/sidcore-dev/jwtdecode-cli/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)


A small, dependency-free command-line tool that decodes a JWT's header and
payload for inspection and debugging, pretty-printed as JSON, with plain
English notes for common time-based claims.

## Do NOT use this to trust a token

**This tool only decodes. It never verifies a signature.** Anyone can put
any claims they want into a JWT and it will decode here just fine — that is
the entire point of a debugging tool like this, but it also means the
output tells you nothing about whether the token is genuine, was issued by
who it claims, or hasn't been tampered with. Never use `jwtdecode-cli`
output as the basis for an authorization decision, and never treat a
successfully-decoded token as proof of anything. If you need to verify a
token, use your JWT library's signature verification against the correct
key — this tool is strictly for looking at what's inside a token you
already have, while debugging.

## Why

Pasting a token into a random website to see what's inside it is a bad
habit, especially for anything from a real system. `jwtdecode-cli` does the
same base64url + JSON decode entirely locally, using only the Python
standard library, so nothing about the token ever leaves your machine.

## Install

```bash
pip install .
```

This installs a `jwtdecode-cli` command on your PATH.

## Usage

```bash
jwtdecode-cli "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkYSBMb3ZlbGFjZSIsImlhdCI6MTczNTY4OTYwMCwiZXhwIjoxNzM1NjkzMjAwfQ.dummySignature"
```

```
WARNING: this only decodes the token -- it does NOT verify the signature.
Never treat this output as proof the token is authentic or untampered.

=== Header ===
{
  "alg": "HS256",
  "typ": "JWT"
}

=== Payload ===
{
  "sub": "1234567890",
  "name": "Ada Lovelace",
  "iat": 1735689600,
  "exp": 1735693200
}

=== Claim notes ===
exp: 1735693200 (2025-01-01T01:00:00Z) -- already passed
iat: 1735689600 (2025-01-01T00:00:00Z)
```

A token can also be piped in on stdin instead of passed as an argument,
which avoids it lingering in your shell history:

```bash
echo -n "$TOKEN" | jwtdecode-cli
```

### Options

| Flag       | Description                                                          |
|------------|-------------------------------------------------------------------------|
| `token`    | The JWT to decode (omit to read it from stdin instead)                  |
| `--json`   | Emit only `{"header": ..., "payload": ...}` as JSON — no banner, no notes |

### Exit codes

- `0` — token decoded successfully
- `1` — no token given, or the token isn't well-formed (wrong number of
  segments, invalid base64url, or a segment that isn't a JSON object)

## Development

```bash
pip install -e .
python -m unittest discover -s tests -v
```

## License

All rights reserved. This code is public for viewing and reference only —
no license is granted to use, copy, modify, or redistribute it. See
[LICENSE](LICENSE) for details.
