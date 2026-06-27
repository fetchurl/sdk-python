# fetchurl Python SDK

Protocol-level client for [fetchurl](https://github.com/fetchurl/spec) content-addressable cache servers.

Zero runtime dependencies — uses only the Python standard library. Works with any HTTP library via `Fetcher` / `AsyncFetcher` protocols.

## Install

```bash
pip install fetchurl-sdk
# or
uv add fetchurl-sdk
```

## Protocol

Normative behavior: **[fetchurl/spec](https://github.com/fetchurl/spec)** (`SPEC.md`).

Reference server: **[fetchurl/fetchurl](https://github.com/fetchurl/fetchurl)**.

## Usage

```python
from fetchurl import fetch, UrllibFetcher, parse_fetchurl_server
import os

servers = parse_fetchurl_server(os.environ.get("FETCHURL_SERVER", ""))
# Or drive FetchSession yourself with your HTTP client — see package docstring.
```

Clients **must** treat the server as untrusted and verify the hash (this SDK does that for you).

## Environment

| Variable | Meaning |
|----------|---------|
| `FETCHURL_SERVER` | Server base URL(s) per the [spec](https://github.com/fetchurl/spec/blob/main/SPEC.md). Empty/absent disables server use. |

## Development

```bash
uv sync --dev
uv run python -m unittest test_fetchurl.py
# Integration (Docker + image):
# FETCHURL_TEST_IMAGE=fetchurl:local uv run --extra test python -m unittest test_fetchurl_integration.py
```
