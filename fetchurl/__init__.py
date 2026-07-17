"""Fetchurl SDK for Python.

Protocol-level client for fetchurl content-addressable cache servers.
Works with any HTTP library through the Fetcher/AsyncFetcher protocols.

Zero dependencies — uses only the Python standard library.

Three levels of usage:

  # 1. One-liner with stdlib
  fetchurl.fetch(UrllibFetcher(), "sha256", hash, urls, output)

  # 2. Custom HTTP client — implement the Fetcher protocol
  class MyFetcher:
      def get(self, url, headers):
          resp = requests.get(url, headers=headers, stream=True)
          return (resp.status_code, resp.raw)

  fetchurl.fetch(MyFetcher(), "sha256", hash, urls, output)

  # 3. Low-level — drive the state machine yourself
  session = FetchSession("sha256", hash, urls)
  while attempt := session.next_attempt():
      # make HTTP request with whatever library you want
      ...
"""

from __future__ import annotations

import hashlib
import os
import random
import re
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import BinaryIO, Protocol, runtime_checkable


# --- Errors ---


class FetchUrlError(Exception):
    """Base exception for fetchurl SDK."""


class UnsupportedAlgorithmError(FetchUrlError):
    """The requested hash algorithm is not supported."""

    def __init__(self, algo: str):
        self.algo = algo
        super().__init__(f"unsupported algorithm: {algo}")


class HashMismatchError(FetchUrlError):
    """The content hash does not match the expected hash."""

    def __init__(self, expected: str, actual: str):
        self.expected = expected
        self.actual = actual
        super().__init__(f"hash mismatch: expected {expected}, got {actual}")


class AllSourcesFailedError(FetchUrlError):
    """All servers and sources failed to provide the content."""

    def __init__(self, last_error: Exception | None = None):
        self.last_error = last_error
        super().__init__("all sources failed")


class PartialWriteError(FetchUrlError):
    """Bytes were written before failure; output is tainted."""

    def __init__(self, cause: Exception):
        self.cause = cause
        super().__init__(f"partial write: {cause}")


class MissingSourceUrlsError(FetchUrlError):
    """Source URLs are required by the protocol."""

    def __init__(self):
        super().__init__("source_urls is required")


# --- Algorithm helpers ---

_SUPPORTED_ALGOS = {"sha1", "sha256", "sha512"}

# Full digest length in hex characters for each supported algorithm.
_DIGEST_HEX_LEN = {
    "sha1": 40,
    "sha256": 64,
    "sha512": 128,
}


def normalize_algo(name: str) -> str:
    """Normalize algorithm name per spec: lowercase, only [a-z0-9]."""
    return re.sub(r"[^a-z0-9]", "", name.lower())


def is_supported(algo: str) -> bool:
    """Check if a hash algorithm is supported."""
    return normalize_algo(algo) in _SUPPORTED_ALGOS


def expected_hex_length(algo: str) -> int:
    """Expected hex length of a full digest for *algo*.

    Raises UnsupportedAlgorithmError if the algorithm is not supported.
    """
    key = normalize_algo(algo)
    try:
        return _DIGEST_HEX_LEN[key]
    except KeyError:
        raise UnsupportedAlgorithmError(key) from None


def normalize_content_hash(algo: str, hash: str | None) -> str:
    """Normalize a content hash per the fetchurl spec: full-length lowercase hex.

    Rejects None, blank, non-hex, and wrong-length values before any network I/O.
    Mixed-case hex is accepted and returned lowercased.

    Raises:
        FetchUrlError: if the hash is missing or not valid hex for the algorithm.
        UnsupportedAlgorithmError: if *algo* is not supported.
    """
    if hash is None or not str(hash).strip():
        raise FetchUrlError("hash is required")
    key = normalize_algo(algo)
    expected_len = expected_hex_length(key)
    lower = str(hash).lower()
    if len(lower) != expected_len:
        raise FetchUrlError(
            f"hash must be {expected_len} hex characters for {key} "
            f"(got {len(lower)})"
        )
    for c in lower:
        if c not in "0123456789abcdef":
            raise FetchUrlError("hash must be hexadecimal")
    return lower


# --- SFV helpers (RFC 8941 string lists) ---


def encode_source_urls(urls: list[str]) -> str:
    """Encode URLs as an RFC 8941 string list for X-Source-Urls header."""
    return ", ".join(
        '"' + url.replace("\\", "\\\\").replace('"', '\\"') + '"' for url in urls
    )


def parse_fetchurl_server(value: str) -> list[str]:
    """Parse FETCHURL_SERVER env var (RFC 8941 string list)."""
    value = value.strip()
    if not value:
        return []
    if not value.startswith('"'):
        return [value]
    results: list[str] = []
    i = 0
    while i < len(value):
        while i < len(value) and value[i] in " \t":
            i += 1
        if i >= len(value):
            break
        if value[i] != '"':
            while i < len(value) and value[i] != ",":
                i += 1
            if i < len(value):
                i += 1
            continue
        i += 1
        s: list[str] = []
        while i < len(value):
            if value[i] == "\\" and i + 1 < len(value):
                s.append(value[i + 1])
                i += 2
            elif value[i] == '"':
                i += 1
                break
            else:
                s.append(value[i])
                i += 1
        results.append("".join(s))
        while i < len(value) and value[i] != ",":
            i += 1
        if i < len(value):
            i += 1
    return results


# --- FetchAttempt ---


@dataclass(frozen=True)
class FetchAttempt:
    """A single fetch attempt with URL and headers."""

    url: str
    headers: dict[str, str] = field(default_factory=dict)


# --- HashVerifier ---


class HashVerifier:
    """Wraps a binary writer, computes hash, verifies on finish().

    Usage::

        verifier = session.verifier(output_file)
        while chunk := body.read(65536):
            verifier.write(chunk)
        verifier.finish()  # raises HashMismatchError on failure
    """

    def __init__(self, algo: str, expected_hash: str, writer: BinaryIO):
        self._writer = writer
        normalized = normalize_algo(algo)
        # Spec: hashes MUST be lowercase hex of the full digest. Fail early on garbage.
        self._expected = normalize_content_hash(normalized, expected_hash)
        self._hasher = hashlib.new(normalized)
        self._bytes_written = 0

    @property
    def bytes_written(self) -> int:
        return self._bytes_written

    def write(self, data: bytes) -> int:
        n = self._writer.write(data)
        if n is None:
            n = len(data)
        self._hasher.update(data[:n])
        self._bytes_written += n
        return n

    def finish(self) -> None:
        """Verify hash. Raises HashMismatchError on failure."""
        actual = self._hasher.hexdigest()
        if actual != self._expected:
            raise HashMismatchError(self._expected, actual)


# --- FetchSession ---


class FetchSession:
    """State machine driving the fetchurl client protocol.

    Servers from ``FETCHURL_SERVER`` are tried first (with X-Source-Urls
    header forwarded), then direct source URLs in random order per spec.

    The public constructor reads ``FETCHURL_SERVER`` from the environment.
    For tests or embedding with an explicit server list, use
    :meth:`with_servers` (does not read the environment).

    The caller iterates through attempts, makes HTTP requests
    with their preferred library, and reports results back::

        session = FetchSession("sha256", hash, source_urls)
        while attempt := session.next_attempt():
            # attempt.url and attempt.headers tell you what to request
            ...
            session.report_success()  # or report_partial()
    """

    def __init__(
        self,
        algo: str,
        hash: str,
        source_urls: list[str],
    ):
        servers = parse_fetchurl_server(os.environ.get("FETCHURL_SERVER", ""))
        self._init(servers, algo, hash, source_urls)

    @classmethod
    def with_servers(
        cls,
        servers: list[str],
        algo: str,
        hash: str,
        source_urls: list[str],
    ) -> FetchSession:
        """Create a session with an explicit list of cache server base URLs.

        Same attempt order as the public constructor: servers first (with
        ``X-Source-Urls``), then direct sources shuffled. Does not read
        ``FETCHURL_SERVER``. Pass an empty ``servers`` list to try only
        ``source_urls``.

        ``servers`` entries are base URLs ready for ``/{algo}/{hash}``
        (trailing ``/`` is stripped).
        """
        session = cls.__new__(cls)
        session._init(list(servers), algo, hash, source_urls)
        return session

    def _init(
        self,
        servers: list[str],
        algo: str,
        hash: str,
        source_urls: list[str],
    ) -> None:
        if not source_urls:
            raise MissingSourceUrlsError()

        # Fail early on blank entries — same spirit as hash validation before any I/O.
        sources: list[str] = []
        for source_url in source_urls:
            if source_url is None or not str(source_url).strip():
                raise FetchUrlError("source URL must not be blank")
            sources.append(source_url)

        # *servers* comes from __init__ (env) or with_servers (explicit); do not re-read env.
        algo = normalize_algo(algo)
        if not is_supported(algo):
            raise UnsupportedAlgorithmError(algo)

        self._algo = algo
        # Spec: hashes MUST be lowercase hex of the full digest. Fail early on garbage.
        self._hash = normalize_content_hash(algo, hash)
        self._done = False
        self._success = False
        self._attempts: list[FetchAttempt] = []
        self._current = 0

        source_header = encode_source_urls(sources)

        for server in servers:
            # SFV can yield empty strings (e.g. ""); skip rather than building a relative path.
            if server is None or not str(server).strip():
                continue
            base = server.rstrip("/")
            if not base:
                continue
            url = f"{base}/{algo}/{self._hash}"
            self._attempts.append(
                FetchAttempt(url=url, headers={"X-Source-Urls": source_header})
            )

        direct = list(sources)
        random.shuffle(direct)
        for url in direct:
            self._attempts.append(FetchAttempt(url=url))

    def next_attempt(self) -> FetchAttempt | None:
        """Get the next attempt, or None if session is finished.

        If an attempt fails without writing bytes, just call next_attempt() again.
        """
        if self._done or self._current >= len(self._attempts):
            return None
        attempt = self._attempts[self._current]
        self._current += 1
        return attempt

    def report_success(self) -> None:
        """Mark the session as successful. Stops further attempts."""
        self._done = True
        self._success = True

    def report_partial(self) -> None:
        """Mark that bytes were written before failure. Stops further attempts."""
        self._done = True

    def succeeded(self) -> bool:
        return self._success

    def verifier(self, writer: BinaryIO) -> HashVerifier:
        """Create a HashVerifier for this session's algo and expected hash."""
        return HashVerifier(self._algo, self._hash, writer)


# --- Fetcher protocols ---


@runtime_checkable
class Fetcher(Protocol):
    """Sync HTTP client protocol.

    Implement this to plug in any HTTP library.

    Example with requests::

        class RequestsFetcher:
            def get(self, url, headers):
                resp = requests.get(url, headers=headers, stream=True)
                return (resp.status_code, resp.raw)
    """

    def get(self, url: str, headers: dict[str, str]) -> tuple[int, BinaryIO]:
        """Make a GET request. Returns (status_code, readable_body)."""
        ...


@runtime_checkable
class AsyncFetcher(Protocol):
    """Async HTTP client protocol.

    Implement this to plug in any async HTTP library.

    Example with aiohttp::

        class AiohttpFetcher:
            def __init__(self):
                self._session = aiohttp.ClientSession()

            async def get(self, url, headers):
                resp = await self._session.get(url, headers=headers)
                return (resp.status, resp.content.iter_chunked(65536))
    """

    async def get(
        self, url: str, headers: dict[str, str]
    ) -> tuple[int, AsyncIterator[bytes]]:
        """Make a GET request. Returns (status_code, async_body_chunks)."""
        ...


# --- UrllibFetcher (stdlib, zero deps) ---


class UrllibFetcher:
    """Fetcher using urllib.request (stdlib, zero dependencies)."""

    def get(self, url: str, headers: dict[str, str]) -> tuple[int, BinaryIO]:
        import urllib.error
        import urllib.request

        req = urllib.request.Request(url, headers=headers)
        try:
            resp = urllib.request.urlopen(req)
            return (resp.status, resp)
        except urllib.error.HTTPError as e:
            return (e.code, e)


# --- Convenience functions ---

_CHUNK_SIZE = 64 * 1024


def _close_body(body: object) -> None:
    """Best-effort close of an HTTP response body.

    urllib and similar clients keep the connection open until the body is
    closed. Errors from close must not override the real fetch outcome or
    abort multi-source fallback (same pattern as the Java SDK).
    """
    close = getattr(body, "close", None)
    if not callable(close):
        return
    try:
        close()
    except Exception:
        return


async def _aclose_body(body: object) -> None:
    """Best-effort close of an async response body / chunk iterator."""
    aclose = getattr(body, "aclose", None)
    if callable(aclose):
        try:
            await aclose()
        except Exception:
            return
        return
    _close_body(body)


def fetch(
    fetcher: Fetcher,
    algo: str,
    hash: str,
    source_urls: list[str],
    out: BinaryIO,
) -> None:
    """High-level sync fetch. Handles the full protocol loop.

    Raises AllSourcesFailedError or PartialWriteError on failure.
    """
    session = FetchSession(algo, hash, source_urls)
    last_error: Exception | None = None

    while attempt := session.next_attempt():
        try:
            status, body = fetcher.get(attempt.url, dict(attempt.headers))
        except Exception as e:
            last_error = e
            continue

        if status != 200:
            last_error = FetchUrlError(f"unexpected status {status}")
            _close_body(body)
            continue

        verifier = session.verifier(out)
        try:
            while chunk := body.read(_CHUNK_SIZE):
                verifier.write(chunk)
            verifier.finish()
            session.report_success()
            return
        except Exception as e:
            last_error = e
            if verifier.bytes_written > 0:
                session.report_partial()
                raise PartialWriteError(e) from e
        finally:
            _close_body(body)

    raise AllSourcesFailedError(last_error)


async def async_fetch(
    fetcher: AsyncFetcher,
    algo: str,
    hash: str,
    source_urls: list[str],
    out: BinaryIO,
) -> None:
    """High-level async fetch. Handles the full protocol loop.

    Raises AllSourcesFailedError or PartialWriteError on failure.
    """
    session = FetchSession(algo, hash, source_urls)
    last_error: Exception | None = None

    while attempt := session.next_attempt():
        try:
            status, chunks = await fetcher.get(attempt.url, dict(attempt.headers))
        except Exception as e:
            last_error = e
            continue

        if status != 200:
            last_error = FetchUrlError(f"unexpected status {status}")
            await _aclose_body(chunks)
            continue

        verifier = session.verifier(out)
        try:
            async for chunk in chunks:
                verifier.write(chunk)
            verifier.finish()
            session.report_success()
            return
        except Exception as e:
            last_error = e
            if verifier.bytes_written > 0:
                session.report_partial()
                raise PartialWriteError(e) from e
        finally:
            await _aclose_body(chunks)

    raise AllSourcesFailedError(last_error)
