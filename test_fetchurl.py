"""Tests for fetchurl SDK."""

import hashlib
import io
import os
import unittest
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread
from unittest.mock import patch

import fetchurl


def sha256hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class TestNormalizeAlgo(unittest.TestCase):
    def test_lowercase(self):
        self.assertEqual(fetchurl.normalize_algo("SHA-256"), "sha256")

    def test_already_normalized(self):
        self.assertEqual(fetchurl.normalize_algo("sha256"), "sha256")

    def test_strips_non_alnum(self):
        self.assertEqual(fetchurl.normalize_algo("SHA_512"), "sha512")


class TestIsSupported(unittest.TestCase):
    def test_supported(self):
        self.assertTrue(fetchurl.is_supported("sha256"))
        self.assertTrue(fetchurl.is_supported("SHA-256"))
        self.assertTrue(fetchurl.is_supported("sha1"))
        self.assertTrue(fetchurl.is_supported("sha512"))

    def test_unsupported(self):
        self.assertFalse(fetchurl.is_supported("md5"))


class TestNormalizeContentHash(unittest.TestCase):
    def test_expected_hex_length(self):
        self.assertEqual(fetchurl.expected_hex_length("sha1"), 40)
        self.assertEqual(fetchurl.expected_hex_length("sha256"), 64)
        self.assertEqual(fetchurl.expected_hex_length("sha512"), 128)
        self.assertEqual(fetchurl.expected_hex_length("SHA-256"), 64)

    def test_expected_hex_length_unsupported(self):
        with self.assertRaises(fetchurl.UnsupportedAlgorithmError):
            fetchurl.expected_hex_length("md5")

    def test_lowercases(self):
        upper = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
        self.assertEqual(
            fetchurl.normalize_content_hash("sha256", upper),
            upper.lower(),
        )

    def test_rejects_wrong_length(self):
        with self.assertRaises(fetchurl.FetchUrlError) as ctx:
            fetchurl.normalize_content_hash("sha256", "abcd")
        self.assertIn("hex characters", str(ctx.exception))

    def test_rejects_non_hex(self):
        almost = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85g"
        with self.assertRaises(fetchurl.FetchUrlError) as ctx:
            fetchurl.normalize_content_hash("sha256", almost)
        self.assertIn("hexadecimal", str(ctx.exception))

    def test_rejects_blank(self):
        with self.assertRaises(fetchurl.FetchUrlError):
            fetchurl.normalize_content_hash("sha256", "  ")
        with self.assertRaises(fetchurl.FetchUrlError):
            fetchurl.normalize_content_hash("sha256", None)  # type: ignore[arg-type]


class TestSFV(unittest.TestCase):
    def test_encode(self):
        self.assertEqual(
            fetchurl.encode_source_urls(["https://a.com", "https://b.com"]),
            '"https://a.com", "https://b.com"',
        )

    def test_parse(self):
        parsed = fetchurl.parse_fetchurl_server('"https://a.com", "https://b.com"')
        self.assertEqual(parsed, ["https://a.com", "https://b.com"])

    def test_roundtrip(self):
        urls = ["https://cdn.example.com/f.tar.gz", "https://mirror.org/a.tgz"]
        encoded = fetchurl.encode_source_urls(urls)
        decoded = fetchurl.parse_fetchurl_server(encoded)
        self.assertEqual(decoded, urls)

    def test_parse_with_params(self):
        parsed = fetchurl.parse_fetchurl_server('"https://a.com";q=0.9, "https://b.com"')
        self.assertEqual(parsed, ["https://a.com", "https://b.com"])

    def test_empty(self):
        self.assertEqual(fetchurl.parse_fetchurl_server(""), [])


class TestHashVerifier(unittest.TestCase):
    def test_success(self):
        data = b"hello world"
        h = sha256hex(data)
        out = io.BytesIO()
        v = fetchurl.HashVerifier("sha256", h, out)
        v.write(data)
        self.assertEqual(v.bytes_written, len(data))
        v.finish()
        self.assertEqual(out.getvalue(), data)

    def test_success_uppercase_expected(self):
        """Spec requires lowercase hex; callers may still pass mixed case."""
        data = b"hello world"
        h = sha256hex(data).upper()
        out = io.BytesIO()
        v = fetchurl.HashVerifier("sha256", h, out)
        v.write(data)
        v.finish()
        self.assertEqual(out.getvalue(), data)

    def test_mismatch(self):
        data = b"hello world"
        wrong_hash = sha256hex(b"wrong")
        out = io.BytesIO()
        v = fetchurl.HashVerifier("sha256", wrong_hash, out)
        v.write(data)
        with self.assertRaises(fetchurl.HashMismatchError) as ctx:
            v.finish()
        self.assertEqual(ctx.exception.expected, wrong_hash)

    def test_rejects_non_hex_expected(self):
        bad = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85g"
        with self.assertRaises(fetchurl.FetchUrlError):
            fetchurl.HashVerifier("sha256", bad, io.BytesIO())

    def test_rejects_wrong_length_expected(self):
        with self.assertRaises(fetchurl.FetchUrlError):
            fetchurl.HashVerifier("sha256", "abcd", io.BytesIO())

    def test_rejects_blank_expected(self):
        with self.assertRaises(fetchurl.FetchUrlError):
            fetchurl.HashVerifier("sha256", "  ", io.BytesIO())


class TestFetchSession(unittest.TestCase):
    def test_missing_source_urls(self):
        with self.assertRaises(fetchurl.MissingSourceUrlsError):
            fetchurl.FetchSession("sha256", "abc", [])

    def test_blank_source_url_rejected(self):
        h = sha256hex(b"test")
        with self.assertRaises(fetchurl.FetchUrlError) as ctx:
            fetchurl.FetchSession("sha256", h, ["http://src", "  "])
        self.assertIn("source URL must not be blank", str(ctx.exception))

    def test_none_source_url_rejected(self):
        h = sha256hex(b"test")
        with self.assertRaises(fetchurl.FetchUrlError) as ctx:
            fetchurl.FetchSession(
                "sha256", h, ["http://src", None]  # type: ignore[list-item]
            )
        self.assertIn("source URL must not be blank", str(ctx.exception))

    @patch.dict(
        os.environ,
        {"FETCHURL_SERVER": '"  ", "http://cache/api/fetchurl", ""'},
    )
    def test_blank_servers_skipped(self):
        """Empty SFV server entries must not become relative /algo/hash URLs."""
        h = sha256hex(b"test")
        session = fetchurl.FetchSession("sha256", h, ["http://src"])

        a1 = session.next_attempt()
        self.assertIsNotNone(a1)
        self.assertTrue(
            a1.url.startswith("http://cache/api/fetchurl/sha256/"),
            f"blank servers must be skipped, got {a1.url}",
        )
        self.assertIn("X-Source-Urls", a1.headers)

        a2 = session.next_attempt()
        self.assertEqual(a2.url, "http://src")
        self.assertEqual(a2.headers, {})
        self.assertIsNone(session.next_attempt())

    def test_unsupported_algo(self):
        with self.assertRaises(fetchurl.UnsupportedAlgorithmError):
            fetchurl.FetchSession("md5", "abc", ["http://src"])

    def test_empty_hash_rejected(self):
        with self.assertRaises(fetchurl.FetchUrlError) as ctx:
            fetchurl.FetchSession("sha256", "", ["http://src"])
        self.assertIn("hash is required", str(ctx.exception))

    def test_blank_hash_rejected(self):
        with self.assertRaises(fetchurl.FetchUrlError) as ctx:
            fetchurl.FetchSession("sha256", "   ", ["http://src"])
        self.assertIn("hash is required", str(ctx.exception))

    def test_none_hash_rejected(self):
        with self.assertRaises(fetchurl.FetchUrlError) as ctx:
            fetchurl.FetchSession("sha256", None, ["http://src"])  # type: ignore[arg-type]
        self.assertIn("hash is required", str(ctx.exception))

    def test_non_hex_hash_rejected(self):
        with self.assertRaises(fetchurl.FetchUrlError) as ctx:
            fetchurl.FetchSession(
                "sha256",
                "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
                ["http://src"],
            )
        self.assertIn("hexadecimal", str(ctx.exception))

    def test_wrong_length_hash_rejected(self):
        with self.assertRaises(fetchurl.FetchUrlError) as ctx:
            fetchurl.FetchSession("sha256", "abcd", ["http://src"])
        self.assertIn("hex characters", str(ctx.exception))

    @patch.dict(os.environ, {"FETCHURL_SERVER": '"http://cache1/api/fetchurl", "http://cache2/api/fetchurl"'})
    def test_attempt_ordering(self):
        h = sha256hex(b"test")
        session = fetchurl.FetchSession(
            "sha256", h, ["http://src1"]
        )

        a1 = session.next_attempt()
        self.assertIsNotNone(a1)
        self.assertTrue(a1.url.startswith("http://cache1/api/fetchurl/sha256/"))
        self.assertIn("X-Source-Urls", a1.headers)

        a2 = session.next_attempt()
        self.assertTrue(a2.url.startswith("http://cache2/api/fetchurl/sha256/"))

        a3 = session.next_attempt()
        self.assertEqual(a3.url, "http://src1")
        self.assertEqual(a3.headers, {})

        self.assertIsNone(session.next_attempt())
        self.assertFalse(session.succeeded())

    @patch.dict(os.environ, {"FETCHURL_SERVER": '"http://cache/api/fetchurl"'})
    def test_hash_lowercased_in_server_url(self):
        h = sha256hex(b"test").upper()
        session = fetchurl.FetchSession("sha256", h, ["http://src"])
        attempt = session.next_attempt()
        self.assertIsNotNone(attempt)
        self.assertTrue(attempt.url.endswith(f"/sha256/{h.lower()}"))
        self.assertNotIn(h, attempt.url)

    @patch.dict(os.environ, {"FETCHURL_SERVER": '"http://cache/api/fetchurl"'})
    def test_success_stops(self):
        h = sha256hex(b"test")
        session = fetchurl.FetchSession("sha256", h, ["http://src"])
        session.next_attempt()
        session.report_success()
        self.assertTrue(session.succeeded())
        self.assertIsNone(session.next_attempt())

    @patch.dict(os.environ, {"FETCHURL_SERVER": '"http://cache/api/fetchurl"'})
    def test_partial_stops(self):
        h = sha256hex(b"test")
        session = fetchurl.FetchSession("sha256", h, ["http://src"])
        session.next_attempt()
        session.report_partial()
        self.assertFalse(session.succeeded())
        self.assertIsNone(session.next_attempt())

    def test_with_servers_explicit_order(self):
        """with_servers does not read FETCHURL_SERVER; servers then direct sources."""
        h = sha256hex(b"test")
        with patch.dict(os.environ, {"FETCHURL_SERVER": '"http://env-must-not-appear/api/fetchurl"'}):
            session = fetchurl.FetchSession.with_servers(
                ["http://cache1/api/fetchurl", "http://cache2/api/fetchurl/"],
                "sha256",
                h,
                ["http://src1"],
            )
        a1 = session.next_attempt()
        self.assertIsNotNone(a1)
        self.assertEqual(a1.url, f"http://cache1/api/fetchurl/sha256/{h}")
        self.assertIn("X-Source-Urls", a1.headers)

        a2 = session.next_attempt()
        self.assertEqual(a2.url, f"http://cache2/api/fetchurl/sha256/{h}")

        a3 = session.next_attempt()
        self.assertEqual(a3.url, "http://src1")
        self.assertEqual(a3.headers, {})
        self.assertIsNone(session.next_attempt())

    def test_with_servers_empty_skips_cache(self):
        """Empty servers list tries only direct sources (no env fallback)."""
        h = sha256hex(b"test")
        with patch.dict(os.environ, {"FETCHURL_SERVER": '"http://env-must-not-appear/api/fetchurl"'}):
            session = fetchurl.FetchSession.with_servers(
                [], "sha256", h, ["http://src-only"]
            )
        attempt = session.next_attempt()
        self.assertIsNotNone(attempt)
        self.assertEqual(attempt.url, "http://src-only")
        self.assertEqual(attempt.headers, {})
        self.assertIsNone(session.next_attempt())

    def test_with_servers_missing_sources(self):
        h = sha256hex(b"test")
        with self.assertRaises(fetchurl.MissingSourceUrlsError):
            fetchurl.FetchSession.with_servers(["http://cache"], "sha256", h, [])


class _CloseableBody(io.BytesIO):
    """BytesIO that records close() so tests can assert response cleanup."""

    def __init__(self, data: bytes = b""):
        super().__init__(data)
        self.closed_count = 0

    def close(self) -> None:
        self.closed_count += 1
        super().close()


class TestFetch(unittest.TestCase):
    """Integration tests using a real HTTP server."""

    @staticmethod
    def _start_server(handler_class) -> tuple[HTTPServer, str]:
        server = HTTPServer(("127.0.0.1", 0), handler_class)
        port = server.server_address[1]
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, f"http://127.0.0.1:{port}"

    @staticmethod
    def _stop_server(server: HTTPServer) -> None:
        """shutdown alone leaves the listening socket open (ResourceWarning)."""
        server.shutdown()
        server.server_close()

    def test_direct_download(self):
        content = b"test content"
        h = sha256hex(content)

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(content)

            def log_message(self, *args):
                pass

        server, url = self._start_server(Handler)
        try:
            out = io.BytesIO()
            # Empty servers (env var not set by default/or empty)
            with patch.dict(os.environ, {}, clear=True):
                fetchurl.fetch(fetchurl.UrllibFetcher(), "sha256", h, [url], out)
            self.assertEqual(out.getvalue(), content)
        finally:
            self._stop_server(server)

    def test_hash_mismatch_raises_partial(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"wrong content")

            def log_message(self, *args):
                pass

        server, url = self._start_server(Handler)
        try:
            out = io.BytesIO()
            with self.assertRaises(fetchurl.PartialWriteError):
                with patch.dict(os.environ, {}, clear=True):
                    fetchurl.fetch(
                        fetchurl.UrllibFetcher(), "sha256", sha256hex(b"right"), [url], out
                    )
        finally:
            self._stop_server(server)

    def test_all_sources_failed(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(404)
                self.end_headers()

            def log_message(self, *args):
                pass

        server, url = self._start_server(Handler)
        try:
            out = io.BytesIO()
            with self.assertRaises(fetchurl.AllSourcesFailedError) as cm:
                with patch.dict(os.environ, {}, clear=True):
                    fetchurl.fetch(
                        fetchurl.UrllibFetcher(), "sha256", sha256hex(b"x"), [url], out
                    )
            self.assertIsInstance(cm.exception.last_error, fetchurl.FetchUrlError)
            self.assertIn("404", str(cm.exception.last_error))
        finally:
            self._stop_server(server)

    def test_server_fallback_to_direct(self):
        content = b"fallback content"
        h = sha256hex(content)

        class BadServer(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(500)
                self.end_headers()

            def log_message(self, *args):
                pass

        class GoodSource(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(content)

            def log_message(self, *args):
                pass

        bad, bad_url = self._start_server(BadServer)
        good, good_url = self._start_server(GoodSource)
        try:
            out = io.BytesIO()
            # Set server via env var
            with patch.dict(os.environ, {"FETCHURL_SERVER": f'"{bad_url}/api/fetchurl"'}):
                fetchurl.fetch(
                    fetchurl.UrllibFetcher(), "sha256", h, [good_url], out
                )
            self.assertEqual(out.getvalue(), content)
        finally:
            self._stop_server(bad)
            self._stop_server(good)

    def test_closes_body_on_success(self):
        content = b"close me"
        h = sha256hex(content)
        body = _CloseableBody(content)

        class OkFetcher:
            def get(self, url, headers):
                return (200, body)

        out = io.BytesIO()
        with patch.dict(os.environ, {}, clear=True):
            fetchurl.fetch(OkFetcher(), "sha256", h, ["http://src"], out)
        self.assertEqual(out.getvalue(), content)
        self.assertGreaterEqual(body.closed_count, 1)

    def test_closes_body_on_non_200(self):
        body = _CloseableBody(b"nope")

        class NotFoundFetcher:
            def get(self, url, headers):
                return (404, body)

        out = io.BytesIO()
        with self.assertRaises(fetchurl.AllSourcesFailedError):
            with patch.dict(os.environ, {}, clear=True):
                fetchurl.fetch(
                    NotFoundFetcher(), "sha256", sha256hex(b"x"), ["http://src"], out
                )
        self.assertGreaterEqual(body.closed_count, 1)

    def test_closes_body_on_hash_mismatch(self):
        body = _CloseableBody(b"wrong content")

        class OkFetcher:
            def get(self, url, headers):
                return (200, body)

        out = io.BytesIO()
        with self.assertRaises(fetchurl.PartialWriteError):
            with patch.dict(os.environ, {}, clear=True):
                fetchurl.fetch(
                    OkFetcher(), "sha256", sha256hex(b"right"), ["http://src"], out
                )
        self.assertGreaterEqual(body.closed_count, 1)

    def test_closes_body_on_non_200_then_falls_back(self):
        content = b"fallback ok"
        h = sha256hex(content)
        bad_body = _CloseableBody(b"")
        good_body = _CloseableBody(content)
        calls = {"n": 0}

        class FallbackFetcher:
            def get(self, url, headers):
                calls["n"] += 1
                if calls["n"] == 1:
                    return (500, bad_body)
                return (200, good_body)

        out = io.BytesIO()
        with patch.dict(os.environ, {}, clear=True):
            fetchurl.fetch(
                FallbackFetcher(), "sha256", h, ["http://a", "http://b"], out
            )
        self.assertEqual(out.getvalue(), content)
        self.assertGreaterEqual(bad_body.closed_count, 1)
        self.assertGreaterEqual(good_body.closed_count, 1)


class TestAsyncFetch(unittest.IsolatedAsyncioTestCase):
    async def test_async_fetch_success_and_closes(self):
        content = b"async content"
        h = sha256hex(content)
        closed = {"n": 0}

        class Chunks:
            def __init__(self, data: bytes):
                self._data = data
                self._done = False

            def __aiter__(self):
                return self

            async def __anext__(self):
                if self._done:
                    raise StopAsyncIteration
                self._done = True
                return self._data

            async def aclose(self):
                closed["n"] += 1

        class AsyncOk:
            async def get(self, url, headers):
                return (200, Chunks(content))

        out = io.BytesIO()
        with patch.dict(os.environ, {}, clear=True):
            await fetchurl.async_fetch(
                AsyncOk(), "sha256", h, ["http://src"], out
            )
        self.assertEqual(out.getvalue(), content)
        self.assertGreaterEqual(closed["n"], 1)

    async def test_async_fetch_closes_on_non_200(self):
        closed = {"n": 0}

        class Chunks:
            def __aiter__(self):
                return self

            async def __anext__(self):
                raise StopAsyncIteration

            async def aclose(self):
                closed["n"] += 1

        class Async404:
            async def get(self, url, headers):
                return (404, Chunks())

        out = io.BytesIO()
        with self.assertRaises(fetchurl.AllSourcesFailedError):
            with patch.dict(os.environ, {}, clear=True):
                await fetchurl.async_fetch(
                    Async404(), "sha256", sha256hex(b"x"), ["http://src"], out
                )
        self.assertGreaterEqual(closed["n"], 1)


if __name__ == "__main__":
    unittest.main()
