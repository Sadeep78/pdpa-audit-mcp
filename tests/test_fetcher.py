"""Unit and integration tests for SafeFetcher with mock transport and SSRF enforcement."""

from unittest.mock import patch

import httpx
import pytest

from pdpa_audit_mcp.config import Settings
from pdpa_audit_mcp.fetcher import SafeFetcher
from pdpa_audit_mcp.safety import SecurityError


class TestSafeFetcher:
    """Tests for streaming byte limits, content type filtering, and redirect validation."""

    @pytest.mark.asyncio
    async def test_content_type_filtering(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={"Content-Type": "application/octet-stream"},
                content=b"\x00\x01\x02\x03",
            )

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        fetcher = SafeFetcher(client=client)

        with patch(
            "pdpa_audit_mcp.fetcher.validate_url", return_value=(True, None, "93.184.216.34")
        ):
            res = await fetcher.fetch("https://example.com/file.bin")
            assert res.status_code == 200
            assert "Unsupported content type" in (res.error_message or "")
            assert res.text == ""

    @pytest.mark.asyncio
    async def test_streaming_decoded_byte_limit_enforced(self):
        """Ensure streaming stops when exceeding 1 MB to prevent decompression bombs."""
        large_body = b"<html>" + (b"A" * 1_200_000) + b"</html>"

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={"Content-Type": "text/html; charset=utf-8"},
                content=large_body,
            )

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        # Set max_bytes to 500 KB for test
        settings = Settings(max_response_bytes=500_000, allow_private=True)
        fetcher = SafeFetcher(settings=settings, client=client)

        with patch(
            "pdpa_audit_mcp.fetcher.validate_url", return_value=(True, None, "93.184.216.34")
        ):
            res = await fetcher.fetch("https://example.com/large.html")
            assert res.is_truncated is True
            assert len(res.text.encode("utf-8")) <= 550_000  # Stopped after crossing threshold

    @pytest.mark.asyncio
    async def test_redirect_to_private_ip_blocked_when_disallowed(self):
        """Verify redirect to 127.0.0.1 is blocked when allow_private=False."""

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/start":
                return httpx.Response(
                    302,
                    headers={"Location": "http://127.0.0.1:8000/internal"},
                )
            return httpx.Response(200, text="Internal")

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        settings = Settings(allow_private=False)
        fetcher = SafeFetcher(settings=settings, client=client)

        with patch(
            "pdpa_audit_mcp.fetcher.validate_url", return_value=(True, None, "93.184.216.34")
        ):
            with pytest.raises(SecurityError, match="Unsafe redirect.*blocked"):
                await fetcher.fetch("https://example.com/start")

    @pytest.mark.asyncio
    async def test_redirect_to_private_ip_allowed_with_flag(self):
        """Verify redirect to local server succeeds when allow_private=True."""

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/start":
                return httpx.Response(
                    302,
                    headers={"Location": "http://127.0.0.1:8000/internal"},
                )
            return httpx.Response(
                200,
                headers={"Content-Type": "text/html"},
                text="<html><body>Safe Local</body></html>",
            )

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        settings = Settings(allow_private=True)
        fetcher = SafeFetcher(settings=settings, client=client)

        res = await fetcher.fetch("http://127.0.0.1:8000/start")
        assert res.status_code == 200
        assert "Safe Local" in res.text
        assert res.final_url == "http://127.0.0.1:8000/internal"

    @pytest.mark.asyncio
    async def test_max_redirects_exceeded(self):
        """Verify exceeding 3 redirects raises SecurityError."""

        def handler(request: httpx.Request) -> httpx.Response:
            # Infinite redirect loop
            return httpx.Response(302, headers={"Location": "https://example.com/loop"})

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        fetcher = SafeFetcher(client=client)

        with patch(
            "pdpa_audit_mcp.fetcher.validate_url", return_value=(True, None, "93.184.216.34")
        ):
            with pytest.raises(SecurityError, match="Redirect limit exceeded"):
                await fetcher.fetch("https://example.com/loop")

    @pytest.mark.asyncio
    async def test_robots_txt_honoured(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/robots.txt":
                return httpx.Response(
                    200,
                    headers={"Content-Type": "text/plain"},
                    text="User-agent: *\nDisallow: /secret/\nAllow: /public/\n",
                )
            return httpx.Response(200, headers={"Content-Type": "text/html"}, text="OK")

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        fetcher = SafeFetcher(client=client)

        with patch(
            "pdpa_audit_mcp.fetcher.validate_url", return_value=(True, None, "93.184.216.34")
        ):
            allowed = await fetcher.can_fetch_url("https://example.com/public/page")
            disallowed = await fetcher.can_fetch_url("https://example.com/secret/admin")

            assert allowed is True
            assert disallowed is False

    def test_proxy_env_vars_ignored(self, monkeypatch):
        """Ensure trust_env=False is strictly configured so proxies are ignored."""
        monkeypatch.setenv("HTTP_PROXY", "http://evil-proxy.local:8080")
        monkeypatch.setenv("HTTPS_PROXY", "https://evil-proxy.local:8443")
        monkeypatch.setenv("ALL_PROXY", "socks5://evil-proxy.local:1080")

        fetcher = SafeFetcher()
        assert fetcher._client.trust_env is False

    @pytest.mark.asyncio
    async def test_client_lifecycle_and_async_context_manager(self):
        """Verify client is created once, reused, and closed properly."""
        async with SafeFetcher() as fetcher:
            assert fetcher._client is not None
            assert fetcher._client.is_closed is False
            client_ref = fetcher._client
            assert fetcher._client is client_ref

        # After exiting context manager, client is closed
        assert client_ref.is_closed is True

    @pytest.mark.asyncio
    async def test_dns_rebinding_default_constructor_ip_pinning(self):
        """Simulate rebinding using default constructor SafeFetcher():
        getaddrinfo returns public IP on call 1 and 127.0.0.1 afterwards.
        Assert connection goes to the public IP and getaddrinfo is called once per hop.
        """
        import socket
        from unittest.mock import AsyncMock, MagicMock

        import httpcore

        call_count = 0

        def rebinding_dns(host, port, *args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))]
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80))]

        # Use default constructor path (no injected transport or client)
        fetcher = SafeFetcher()

        with patch("socket.getaddrinfo", side_effect=rebinding_dns):
            with patch.object(
                httpcore.AnyIOBackend, "connect_tcp", new_callable=AsyncMock
            ) as mock_connect:
                # Return a dummy stream so request completes
                dummy_stream = MagicMock()
                dummy_stream.read = AsyncMock(return_value=b"")
                dummy_stream.aclose = AsyncMock()
                mock_connect.return_value = dummy_stream

                try:
                    await fetcher.fetch("http://rebinding-target.com")
                except Exception:
                    pass

                # Assert connection went to the pinned public IP
                assert mock_connect.await_count == 1
                assert mock_connect.await_args.args[:2] == ("93.184.216.34", 80)
                # Assert getaddrinfo was called exactly once for that hop
                assert call_count == 1

        await fetcher.aclose()
        assert fetcher._client.is_closed is True

    @pytest.mark.asyncio
    async def test_fetch_overall_deadline_timeout(self):
        """Ensure per-fetch overall deadline terminates slow drip streaming."""
        import asyncio

        async def slow_stream():
            yield b"<html>"
            await asyncio.sleep(0.5)
            yield b"</html>"

        def slow_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={"Content-Type": "text/html"},
                content=slow_stream(),
            )

        client = httpx.AsyncClient(transport=httpx.MockTransport(slow_handler))
        settings = Settings(fetch_deadline_seconds=0.1, allow_private=True)
        fetcher = SafeFetcher(settings=settings, client=client)

        with patch(
            "pdpa_audit_mcp.fetcher.validate_url", return_value=(True, None, "93.184.216.34")
        ):
            res = await fetcher.fetch("https://example.com/slow")
            assert res.status_code == 0
            assert "deadline" in (res.error_message or "").lower()

        await fetcher.aclose()

    @pytest.mark.asyncio
    async def test_cache_normalisation_single_key(self):
        """Ensure URL is stripped once and uses identical key for lookup and store."""
        call_count = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            return httpx.Response(200, headers={"Content-Type": "text/html"}, text="Page")

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        fetcher = SafeFetcher(client=client)

        with patch(
            "pdpa_audit_mcp.fetcher.validate_url", return_value=(True, None, "93.184.216.34")
        ):
            res1 = await fetcher.fetch("  https://example.com/page  ")
            assert res1.text == "Page"
            assert "https://example.com/page" in fetcher.page_cache

            # Second fetch with or without whitespace returns cached
            res2 = await fetcher.fetch("https://example.com/page")
            assert res2.text == "Page"
            assert call_count == 1

        await fetcher.aclose()

    @pytest.mark.asyncio
    async def test_redirect_counted_once_toward_crawl_limit(self):
        """Ensure a redirected page counts only once towards max_crawl_pages."""

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/old":
                return httpx.Response(301, headers={"Location": "https://example.com/new"})
            return httpx.Response(200, headers={"Content-Type": "text/html"}, text="New")

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        fetcher = SafeFetcher(client=client)

        with patch(
            "pdpa_audit_mcp.fetcher.validate_url", return_value=(True, None, "93.184.216.34")
        ):
            await fetcher.fetch("https://example.com/old")
            assert len(fetcher._crawled_canonical_urls) == 1
            assert "https://example.com/new" in fetcher._crawled_canonical_urls

        await fetcher.aclose()

    @pytest.mark.asyncio
    async def test_robots_txt_not_counted_toward_crawl_limit(self):
        """Ensure robots.txt does not count towards max_crawl_pages."""

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/robots.txt":
                return httpx.Response(200, text="User-agent: *\nDisallow: /admin")
            return httpx.Response(200, headers={"Content-Type": "text/html"}, text="Page")

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        settings = Settings(max_crawl_pages=1, allow_private=True)
        fetcher = SafeFetcher(settings=settings, client=client)

        with patch(
            "pdpa_audit_mcp.fetcher.validate_url", return_value=(True, None, "93.184.216.34")
        ):
            # Check robots.txt
            can_fetch = await fetcher.can_fetch_url("https://example.com/public")
            assert can_fetch is True
            # robots.txt must NOT be counted in _crawled_canonical_urls
            assert len(fetcher._crawled_canonical_urls) == 0

            # First real page fetch works (reaches 1)
            res1 = await fetcher.fetch("https://example.com/p1")
            assert res1.status_code == 200
            assert len(fetcher._crawled_canonical_urls) == 1

            # Second page hits limit of 1
            res2 = await fetcher.fetch("https://example.com/p2")
            assert res2.status_code == 0
            assert "crawl limit" in (res2.error_message or "").lower()

        await fetcher.aclose()

    @pytest.mark.asyncio
    async def test_redirect_chain_revalidates_every_hop(self):
        """Ensure redirect chain re-validates each hop and blocks metadata IP on hop 2."""

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/hop1":
                return httpx.Response(302, headers={"Location": "https://example.com/hop2"})
            if request.url.path == "/hop2":
                return httpx.Response(
                    302, headers={"Location": "http://169.254.169.254/latest/meta-data"}
                )
            return httpx.Response(200, text="Final")

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        fetcher = SafeFetcher(client=client)

        from pdpa_audit_mcp.safety import validate_url as real_validate_url

        def redirect_validate(u: str, **kwargs):
            if "169.254.169.254" in u:
                return real_validate_url(u, **kwargs)
            return (True, None, "93.184.216.34")

        with patch("pdpa_audit_mcp.fetcher.validate_url", side_effect=redirect_validate):
            with pytest.raises(SecurityError, match="Unsafe redirect.*blocked"):
                await fetcher.fetch("https://example.com/hop1")

        await fetcher.aclose()

    @pytest.mark.asyncio
    async def test_real_gzip_bomb_truncated_safely(self):
        """Verify that streaming decoded bytes truncates gzip payloads exceeding 1MB."""
        import gzip

        # 1.5 MB uncompressed HTML payload
        uncompressed = (
            b"<html><body>" + (b"PDPA Privacy Safeguard Test " * 60_000) + b"</body></html>"
        )
        assert len(uncompressed) > 1_500_000
        # Highly compressible (~15 KB compressed)
        compressed = gzip.compress(uncompressed)
        assert len(compressed) < 50_000

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={"Content-Type": "text/html; charset=utf-8", "Content-Encoding": "gzip"},
                content=compressed,
            )

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        # Default max_bytes = 1_000_000 (1 MB)
        fetcher = SafeFetcher(client=client)

        with patch(
            "pdpa_audit_mcp.fetcher.validate_url", return_value=(True, None, "93.184.216.34")
        ):
            res = await fetcher.fetch("https://example.com/gzip-bomb.html")
            assert res.is_truncated is True
            # Decoded text size must be capped at max_bytes (1 MB)
            assert len(res.text.encode("utf-8")) <= fetcher.max_bytes
            assert "PDPA Privacy Safeguard Test" in res.text
