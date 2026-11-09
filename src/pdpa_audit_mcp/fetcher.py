"""Async HTTP client wrapper with SSRF protection, streaming byte limits,
and redirect validation.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse, urlsplit
from urllib.robotparser import RobotFileParser

import httpx

from pdpa_audit_mcp.config import get_settings
from pdpa_audit_mcp.safety import (
    SecurityError,
    SSRFProtectedTransport,
    validate_redirect,
    validate_url,
)

if TYPE_CHECKING:
    from pdpa_audit_mcp.config import Settings


@dataclass
class FetchResult:
    """Structured result of a safe HTTP fetch operation."""

    url: str
    final_url: str
    status_code: int
    text: str
    headers: dict[str, str] = field(default_factory=dict)
    redirect_history: list[str] = field(default_factory=list)
    is_truncated: bool = False
    content_type: str = ""
    error_message: str | None = None


class SafeFetcher:
    """Async HTTP fetcher enforcing SSRF protection, manual redirect validation,
    streaming decoded byte limits (1 MB), overall deadline, and robots.txt parsing.
    """

    def __init__(
        self,
        settings: Settings | None = None,
        client: httpx.AsyncClient | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        self.settings = settings or get_settings()
        self.user_agent = self.settings.user_agent
        self.timeout = self.settings.timeout_seconds
        self.fetch_deadline_seconds = getattr(self.settings, "fetch_deadline_seconds", 20.0)
        self.max_bytes = self.settings.max_response_bytes
        self.max_redirects = self.settings.max_redirects
        self.allow_private = self.settings.allow_private

        # Transport setup: default constructor path creates SSRFProtectedTransport in __init__
        if transport is not None:
            self._transport = transport
        elif client is not None and getattr(client, "_transport", None) is not None:
            self._transport = client._transport
        else:
            self._transport = SSRFProtectedTransport(allow_private=self.allow_private)

        # Client setup: created once, reused for all requests
        if client is not None:
            self._client = client
            self._owns_client = False
        else:
            self._client = httpx.AsyncClient(
                transport=self._transport,
                follow_redirects=False,
                trust_env=False,
                timeout=self.timeout,
            )
            self._owns_client = True

        self._robot_parsers: dict[str, RobotFileParser] = {}
        self.page_cache: dict[str, FetchResult] = {}
        self._crawled_canonical_urls: set[str] = set()

    async def __aenter__(self) -> SafeFetcher:
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        """Close internal HTTP client when owned."""
        if self._owns_client and self._client is not None:
            await self._client.aclose()

    async def fetch(
        self,
        url: str,
        check_content_type: bool = True,
        use_cache: bool = True,
        is_robots_txt: bool = False,
    ) -> FetchResult:
        """Fetch a single URL with manual redirect following, IP pinning, size caps, and caching."""
        normalized_url = url.strip()

        # Check page cache using normalized key
        if use_cache and normalized_url in self.page_cache:
            return self.page_cache[normalized_url]

        # Check crawl limit (robots.txt does not count towards max_crawl_pages)
        limit = self.settings.max_crawl_pages
        if not is_robots_txt and len(self._crawled_canonical_urls) >= limit:
            return FetchResult(
                url=url,
                final_url=normalized_url,
                status_code=0,
                text="",
                error_message=f"Maximum page crawl limit of {limit} reached.",
            )

        deadline = self.fetch_deadline_seconds
        try:
            async with asyncio.timeout(deadline):
                return await self._fetch_internal(
                    url=url,
                    normalized_url=normalized_url,
                    check_content_type=check_content_type,
                    use_cache=use_cache,
                    is_robots_txt=is_robots_txt,
                )
        except TimeoutError:
            return FetchResult(
                url=url,
                final_url=normalized_url,
                status_code=0,
                text="",
                error_message=f"Fetch operation exceeded overall deadline of {deadline}s.",
            )

    async def _fetch_internal(
        self,
        url: str,
        normalized_url: str,
        check_content_type: bool,
        use_cache: bool,
        is_robots_txt: bool,
    ) -> FetchResult:
        current_url = normalized_url
        redirect_history: list[str] = []
        redirect_count = 0

        # Step 1: Initial SSRF check and IP resolution on hop 1
        valid, err, pinned_ip = validate_url(current_url, allow_private=self.allow_private)
        if not valid:
            raise SecurityError(f"SSRF validation blocked '{current_url}': {err}")

        parsed_origin = urlsplit(current_url)
        if (
            pinned_ip
            and isinstance(self._transport, SSRFProtectedTransport)
            and parsed_origin.hostname
        ):
            self._transport.pin_host(parsed_origin.hostname, pinned_ip)

        headers = {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }

        while True:
            try:
                req = self._client.build_request("GET", current_url, headers=headers)
                response = await self._client.send(req, stream=True)
            except SecurityError:
                raise
            except (httpx.HTTPError, OSError, TimeoutError) as exc:
                return FetchResult(
                    url=url,
                    final_url=current_url,
                    status_code=0,
                    text="",
                    redirect_history=redirect_history,
                    error_message=f"HTTP request failed: {exc}",
                )

            # Check for redirect status codes
            if response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get("Location")
                await response.aclose()

                if not location:
                    return FetchResult(
                        url=url,
                        final_url=current_url,
                        status_code=response.status_code,
                        text="",
                        redirect_history=redirect_history,
                        error_message="Redirect received without Location header.",
                    )

                redirect_history.append(current_url)
                valid, r_err, next_url, next_ip = validate_redirect(
                    current_url=current_url,
                    location_header=location,
                    redirect_count=redirect_count,
                    max_redirects=self.max_redirects,
                    allow_private=self.allow_private,
                )
                if not valid or not next_url:
                    raise SecurityError(f"Unsafe redirect from '{current_url}' blocked: {r_err}")

                redirect_count += 1
                current_url = next_url

                # Pin new redirect destination IP if using SSRFProtectedTransport
                next_parsed = urlsplit(next_url)
                if (
                    next_ip
                    and isinstance(self._transport, SSRFProtectedTransport)
                    and next_parsed.hostname
                ):
                    self._transport.pin_host(next_parsed.hostname, next_ip)

                continue

            # Non-redirect response: inspect content-type
            resp_headers = dict(response.headers)
            content_type = resp_headers.get("content-type", "").lower()

            if check_content_type and not any(
                allowed in content_type
                for allowed in ("text/html", "application/xhtml+xml", "text/plain")
            ):
                await response.aclose()
                return FetchResult(
                    url=url,
                    final_url=current_url,
                    status_code=response.status_code,
                    text="",
                    headers=resp_headers,
                    redirect_history=redirect_history,
                    content_type=content_type,
                    error_message=(
                        f"Unsupported content type '{content_type}'. Only HTML is parsed."
                    ),
                )

            # Stream decoded bytes up to max_bytes (1 MB cap to prevent zip/decompression bombs)
            chunks: list[bytes] = []
            total_bytes = 0
            is_truncated = False

            try:
                async for chunk in response.aiter_bytes():
                    remaining = self.max_bytes - total_bytes
                    if len(chunk) > remaining:
                        chunks.append(chunk[:remaining])
                        total_bytes += remaining
                        is_truncated = True
                        break
                    chunks.append(chunk)
                    total_bytes += len(chunk)
                    if total_bytes >= self.max_bytes:
                        is_truncated = True
                        break
            finally:
                await response.aclose()

            body_bytes = b"".join(chunks)
            encoding = response.encoding or "utf-8"
            decoded_text = body_bytes.decode(encoding, errors="replace")

            res = FetchResult(
                url=url,
                final_url=current_url,
                status_code=response.status_code,
                text=decoded_text,
                headers=resp_headers,
                redirect_history=redirect_history,
                is_truncated=is_truncated,
                content_type=content_type,
            )
            if use_cache:
                self.page_cache[normalized_url] = res
                if current_url != normalized_url:
                    self.page_cache[current_url] = res
            if not is_robots_txt:
                self._crawled_canonical_urls.add(current_url)
            return res

    async def can_fetch_url(self, target_url: str) -> bool:
        """Check robots.txt permissions for target_url before crawling."""
        parsed = urlparse(target_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        if origin not in self._robot_parsers:
            rp = RobotFileParser()
            robots_url = f"{origin}/robots.txt"
            try:
                res = await self.fetch(robots_url, check_content_type=False, is_robots_txt=True)
                if res.status_code == 200 and res.text:
                    rp.parse(res.text.splitlines())
                else:
                    rp.allow_all = True
            except SecurityError:
                raise
            except (httpx.HTTPError, OSError, TimeoutError):
                rp.allow_all = True
            self._robot_parsers[origin] = rp

        return self._robot_parsers[origin].can_fetch(self.user_agent, target_url)
