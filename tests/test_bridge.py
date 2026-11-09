"""Unit and integration tests for the REST bridge, dashboard, and host/token security."""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from pdpa_audit_mcp.api.bridge import (
    _AUDIT_LOCK,
    BRIDGE_TOKEN,
    DASHBOARD_PATH,
    app,
    verify_bind_host,
)

client = TestClient(app, base_url="http://127.0.0.1:8765")
AUTH_HEADERS = {"X-Bridge-Token": BRIDGE_TOKEN}


class TestBridgeSecurityControls:
    """Tests for Host validation, per-run token, Origin checks, Content-Type, and size limits."""

    def test_health_endpoint_accessible_without_token(self):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok", "service": "pdpa-audit-bridge"}

        # Verify standard security response headers
        assert resp.headers["Cache-Control"] == "no-store"
        assert resp.headers["X-Content-Type-Options"] == "nosniff"
        assert resp.headers["Referrer-Policy"] == "no-referrer"
        assert "default-src 'none'" in resp.headers["Content-Security-Policy"]
        assert "nonce-" in resp.headers["Content-Security-Policy"]

    def test_dashboard_served_at_root_with_injected_token_and_nonce(self):
        resp = client.get("/")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        body = resp.text

        # Verify token is injected in meta tag
        assert f'<meta name="bridge-token" content="{BRIDGE_TOKEN}">' in body

        # Extract CSP nonce from headers and verify it is injected in style/script
        csp_header = resp.headers["Content-Security-Policy"]
        nonce_match = re.search(r"script-src 'nonce-([a-zA-Z0-9_\-]+)'", csp_header)
        assert nonce_match is not None
        nonce = nonce_match.group(1)
        assert f'<script nonce="{nonce}">' in body
        assert f'<style nonce="{nonce}">' in body

    def test_csp_nonce_per_response_and_token_never_leaked(self):
        """Confirm CSP nonce is generated per-response and token is never leaked."""
        resp1 = client.get("/")
        resp2 = client.get("/")
        assert resp1.status_code == 200
        assert resp2.status_code == 200

        csp_pat = r"script-src 'nonce-([a-zA-Z0-9_\-]+)'"
        m1 = re.search(csp_pat, resp1.headers["Content-Security-Policy"])
        m2 = re.search(csp_pat, resp2.headers["Content-Security-Policy"])
        assert m1 is not None and m2 is not None

        nonce1 = m1.group(1)
        nonce2 = m2.group(1)

        # 1. Nonce is generated per response and changes
        assert nonce1 != nonce2
        # 2. Nonce is different from the per-run bridge token
        assert nonce1 != BRIDGE_TOKEN
        assert nonce2 != BRIDGE_TOKEN

        # 3. Token is never placed in error messages, URLs, or query strings
        err_resp = client.get("/checklist", headers={"X-Bridge-Token": "invalid-attempt"})
        assert err_resp.status_code == 401
        assert BRIDGE_TOKEN not in err_resp.text
        assert BRIDGE_TOKEN not in str(err_resp.url)

        type_err = client.post("/audit/full", headers={"X-Bridge-Token": "bad"})
        assert BRIDGE_TOKEN not in type_err.text

    def test_token_authentication_enforced_on_audit_endpoints(self):
        # Missing token
        resp_missing = client.get("/checklist")
        assert resp_missing.status_code == 401
        assert "invalid or missing" in resp_missing.json()["error_message"].lower()

        # Invalid token
        resp_invalid = client.get("/checklist", headers={"X-Bridge-Token": "bad-token-12345"})
        assert resp_invalid.status_code == 401

        # Valid token
        resp_valid = client.get("/checklist", headers=AUTH_HEADERS)
        assert resp_valid.status_code == 200
        assert resp_valid.json()["status"] == "ok"

    def test_host_header_spoofing_rejected(self):
        """Host headers pointing to unauthorized domains must be rejected (blocks DNS rebinding)."""
        resp = client.get("/health", headers={"Host": "evil.attacker.com"})
        assert resp.status_code == 421
        assert "misdirected host" in resp.json()["error_message"].lower()

    def test_foreign_origin_rejected_and_no_cors_headers(self):
        """Requests from foreign Origins must be rejected with 403 and never receive CORS."""
        resp = client.get("/health", headers={"Origin": "http://evil.com"})
        assert resp.status_code == 403
        assert "forbidden" in resp.json()["error_message"].lower()
        assert "Access-Control-Allow-Origin" not in resp.headers

        # Valid same-origin passes
        resp_local = client.get("/health", headers={"Origin": "http://127.0.0.1:8765"})
        assert resp_local.status_code == 200
        assert "Access-Control-Allow-Origin" not in resp_local.headers

    def test_post_endpoints_require_application_json(self):
        """POST endpoints must reject non-JSON content-type with 415."""
        resp = client.post(
            "/audit/privacy-policy",
            headers={"X-Bridge-Token": BRIDGE_TOKEN, "Content-Type": "text/plain"},
            content="url=https://example.com",
        )
        assert resp.status_code == 415
        assert "unsupported media type" in resp.json()["error_message"].lower()

    def test_oversized_body_rejected_413(self):
        """POST payloads exceeding 64 KB must be rejected with 413."""
        oversized = "a" * 70_000
        resp = client.post(
            "/audit/privacy-policy",
            headers={"X-Bridge-Token": BRIDGE_TOKEN, "Content-Type": "application/json"},
            content=f'{{"url": "{oversized}"}}',
        )
        assert resp.status_code == 413
        assert "payload too large" in resp.json()["error_message"].lower()

    @pytest.mark.asyncio
    async def test_concurrent_audit_locked_429(self):
        """At most one audit may run at a time; concurrent requests receive 429."""
        async with _AUDIT_LOCK:
            resp = client.post(
                "/audit/full",
                headers={"X-Bridge-Token": BRIDGE_TOKEN, "Content-Type": "application/json"},
                json={"url": "https://example.com"},
            )
            assert resp.status_code == 429
            assert "another audit is currently in progress" in resp.json()["error_message"].lower()

    def test_non_ascii_token_returns_401_never_500(self):
        """Non-ASCII token headers must be handled via UTF-8 comparison returning 401."""
        resp = client.get("/checklist", headers={"X-Bridge-Token": "tést-tøken-🔑".encode()})
        assert resp.status_code == 401
        assert resp.json()["status"] == "error"
        assert resp.headers["Cache-Control"] == "no-store"
        assert resp.headers["X-Content-Type-Options"] == "nosniff"
        assert "default-src 'none'" in resp.headers["Content-Security-Policy"]

    def test_streaming_oversized_body_without_content_length_rejected_413(self):
        """Stream chunks exceeding 64 KB without Content-Length must abort with 413."""

        def chunk_generator():
            for _ in range(70):
                yield b"x" * 1024

        resp = client.post(
            "/audit/privacy-policy",
            headers={"X-Bridge-Token": BRIDGE_TOKEN, "Content-Type": "application/json"},
            content=chunk_generator(),
        )
        assert resp.status_code == 413
        assert "payload too large" in resp.json()["error_message"].lower()
        assert resp.headers["Cache-Control"] == "no-store"
        assert resp.headers["X-Content-Type-Options"] == "nosniff"
        assert "default-src 'none'" in resp.headers["Content-Security-Policy"]

    def test_security_headers_present_on_all_early_error_responses(self):
        """Early 401/403/413/415/421 responses must all carry full defensive security headers."""
        # 421 Misdirected Host
        r421 = client.get("/health", headers={"Host": "attacker.com"})
        assert r421.status_code == 421
        assert r421.headers["X-Content-Type-Options"] == "nosniff"
        assert r421.headers["Cache-Control"] == "no-store"
        assert "nonce-" in r421.headers["Content-Security-Policy"]

        # 403 Forbidden Origin
        r403 = client.get("/health", headers={"Origin": "http://evil.com"})
        assert r403.status_code == 403
        assert r403.headers["X-Content-Type-Options"] == "nosniff"
        assert r403.headers["Cache-Control"] == "no-store"

        # 401 Unauthorized
        r401 = client.get("/checklist", headers={"X-Bridge-Token": "wrong"})
        assert r401.status_code == 401
        assert r401.headers["X-Content-Type-Options"] == "nosniff"
        assert r401.headers["Cache-Control"] == "no-store"

        # 415 Unsupported Media Type
        r415 = client.post(
            "/audit/privacy-policy",
            headers={"X-Bridge-Token": BRIDGE_TOKEN, "Content-Type": "text/plain"},
            content="test",
        )
        assert r415.status_code == 415
        assert r415.headers["X-Content-Type-Options"] == "nosniff"
        assert r415.headers["Cache-Control"] == "no-store"

        # 413 Payload Too Large
        r413 = client.post(
            "/audit/privacy-policy",
            headers={"X-Bridge-Token": BRIDGE_TOKEN, "Content-Type": "application/json"},
            content="a" * 70_000,
        )
        assert r413.status_code == 413
        assert r413.headers["X-Content-Type-Options"] == "nosniff"
        assert r413.headers["Cache-Control"] == "no-store"

    def test_exact_host_and_origin_allowlist_matching(self):
        """Host and Origin matching must strictly accept loopbacks with exact port."""
        # Host: localhost:8765 -> allowed
        r_lh = client.get("/health", headers={"Host": "localhost:8765"})
        assert r_lh.status_code == 200

        # Host: [::1]:8765 -> allowed
        r_v6 = client.get("/health", headers={"Host": "[::1]:8765"})
        assert r_v6.status_code == 200

        # Origin: http://localhost:8765 -> allowed
        r_org_lh = client.get("/health", headers={"Origin": "http://localhost:8765"})
        assert r_org_lh.status_code == 200

        # Origin: http://[::1]:8765 -> allowed
        r_org_v6 = client.get("/health", headers={"Origin": "http://[::1]:8765"})
        assert r_org_v6.status_code == 200

    def test_verify_bind_host_refuses_non_local_default(self, monkeypatch):
        """Bridge must refuse to bind non-local addresses unless explicitly allowed."""
        # Local allowed (including IPv6 loopback)
        verify_bind_host("127.0.0.1")
        verify_bind_host("localhost")
        verify_bind_host("::1")
        verify_bind_host("[::1]")

        # Non-local refused
        with pytest.raises(ValueError, match="Refusing to bind to non-local host"):
            verify_bind_host("0.0.0.0")

        with pytest.raises(ValueError, match="Refusing to bind to non-local host"):
            verify_bind_host("192.168.1.50")

        # Override with env var
        monkeypatch.setenv("PDPA_BRIDGE_ALLOW_NON_LOCAL", "true")
        verify_bind_host("0.0.0.0")


class TestDashboardHtmlInvariants:
    """Static security tests for dashboard/index.html to ensure no DOM injection or leaks."""

    def test_dashboard_file_exists(self):
        assert DASHBOARD_PATH.exists()

    def test_no_unsafe_dom_injection_methods(self):
        """Verify dashboard is free from all dangerous DOM sinks and dynamic evaluation."""
        content = DASHBOARD_PATH.read_text(encoding="utf-8")
        assert ".innerHTML" not in content and "innerHTML" not in content
        assert ".outerHTML" not in content and "outerHTML" not in content
        assert "insertAdjacentHTML" not in content
        assert "document.write" not in content
        assert "eval(" not in content
        assert "new Function(" not in content
        assert "srcdoc" not in content

        # No setTimeout or setInterval with string arguments (code execution sink)
        assert re.search(r"set(Timeout|Interval)\s*\(\s*['\"]", content) is None

        # No inline event handler assignments via setAttribute('on...')
        assert re.search(r"setAttribute\s*\(\s*['\"]on", content, re.IGNORECASE) is None

        # No assignment to .src or .action or location from audited data
        assert re.search(r"\.src\s*=", content) is None
        assert re.search(r"\.action\s*=", content) is None
        assert re.search(r"\blocation(\.href)?\s*=", content) is None

        # The only allowed .href assignment is for local blob download, never from audited data
        href_assignments = re.findall(r"(\w+\.href\s*=\s*[^;]+;)", content)
        assert len(href_assignments) == 1
        assert "blobUrl" in href_assignments[0]

    def test_no_external_requests_or_absolute_schemes(self):
        content = DASHBOARD_PATH.read_text(encoding="utf-8")
        assert "http://" not in content
        assert "https://" not in content

    def test_malicious_evidence_delivered_as_plain_data_and_report_keeps_it_inert(self):
        """Verify an audit result containing XSS HTML payloads is formatted inertly by /report."""
        malicious_evidence = "<img src=x onerror=alert(1)> [Click](http://evil.com)"
        audit_payload = {
            "status": "ok",
            "target": "https://example.com",
            "timestamp": "2026-11-09T00:00:00Z",
            "summary": {
                "overall_score": 50.0,
                "readiness_label": "Partially Ready",
                "category_scores": [],
                "total_passed": 1,
                "total_failed": 1,
                "total_needs_review": 0,
                "total_not_evaluated": 0,
            },
            "findings": [
                {
                    "rule_id": "security_https_enforced",
                    "category": "Security Safeguards",
                    "title": "HTTPS Enforced",
                    "severity": "high",
                    "status": "failed",
                    "evidence": malicious_evidence,
                    "recommendation": "Review security configuration",
                }
            ],
        }

        resp = client.post(
            "/report",
            headers={"X-Bridge-Token": BRIDGE_TOKEN, "Content-Type": "application/json"},
            json={"audit_result": audit_payload, "format": "markdown"},
        )
        assert resp.status_code == 200
        md = resp.text

        # In markdown, untrusted evidence must be rendered within code spans
        assert f"`{malicious_evidence}`" in md or "`<img src=x onerror=alert(1)>" in md
        # Legal disclaimer present top and bottom
        assert "LEGAL DISCLAIMER" in md

    def test_report_endpoint_unexpected_exception_logs_to_stderr_and_returns_500(
        self, monkeypatch, capsys
    ):
        """Unexpected report formatting errors must return generic 500 JSON and log to stderr."""
        from unittest.mock import patch

        client = TestClient(app, base_url="http://127.0.0.1:8765")
        with patch(
            "pdpa_audit_mcp.api.bridge._generate_gap_report",
            side_effect=RuntimeError("Secret internal parser crash"),
        ):
            resp = client.post(
                "/report",
                headers={"X-Bridge-Token": BRIDGE_TOKEN, "Content-Type": "application/json"},
                json={"audit_result": {}, "format": "markdown"},
            )
        assert resp.status_code == 500
        data = resp.json()
        assert data["status"] == "error"
        assert "Secret internal parser crash" not in data["error_message"]
        assert "An unexpected error occurred while generating the report." in data["error_message"]

        # Check stderr has the error details
        captured = capsys.readouterr()
        assert "Secret internal parser crash" in captured.err

    @pytest.mark.asyncio
    async def test_asgi_middleware_does_not_send_second_response_start_if_already_started(self):
        """When an exception occurs after response.start was sent, do not send another."""
        from pdpa_audit_mcp.api.bridge import BridgeSecurityMiddleware

        messages_sent: list[dict] = []

        async def broken_app(scope, receive, send):
            # Send initial response start
            await send({"type": "http.response.start", "status": 200, "headers": []})
            # Simulate a streaming or processing crash after response has started
            raise RuntimeError("Crash after response start")

        middleware = BridgeSecurityMiddleware(broken_app)

        scope = {
            "type": "http",
            "method": "GET",
            "path": "/health",
            "headers": [(b"host", b"127.0.0.1:8765")],
        }

        async def mock_receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def mock_send(message):
            messages_sent.append(message)

        # Middleware catches exception and logs to stderr without sending a 2nd response.start
        await middleware(scope, mock_receive, mock_send)

        # Count how many http.response.start messages were sent
        start_messages = [m for m in messages_sent if m["type"] == "http.response.start"]
        assert len(start_messages) == 1, f"Expected exactly 1 response.start, got: {start_messages}"
