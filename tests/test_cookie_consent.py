"""Unit tests for detect_cookie_consent tool against good and bad fixtures."""

from pathlib import Path

import httpx
import pytest

from pdpa_audit_mcp.models import RuleFindingStatus
from pdpa_audit_mcp.tools.cookie_consent import detect_cookie_consent

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _load_fixture(site: str, filename: str) -> str:
    path = FIXTURES_DIR / site / filename
    return path.read_text(encoding="utf-8")


class TestDetectCookieConsent:
    """Tests for CMP banner identification, accept/reject buttons, and tracker auditing."""

    @pytest.mark.asyncio
    async def test_good_site_cookie_consent_passes(self):
        good_html = _load_fixture("good_site", "index.html")

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, headers={"Content-Type": "text/html"}, text=good_html)

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        result = await detect_cookie_consent("https://example.com", client=client)

        assert result.status == "ok"
        assert result.data["banner_detected"] is True
        assert result.data["buttons"]["has_accept"] is True
        assert result.data["buttons"]["has_reject"] is True
        assert result.data["trackers_count"] == 0

        findings_by_id = {f.rule_id: f for f in result.findings}

        # No trackers present -> NOT_APPLICABLE
        assert findings_by_id["consent_before_tracking"].status == RuleFindingStatus.NOT_APPLICABLE
        # Both accept and reject buttons available
        assert findings_by_id["consent_easy_withdrawal"].status == RuleFindingStatus.PASSED
        # No Set-Cookie header present -> NOT_APPLICABLE
        assert (
            findings_by_id["security_secure_cookie_flags"].status
            == RuleFindingStatus.NOT_APPLICABLE
        )

    @pytest.mark.asyncio
    async def test_bad_site_missing_reject_and_trackers_detected(self):
        bad_html = _load_fixture("bad_site", "index.html")

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, headers={"Content-Type": "text/html"}, text=bad_html)

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        result = await detect_cookie_consent("https://example.com", client=client)

        assert result.status == "ok"
        assert result.data["banner_detected"] is True
        assert result.data["buttons"]["has_accept"] is True
        assert result.data["buttons"]["has_reject"] is False
        assert result.data["trackers_count"] >= 2  # Google Analytics and Meta Pixel

        findings_by_id = {f.rule_id: f for f in result.findings}

        # Banner exists with trackers -> needs_review with note
        finding_trackers = findings_by_id["consent_before_tracking"]
        assert finding_trackers.status == RuleFindingStatus.NEEDS_REVIEW
        assert "cannot verify trackers are blocked before consent from static HTML" in (
            finding_trackers.details.get("note", "")
        )

        # Missing reject button -> FAILED
        finding_reject = findings_by_id["consent_easy_withdrawal"]
        assert finding_reject.status == RuleFindingStatus.FAILED
        assert "missing an explicit reject option" in finding_reject.evidence

    @pytest.mark.asyncio
    async def test_trackers_present_with_no_banner_fails(self):
        """Trackers present without any CMP banner must fail immediately."""
        html_with_tracker_only = """
        <html>
        <head>
          <script src="https://www.google-analytics.com/analytics.js"></script>
        </head>
        <body>
          <h1>Tracker without banner</h1>
        </body>
        </html>
        """

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200, headers={"Content-Type": "text/html"}, text=html_with_tracker_only
            )

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        result = await detect_cookie_consent("https://example.com", client=client)

        assert result.status == "ok"
        assert result.data["banner_detected"] is False

        findings_by_id = {f.rule_id: f for f in result.findings}
        assert findings_by_id["consent_before_tracking"].status == RuleFindingStatus.FAILED
        assert "with no consent banner" in findings_by_id["consent_before_tracking"].evidence

    @pytest.mark.asyncio
    async def test_inline_tracker_snippet_without_external_src(self):
        """Detect tracking scripts from inline invocations without external src attribute."""
        html_with_inline_trackers = """
        <html>
        <head>
          <script>
            window.dataLayer = window.dataLayer || [];
            function gtag(){dataLayer.push(arguments);}
            gtag('js', new Date());
            gtag('config', 'G-XXXXXXX');
          </script>
          <script>
            !function(f,b,e,v,n,t,s)
            {if(f.fbq)return;n=f.fbq=function(){n.callMethod?
            n.callMethod.apply(n,arguments):n.queue.push(arguments)};
            fbq('init', '1234567890');
            fbq('track', 'PageView');}();
          </script>
        </head>
        <body>
          <h1>Inline Trackers Test</h1>
        </body>
        </html>
        """

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200, headers={"Content-Type": "text/html"}, text=html_with_inline_trackers
            )

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        result = await detect_cookie_consent("https://example.com", client=client)

        assert result.status == "ok"
        assert result.data["trackers_count"] >= 2
        tracker_names = [t["tracker"] for t in result.data["trackers"]]
        assert any("Google Analytics" in n for n in tracker_names)
        assert any("Meta" in n for n in tracker_names)

        findings_by_id = {f.rule_id: f for f in result.findings}
        assert findings_by_id["consent_before_tracking"].status == RuleFindingStatus.FAILED

    @pytest.mark.asyncio
    async def test_sinhala_and_tamil_cookie_banner_buttons(self):
        """Verify accept and reject buttons in Sinhala and Tamil cookie banners."""
        # Sinhala banner
        si_banner_html = """
        <html>
        <body>
          <div id="cookie-banner">
            <p>කුකීස් භාවිතය පිළිබඳ දැන්වීම</p>
            <button id="accept">පිළිගන්න</button>
            <button id="reject">ප්‍රතික්ෂේප කරන්න</button>
            <button id="manage">මනාප සැකසුම්</button>
          </div>
        </body>
        </html>
        """
        # Tamil banner
        ta_banner_html = """
        <html>
        <body>
          <div class="cookie-consent">
            <p>குக்கீ பயன்பாட்டு அறிவிப்பு</p>
            <button>ஏற்றுக்கொள்</button>
            <button>நிராகரி</button>
            <button>விருப்பங்கள்</button>
          </div>
        </body>
        </html>
        """

        for html_text, lang in [(si_banner_html, "si"), (ta_banner_html, "ta")]:

            def make_handler(content: str):
                def handler(request: httpx.Request) -> httpx.Response:
                    return httpx.Response(
                        200,
                        headers={"Content-Type": "text/html; charset=utf-8"},
                        text=content,
                    )

                return handler

            client = httpx.AsyncClient(transport=httpx.MockTransport(make_handler(html_text)))
            result = await detect_cookie_consent(f"https://example.com/{lang}", client=client)

            assert result.status == "ok"
            assert result.data["banner_detected"] is True
            assert result.data["buttons"]["has_accept"] is True, (
                f"Failed accept button detection for {lang}"
            )
            assert result.data["buttons"]["has_reject"] is True, (
                f"Failed reject button detection for {lang}"
            )
            assert result.data["buttons"]["has_manage"] is True, (
                f"Failed manage button detection for {lang}"
            )
            findings_by_id = {f.rule_id: f for f in result.findings}
            assert findings_by_id["consent_easy_withdrawal"].status == RuleFindingStatus.PASSED
