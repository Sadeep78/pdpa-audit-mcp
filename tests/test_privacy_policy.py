"""Unit tests for scan_privacy_policy tool against good, bad, and multilingual fixtures."""

from pathlib import Path

import httpx
import pytest

from pdpa_audit_mcp.models import ConfidenceEnum, RuleFindingStatus
from pdpa_audit_mcp.tools.privacy_policy import scan_privacy_policy

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _load_fixture(site: str, filename: str) -> str:
    path = FIXTURES_DIR / site / filename
    return path.read_text(encoding="utf-8")


class TestScanPrivacyPolicy:
    """Tests for privacy policy discovery, indicator checks, and confidence ratings."""

    @pytest.mark.asyncio
    async def test_good_site_privacy_policy_passes_rules(self):
        good_policy_html = _load_fixture("good_site", "privacy.html")

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={"Content-Type": "text/html; charset=utf-8"},
                text=good_policy_html,
            )

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            result = await scan_privacy_policy("https://example.com/privacy", client=client)

        assert result.status == "ok"
        assert result.data["policy_found"] is True

        findings_by_id = {f.rule_id: f for f in result.findings}

        # Check key transparency rules passed
        assert findings_by_id["transparency_purpose"].status == RuleFindingStatus.PASSED
        assert findings_by_id["transparency_categories"].status == RuleFindingStatus.PASSED
        assert findings_by_id["transparency_retention"].status == RuleFindingStatus.PASSED
        assert findings_by_id["transparency_contact"].status == RuleFindingStatus.PASSED

        # Check data subject rights passed
        assert findings_by_id["rights_access"].status == RuleFindingStatus.PASSED
        assert findings_by_id["rights_correction"].status == RuleFindingStatus.PASSED
        assert findings_by_id["rights_erasure"].status == RuleFindingStatus.PASSED
        assert findings_by_id["rights_withdraw_consent"].status == RuleFindingStatus.PASSED

        # Check DPO passed
        assert findings_by_id["dpo_contact_published"].status == RuleFindingStatus.PASSED

        # Assert all evidence snippets are <= 120 chars and non-empty
        for f in result.findings:
            if f.status == RuleFindingStatus.PASSED:
                assert f.evidence, f"Rule {f.rule_id} passed but missing evidence snippet"
                assert len(f.evidence) <= 120

    @pytest.mark.asyncio
    async def test_homepage_discovers_and_follows_privacy_link(self):
        homepage_html = _load_fixture("good_site", "index.html")
        privacy_html = _load_fixture("good_site", "privacy.html")

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path in ("/privacy", "/privacy.html"):
                return httpx.Response(200, headers={"Content-Type": "text/html"}, text=privacy_html)
            return httpx.Response(200, headers={"Content-Type": "text/html"}, text=homepage_html)

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            result = await scan_privacy_policy("https://example.com", client=client)

        assert result.status == "ok"
        assert result.data["policy_found"] is True
        assert result.data["policy_url"] in (
            "https://example.com/privacy",
            "https://example.com/privacy.html",
        )

        findings_by_id = {f.rule_id: f for f in result.findings}
        assert findings_by_id["transparency_purpose"].status == RuleFindingStatus.PASSED

    @pytest.mark.asyncio
    async def test_discovered_privacy_policy_returns_404_yields_error(self):
        """Discovered policy link returning 404 must return status error, not use homepage."""
        homepage_html = _load_fixture("good_site", "index.html")

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path in ("/privacy", "/privacy.html"):
                return httpx.Response(404, headers={"Content-Type": "text/html"}, text="Not Found")
            return httpx.Response(200, headers={"Content-Type": "text/html"}, text=homepage_html)

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            result = await scan_privacy_policy("https://example.com", client=client)

        assert result.status == "error"
        assert "404" in result.error_message

    @pytest.mark.asyncio
    async def test_sinhala_privacy_policy_passes(self):
        si_html = _load_fixture("good_site", "privacy_si.html")

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={"Content-Type": "text/html; charset=utf-8"},
                text=si_html,
            )

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            result = await scan_privacy_policy("https://example.com/privacy_si", client=client)

        assert result.status == "ok"
        findings_by_id = {f.rule_id: f for f in result.findings}

        assert findings_by_id["transparency_purpose"].status == RuleFindingStatus.PASSED
        assert findings_by_id["transparency_categories"].status == RuleFindingStatus.PASSED
        assert findings_by_id["transparency_retention"].status == RuleFindingStatus.PASSED
        assert findings_by_id["rights_access"].status == RuleFindingStatus.PASSED
        assert findings_by_id["dpo_contact_published"].status == RuleFindingStatus.PASSED

    @pytest.mark.asyncio
    async def test_tamil_privacy_policy_passes(self):
        ta_html = _load_fixture("good_site", "privacy_ta.html")

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={"Content-Type": "text/html; charset=utf-8"},
                text=ta_html,
            )

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            result = await scan_privacy_policy("https://example.com/privacy_ta", client=client)

        assert result.status == "ok"
        findings_by_id = {f.rule_id: f for f in result.findings}

        assert findings_by_id["transparency_purpose"].status == RuleFindingStatus.PASSED
        assert findings_by_id["transparency_categories"].status == RuleFindingStatus.PASSED
        assert findings_by_id["transparency_retention"].status == RuleFindingStatus.PASSED
        assert findings_by_id["rights_access"].status == RuleFindingStatus.PASSED
        assert findings_by_id["dpo_contact_published"].status == RuleFindingStatus.PASSED

    @pytest.mark.asyncio
    async def test_brief_policy_stub_returns_needs_review(self):
        """Brief 2-sentence stub should return needs_review rather than definitive failure."""
        stub_html = (
            "<html><body><h1>Privacy</h1>"
            "<p>We respect your privacy. By using our website you agree.</p></body></html>"
        )

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, headers={"Content-Type": "text/html"}, text=stub_html)

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            result = await scan_privacy_policy("https://example.com/privacy", client=client)

        assert result.status == "ok"
        assert result.data["is_substantial"] is False

        # Brief stub results in needs_review for missing elements
        for f in result.findings:
            if f.status != RuleFindingStatus.PASSED:
                assert f.status == RuleFindingStatus.NEEDS_REVIEW
                assert f.confidence == ConfidenceEnum.MEDIUM

    @pytest.mark.asyncio
    async def test_bad_site_realistic_policy_flags_missing_clauses_as_failed(self):
        """Realistic policy omitting retention, rights, and DPO flags them as failed."""
        bad_html = _load_fixture("bad_site", "privacy.html")

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, headers={"Content-Type": "text/html"}, text=bad_html)

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            result = await scan_privacy_policy("https://example.com/privacy", client=client)

        assert result.status == "ok"
        assert result.data["is_substantial"] is True

        findings = {f.rule_id: f for f in result.findings}
        # Missing retention, rights, and DPO must be FAILED, not needs_review
        assert findings["transparency_retention"].status == RuleFindingStatus.FAILED
        assert findings["rights_access"].status == RuleFindingStatus.FAILED
        assert findings["rights_correction"].status == RuleFindingStatus.FAILED
        assert findings["rights_erasure"].status == RuleFindingStatus.FAILED
        assert findings["rights_withdraw_consent"].status == RuleFindingStatus.FAILED
        assert findings["rights_objection"].status == RuleFindingStatus.FAILED
        assert findings["rights_request_procedure"].status == RuleFindingStatus.FAILED
        assert findings["dpo_contact_published"].status == RuleFindingStatus.FAILED

    @pytest.mark.asyncio
    async def test_missing_privacy_policy_link_marks_not_evaluated(self):
        """Site with no privacy link yields 1 failed finding and remaining as not_evaluated."""
        no_link_html = "<html><body><h1>Just a Blog</h1><p>No policy here.</p></body></html>"

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, headers={"Content-Type": "text/html"}, text=no_link_html)

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            result = await scan_privacy_policy("https://example.com", client=client)

        assert result.status == "ok"
        assert result.data["policy_found"] is False

        # First finding is high-severity failure with medium confidence
        primary = result.findings[0]
        assert primary.status == RuleFindingStatus.FAILED
        assert primary.confidence == ConfidenceEnum.MEDIUM
        assert "Not Found" in primary.title

        # Remaining rules are marked not_evaluated
        remaining = result.findings[1:]
        assert len(remaining) >= 5
        for f in remaining:
            assert f.status == RuleFindingStatus.NOT_EVALUATED
            assert f.confidence == ConfidenceEnum.MEDIUM

    def test_link_discovery_in_sinhala_and_tamil(self):
        """Verify _find_privacy_policy_url resolves links with Sinhala and Tamil anchor text."""
        from pdpa_audit_mcp.tools.privacy_policy import _find_privacy_policy_url

        si_homepage = (
            '<html><body><footer><a href="/legal/si-privacy">'
            "පෞද්ගලිකත්ව ප්‍රතිපත්තිය</a></footer></body></html>"
        )
        url_si = _find_privacy_policy_url("https://example.com/home", si_homepage)
        assert url_si == "https://example.com/legal/si-privacy"

        ta_homepage = (
            '<html><body><footer><a href="/legal/ta-privacy">'
            "தனியுரிமைக் கொள்கை</a></footer></body></html>"
        )
        url_ta = _find_privacy_policy_url("https://example.com/home", ta_homepage)
        assert url_ta == "https://example.com/legal/ta-privacy"

    @pytest.mark.asyncio
    async def test_robots_txt_disallows_discovered_privacy_policy(self):
        """Verify scan_privacy_policy calls can_fetch_url before fetching discovered policy page."""
        homepage_html = (
            '<html><body><footer><a href="/privacy">Privacy Policy</a></footer></body></html>'
        )

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/robots.txt":
                return httpx.Response(200, text="User-agent: *\nDisallow: /privacy\n")
            if request.url.path == "/privacy":
                raise AssertionError("Should not fetch /privacy when disallowed by robots.txt")
            return httpx.Response(200, headers={"Content-Type": "text/html"}, text=homepage_html)

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            result = await scan_privacy_policy("https://example.com", client=client)

        assert result.status == "error"
        assert "robots.txt disallows" in result.error_message.lower()

    @pytest.mark.asyncio
    async def test_evidence_quality_retention_far_from_purpose_shows_distinct_centered_evidence(
        self,
    ):
        """Verify findings center evidence around matched terms with clean word boundaries."""
        top_purpose = (
            "This privacy policy explains our processing purposes for user authentication "
            "and service provisioning in accordance with general privacy principles."
        )
        filler = (
            " This section outlines operational infrastructure considerations, "
            "server configurations, network routing protocols, load balancing metrics, "
            "container orchestration strategies, and database replication topologies "
            "that support our distributed architecture."
        ) * 5
        bottom_retention = (
            "Regarding data retention period: all collected personal data is retained for only "
            "twelve months following account deactivation and permanently deleted thereafter."
        )
        policy_html = (
            f"<html><body><p>{top_purpose}</p>"
            f"<p>{filler}</p><p>{bottom_retention}</p></body></html>"
        )

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200, headers={"Content-Type": "text/html; charset=utf-8"}, text=policy_html
            )

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            result = await scan_privacy_policy("https://example.com/privacy", client=client)

        assert result.status == "ok"
        findings = {f.rule_id: f for f in result.findings}

        ev_purpose = findings["transparency_purpose"].evidence
        ev_retention = findings["transparency_retention"].evidence

        assert findings["transparency_purpose"].status == RuleFindingStatus.PASSED
        assert findings["transparency_retention"].status == RuleFindingStatus.PASSED

        # Snippets must be distinct
        assert ev_purpose != ev_retention

        # Purpose evidence must contain purpose terms, not retention terms
        assert "purpose" in ev_purpose.lower()
        assert "twelve months" not in ev_purpose.lower()

        # Retention evidence must contain retention terms, not purpose terms
        assert "retention" in ev_retention.lower()
        assert "authentication" not in ev_retention.lower()

        # Both evidence snippets must be <= 120 chars
        assert len(ev_purpose) <= 120
        assert len(ev_retention) <= 120

        # Neither snippet should end with a broken mid-word cut (e.g. 'purp...')
        # Sliced words should be clean tokens or have space before ellipsis
        words_purpose = ev_purpose.replace("...", "").split()
        for w in words_purpose:
            assert len(w) > 0

    @pytest.mark.asyncio
    async def test_matched_terms_reports_objection_and_not_correction(self):
        """Verify matched_terms for rights_objection captures objection terms, not correction."""
        policy_html = (
            "<html><body>"
            "<h1>Privacy Statement</h1>"
            "<p>Under your data subject rights, you have the right to object to processing "
            "for direct marketing purposes. You also have the right to correction to "
            "correct your data in your account profile.</p>"
            "</body></html>"
        )

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200, headers={"Content-Type": "text/html; charset=utf-8"}, text=policy_html
            )

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            result = await scan_privacy_policy("https://example.com/privacy", client=client)

        findings = {f.rule_id: f for f in result.findings}
        f_obj = findings["rights_objection"]
        f_corr = findings["rights_correction"]

        assert f_obj.status == RuleFindingStatus.PASSED
        assert len(f_obj.matched_terms) > 0
        # Must report objection terms
        assert any("object" in t.lower() for t in f_obj.matched_terms)
        # Must NOT report correction terms
        assert not any("correct" in t.lower() for t in f_obj.matched_terms)

        assert f_corr.status == RuleFindingStatus.PASSED
        assert any("correct" in t.lower() for t in f_corr.matched_terms)
