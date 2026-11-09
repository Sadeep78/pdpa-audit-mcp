"""Unit tests for detect_third_party_transfers tool."""

from pathlib import Path

import httpx
import pytest

from pdpa_audit_mcp.models import RuleFindingStatus
from pdpa_audit_mcp.tools.transfers import detect_third_party_transfers

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _load_fixture(site: str, filename: str) -> str:
    path = FIXTURES_DIR / site / filename
    return path.read_text(encoding="utf-8")


class TestDetectThirdPartyTransfers:
    """Tests for external domain extraction, vendor categorization, and policy disclosure checks."""

    @pytest.mark.asyncio
    async def test_good_site_no_external_domains_passes(self):
        good_html = _load_fixture("good_site", "index.html")

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, headers={"Content-Type": "text/html"}, text=good_html)

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        result = await detect_third_party_transfers("https://example.com", client=client)

        assert result.status == "ok"
        assert result.data["external_domains_count"] == 0

        finding = result.findings[0]
        assert finding.rule_id == "transfer_cross_border_disclosed"
        assert finding.status == RuleFindingStatus.NOT_APPLICABLE
        assert "No external third-party domains" in finding.evidence

    @pytest.mark.asyncio
    async def test_bad_site_categorizes_domains_and_fails_if_undisclosed(self):
        bad_html = _load_fixture("bad_site", "index.html")

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, headers={"Content-Type": "text/html"}, text=bad_html)

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        result = await detect_third_party_transfers("https://example.com", client=client)

        assert result.status == "ok"
        categories = result.data["categories"]

        # Ensure correct categorization
        assert "analytics" in categories
        assert any("google-analytics.com" in d for d in categories["analytics"])

        assert "advertising" in categories
        assert any("facebook.net" in d for d in categories["advertising"])

        assert "cdn" in categories
        assert any("cloudflare.com" in d for d in categories["cdn"])

        assert "fonts" in categories
        assert any("googleapis.com" in d for d in categories["fonts"])

        # Check vendor labeling: do not claim outside SL from domain alone
        domains_data = result.data["domains"]
        for domain, entries in domains_data.items():
            for entry in entries:
                assert (
                    entry["vendor_classification"] == "third-party processor, location unverified"
                )

        # Transfer disclosure failed because bad_site has no policy text disclosing it
        finding = result.findings[0]
        assert finding.rule_id == "transfer_cross_border_disclosed"
        assert finding.status == RuleFindingStatus.FAILED

    @pytest.mark.asyncio
    async def test_external_domains_pass_when_policy_discloses_transfers(self):
        bad_html = _load_fixture("bad_site", "index.html")
        policy_disclosing_transfers = (
            "We transfer personal data to third-party cloud hosting providers outside Sri Lanka "
            "with adequate cross-border transfer agreements and safeguards."
        )

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, headers={"Content-Type": "text/html"}, text=bad_html)

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        result = await detect_third_party_transfers(
            "https://example.com",
            client=client,
            policy_text=policy_disclosing_transfers,
        )

        assert result.status == "ok"
        finding = result.findings[0]
        assert finding.rule_id == "transfer_cross_border_disclosed"
        assert finding.status == RuleFindingStatus.PASSED
        assert "cross-border transfer disclosed" in finding.evidence.lower()
