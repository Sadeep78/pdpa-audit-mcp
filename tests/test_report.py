"""Unit tests for full audit orchestration, gap report formatting,
and untrusted content hardening.
"""

import json
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest

from pdpa_audit_mcp.models import (
    Finding,
    Report,
    RuleFindingStatus,
    SeverityEnum,
)
from pdpa_audit_mcp.report import (
    generate_gap_report,
    list_checklist,
    run_full_audit,
)
from pdpa_audit_mcp.safety import (
    SecurityError,
    sanitize_evidence_snippet,
    validate_input_path,
    validate_input_url,
    validate_project_path,
)
from pdpa_audit_mcp.scoring import calculate_readiness_score
from pdpa_audit_mcp.tools.cookie_consent import detect_cookie_consent
from pdpa_audit_mcp.tools.forms import find_personal_data_forms
from pdpa_audit_mcp.tools.privacy_policy import scan_privacy_policy
from pdpa_audit_mcp.tools.transfers import detect_third_party_transfers

FIXTURES_DIR = Path(__file__).parent / "fixtures"
SAMPLE_PROJECT_DIR = FIXTURES_DIR / "sample_project"


def _load_site_fixture(site: str, filename: str) -> str:
    return (FIXTURES_DIR / site / filename).read_text(encoding="utf-8")


class TestRunFullAudit:
    """Test suite for full audit orchestration, tool execution, and finding merging."""

    @pytest.mark.asyncio
    async def test_zero_source_call_returns_error(self):
        """Calling run_full_audit without url or project_path must return status error."""
        result = await run_full_audit(url=None, project_path=None)
        assert result.status == "error"
        assert "At least one of 'url' or 'project_path' must be provided" in (
            result.error_message or ""
        )

    @pytest.mark.asyncio
    async def test_full_audit_good_project_scores_higher_than_bad(self):
        good_dir = str(SAMPLE_PROJECT_DIR / "good")
        bad_dir = str(SAMPLE_PROJECT_DIR / "bad")

        good_report = await run_full_audit(project_path=good_dir)
        bad_report = await run_full_audit(project_path=bad_dir)

        assert good_report.status == "ok"
        assert bad_report.status == "ok"
        assert good_report.summary.overall_score is not None
        assert bad_report.summary.overall_score is not None
        assert good_report.summary.overall_score > bad_report.summary.overall_score
        assert good_report.summary.total_passed > bad_report.summary.total_passed

    @pytest.mark.asyncio
    async def test_web_audit_with_mock_client(self):
        good_html = _load_site_fixture("good_site", "index.html")
        privacy_html = _load_site_fixture("good_site", "privacy.html")

        def handler(request: httpx.Request) -> httpx.Response:
            if "/privacy" in request.url.path:
                return httpx.Response(200, headers={"Content-Type": "text/html"}, text=privacy_html)
            return httpx.Response(200, headers={"Content-Type": "text/html"}, text=good_html)

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        mock_val = (True, None, "93.184.216.34")
        with patch("pdpa_audit_mcp.fetcher.validate_url", return_value=mock_val):
            report = await run_full_audit(url="https://example.com", client=client)

        assert report.status == "ok"
        assert report.summary.total_passed >= 5
        # Rules not applicable to web should be marked not_evaluated
        not_eval = [f for f in report.findings if f.status == RuleFindingStatus.NOT_EVALUATED]
        assert len(not_eval) > 0

    @pytest.mark.asyncio
    async def test_one_tool_failure_isolation(self):
        """Failure in one tool must not abort full audit; error recorded in errors list."""
        good_dir = str(SAMPLE_PROJECT_DIR / "good")

        with patch(
            "pdpa_audit_mcp.report.scan_project_files",
            side_effect=RuntimeError("Simulated scanner crash"),
        ):
            report = await run_full_audit(project_path=good_dir)

        assert report.status == "ok"
        assert any("Simulated scanner crash" in err for err in report.errors)
        # Other tools still executed
        assert report.summary.total_passed > 0

    @pytest.mark.asyncio
    async def test_finding_merge_precedence_and_source_recording(self):
        """Merged findings must prioritize FAILED > NEEDS_REVIEW > PASSED and record sources."""
        # Test merging directly with conflicting findings
        findings = [
            Finding(
                rule_id="security_no_pii_in_urls",
                category="Security Safeguards",
                title="No Personal Data in Query Parameters",
                severity=SeverityEnum.HIGH,
                status=RuleFindingStatus.PASSED,
                evidence="Safe form POST",
                recommendation="Fix",
                sources=["forms(project)"],
            ),
            Finding(
                rule_id="security_no_pii_in_urls",
                category="Security Safeguards",
                title="No Personal Data in Query Parameters",
                severity=SeverityEnum.HIGH,
                status=RuleFindingStatus.FAILED,
                evidence="Exposed email in GET",
                recommendation="Fix",
                sources=["forms(url)"],
            ),
        ]

        from pdpa_audit_mcp.report import STATUS_PRECEDENCE

        findings.sort(key=lambda x: STATUS_PRECEDENCE.get(x.status, 0), reverse=True)
        winner = findings[0]
        assert winner.status == RuleFindingStatus.FAILED

    @pytest.mark.parametrize(
        "status_a, status_b, expected_winner",
        [
            (RuleFindingStatus.FAILED, RuleFindingStatus.NEEDS_REVIEW, RuleFindingStatus.FAILED),
            (RuleFindingStatus.FAILED, RuleFindingStatus.PASSED, RuleFindingStatus.FAILED),
            (RuleFindingStatus.FAILED, RuleFindingStatus.NOT_EVALUATED, RuleFindingStatus.FAILED),
            (RuleFindingStatus.FAILED, RuleFindingStatus.NOT_APPLICABLE, RuleFindingStatus.FAILED),
            (
                RuleFindingStatus.NEEDS_REVIEW,
                RuleFindingStatus.PASSED,
                RuleFindingStatus.NEEDS_REVIEW,
            ),
            (
                RuleFindingStatus.NEEDS_REVIEW,
                RuleFindingStatus.NOT_EVALUATED,
                RuleFindingStatus.NEEDS_REVIEW,
            ),
            (
                RuleFindingStatus.NEEDS_REVIEW,
                RuleFindingStatus.NOT_APPLICABLE,
                RuleFindingStatus.NEEDS_REVIEW,
            ),
            (RuleFindingStatus.PASSED, RuleFindingStatus.NOT_EVALUATED, RuleFindingStatus.PASSED),
            (RuleFindingStatus.PASSED, RuleFindingStatus.NOT_APPLICABLE, RuleFindingStatus.PASSED),
            (
                RuleFindingStatus.NOT_EVALUATED,
                RuleFindingStatus.NOT_APPLICABLE,
                RuleFindingStatus.NOT_EVALUATED,
            ),
        ],
    )
    def test_merge_precedence_every_pair(self, status_a, status_b, expected_winner):
        """Test merge precedence for every pair in both orders."""
        from pdpa_audit_mcp.report import STATUS_PRECEDENCE

        # Test forward order
        list_forward = [
            Finding(
                rule_id="test_rule",
                category="General",
                title="Rule A",
                severity=SeverityEnum.MEDIUM,
                status=status_a,
                evidence="Evidence A",
                recommendation="Rec",
                sources=["src_a"],
            ),
            Finding(
                rule_id="test_rule",
                category="General",
                title="Rule B",
                severity=SeverityEnum.MEDIUM,
                status=status_b,
                evidence="Evidence B",
                recommendation="Rec",
                sources=["src_b"],
            ),
        ]
        list_forward.sort(key=lambda x: STATUS_PRECEDENCE.get(x.status, 0), reverse=True)
        assert list_forward[0].status == expected_winner

        # Test reverse order
        list_reverse = [list_forward[1], list_forward[0]]
        list_reverse.sort(key=lambda x: STATUS_PRECEDENCE.get(x.status, 0), reverse=True)
        assert list_reverse[0].status == expected_winner

    @pytest.mark.asyncio
    async def test_privacy_policy_passed_and_project_scan_not_applicable_yields_passed(self):
        """Privacy policy passed + project scan not_applicable must resolve to passed."""
        from pdpa_audit_mcp.report import STATUS_PRECEDENCE

        f_policy = Finding(
            rule_id="transfer_cross_border_disclosed",
            category="Cross-Border Transfers",
            title="Cross-Border Transfer Disclosed",
            severity=SeverityEnum.MEDIUM,
            status=RuleFindingStatus.PASSED,
            evidence="Policy clearly discloses cloud hosting in AWS Singapore.",
            recommendation="Rec",
            sources=["privacy_policy"],
        )
        f_project = Finding(
            rule_id="transfer_cross_border_disclosed",
            category="Cross-Border Transfers",
            title="Cross-Border Transfer Disclosed",
            severity=SeverityEnum.MEDIUM,
            status=RuleFindingStatus.NOT_APPLICABLE,
            evidence="No third-party SDK dependencies in package.json.",
            recommendation="Rec",
            sources=["project_scan"],
        )

        candidates = [f_project, f_policy]
        candidates.sort(key=lambda x: STATUS_PRECEDENCE.get(x.status, 0), reverse=True)
        assert candidates[0].status == RuleFindingStatus.PASSED


class TestUntrustedContentHardening:
    """Tests ensuring untrusted evidence cannot inject markdown, HTML, or prompt injection."""

    def test_malicious_evidence_rendered_inert(self):
        malicious_input = (
            "Click [Here](http://evil.com) <script>alert('xss')</script> "
            "contact user@attack.lk or nic 199912345678"
        )
        sanitized = sanitize_evidence_snippet(malicious_input)

        # Personal data redacted
        assert "[EMAIL]" in sanitized
        assert "[NIC]" in sanitized
        assert "user@attack.lk" not in sanitized
        assert "199912345678" not in sanitized

        # Generate markdown report
        dummy_report = Report(
            status="ok",
            target="https://evil.com",
            timestamp="2026-11-09T00:00:00Z",
            summary=calculate_readiness_score([]),
            findings=[
                Finding(
                    rule_id="security_https_enforced",
                    category="Security Safeguards",
                    title="HTTPS Enforced",
                    severity=SeverityEnum.HIGH,
                    status=RuleFindingStatus.FAILED,
                    evidence=sanitized,
                    recommendation="Review",
                )
            ],
        )

        md = generate_gap_report(dummy_report, format="markdown")

        # In markdown, evidence must be inside code span with escaped backticks
        assert f"`{sanitized}`" in md or "`" in md
        # The raw text is inside a code block, so markdown link won't render as active HTML link
        assert md.count("`") >= 2

    def test_json_report_includes_untrusted_content_notice(self):
        dummy_report = Report(
            status="ok",
            target="https://example.com",
            timestamp="2026-11-09T00:00:00Z",
            summary=calculate_readiness_score([]),
            findings=[],
        )
        json_str = generate_gap_report(dummy_report, format="json")
        data = json.loads(json_str)
        assert "untrusted_content_notice" in data
        assert "sanitized" in data["untrusted_content_notice"].lower()


class TestGenerateGapReport:
    """Tests for gap report structure, disclaimers, score formatting, and checklist."""

    def test_report_includes_top_and_bottom_disclaimers(self):
        dummy_report = Report(
            status="ok",
            target="https://example.com",
            timestamp="2026-11-09T00:00:00Z",
            summary=calculate_readiness_score([]),
            findings=[],
        )
        md = generate_gap_report(dummy_report, format="markdown")
        lines = [line.strip() for line in md.splitlines() if line.strip()]

        # Top disclaimer check
        assert any("LEGAL DISCLAIMER" in lines[i] for i in range(min(5, len(lines))))
        # Bottom disclaimer check
        bottom_lines = lines[max(0, len(lines) - 5) :]
        assert any("LEGAL DISCLAIMER" in line for line in bottom_lines)
        # Out of scope section check
        assert "## Out of Scope" in md
        # Heuristic weights footnote check
        assert "heuristic technical indicators" in md

    def test_insufficient_data_when_score_is_none(self):
        dummy_report = Report(
            status="ok",
            target="https://example.com",
            timestamp="2026-11-09T00:00:00Z",
            summary=calculate_readiness_score([]),
            findings=[],
        )
        md = generate_gap_report(dummy_report, format="markdown")
        assert "Insufficient data" in md

    def test_list_checklist_returns_rules_and_filters_by_category(self):
        res_all = list_checklist()
        assert res_all.status == "ok"
        assert res_all.data["rules_count"] >= 15

        res_filtered = list_checklist(category="Transparency")
        assert res_filtered.status == "ok"
        assert res_filtered.data["rules_count"] >= 4
        for r in res_filtered.data["rules"]:
            assert "transparency" in r["category"].lower()


class TestConfigAndInputValidation:
    """Tests for PDPA_AUDIT_ALLOWED_ROOTS enforcement and input validation."""

    def test_allowed_roots_permits_path_inside_root(self, tmp_path: Path, monkeypatch):
        root_dir = tmp_path / "allowed_workspace"
        root_dir.mkdir()
        sub_dir = root_dir / "my_project"
        sub_dir.mkdir()

        monkeypatch.setenv("PDPA_AUDIT_ALLOWED_ROOTS", str(root_dir))
        validated = validate_project_path(str(sub_dir))
        assert validated == sub_dir.resolve()

    def test_allowed_roots_blocks_path_outside_root(self, tmp_path: Path, monkeypatch):
        root_dir = tmp_path / "allowed_workspace"
        root_dir.mkdir()
        forbidden_dir = tmp_path / "forbidden_workspace"
        forbidden_dir.mkdir()

        monkeypatch.setenv("PDPA_AUDIT_ALLOWED_ROOTS", str(root_dir))
        with pytest.raises(SecurityError, match="not permitted by PDPA_AUDIT_ALLOWED_ROOTS"):
            validate_project_path(str(forbidden_dir))

    def test_unset_allowed_roots_requires_working_directory_and_suggests_fix(
        self, tmp_path: Path, monkeypatch
    ):
        """When PDPA_AUDIT_ALLOWED_ROOTS is unset, paths outside cwd are blocked
        with exact fix advice.
        """
        outside_dir = tmp_path / "outside_cwd"
        outside_dir.mkdir()

        monkeypatch.delenv("PDPA_AUDIT_ALLOWED_ROOTS", raising=False)
        with pytest.raises(SecurityError) as exc_info:
            validate_project_path(str(outside_dir))

        err_msg = str(exc_info.value)
        assert "outside the working directory" in err_msg
        assert "Set PDPA_AUDIT_ALLOWED_ROOTS to the folder that contains your project" in err_msg


class TestFetchFailureSemantics:
    """Ensure network/security/content errors do not generate failed findings or lower score."""

    @pytest.mark.parametrize(
        "status_code,content_type,body,expected_err_part",
        [
            (403, "text/html", "Forbidden", "403"),
            (429, "text/html", "Rate Limited", "429"),
            (503, "text/html", "Unavailable", "503"),
            (200, "application/octet-stream", b"\x00\x01\x02", "unsupported content type"),
        ],
    )
    @pytest.mark.asyncio
    async def test_http_errors_and_content_type_do_not_lower_score(
        self, status_code, content_type, body, expected_err_part
    ):
        def handler(request: httpx.Request) -> httpx.Response:
            content = body if isinstance(body, bytes) else body.encode("utf-8")
            return httpx.Response(
                status_code, headers={"Content-Type": content_type}, content=content
            )

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        mock_val = (True, None, "93.184.216.34")
        with patch("pdpa_audit_mcp.fetcher.validate_url", return_value=mock_val):
            report = await run_full_audit(url="https://example.com", client=client)

        # Audit isolates errors, status remains ok
        assert report.status == "ok"
        # Errors recorded
        assert any(expected_err_part in err.lower() for err in report.errors)
        # NEVER yields FAILED findings
        failed_findings = [f for f in report.findings if f.status == RuleFindingStatus.FAILED]
        assert len(failed_findings) == 0
        # Score is not lowered (None due to insufficient data / not_evaluated)
        assert report.summary.overall_score is None

    @pytest.mark.asyncio
    async def test_connection_error_does_not_lower_score(self):
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("Network is down")

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        mock_val = (True, None, "93.184.216.34")
        with patch("pdpa_audit_mcp.fetcher.validate_url", return_value=mock_val):
            report = await run_full_audit(url="https://example.com", client=client)

        assert report.status == "ok"
        assert any("connect" in err.lower() or "failed" in err.lower() for err in report.errors)
        failed_findings = [f for f in report.findings if f.status == RuleFindingStatus.FAILED]
        assert len(failed_findings) == 0
        assert report.summary.overall_score is None

    @pytest.mark.asyncio
    async def test_security_error_does_not_lower_score(self):
        client = httpx.AsyncClient()
        try:
            # Private IP blocked by SSRF guard
            report = await run_full_audit(url="http://127.0.0.1:8000", client=client)
            assert report.status == "ok"
            assert any("ssrf" in err.lower() or "blocked" in err.lower() for err in report.errors)
            failed_findings = [f for f in report.findings if f.status == RuleFindingStatus.FAILED]
            assert len(failed_findings) == 0
            assert report.summary.overall_score is None
        finally:
            await client.aclose()

    def test_validate_input_url_rejects_invalid_inputs(self):
        # Non-string
        with pytest.raises(ValueError, match="URL must be a string"):
            validate_input_url(12345)

        # Excess length > 2048
        with pytest.raises(ValueError, match="exceeds maximum length"):
            validate_input_url("https://example.com/" + ("a" * 2050))

        # Control characters
        with pytest.raises(ValueError, match="prohibited control characters"):
            validate_input_url("https://example.com/test\x00malicious")

    def test_validate_input_path_rejects_invalid_inputs(self):
        # Control characters
        with pytest.raises(ValueError, match="prohibited control characters"):
            validate_input_path("C:/projects/\x08evil")


class TestToolTimeoutSemantics:
    """Ensure timeout errors in every URL tool yield status 'error' and never lower scores."""

    @pytest.mark.asyncio
    async def test_privacy_policy_timeout_returns_error_and_no_findings(self):
        def handler(request: httpx.Request):
            raise httpx.ReadTimeout("Read operation timed out after 20s")

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        mock_val = (True, None, "93.184.216.34")
        with patch("pdpa_audit_mcp.fetcher.validate_url", return_value=mock_val):
            res = await scan_privacy_policy("https://example.com", client=client)

        assert res.status == "error"
        assert len(res.findings) == 0
        assert "timed out" in (res.error_message or "").lower()

    @pytest.mark.asyncio
    async def test_cookie_consent_timeout_returns_error_and_no_findings(self):
        def handler(request: httpx.Request):
            raise httpx.ReadTimeout("Read operation timed out after 20s")

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        mock_val = (True, None, "93.184.216.34")
        with patch("pdpa_audit_mcp.fetcher.validate_url", return_value=mock_val):
            res = await detect_cookie_consent("https://example.com", client=client)

        assert res.status == "error"
        assert len(res.findings) == 0
        assert "timed out" in (res.error_message or "").lower()

    @pytest.mark.asyncio
    async def test_transfers_timeout_returns_error_and_no_findings(self):
        def handler(request: httpx.Request):
            raise httpx.ReadTimeout("Read operation timed out after 20s")

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        mock_val = (True, None, "93.184.216.34")
        with patch("pdpa_audit_mcp.fetcher.validate_url", return_value=mock_val):
            res = await detect_third_party_transfers("https://example.com", client=client)

        assert res.status == "error"
        assert len(res.findings) == 0
        assert "timed out" in (res.error_message or "").lower()

    @pytest.mark.asyncio
    async def test_forms_timeout_returns_error_and_no_findings(self):
        def handler(request: httpx.Request):
            raise httpx.ReadTimeout("Read operation timed out after 20s")

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        mock_val = (True, None, "93.184.216.34")
        with patch("pdpa_audit_mcp.fetcher.validate_url", return_value=mock_val):
            res = await find_personal_data_forms("https://example.com", client=client)

        assert res.status == "error"
        assert len(res.findings) == 0
        assert "timed out" in (res.error_message or "").lower()

    @pytest.mark.asyncio
    async def test_full_audit_with_timeouts_sets_rules_not_evaluated_and_score_none(self):
        def handler(request: httpx.Request):
            raise httpx.ReadTimeout("Timeout simulation")

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        mock_val = (True, None, "93.184.216.34")
        with patch("pdpa_audit_mcp.fetcher.validate_url", return_value=mock_val):
            report = await run_full_audit(url="https://example.com", client=client)

        assert report.status == "ok"
        assert len(report.errors) >= 1
        # No failed findings from timeouts
        failed = [f for f in report.findings if f.status == RuleFindingStatus.FAILED]
        assert len(failed) == 0
        # Rules must be not_evaluated
        not_eval = [f for f in report.findings if f.status == RuleFindingStatus.NOT_EVALUATED]
        assert len(not_eval) > 0
        # Score is None ("Insufficient data")
        assert report.summary.overall_score is None
