"""Unit tests for scan_project_files and check_breach_readiness tools."""

import os
from pathlib import Path

import pytest

from pdpa_audit_mcp.models import ConfidenceEnum, RuleFindingStatus
from pdpa_audit_mcp.scoring import calculate_readiness_score
from pdpa_audit_mcp.tools.breach_readiness import check_breach_readiness
from pdpa_audit_mcp.tools.forms import find_personal_data_forms
from pdpa_audit_mcp.tools.project_scan import scan_project_files

SAMPLE_PROJECT_DIR = Path(__file__).parent / "fixtures" / "sample_project"


@pytest.fixture(autouse=True)
def allow_workspace_and_tmp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv(
        "PDPA_AUDIT_ALLOWED_ROOTS",
        os.pathsep.join([str(Path.cwd()), str(tmp_path.parent)]),
    )


class TestProjectScan:
    """Test suite for static code and dependency scanning."""

    @pytest.mark.asyncio
    async def test_good_project_scan_passes_checks(self):
        good_dir = SAMPLE_PROJECT_DIR / "good"
        result = await scan_project_files(str(good_dir))

        assert result.status == "ok"
        assert result.data["has_deletion_logic"] is True
        assert result.data["logging_incidents_count"] == 0

        findings = {f.rule_id: f for f in result.findings}

        # Erasure / retention logic detected in code
        assert findings["erasure_mechanism_in_code"].status == RuleFindingStatus.PASSED

        # No personal data logging detected
        assert findings["no_pii_in_logs"].status == RuleFindingStatus.PASSED

        # No tracking SDKs -> NOT_APPLICABLE
        assert (
            findings["transfer_cross_border_disclosed"].status == RuleFindingStatus.NOT_APPLICABLE
        )

    @pytest.mark.asyncio
    async def test_bad_project_scan_detects_flaws(self):
        bad_dir = SAMPLE_PROJECT_DIR / "bad"
        result = await scan_project_files(str(bad_dir))

        assert result.status == "ok"
        assert result.data["has_deletion_logic"] is False
        assert result.data["logging_incidents_count"] >= 1

        findings_by_id: dict[str, list] = {}
        for f in result.findings:
            findings_by_id.setdefault(f.rule_id, []).append(f)

        # 1. Erasure: Missing retention/deletion on schema
        erasure_finding = findings_by_id["erasure_mechanism_in_code"][0]
        assert erasure_finding.status == RuleFindingStatus.NEEDS_REVIEW
        assert "no automated deletion or retention methods" in erasure_finding.evidence

        # 2. Logging: Insecure PII logging in app.js
        log_finding = findings_by_id["no_pii_in_logs"][0]
        assert log_finding.status == RuleFindingStatus.FAILED
        assert "app.js:" in log_finding.evidence
        assert "email" in log_finding.matched_terms

        # 3. Third-party SDKs detected
        transfer_findings = findings_by_id["transfer_cross_border_disclosed"]
        assert len(transfer_findings) >= 2
        for tf in transfer_findings:
            assert tf.status == RuleFindingStatus.NEEDS_REVIEW
            assert "third-party processor, location unverified" in tf.details.get("note", "")

    @pytest.mark.asyncio
    async def test_breach_readiness_on_good_project(self):
        good_dir = SAMPLE_PROJECT_DIR / "good"
        result = await check_breach_readiness(str(good_dir))

        assert result.status == "ok"
        assert result.data["has_roles_and_responsibilities"] is True
        assert result.data["has_security_contact"] is True
        assert result.data["has_escalation_timelines"] is True

        findings = {f.rule_id: f for f in result.findings}
        assert findings["breach_response_plan_documented"].status == RuleFindingStatus.PASSED
        assert findings["breach_notification_contact"].status == RuleFindingStatus.PASSED
        assert findings["breach_internal_escalation"].status == RuleFindingStatus.PASSED

    @pytest.mark.asyncio
    async def test_breach_readiness_on_bad_project_never_fails(self):
        """Hard rule: Missing breach docs must return needs_review, never failed."""
        bad_dir = SAMPLE_PROJECT_DIR / "bad"
        result = await check_breach_readiness(str(bad_dir))

        assert result.status == "ok"
        for f in result.findings:
            assert f.status == RuleFindingStatus.NEEDS_REVIEW, f"Rule {f.rule_id} should not fail"
            assert f.confidence == ConfidenceEnum.LOW
            assert "not found" in f.evidence.lower()

    @pytest.mark.asyncio
    async def test_overall_score_higher_for_good_than_bad(self):
        """Assert good project achieves higher readiness score than bad project."""
        good_dir = str(SAMPLE_PROJECT_DIR / "good")
        bad_dir = str(SAMPLE_PROJECT_DIR / "bad")

        # Run forms, scan, breach on good project
        f_good = await find_personal_data_forms(good_dir)
        p_good = await scan_project_files(good_dir)
        b_good = await check_breach_readiness(good_dir)
        all_good_findings = f_good.findings + p_good.findings + b_good.findings

        # Run forms, scan, breach on bad project
        f_bad = await find_personal_data_forms(bad_dir)
        p_bad = await scan_project_files(bad_dir)
        b_bad = await check_breach_readiness(bad_dir)
        all_bad_findings = f_bad.findings + p_bad.findings + b_bad.findings

        good_summary = calculate_readiness_score(all_good_findings)
        bad_summary = calculate_readiness_score(all_bad_findings)

        assert good_summary.overall_score is not None
        assert bad_summary.overall_score is not None
        assert good_summary.overall_score > bad_summary.overall_score
        assert good_summary.total_passed > bad_summary.total_passed
        assert bad_summary.total_failed > good_summary.total_failed

    @pytest.mark.asyncio
    async def test_symlink_or_junction_escaping_root_not_followed(self, tmp_path: Path):
        """Verify that a symlink or junction escaping the project root is skipped."""
        base_dir = tmp_path / "project"
        base_dir.mkdir()
        (base_dir / "app.py").write_text("print('Safe app')", encoding="utf-8")

        outside_dir = tmp_path / "outside"
        outside_dir.mkdir()
        (outside_dir / "evil.py").write_text("console.log(user.nic)", encoding="utf-8")

        junction_dir = base_dir / "linked_outside"
        linked = False
        try:
            import _winapi

            _winapi.CreateJunction(str(outside_dir), str(junction_dir))
            linked = True
        except (ImportError, OSError, AttributeError):
            try:
                junction_dir.symlink_to(outside_dir, target_is_directory=True)
                linked = True
            except (OSError, NotImplementedError):
                pass

        if not linked:
            pytest.skip("Symlink/Junction creation not permitted in this environment.")

        result = await scan_project_files(str(base_dir))
        assert result.status == "ok"
        # The outside file must not be scanned, so no logging incident detected
        assert result.data["logging_incidents_count"] == 0

    @pytest.mark.asyncio
    async def test_excluded_directories_skipped(self, tmp_path: Path):
        """Verify node_modules, .git, venv are strictly skipped by scan_project_files."""
        base_dir = tmp_path / "project"
        base_dir.mkdir()
        (base_dir / "safe.py").write_text("print('Safe')", encoding="utf-8")

        # Create excluded directories containing files with PII logging
        for ex_name in ("node_modules", ".git", "venv"):
            ex_dir = base_dir / ex_name
            ex_dir.mkdir(parents=True)
            (ex_dir / f"bad_{ex_name}.py").write_text(
                "console.log(user.email, user.nic)", encoding="utf-8"
            )

        result = await scan_project_files(str(base_dir))
        assert result.status == "ok"
        assert result.data["logging_incidents_count"] == 0

    @pytest.mark.asyncio
    async def test_file_over_1mb_skipped(self, tmp_path: Path):
        """Verify files exceeding 1 MB are skipped during project scan."""
        base_dir = tmp_path / "project"
        base_dir.mkdir()
        (base_dir / "safe.py").write_text("print('Safe')", encoding="utf-8")

        # 1.2 MB file containing PII logging
        huge_file = base_dir / "huge_data.py"
        huge_file.write_text("# " + ("X" * 1_200_000) + "\nconsole.log(user.nic)", encoding="utf-8")

        result = await scan_project_files(str(base_dir))
        assert result.status == "ok"
        assert result.data["logging_incidents_count"] == 0

    @pytest.mark.asyncio
    async def test_pii_logging_reports_file_line_only_and_no_content_leak(self, tmp_path: Path):
        """Verify logging calls report file:line only; log content and values never appear."""
        base_dir = tmp_path / "project"
        base_dir.mkdir()
        leaker = base_dir / "service.js"
        leaker.write_text(
            'console.log("CLASSIFIED_TOKEN_VALUE_XYZ", user.email, "SECRET_DATA_ABC");\n',
            encoding="utf-8",
        )

        result = await scan_project_files(str(base_dir))
        assert result.status == "ok"
        assert result.data["logging_incidents_count"] == 1

        incident = result.data["logging_incidents"][0]
        assert incident["file"] == "service.js"
        assert incident["line"] == 1
        assert incident["field_pattern"] == "email"

        # Verify that secret payload content never appears anywhere in the serialized tool result
        serialized = result.model_dump_json()
        assert "CLASSIFIED_TOKEN_VALUE_XYZ" not in serialized
        assert "SECRET_DATA_ABC" not in serialized

    @pytest.mark.asyncio
    async def test_breach_readiness_plan_found_isolated(self, tmp_path: Path):
        """Isolated test verifying check_breach_readiness passes when incident plan is present."""
        base_dir = tmp_path / "project"
        base_dir.mkdir()
        (base_dir / "INCIDENT_PLAN.md").write_text(
            "# Incident Plan\nRoles and responsibilities: DPO and incident lead.\n"
            "Timeline: within 72 hours. Escalation register maintained.\n"
            "Contact: security@mycompany.lk\n",
            encoding="utf-8",
        )

        result = await check_breach_readiness(str(base_dir))
        assert result.status == "ok"
        assert len(result.findings) == 3
        for f in result.findings:
            assert f.status == RuleFindingStatus.PASSED
            assert f.confidence == ConfidenceEnum.HIGH

    @pytest.mark.asyncio
    async def test_breach_readiness_nothing_found_returns_needs_review_with_low_confidence(
        self, tmp_path: Path
    ):
        """Isolated test: check_breach_readiness returns needs_review with low confidence."""
        empty_dir = tmp_path / "empty_project"
        empty_dir.mkdir()
        (empty_dir / "index.html").write_text("<h1>App</h1>", encoding="utf-8")

        result = await check_breach_readiness(str(empty_dir))
        assert result.status == "ok"
        assert len(result.findings) == 3
        for f in result.findings:
            assert f.status == RuleFindingStatus.NEEDS_REVIEW
            assert f.confidence == ConfidenceEnum.LOW
            assert f.status != RuleFindingStatus.FAILED

    @pytest.mark.asyncio
    async def test_erasure_mechanism_in_code_statuses(self, tmp_path: Path, monkeypatch):
        """Verify erasure_mechanism_in_code returns PASSED, NEEDS_REVIEW, and NOT_APPLICABLE."""
        monkeypatch.setenv("PDPA_AUDIT_ALLOWED_ROOTS", str(tmp_path))

        # Case 1: No models detected -> NOT_APPLICABLE
        dir_no_models = tmp_path / "proj_no_models"
        dir_no_models.mkdir()
        (dir_no_models / "app.py").write_text("print('hello')", encoding="utf-8")
        res1 = await scan_project_files(str(dir_no_models))
        f1 = {f.rule_id: f for f in res1.findings}["erasure_mechanism_in_code"]
        assert f1.status == RuleFindingStatus.NOT_APPLICABLE

        # Case 2: Models detected without deletion -> NEEDS_REVIEW
        dir_no_del = tmp_path / "proj_no_del"
        dir_no_del.mkdir()
        (dir_no_del / "models.py").write_text(
            "class User(models.Model):\n    email = Column(String)\n    name = Column(String)\n",
            encoding="utf-8",
        )
        res2 = await scan_project_files(str(dir_no_del))
        f2 = {f.rule_id: f for f in res2.findings}["erasure_mechanism_in_code"]
        assert f2.status == RuleFindingStatus.NEEDS_REVIEW

        # Case 3: Models detected with deletion -> PASSED
        dir_with_del = tmp_path / "proj_with_del"
        dir_with_del.mkdir()
        (dir_with_del / "models.py").write_text(
            "class User(models.Model):\n"
            "    email = Column(String)\n"
            "    def purge_user_data(self):\n"
            "        self.delete()\n",
            encoding="utf-8",
        )
        res3 = await scan_project_files(str(dir_with_del))
        f3 = {f.rule_id: f for f in res3.findings}["erasure_mechanism_in_code"]
        assert f3.status == RuleFindingStatus.PASSED

    @pytest.mark.asyncio
    async def test_no_pii_in_logs_statuses(self, tmp_path: Path, monkeypatch):
        """Verify no_pii_in_logs returns FAILED, PASSED, and NOT_APPLICABLE."""
        monkeypatch.setenv("PDPA_AUDIT_ALLOWED_ROOTS", str(tmp_path))

        # Case 1: PII logging -> FAILED with file:line and matched_terms
        dir_pii_log = tmp_path / "proj_pii_log"
        dir_pii_log.mkdir()
        (dir_pii_log / "app.py").write_text("console.log(user.email)\n", encoding="utf-8")
        res1 = await scan_project_files(str(dir_pii_log))
        f1 = {f.rule_id: f for f in res1.findings}["no_pii_in_logs"]
        assert f1.status == RuleFindingStatus.FAILED
        assert "app.py:1" in f1.evidence
        assert "email" in f1.matched_terms

        # Case 2: Clean logging -> PASSED
        dir_clean_log = tmp_path / "proj_clean_log"
        dir_clean_log.mkdir()
        (dir_clean_log / "app.py").write_text("console.log('Server started')\n", encoding="utf-8")
        res2 = await scan_project_files(str(dir_clean_log))
        f2 = {f.rule_id: f for f in res2.findings}["no_pii_in_logs"]
        assert f2.status == RuleFindingStatus.PASSED
        assert "no personal data fields referenced" in f2.evidence.lower()

        # Case 3: No logging calls -> NOT_APPLICABLE
        dir_no_log = tmp_path / "proj_no_log"
        dir_no_log.mkdir()
        (dir_no_log / "app.py").write_text("x = 10\ny = 20\n", encoding="utf-8")
        res3 = await scan_project_files(str(dir_no_log))
        f3 = {f.rule_id: f for f in res3.findings}["no_pii_in_logs"]
        assert f3.status == RuleFindingStatus.NOT_APPLICABLE
        assert "no logging calls found" in f3.evidence.lower()
