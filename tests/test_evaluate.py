"""Tests for scripts/evaluate.py CLI evaluation sheet generator."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from scripts import evaluate


def test_evaluate_refuses_to_run_without_confirm_authorised(capsys):
    """Verify scripts/evaluate.py exits with code 1 when --confirm-authorised is omitted."""
    with pytest.raises(SystemExit) as exc_info:
        evaluate.main(["--url", "https://example.com"])

    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert "only audit sites/projects you own or are authorised to audit" in captured.err


def test_evaluate_refuses_when_neither_url_nor_project_provided(capsys):
    """Verify scripts/evaluate.py exits with code 1 when no target is provided."""
    with pytest.raises(SystemExit) as exc_info:
        evaluate.main(["--confirm-authorised"])

    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert "At least one of --url or --project must be specified" in captured.err


def test_evaluate_generates_markdown_sheet(tmp_path: Path, monkeypatch):
    """Verify scripts/evaluate.py writes a Markdown labeling sheet with expected columns."""
    sample_proj = Path(__file__).parent / "fixtures" / "sample_project" / "good"
    monkeypatch.setenv(
        "PDPA_AUDIT_ALLOWED_ROOTS",
        os.pathsep.join([str(Path.cwd()), str(tmp_path.parent)]),
    )

    out_file = tmp_path / "test_sheet.md"

    # Run main with valid arguments
    evaluate.main(
        [
            "--project",
            str(sample_proj),
            "--confirm-authorised",
            "--out",
            str(out_file),
        ]
    )

    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")

    # Verify table headers
    expected_header = (
        "| Target | Rule ID | Tool Status | Matched Terms | Evidence Snippet | URL to inspect "
        "| Requirement actually met? (yes/no) "
        "| Human verdict (correct / false pass / false fail / n/a) "
        "| Notes |"
    )
    assert expected_header in content
    assert "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |" in content

    # Verify rows exist for rules
    assert "erasure_mechanism_in_code" in content
    assert "no_pii_in_logs" in content
