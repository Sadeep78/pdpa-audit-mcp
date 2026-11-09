"""Offline demonstration script for pdpa-audit-mcp.

Spins up local fixture servers, runs full technical audits against both
good and bad sites/projects, prints their scores with coverage metrics,
displays a per-rule findings table, and saves Markdown gap reports to docs/examples/.
"""

from __future__ import annotations

import asyncio
import http.server
import os
import threading
from pathlib import Path
from typing import Any

# Enable private / localhost targets specifically for this demo script
os.environ["PDPA_AUDIT_ALLOW_PRIVATE"] = "true"
PROJECT_ROOT = Path(__file__).parent.parent.resolve()
os.environ["PDPA_AUDIT_ALLOWED_ROOTS"] = str(PROJECT_ROOT)

from pdpa_audit_mcp.report import generate_gap_report, run_full_audit  # noqa: E402


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    """HTTP request handler that silences console access logs and supports extensionless HTML."""

    def log_message(self, format: str, *args: Any) -> None:
        """Silence standard http.server stdout/stderr logging noise."""
        pass

    def translate_path(self, path: str) -> str:
        """Translate URL path to filesystem path with automatic .html extension fallback."""
        translated = super().translate_path(path)
        if not os.path.exists(translated) and os.path.exists(translated + ".html"):
            return translated + ".html"
        return translated


def _start_server(directory: Path, port: int) -> http.server.ThreadingHTTPServer:
    handler = lambda *args, **kwargs: QuietHandler(*args, directory=str(directory), **kwargs)  # noqa: E731
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


async def run_demo():
    fixtures_dir = PROJECT_ROOT / "tests" / "fixtures"
    good_site_dir = fixtures_dir / "good_site"
    bad_site_dir = fixtures_dir / "bad_site"

    good_proj_dir = fixtures_dir / "sample_project" / "good"
    bad_proj_dir = fixtures_dir / "sample_project" / "bad"

    examples_dir = PROJECT_ROOT / "docs" / "examples"
    examples_dir.mkdir(parents=True, exist_ok=True)

    # Pick non-conflicting local ports
    port_good = 8991
    port_bad = 8992

    server_good = _start_server(good_site_dir, port_good)
    server_bad = _start_server(bad_site_dir, port_bad)

    print("=" * 78)
    print("SRI LANKA PDPA TECHNICAL READINESS AUDIT DEMO (OFFLINE)")
    print("=" * 78)
    print(f"[*] Started local server for good site at http://127.0.0.1:{port_good}")
    print(f"[*] Started local server for bad site at  http://127.0.0.1:{port_bad}")

    print("\n[NOTE] Root Cause Analysis & Fixture Bug Fix:")
    print("Why good_site passed privacy-policy rules originally:")
    print("  index.html linked to /privacy, but static server served privacy.html.")
    print("  SimpleHTTPRequestHandler returned 404. In privacy_policy.py, non-200 from")
    print("  fetch(found_link) silently fell back to index.html (< 50 words), marking all")
    print("  unmatched rules needs_review (excluded from score denominator). With 0 failed")
    print("  rules, passed / passed yielded 100.0%.")
    print("  Fixed by: updating links to /privacy.html, adding extensionless .html fallback,")
    print("  and failing fast in privacy_policy.py on non-200 responses.")

    try:
        # Audit Good Site & Project
        print("\n--> Auditing 'good_site' and compliant sample project...")
        good_report = await run_full_audit(
            url=f"http://127.0.0.1:{port_good}",
            project_path=str(good_proj_dir),
        )
        good_summary = good_report.summary
        good_score = (
            f"{good_summary.overall_score:.1f}%"
            if good_summary.overall_score is not None
            else "Insufficient data"
        )
        good_cov = f"{good_summary.coverage:.1f}%" if good_summary.coverage is not None else "N/A"
        good_wt_cov = (
            f"{good_summary.weight_coverage:.1f}%"
            if good_summary.weight_coverage is not None
            else "N/A"
        )
        print(f"    Overall Score:    {good_score} ({good_summary.readiness_label})")
        print(
            f"    Rule Coverage:    {good_cov} "
            f"({good_summary.assessed_rules}/{good_summary.applicable_rules} rules assessed)"
        )
        print(f"    Weight Coverage:  {good_wt_cov}")
        print(
            f"    Passed: {good_summary.total_passed} | "
            f"Failed: {good_summary.total_failed} | "
            f"Needs Review: {good_summary.total_needs_review} | "
            f"Not Applicable: {good_summary.total_not_applicable} | "
            f"Not Evaluated: {good_summary.total_not_evaluated}"
        )

        # Print per-rule findings table for good_site
        print("\n" + "-" * 78)
        print(f"{'Rule ID':<32} {'Status':<16} {'Source Tools':<20} {'Matched Terms'}")
        print("-" * 78)
        for f in good_report.findings:
            source = ", ".join(f.sources) if f.sources else str(f.check_type)
            terms = ", ".join(f.matched_terms) if f.matched_terms else "-"
            if len(terms) > 30:
                terms = terms[:27] + "..."
            print(f"{f.rule_id:<32} {f.status.value:<16} {source:<20} {terms}")
        print("-" * 78)

        # Print category scores table for good_site
        print("\nCategory Breakdown (good_site):")
        print(
            f"{'Category':<24} {'Score':<8} {'Passed':<8} {'Failed':<8} "
            f"{'Needs Review':<14} {'Not Applicable':<16}"
        )
        print("-" * 78)
        for cat in good_summary.category_scores:
            score_str = f"{cat.score:.1f}%" if cat.score is not None else "N/A"
            print(
                f"{cat.category:<24} {score_str:<8} {cat.passed_count:<8} "
                f"{cat.failed_count:<8} {cat.needs_review_count:<14} "
                f"{cat.not_applicable_count:<16}"
            )
        print("-" * 78)

        good_md = generate_gap_report(good_report.model_dump(), format="markdown")
        good_report_file = examples_dir / "good_site.md"
        good_report_file.write_text(good_md, encoding="utf-8")
        print(f"\n    Saved report to:  {good_report_file.relative_to(PROJECT_ROOT)}")

        # Audit Bad Site & Project
        print("\n--> Auditing 'bad_site' and non-conforming sample project...")
        bad_report = await run_full_audit(
            url=f"http://127.0.0.1:{port_bad}",
            project_path=str(bad_proj_dir),
        )
        bad_summary = bad_report.summary
        bad_score = (
            f"{bad_summary.overall_score:.1f}%"
            if bad_summary.overall_score is not None
            else "Insufficient data"
        )
        bad_cov = f"{bad_summary.coverage:.1f}%" if bad_summary.coverage is not None else "N/A"
        bad_wt_cov = (
            f"{bad_summary.weight_coverage:.1f}%"
            if bad_summary.weight_coverage is not None
            else "N/A"
        )
        print(f"    Overall Score:    {bad_score} ({bad_summary.readiness_label})")
        print(
            f"    Rule Coverage:    {bad_cov} "
            f"({bad_summary.assessed_rules}/{bad_summary.applicable_rules} rules assessed)"
        )
        print(f"    Weight Coverage:  {bad_wt_cov}")
        print(
            f"    Passed: {bad_summary.total_passed} | "
            f"Failed: {bad_summary.total_failed} | "
            f"Needs Review: {bad_summary.total_needs_review} | "
            f"Not Applicable: {bad_summary.total_not_applicable} | "
            f"Not Evaluated: {bad_summary.total_not_evaluated}"
        )

        # Print per-rule findings table for bad_site
        print("\n" + "-" * 78)
        print(f"{'Rule ID':<32} {'Status':<16} {'Source Tools':<20} {'Matched Terms'}")
        print("-" * 78)
        for f in bad_report.findings:
            source = ", ".join(f.sources) if f.sources else str(f.check_type)
            terms = ", ".join(f.matched_terms) if f.matched_terms else "-"
            if len(terms) > 30:
                terms = terms[:27] + "..."
            print(f"{f.rule_id:<32} {f.status.value:<16} {source:<20} {terms}")
        print("-" * 78)

        # Print category scores table for bad_site
        print("\nCategory Breakdown (bad_site):")
        print(
            f"{'Category':<24} {'Score':<8} {'Passed':<8} {'Failed':<8} "
            f"{'Needs Review':<14} {'Not Applicable':<16}"
        )
        print("-" * 78)
        for cat in bad_summary.category_scores:
            score_str = f"{cat.score:.1f}%" if cat.score is not None else "N/A"
            print(
                f"{cat.category:<24} {score_str:<8} {cat.passed_count:<8} "
                f"{cat.failed_count:<8} {cat.needs_review_count:<14} "
                f"{cat.not_applicable_count:<16}"
            )
        print("-" * 78)

        bad_md = generate_gap_report(bad_report.model_dump(), format="markdown")
        bad_report_file = examples_dir / "bad_site.md"
        bad_report_file.write_text(bad_md, encoding="utf-8")
        print(f"    Saved report to:  {bad_report_file.relative_to(PROJECT_ROOT)}")

        print("\n" + "=" * 78)
        print("DEMO AUDIT COMPLETED SUCCESSFULLY")
        print("=" * 78)

    finally:
        server_good.shutdown()
        server_bad.shutdown()


def main():
    asyncio.run(run_demo())


if __name__ == "__main__":
    main()
