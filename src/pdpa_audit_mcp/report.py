"""Full audit orchestrator and gap analysis report generator for Sri Lanka PDPA readiness."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal

from pdpa_audit_mcp.checklist import get_rules_by_category, load_checklist
from pdpa_audit_mcp.config import DEFENSIVE_USE_NOTICE, LEGAL_DISCLAIMER, LEGAL_REF_PENDING
from pdpa_audit_mcp.fetcher import SafeFetcher
from pdpa_audit_mcp.models import (
    CheckTypeEnum,
    ConfidenceEnum,
    Finding,
    Report,
    RuleFindingStatus,
    SeverityEnum,
    ToolResult,
)
from pdpa_audit_mcp.safety import (
    SecurityError,
    sanitize_evidence_snippet,
    validate_input_path,
    validate_input_url,
)
from pdpa_audit_mcp.scoring import calculate_readiness_score
from pdpa_audit_mcp.tools.breach_readiness import check_breach_readiness
from pdpa_audit_mcp.tools.cookie_consent import detect_cookie_consent
from pdpa_audit_mcp.tools.forms import find_personal_data_forms
from pdpa_audit_mcp.tools.privacy_policy import scan_privacy_policy
from pdpa_audit_mcp.tools.project_scan import scan_project_files
from pdpa_audit_mcp.tools.transfers import detect_third_party_transfers

if TYPE_CHECKING:
    import httpx

STATUS_PRECEDENCE: dict[RuleFindingStatus, int] = {
    RuleFindingStatus.FAILED: 5,
    RuleFindingStatus.NEEDS_REVIEW: 4,
    RuleFindingStatus.PASSED: 3,
    RuleFindingStatus.NOT_EVALUATED: 2,
    RuleFindingStatus.NOT_APPLICABLE: 1,
}

SEVERITY_ORDER: dict[SeverityEnum | str, int] = {
    SeverityEnum.HIGH: 0,
    "high": 0,
    SeverityEnum.MEDIUM: 1,
    "medium": 1,
    SeverityEnum.LOW: 2,
    "low": 2,
}

DEFAULT_OUT_OF_SCOPE: list[str] = [
    "Client-side JavaScript rendering not visible in initial static HTML responses.",
    "Internal organizational data retention schedules and physical server purge routines.",
    "Formal appointment and legal qualifications of the Data Protection Officer.",
    "Third-party processing contracts, cloud vendor agreements, and adequacy documentation.",
    "Physical premises security, employee background checks, and organizational governance.",
]


def _format_markdown_evidence(evidence: str) -> str:
    """Format evidence snippet inside an inline code span with backticks escaped."""
    if not evidence:
        return "`None`"
    # Double-sanitize to ensure zero-width chars and control chars are stripped
    clean = sanitize_evidence_snippet(evidence, max_chars=120)
    # Escape backticks so malicious markdown injection cannot break out of code span
    clean_escaped = clean.replace("`", r"\`")
    return f"`{clean_escaped}`"


def list_checklist(category: str | None = None) -> ToolResult:
    """List technical readiness checklist rules, optionally filtered by category.

    Use only on sites/projects you own or are authorised to audit.
    """
    try:
        rules = get_rules_by_category(category) if category else load_checklist()
        rules_data = [
            {
                "id": r.id,
                "category": r.category,
                "title": r.title,
                "severity": r.severity.value,
                "weight": r.weight,
                "check_type": r.check_type.value,
                "legal_ref": r.display_legal_ref,
                "recommendation": r.recommendation,
                "detector": r.detector,
            }
            for r in rules
        ]
        return ToolResult(
            status="ok",
            tool_name="list_checklist",
            findings=[],
            data={"rules_count": len(rules_data), "rules": rules_data},
            disclaimer=LEGAL_DISCLAIMER,
        )
    except (FileNotFoundError, ValueError, OSError) as exc:
        return ToolResult(
            status="error",
            tool_name="list_checklist",
            findings=[],
            error_message=f"Failed to list checklist rules: {exc}",
            disclaimer=LEGAL_DISCLAIMER,
        )


async def run_full_audit(
    url: str | None = None,
    project_path: str | None = None,
    client: httpx.AsyncClient | None = None,
    timeout_seconds: float = 60.0,
) -> Report:
    """Run a comprehensive PDPA readiness gap analysis across web and/or project targets.

    At least one of `url` or `project_path` must be provided.
    Use only on sites/projects you own or are authorised to audit.
    """
    now_iso = datetime.now(UTC).isoformat()

    if not url and not project_path:
        summary = calculate_readiness_score([])
        return Report(
            status="error",
            target="none",
            timestamp=now_iso,
            summary=summary,
            error_message="At least one of 'url' or 'project_path' must be provided.",
            disclaimer=LEGAL_DISCLAIMER,
        )

    # Validate inputs
    clean_url: str | None = None
    clean_path: str | None = None

    if url:
        try:
            clean_url = validate_input_url(url)
        except (SecurityError, ValueError) as exc:
            summary = calculate_readiness_score([])
            return Report(
                status="error",
                target=str(url),
                timestamp=now_iso,
                summary=summary,
                error_message=f"Invalid URL: {exc}",
                disclaimer=LEGAL_DISCLAIMER,
            )

    if project_path:
        try:
            clean_path = validate_input_path(project_path)
        except (SecurityError, ValueError) as exc:
            summary = calculate_readiness_score([])
            return Report(
                status="error",
                target=str(project_path),
                timestamp=now_iso,
                summary=summary,
                error_message=f"Invalid project path: {exc}",
                disclaimer=LEGAL_DISCLAIMER,
            )

    target_desc = f"URL={clean_url or 'None'}, Project={clean_path or 'None'}"
    all_rules = load_checklist()
    rules_map = {r.id: r for r in all_rules}

    # Initialize shared fetcher with page cache for all URL audit tools
    shared_fetcher = SafeFetcher(client=client)
    collected_findings: list[Finding] = []
    audit_errors: list[str] = []

    async def _execute_audit_coros():
        # URL Tools
        if clean_url:
            # 1. Privacy policy
            try:
                res_policy = await scan_privacy_policy(clean_url, fetcher=shared_fetcher)
                if res_policy.status == "error":
                    audit_errors.append(f"privacy_policy: {res_policy.error_message}")
                for f in res_policy.findings:
                    f.sources = ["privacy_policy"]
                    collected_findings.append(f)
            except Exception as exc:  # noqa: BLE001 - Deliberate tool isolation boundary in full audit orchestration
                audit_errors.append(f"privacy_policy failed: {exc}")

            # 2. Cookie consent
            try:
                res_cookies = await detect_cookie_consent(clean_url, fetcher=shared_fetcher)
                if res_cookies.status == "error":
                    audit_errors.append(f"cookie_consent: {res_cookies.error_message}")
                for f in res_cookies.findings:
                    f.sources = ["cookie_consent"]
                    collected_findings.append(f)
            except Exception as exc:  # noqa: BLE001 - Deliberate tool isolation boundary in full audit orchestration
                audit_errors.append(f"cookie_consent failed: {exc}")

            # 3. Third-party transfers
            try:
                res_transfers = await detect_third_party_transfers(
                    clean_url, fetcher=shared_fetcher
                )
                if res_transfers.status == "error":
                    audit_errors.append(f"transfers: {res_transfers.error_message}")
                for f in res_transfers.findings:
                    f.sources = ["transfers"]
                    collected_findings.append(f)
            except Exception as exc:  # noqa: BLE001 - Deliberate tool isolation boundary in full audit orchestration
                audit_errors.append(f"transfers failed: {exc}")

            # 4. Forms via URL
            try:
                res_forms_url = await find_personal_data_forms(clean_url, fetcher=shared_fetcher)
                if res_forms_url.status == "error":
                    audit_errors.append(f"forms(url): {res_forms_url.error_message}")
                for f in res_forms_url.findings:
                    f.sources = ["forms(url)"]
                    collected_findings.append(f)
            except Exception as exc:  # noqa: BLE001 - Deliberate tool isolation boundary in full audit orchestration
                audit_errors.append(f"forms(url) failed: {exc}")

        # Project Tools
        if clean_path:
            # 5. Project files scan
            try:
                res_proj = await scan_project_files(clean_path)
                if res_proj.status == "error":
                    audit_errors.append(f"project_scan: {res_proj.error_message}")
                for f in res_proj.findings:
                    f.sources = ["project_scan"]
                    collected_findings.append(f)
            except Exception as exc:  # noqa: BLE001 - Deliberate tool isolation boundary in full audit orchestration
                audit_errors.append(f"project_scan failed: {exc}")

            # 6. Breach readiness
            try:
                res_breach = await check_breach_readiness(clean_path)
                if res_breach.status == "error":
                    audit_errors.append(f"breach_readiness: {res_breach.error_message}")
                for f in res_breach.findings:
                    f.sources = ["breach_readiness"]
                    collected_findings.append(f)
            except Exception as exc:  # noqa: BLE001 - Deliberate tool isolation boundary in full audit orchestration
                audit_errors.append(f"breach_readiness failed: {exc}")

            # 7. Forms via project files
            try:
                res_forms_path = await find_personal_data_forms(clean_path)
                if res_forms_path.status == "error":
                    audit_errors.append(f"forms(project): {res_forms_path.error_message}")
                for f in res_forms_path.findings:
                    f.sources = ["forms(project)"]
                    collected_findings.append(f)
            except Exception as exc:  # noqa: BLE001 - Deliberate tool isolation boundary in full audit orchestration
                audit_errors.append(f"forms(project) failed: {exc}")

    try:
        await asyncio.wait_for(_execute_audit_coros(), timeout=timeout_seconds)
    except TimeoutError:
        audit_errors.append(f"Full audit exceeded time budget of {timeout_seconds}s.")
    except Exception as exc:  # noqa: BLE001 - Deliberate boundary for full audit orchestration
        audit_errors.append(f"Unexpected error during full audit execution: {exc}")
    finally:
        await shared_fetcher.aclose()

    # Merge findings across multiple sources with conservative precedence:
    # FAILED > NEEDS_REVIEW > PASSED > NOT_EVALUATED > NOT_APPLICABLE
    # (An inspected 'passed' beats unrun/empty; an unrun source beats 'not applicable')
    findings_by_rule: dict[str, list[Finding]] = {}
    for f in collected_findings:
        findings_by_rule.setdefault(f.rule_id, []).append(f)

    merged_findings: list[Finding] = []

    for rule_id, f_list in findings_by_rule.items():
        # Sort by status precedence descending; prefer URL sources when status is tied
        f_list.sort(
            key=lambda x: (
                STATUS_PRECEDENCE.get(x.status, 0),
                1
                if any(
                    "url" in s or "transfers" in s or "privacy" in s or "cookie" in s
                    for s in x.sources
                )
                else 0,
            ),
            reverse=True,
        )
        winner = f_list[0]

        seen_src: set[str] = set()
        all_sources: list[str] = []
        for item in f_list:
            for s in item.sources:
                if s and s not in seen_src:
                    seen_src.add(s)
                    all_sources.append(s)

        evidence_snippets = [item.evidence for item in f_list if item.evidence]
        combined_evidence = " | ".join(dict.fromkeys(evidence_snippets))
        sanitized_ev = sanitize_evidence_snippet(combined_evidence, max_chars=120)

        combined_matched_terms = list(
            dict.fromkeys(t for item in f_list for t in getattr(item, "matched_terms", []))
        )[:5]

        rule_obj = rules_map.get(rule_id)
        merged_findings.append(
            Finding(
                rule_id=winner.rule_id,
                category=winner.category,
                title=winner.title,
                severity=winner.severity,
                status=winner.status,
                evidence=sanitized_ev,
                matched_terms=combined_matched_terms,
                recommendation=winner.recommendation,
                confidence=winner.confidence,
                legal_ref=winner.legal_ref,
                legal_ref_verified=rule_obj.legal_ref_verified if rule_obj else False,
                source_url=rule_obj.source_url if rule_obj else None,
                check_type=winner.check_type,
                sources=all_sources,
                details=winner.details,
            )
        )

    # Check for rules not evaluated by any tool in this run
    evaluated_ids = {f.rule_id for f in merged_findings}
    for rule in all_rules:
        if rule.id not in evaluated_ids:
            if rule.check_type == CheckTypeEnum.MANUAL:
                merged_findings.append(
                    Finding(
                        rule_id=rule.id,
                        category=rule.category,
                        title=rule.title,
                        severity=rule.severity,
                        status=RuleFindingStatus.NEEDS_REVIEW,
                        confidence=ConfidenceEnum.LOW,
                        evidence="Manual review required: cannot be audited purely statically.",
                        recommendation=rule.recommendation,
                        legal_ref=rule.legal_ref,
                        legal_ref_verified=rule.legal_ref_verified,
                        source_url=rule.source_url,
                        check_type=CheckTypeEnum.MANUAL,
                        sources=["checklist"],
                    )
                )
            else:
                merged_findings.append(
                    Finding(
                        rule_id=rule.id,
                        category=rule.category,
                        title=rule.title,
                        severity=rule.severity,
                        status=RuleFindingStatus.NOT_EVALUATED,
                        confidence=ConfidenceEnum.LOW,
                        evidence="Not assessed in this run (associated tool was not executed).",
                        recommendation=rule.recommendation,
                        legal_ref=rule.legal_ref,
                        legal_ref_verified=rule.legal_ref_verified,
                        source_url=rule.source_url,
                        check_type=rule.check_type,
                        sources=["checklist"],
                    )
                )

    # Calculate overall and category scores
    summary = calculate_readiness_score(merged_findings, rules_map)

    needs_review = [f for f in merged_findings if f.status == RuleFindingStatus.NEEDS_REVIEW]
    not_applicable = [f for f in merged_findings if f.status == RuleFindingStatus.NOT_APPLICABLE]
    not_assessed = [f for f in merged_findings if f.status == RuleFindingStatus.NOT_EVALUATED]

    return Report(
        status="ok",
        target=target_desc,
        timestamp=now_iso,
        summary=summary,
        findings=merged_findings,
        needs_human_review=needs_review,
        not_applicable=not_applicable,
        not_assessed=not_assessed,
        out_of_scope=DEFAULT_OUT_OF_SCOPE,
        errors=audit_errors,
        disclaimer=LEGAL_DISCLAIMER,
    )


def generate_gap_report(
    audit_result: Report | dict[str, Any],
    format: Literal["markdown", "json"] = "markdown",
) -> str:
    """Generate a formatted markdown or JSON gap analysis report from an audit result.

    Includes disclaimers top and bottom, untrusted content hardening, and prioritised findings.
    """
    if isinstance(audit_result, dict):
        report = Report.model_validate(audit_result)
    else:
        report = audit_result

    if format.lower() == "json":
        return report.model_dump_json(indent=2)

    # Markdown format generation
    lines: list[str] = []

    # 1. Top Legal Disclaimer
    lines.append(f"> **LEGAL DISCLAIMER**: {report.disclaimer}")
    lines.append("")
    lines.append(f"> **DEFENSIVE NOTICE**: {DEFENSIVE_USE_NOTICE}")
    lines.append("")

    # 2. Header
    lines.append("# Sri Lanka PDPA Technical Readiness Gap Analysis Report")
    lines.append("")

    # 3. Executive Summary
    summary = report.summary
    if summary.overall_score is None:
        score_str = "Insufficient data"
        label_str = "Insufficient data"
        lines.append("## Executive Summary")
        lines.append(f"- **Target**: {report.target}")
        lines.append(f"- **Timestamp**: {report.timestamp}")
        lines.append(f"- **Overall Readiness Score**: {score_str} ({label_str})")
    else:
        score_str = f"{summary.overall_score:.1f}%"
        label_str = summary.readiness_label
        cov_str = f"{summary.coverage:.1f}%" if summary.coverage is not None else "N/A"
        weight_cov_str = (
            f"{summary.weight_coverage:.1f}%" if summary.weight_coverage is not None else "N/A"
        )
        review_note = (
            f" | {summary.total_needs_review} rules require human review"
            if summary.total_needs_review > 0
            else ""
        )
        lines.append("## Executive Summary")
        lines.append(f"- **Target**: {report.target}")
        lines.append(f"- **Timestamp**: {report.timestamp}")
        score_detail = (
            f"- **Overall Readiness Score**: {score_str} "
            f"({label_str} | Coverage: {cov_str} [weight: {weight_cov_str}]{review_note})"
        )
        lines.append(score_detail)

    lines.append(
        f"- **Audit Execution Status**: {report.status.upper()} "
        f"*(Assessed: {summary.assessed_rules}/{summary.applicable_rules}, "
        f"Needs review: {summary.total_needs_review}, "
        f"Not applicable: {summary.total_not_applicable}, "
        f"Not assessed: {summary.total_not_evaluated})*"
    )
    lines.append("")

    # Category Breakdown Table
    lines.append("### Category Breakdown")
    lines.append(
        "| Category | Score | Passed | Failed | Needs Review | Not Applicable | Not Evaluated |"
    )
    lines.append("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |")
    for cat in summary.category_scores:
        cat_score_str = f"{cat.score:.1f}%" if cat.score is not None else "Insufficient data"
        lines.append(
            f"| {cat.category} | {cat_score_str} | {cat.passed_count} | {cat.failed_count} | "
            f"{cat.needs_review_count} | {cat.not_applicable_count} | {cat.not_evaluated_count} |"
        )
    lines.append("")

    # 4. Failed Items Grouped by Priority (High, Medium, Low)
    failed_items = [f for f in report.findings if f.status == RuleFindingStatus.FAILED]
    high_gaps = [f for f in failed_items if f.severity == SeverityEnum.HIGH]
    med_gaps = [f for f in failed_items if f.severity == SeverityEnum.MEDIUM]
    low_gaps = [f for f in failed_items if f.severity == SeverityEnum.LOW]

    def _render_gap_list(items: list[Finding], section_title: str) -> None:
        lines.append(f"## {section_title}")
        if not items:
            lines.append("No technical failures detected in this severity tier.")
            lines.append("")
            return
        for idx, item in enumerate(items, start=1):
            legal_ref_note = item.legal_ref if item.legal_ref_verified else LEGAL_REF_PENDING
            ev_snippet = _format_markdown_evidence(item.evidence)
            sources_note = f" (sources: {', '.join(item.sources)})" if item.sources else ""
            lines.append(f"### {idx}. {item.title} (`{item.rule_id}`) [{item.severity.upper()}]")
            lines.append(f"- **Category**: {item.category}")
            lines.append(f"- **Status**: {item.status.value}")
            lines.append(f"- **Severity**: {item.severity.value}")
            lines.append(f"- **PDPA Section**: {legal_ref_note}")
            lines.append(f"- **Description**: {item.title}")
            rec = item.recommendation or "Review and remediate technical indicator."
            lines.append(f"- **Remediation Recommendation**: {rec}")
            if item.matched_terms:
                lines.append(f"- **Matched Terms**: {', '.join(item.matched_terms)}")
            lines.append(f"- **Evidence**: {ev_snippet}{sources_note}")
            lines.append("")

    _render_gap_list(high_gaps, "High-Priority Gaps")
    _render_gap_list(med_gaps, "Medium-Priority Gaps")
    _render_gap_list(low_gaps, "Low-Priority Gaps")

    # 5. Items Needing Human Review
    lines.append("## Needs Manual Review")
    if report.needs_human_review:
        for idx, item in enumerate(report.needs_human_review, start=1):
            ev_snippet = _format_markdown_evidence(item.evidence)
            legal_ref_note = item.legal_ref if item.legal_ref_verified else LEGAL_REF_PENDING
            rec = item.recommendation or "Conduct manual audit/review of processes and policies."
            lines.append(f"### {idx}. {item.title} (`{item.rule_id}`) - Category: {item.category}")
            lines.append(f"- **Status**: {item.status.value} (Confidence: {item.confidence})")
            lines.append(f"- **PDPA Section**: {legal_ref_note}")
            lines.append(f"- **Remediation Recommendation**: {rec}")
            if item.matched_terms:
                lines.append(f"- **Matched Terms**: {', '.join(item.matched_terms)}")
            lines.append(f"- **Observation**: {ev_snippet}")
            lines.append("")
    else:
        lines.append("No items flagged for manual review.")
        lines.append("")

    # 6. Not Applicable in This Run
    lines.append("## Not Applicable")
    if report.not_applicable:
        for idx, item in enumerate(report.not_applicable, start=1):
            ev_snippet = _format_markdown_evidence(item.evidence)
            lines.append(f"### {idx}. {item.title} (`{item.rule_id}`) - Category: {item.category}")
            lines.append(f"- **Status**: {item.status.value}")
            lines.append(f"- **Reason**: {ev_snippet}")
            lines.append("")
    else:
        lines.append("No rules classified as not applicable.")
        lines.append("")

    # 7. Not Evaluated in This Run
    lines.append("## Not Evaluated")
    if report.not_assessed:
        for item in report.not_assessed:
            lines.append(
                f"- **{item.title}** (`{item.rule_id}`) - Category: {item.category} "
                f"*(Check Type: {item.check_type})*"
            )
    else:
        lines.append("All technical rules were evaluated.")
    lines.append("")

    # 8. Out of Scope (Static Analysis Limitations)
    lines.append("## Out of Scope")
    lines.append("The following aspects cannot be validated via automated static scanning:")
    for oos in report.out_of_scope:
        lines.append(f"- {oos}")
    lines.append("")

    # 9. Errors Encountered During Audit
    if report.errors:
        lines.append("## Execution Warnings & Isolated Tool Errors")
        for err in report.errors:
            lines.append(f"- {err}")
        lines.append("")

    # 10. Heuristic Weights Footnote
    lines.append(
        "*Note: Rule weights and severities are heuristic technical indicators and do not reflect "
        "legal priority or liability under Sri Lanka PDPA No. 9 of 2022.*"
    )
    lines.append("")

    # 11. Bottom Legal Disclaimer
    lines.append(f"> **LEGAL DISCLAIMER**: {report.disclaimer}")

    return "\n".join(lines)
