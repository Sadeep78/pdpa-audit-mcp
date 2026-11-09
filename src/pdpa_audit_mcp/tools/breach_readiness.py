"""Breach readiness and incident response documentation auditor under Sri Lanka PDPA."""

from __future__ import annotations

import re
from pathlib import Path

from pdpa_audit_mcp.checklist import get_rule_by_id
from pdpa_audit_mcp.config import DEFENSIVE_USE_NOTICE, LEGAL_DISCLAIMER
from pdpa_audit_mcp.models import (
    CheckTypeEnum,
    ConfidenceEnum,
    Finding,
    RuleFindingStatus,
    ToolResult,
)
from pdpa_audit_mcp.safety import (
    SecurityError,
    is_safe_file_path,
    is_safe_file_size,
    sanitize_evidence_snippet,
    validate_project_path,
)

TOOL_DESCRIPTION: str = (
    "Audit repository documentation for personal data breach response readiness, "
    "incident escalation procedures, and security contacts under Sri Lanka PDPA No. 9 of 2022. "
    f"{DEFENSIVE_USE_NOTICE}"
)

# Incident doc search patterns
DOC_PATTERNS: list[str] = [
    "incident*",
    "breach*",
    "security.md",
    "security.txt",
]

DOC_DIRS: list[str] = ["docs", ".github", "documentation"]

_ROLES_KEYWORDS: list[str] = [
    "roles",
    "responsibilities",
    "dpo",
    "incident lead",
    "team",
    "coordinator",
]
_ESCALATION_KEYWORDS: list[str] = [
    "escalation",
    "internal notification",
    "timeline",
    "72 hours",
    "immediate",
    "register",
    "log",
]
_CONTACT_EMAIL_REGEX = re.compile(r"\bsecurity@[a-zA-Z0-9.\-_]+\b", re.IGNORECASE)


def _find_incident_docs(base_dir: Path) -> list[tuple[Path, str]]:
    """Locate incident response and security documentation files."""
    found: list[tuple[Path, str]] = []

    # Check root level and common doc folders
    candidate_paths: list[Path] = []
    for pattern in DOC_PATTERNS:
        candidate_paths.extend(base_dir.glob(pattern))
        candidate_paths.extend(base_dir.glob(pattern.upper()))
        for doc_dir in DOC_DIRS:
            d = base_dir / doc_dir
            if d.is_dir() and is_safe_file_path(base_dir, d):
                candidate_paths.extend(d.glob(pattern))
                candidate_paths.extend(d.glob(pattern.upper()))

    seen_paths: set[Path] = set()
    for p in candidate_paths:
        if p.is_file() and p not in seen_paths:
            seen_paths.add(p)
            if is_safe_file_path(base_dir, p) and is_safe_file_size(p):
                try:
                    text = p.read_text(encoding="utf-8", errors="replace")
                    found.append((p, text))
                except (OSError, UnicodeDecodeError):
                    pass

    return found


async def check_breach_readiness(path: str) -> ToolResult:
    """Evaluate repository documentation for incident response and breach readiness.

    Defensive use only.
    """
    try:
        base_dir = validate_project_path(path)
    except (SecurityError, ValueError) as exc:
        return ToolResult(
            status="error",
            tool_name="check_breach_readiness",
            error_message=f"Invalid or unsafe project path: {exc}",
            disclaimer=LEGAL_DISCLAIMER,
        )

    doc_files = _find_incident_docs(base_dir)
    has_docs = len(doc_files) > 0

    combined_text = "\n".join(t for _, t in doc_files).lower()
    doc_names = [str(p.relative_to(base_dir)) for p, _ in doc_files]

    # Evaluate specific elements
    has_roles = any(kw in combined_text for kw in _ROLES_KEYWORDS)
    has_escalation = any(kw in combined_text for kw in _ESCALATION_KEYWORDS)
    contact_match = _CONTACT_EMAIL_REGEX.search(combined_text)

    # Also check if security.txt exists in root or .well-known
    security_txt_exists = any(
        (base_dir / name).exists() for name in ("security.txt", ".well-known/security.txt")
    )

    findings: list[Finding] = []

    # Rule 1: breach_response_plan_documented
    rule_plan = get_rule_by_id("breach_response_plan_documented")
    if has_docs and has_roles:
        findings.append(
            Finding(
                rule_id="breach_response_plan_documented",
                category="Breach Readiness",
                title=rule_plan.title if rule_plan else "Incident Response Plan",
                severity=rule_plan.severity if rule_plan else "high",
                status=RuleFindingStatus.PASSED,
                confidence=ConfidenceEnum.HIGH,
                evidence=sanitize_evidence_snippet(
                    f"Incident response docs in {doc_names} outlining roles and containment."
                ),
                recommendation=(
                    "Conduct regular incident response tabletop drills to maintain readiness."
                ),
                legal_ref="TODO_VERIFY",
                check_type=CheckTypeEnum.BREACH,
                details={"documentation_files": doc_names},
            )
        )
    else:
        # HARD RULE: Never report FAILED for missing breach docs
        findings.append(
            Finding(
                rule_id="breach_response_plan_documented",
                category="Breach Readiness",
                title=rule_plan.title if rule_plan else "Incident Response Plan",
                severity=rule_plan.severity if rule_plan else "high",
                status=RuleFindingStatus.NEEDS_REVIEW,
                confidence=ConfidenceEnum.LOW,
                evidence="Incident response plan documentation not found in repository.",
                recommendation=(
                    "Establish an incident response procedure for personal data breaches. "
                    "Note that policies may be maintained outside code repositories."
                ),
                legal_ref="TODO_VERIFY",
                check_type=CheckTypeEnum.BREACH,
                details={"note": "plan may exist outside repository"},
            )
        )

    # Rule 2: breach_notification_contact
    rule_contact = get_rule_by_id("breach_notification_contact")
    if contact_match or security_txt_exists:
        email_str = contact_match.group(0) if contact_match else "security.txt contact"
        findings.append(
            Finding(
                rule_id="breach_notification_contact",
                category="Breach Readiness",
                title=rule_contact.title if rule_contact else "Breach Notification Contact",
                severity=rule_contact.severity if rule_contact else "medium",
                status=RuleFindingStatus.PASSED,
                confidence=ConfidenceEnum.HIGH,
                evidence=sanitize_evidence_snippet(
                    f"Designated security incident contact published: {email_str}"
                ),
                recommendation="Ensure security inbox is monitored with escalation paths.",
                legal_ref="TODO_VERIFY",
                check_type=CheckTypeEnum.BREACH,
            )
        )
    else:
        findings.append(
            Finding(
                rule_id="breach_notification_contact",
                category="Breach Readiness",
                title=rule_contact.title if rule_contact else "Breach Notification Contact",
                severity=rule_contact.severity if rule_contact else "medium",
                status=RuleFindingStatus.NEEDS_REVIEW,
                confidence=ConfidenceEnum.LOW,
                evidence="Dedicated security contact or security.txt not found in repository.",
                recommendation=(
                    "Publish a designated security contact email or RFC 9116 security.txt file "
                    "to streamline vulnerability and breach reporting."
                ),
                legal_ref="TODO_VERIFY",
                check_type=CheckTypeEnum.BREACH,
                details={"note": "security contact details may be managed externally"},
            )
        )

    # Rule 3: breach_internal_escalation
    rule_escalation = get_rule_by_id("breach_internal_escalation")
    if has_docs and has_escalation:
        findings.append(
            Finding(
                rule_id="breach_internal_escalation",
                category="Breach Readiness",
                title=rule_escalation.title if rule_escalation else "Breach Escalation Timelines",
                severity=rule_escalation.severity if rule_escalation else "medium",
                status=RuleFindingStatus.PASSED,
                confidence=ConfidenceEnum.HIGH,
                evidence="Documentation specifies incident escalation timelines and breach log.",
                recommendation=(
                    "Maintain the incident register documenting facts and corrective actions."
                ),
                legal_ref="TODO_VERIFY",
                check_type=CheckTypeEnum.BREACH,
            )
        )
    else:
        findings.append(
            Finding(
                rule_id="breach_internal_escalation",
                category="Breach Readiness",
                title=rule_escalation.title if rule_escalation else "Breach Escalation Timelines",
                severity=rule_escalation.severity if rule_escalation else "medium",
                status=RuleFindingStatus.NEEDS_REVIEW,
                confidence=ConfidenceEnum.LOW,
                evidence="Internal breach escalation timelines not found in repository.",
                recommendation=(
                    "Define internal escalation timelines and establish a breach register "
                    "documenting severity, root causes, and remediation measures."
                ),
                legal_ref="TODO_VERIFY",
                check_type=CheckTypeEnum.BREACH,
                details={"note": "escalation procedures may be documented in corporate policies"},
            )
        )

    return ToolResult(
        status="ok",
        tool_name="check_breach_readiness",
        findings=findings,
        data={
            "documents_found": doc_names,
            "has_roles_and_responsibilities": has_roles,
            "has_escalation_timelines": has_escalation,
            "has_security_contact": bool(contact_match or security_txt_exists),
        },
        disclaimer=LEGAL_DISCLAIMER,
    )
