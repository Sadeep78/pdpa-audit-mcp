"""Static code and repository scanner for personal data models, logging, and SDK dependencies."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from pdpa_audit_mcp.checklist import get_rule_by_id
from pdpa_audit_mcp.config import DEFENSIVE_USE_NOTICE, LEGAL_DISCLAIMER
from pdpa_audit_mcp.models import (
    CheckTypeEnum,
    ConfidenceEnum,
    Finding,
    RuleFindingStatus,
    SeverityEnum,
    ToolResult,
)
from pdpa_audit_mcp.safety import (
    SecurityError,
    is_safe_file_path,
    is_safe_file_size,
    sanitize_evidence_snippet,
    validate_project_path,
)
from pdpa_audit_mcp.tools.constants import (
    PERSONAL_FIELD_NAMES,
    SENSITIVE_FIELD_NAMES,
    THIRD_PARTY_SDK_PATTERNS,
)

TOOL_DESCRIPTION: str = (
    "Scan a local project directory for personal data models and retention/deletion logic, "
    "logging of personal data fields (file and line number only), and third-party SDK dependencies "
    "under Sri Lanka PDPA No. 9 of 2022. "
    f"{DEFENSIVE_USE_NOTICE}"
)

MAX_PROJECT_FILES: int = 5000
MAX_TOTAL_SCAN_BYTES: int = 20 * 1024 * 1024  # 20 MB total read cap

CODE_EXTENSIONS: set[str] = {
    ".py",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".php",
    ".go",
    ".java",
    ".rb",
    ".sql",
    ".prisma",
}

DEPENDENCY_FILES: set[str] = {
    "package.json",
    "requirements.txt",
    "pyproject.toml",
    "pipfile",
    "gemfile",
}

# Regex to detect logging statements
_LOGGING_PATTERN = re.compile(
    r"(?:console\.(?:log|info|warn|error|debug)|logger\.(?:info|debug|warn|error|critical)"
    r"|logging\.(?:info|debug|warn|error|critical)|print)\s*\((.*?)\)",
    re.IGNORECASE,
)

# Deletion/retention keywords in schemas and methods
_DELETION_KEYWORDS: set[str] = {
    "delete",
    "purge",
    "destroy",
    "retention",
    "anonymize",
    "soft_delete",
    "cascade",
    "erasure",
    "ttl",
    "expired",
}


def _scan_dependencies(base_dir: Path) -> list[dict[str, str]]:
    """Scan dependency manifest files for known third-party tracking, analytics, and cloud SDKs."""
    found_sdks: list[dict[str, str]] = []

    for dep_file in base_dir.rglob("*"):
        if not dep_file.is_file():
            continue
        if dep_file.name.lower() not in DEPENDENCY_FILES:
            continue
        if not is_safe_file_path(base_dir, dep_file) or not is_safe_file_size(dep_file):
            continue

        try:
            content = dep_file.read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeDecodeError):
            continue

        file_lower = content.lower()

        if dep_file.name.lower() == "package.json":
            try:
                pkg_data = json.loads(content)
                all_deps: dict[str, str] = {}
                all_deps.update(pkg_data.get("dependencies", {}))
                all_deps.update(pkg_data.get("devDependencies", {}))
                for pkg_name in all_deps:
                    for pattern, sdk_name in THIRD_PARTY_SDK_PATTERNS.items():
                        if pattern.lower() in pkg_name.lower():
                            found_sdks.append(
                                {
                                    "sdk": sdk_name,
                                    "package": pkg_name,
                                    "file": str(dep_file.relative_to(base_dir)),
                                }
                            )
            except (json.JSONDecodeError, TypeError, KeyError):
                pass
        else:
            # Requirements.txt, pyproject.toml, Gemfile
            for line in file_lower.splitlines():
                clean_line = line.strip()
                if not clean_line or clean_line.startswith("#"):
                    continue
                for pattern, sdk_name in THIRD_PARTY_SDK_PATTERNS.items():
                    if pattern in clean_line:
                        found_sdks.append(
                            {
                                "sdk": sdk_name,
                                "package": pattern,
                                "file": str(dep_file.relative_to(base_dir)),
                            }
                        )
                        break

    return found_sdks


def _detect_pii_logging(rel_path: str, content: str) -> tuple[list[dict[str, Any]], int]:
    """Scan code content for logging of personal data fields.

    NEVER returns or logs line content or raw values; reports file, line number,
    and matched field identifier only.
    Returns: (list_of_pii_incidents, total_logging_calls_found)
    """
    pii_log_incidents: list[dict[str, Any]] = []
    total_logging_calls = 0
    lines = content.splitlines()

    target_fields = sorted(set(PERSONAL_FIELD_NAMES + SENSITIVE_FIELD_NAMES))

    for line_no, line in enumerate(lines, start=1):
        # Quick skip if line has no logging invocation
        if not any(kw in line for kw in ("console.", "logger.", "logging.", "print(")):
            continue

        match = _LOGGING_PATTERN.search(line)
        if not match:
            continue

        total_logging_calls += 1
        args_str = match.group(1).lower()

        # Check if any personal data field is referenced in the logging argument
        for field in target_fields:
            if not field or len(field) < 2:
                continue
            # Look for property access (.email), dictionary access (['email']), or identifier
            field_regex = re.compile(
                rf"(?:\b|\.|\[['\"]){re.escape(field)}(?:['\"]\]|\b)", re.IGNORECASE
            )
            if field_regex.search(args_str):
                pii_log_incidents.append(
                    {
                        "file": rel_path,
                        "line": line_no,
                        "field_pattern": field,
                    }
                )

    return pii_log_incidents, total_logging_calls


def _detect_schemas_and_deletion(
    base_dir: Path,
) -> tuple[list[str], bool]:
    """Detect database schemas and models containing personal data and verify deletion logic.

    Returns: (list_of_detected_models, has_deletion_logic)
    """
    detected_models: list[str] = []
    has_deletion = False
    all_target_fields = set(PERSONAL_FIELD_NAMES + SENSITIVE_FIELD_NAMES)

    for path in base_dir.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in CODE_EXTENSIONS:
            continue
        if not is_safe_file_path(base_dir, path) or not is_safe_file_size(path):
            continue

        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeDecodeError):
            continue

        content_lower = content.lower()

        # Check for deletion or retention code (ignore purely commented lines)
        for line in content.splitlines():
            clean = line.strip().lower()
            if clean.startswith(("#", "//", "--", "/*", "*")):
                continue
            if any(re.search(rf"\b{re.escape(dkw)}\b", clean) for dkw in _DELETION_KEYWORDS):
                has_deletion = True
                break

        # Check SQL tables
        if path.suffix.lower() == ".sql" or "create table" in content_lower:
            table_matches = re.finditer(
                r"create\s+table\s+([a-zA-Z0-9_]+)\s*\((.*?)\);",
                content,
                re.DOTALL | re.IGNORECASE,
            )
            for tm in table_matches:
                tbl_name = tm.group(1)
                tbl_body = tm.group(2).lower()
                found_fields = [f for f in all_target_fields if re.search(rf"\b{f}\b", tbl_body)]
                if found_fields:
                    detected_models.append(f"SQL table '{tbl_name}' (fields: {found_fields[:3]})")

        # Check Django / SQLAlchemy models
        if "class " in content and any(
            kw in content for kw in ("models.Model", "Base", "declarative_base")
        ):
            class_matches = re.finditer(r"class\s+([a-zA-Z0-9_]+)\s*\([^)]+\):", content)
            for cm in class_matches:
                cls_name = cm.group(1)
                # Check class block for personal data fields
                if any(re.search(rf"\b{f}\b", content_lower) for f in all_target_fields):
                    detected_models.append(f"Model '{cls_name}'")

        # Check Prisma schemas
        if path.suffix.lower() == ".prisma":
            prisma_models = re.finditer(r"model\s+([a-zA-Z0-9_]+)\s*\{(.*?)\}", content, re.DOTALL)
            for pm in prisma_models:
                m_name = pm.group(1)
                m_body = pm.group(2).lower()
                if any(re.search(rf"\b{f}\b", m_body) for f in all_target_fields):
                    detected_models.append(f"Prisma model '{m_name}'")

    return list(set(detected_models)), has_deletion


async def scan_project_files(path: str) -> ToolResult:
    """Analyze a local project directory for personal data models, logging, and SDKs.

    Defensive use only.
    """
    try:
        base_dir = validate_project_path(path)
    except (SecurityError, ValueError) as exc:
        return ToolResult(
            status="error",
            tool_name="scan_project_files",
            error_message=f"Invalid or unsafe project path: {exc}",
            disclaimer=LEGAL_DISCLAIMER,
        )

    findings: list[Finding] = []
    scanned_files_count = 0
    total_bytes_read = 0
    total_logging_calls = 0

    all_logging_incidents: list[dict[str, Any]] = []

    # File traversal with hard caps (5000 files, 20 MB read limit)
    for p in base_dir.rglob("*"):
        if scanned_files_count >= MAX_PROJECT_FILES:
            break
        if total_bytes_read >= MAX_TOTAL_SCAN_BYTES:
            break
        if not p.is_file():
            continue
        if p.suffix.lower() not in CODE_EXTENSIONS:
            continue
        if not is_safe_file_path(base_dir, p) or not is_safe_file_size(p):
            continue

        try:
            f_size = p.stat().st_size
            total_bytes_read += f_size
            scanned_files_count += 1
            content = p.read_text(encoding="utf-8", errors="replace")
            rel_p = str(p.relative_to(base_dir))
            incidents, file_log_count = _detect_pii_logging(rel_p, content)
            all_logging_incidents.extend(incidents)
            total_logging_calls += file_log_count
        except (OSError, UnicodeDecodeError):
            continue

    # 1. Evaluate Model Schemas and Deletion / Retention Readiness
    models_found, has_deletion = _detect_schemas_and_deletion(base_dir)
    rule_erasure = get_rule_by_id("erasure_mechanism_in_code")
    erasure_terms = [m.split()[0] for m in models_found][:5] if models_found else []

    if models_found and not has_deletion:
        findings.append(
            Finding(
                rule_id="erasure_mechanism_in_code",
                category="Data Subject Rights",
                title=(rule_erasure.title if rule_erasure else "Code-Level Data Erasure Mechanism"),
                severity=rule_erasure.severity if rule_erasure else SeverityEnum.MEDIUM,
                status=RuleFindingStatus.NEEDS_REVIEW,
                confidence=ConfidenceEnum.MEDIUM,
                evidence=sanitize_evidence_snippet(
                    f"Models with personal data identified ({len(models_found)}), "
                    "but no automated deletion or retention methods detected in codebase."
                ),
                matched_terms=erasure_terms,
                recommendation=(
                    "Implement explicit personal data erasure/purge procedures and automated "
                    "retention policies to support data subject deletion rights."
                ),
                legal_ref="TODO_VERIFY",
                check_type=CheckTypeEnum.PROJECT,
                details={"models_detected": models_found[:5]},
            )
        )
    elif models_found and has_deletion:
        findings.append(
            Finding(
                rule_id="erasure_mechanism_in_code",
                category="Data Subject Rights",
                title=(rule_erasure.title if rule_erasure else "Code-Level Data Erasure Mechanism"),
                severity=rule_erasure.severity if rule_erasure else SeverityEnum.MEDIUM,
                status=RuleFindingStatus.PASSED,
                confidence=ConfidenceEnum.HIGH,
                evidence="Data models include explicit deletion, purge, or retention handling.",
                matched_terms=erasure_terms,
                recommendation="Maintain routine testing of data deletion and retention routines.",
                legal_ref="TODO_VERIFY",
                check_type=CheckTypeEnum.PROJECT,
                details={"models_detected": models_found[:5]},
            )
        )
    else:
        findings.append(
            Finding(
                rule_id="erasure_mechanism_in_code",
                category="Data Subject Rights",
                title=(rule_erasure.title if rule_erasure else "Code-Level Data Erasure Mechanism"),
                severity=rule_erasure.severity if rule_erasure else SeverityEnum.MEDIUM,
                status=RuleFindingStatus.NOT_APPLICABLE,
                confidence=ConfidenceEnum.HIGH,
                evidence="No database models with personal data detected in scanned files.",
                recommendation="If personal data schemas are added, define deletion logic.",
                legal_ref="TODO_VERIFY",
                check_type=CheckTypeEnum.PROJECT,
            )
        )

    # 2. Evaluate Personal Data Logging Incidents
    rule_pii_logs = get_rule_by_id("no_pii_in_logs")
    if all_logging_incidents:
        locs = [f"{i['file']}:{i['line']}" for i in all_logging_incidents[:3]]
        matched_fields = list(dict.fromkeys(i["field_pattern"] for i in all_logging_incidents))[:5]
        findings.append(
            Finding(
                rule_id="no_pii_in_logs",
                category="Security Safeguards",
                title=rule_pii_logs.title if rule_pii_logs else "No Personal Data in Logs",
                severity=rule_pii_logs.severity if rule_pii_logs else SeverityEnum.HIGH,
                status=RuleFindingStatus.FAILED,
                confidence=ConfidenceEnum.HIGH,
                evidence=sanitize_evidence_snippet(
                    f"Logging calls referencing personal data detected at: {', '.join(locs)}"
                ),
                matched_terms=matched_fields,
                recommendation=(
                    rule_pii_logs.recommendation
                    if rule_pii_logs
                    else "Refactor logging statements to remove personal data fields."
                ),
                legal_ref="TODO_VERIFY",
                check_type=CheckTypeEnum.PROJECT,
                details={"logging_incidents": all_logging_incidents},
            )
        )
    elif total_logging_calls > 0:
        findings.append(
            Finding(
                rule_id="no_pii_in_logs",
                category="Security Safeguards",
                title=rule_pii_logs.title if rule_pii_logs else "No Personal Data in Logs",
                severity=rule_pii_logs.severity if rule_pii_logs else SeverityEnum.HIGH,
                status=RuleFindingStatus.PASSED,
                confidence=ConfidenceEnum.HIGH,
                evidence="Inspected logging calls; no personal data fields referenced.",
                recommendation=(
                    rule_pii_logs.recommendation
                    if rule_pii_logs
                    else "Enforce code review policies against logging personal data."
                ),
                legal_ref="TODO_VERIFY",
                check_type=CheckTypeEnum.PROJECT,
            )
        )
    else:
        findings.append(
            Finding(
                rule_id="no_pii_in_logs",
                category="Security Safeguards",
                title=rule_pii_logs.title if rule_pii_logs else "No Personal Data in Logs",
                severity=rule_pii_logs.severity if rule_pii_logs else SeverityEnum.HIGH,
                status=RuleFindingStatus.NOT_APPLICABLE,
                confidence=ConfidenceEnum.HIGH,
                evidence="No logging calls found in scanned source files.",
                recommendation=(
                    rule_pii_logs.recommendation
                    if rule_pii_logs
                    else "Enforce code review policies against logging personal data."
                ),
                legal_ref="TODO_VERIFY",
                check_type=CheckTypeEnum.PROJECT,
            )
        )

    # 3. Evaluate Third-Party SDKs in Dependencies
    sdks = _scan_dependencies(base_dir)
    rule_transfer = get_rule_by_id("transfer_cross_border_disclosed")

    if sdks:
        for s in sdks[:5]:
            findings.append(
                Finding(
                    rule_id="transfer_cross_border_disclosed",
                    category="Cross-Border Transfers",
                    title=rule_transfer.title if rule_transfer else "Third-Party Processing SDK",
                    severity=rule_transfer.severity if rule_transfer else "medium",
                    status=RuleFindingStatus.NEEDS_REVIEW,
                    confidence=ConfidenceEnum.MEDIUM,
                    evidence=sanitize_evidence_snippet(
                        f"Project manifest {s['file']} imports {s['sdk']} ({s['package']})."
                    ),
                    matched_terms=[s["sdk"]],
                    recommendation=(
                        f"Verify data processing agreement with {s['sdk']} and disclose "
                        "international data processing in the privacy policy."
                    ),
                    legal_ref="TODO_VERIFY",
                    check_type=CheckTypeEnum.PROJECT,
                    details={
                        "note": "third-party processor, location unverified",
                        "sdk": s["sdk"],
                        "package": s["package"],
                        "file": s["file"],
                    },
                )
            )
    else:
        findings.append(
            Finding(
                rule_id="transfer_cross_border_disclosed",
                category="Cross-Border Transfers",
                title=rule_transfer.title if rule_transfer else "Third-Party Processing SDK",
                severity=rule_transfer.severity if rule_transfer else "medium",
                status=RuleFindingStatus.NOT_APPLICABLE,
                confidence=ConfidenceEnum.HIGH,
                evidence="No third-party analytics or tracking SDKs detected in manifests.",
                recommendation="Review newly added external dependencies for transfer safeguards.",
                legal_ref="TODO_VERIFY",
                check_type=CheckTypeEnum.PROJECT,
            )
        )

    return ToolResult(
        status="ok",
        tool_name="scan_project_files",
        findings=findings,
        data={
            "scanned_files_count": scanned_files_count,
            "total_bytes_read": total_bytes_read,
            "models_detected": models_found,
            "has_deletion_logic": has_deletion,
            "logging_incidents_count": len(all_logging_incidents),
            "logging_incidents": all_logging_incidents,
            "third_party_sdks": sdks,
        },
        disclaimer=LEGAL_DISCLAIMER,
    )
