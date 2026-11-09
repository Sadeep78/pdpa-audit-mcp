"""FastMCP stdio server exposing Sri Lanka PDPA No. 9 of 2022 technical readiness audit tools."""

from __future__ import annotations

import logging
import sys
from importlib.metadata import PackageNotFoundError, version
from typing import Any, Literal

from fastmcp import FastMCP

from pdpa_audit_mcp.config import DEFENSIVE_USE_NOTICE, LEGAL_DISCLAIMER
from pdpa_audit_mcp.models import Report, ToolResult
from pdpa_audit_mcp.report import (
    generate_gap_report as _generate_gap_report,
)
from pdpa_audit_mcp.report import (
    list_checklist as _list_checklist,
)
from pdpa_audit_mcp.report import (
    run_full_audit as _run_full_audit,
)
from pdpa_audit_mcp.safety import (
    SecurityError,
    validate_input_path,
    validate_input_url,
)
from pdpa_audit_mcp.scoring import calculate_readiness_score
from pdpa_audit_mcp.tools.breach_readiness import check_breach_readiness as _check_breach_readiness
from pdpa_audit_mcp.tools.cookie_consent import detect_cookie_consent as _detect_cookie_consent
from pdpa_audit_mcp.tools.forms import find_personal_data_forms as _find_personal_data_forms
from pdpa_audit_mcp.tools.privacy_policy import scan_privacy_policy as _scan_privacy_policy
from pdpa_audit_mcp.tools.project_scan import scan_project_files as _scan_project_files
from pdpa_audit_mcp.tools.transfers import (
    detect_third_party_transfers as _detect_third_party_transfers,
)

# Enforce stdio hygiene: all application and server logs go to stderr
logging.basicConfig(
    stream=sys.stderr,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("pdpa-audit-mcp")

try:
    __version__ = version("pdpa-audit-mcp")
except PackageNotFoundError:
    __version__ = "0.1.0"

mcp = FastMCP("pdpa-audit-mcp", version=__version__)

_AUTH_NOTICE = (
    f"Use only on sites/projects you own or are authorised to audit. {DEFENSIVE_USE_NOTICE}"
)


@mcp.tool(
    description=(
        "Audit website privacy policy for technical transparency and data subject rights. "
        f"{_AUTH_NOTICE}"
    )
)
async def scan_privacy_policy(url: str) -> dict[str, Any]:
    """Scan website privacy policy for PDPA transparency and data subject rights."""
    try:
        clean_url = validate_input_url(url)
        res = await _scan_privacy_policy(clean_url)
        return res.model_dump()
    except (SecurityError, ValueError) as exc:
        return ToolResult(
            status="error",
            tool_name="scan_privacy_policy",
            error_message=str(exc),
            disclaimer=LEGAL_DISCLAIMER,
        ).model_dump()
    except Exception as exc:  # noqa: BLE001 - Deliberate MCP tool wrapper boundary to prevent stdio server crashes
        logger.error("scan_privacy_policy unexpected error: %s", exc)
        return ToolResult(
            status="error",
            tool_name="scan_privacy_policy",
            error_message=f"Privacy policy audit failed: {exc}",
            disclaimer=LEGAL_DISCLAIMER,
        ).model_dump()


@mcp.tool(
    description=(
        "Detect cookie consent banners, CMP markup, and tracking scripts in static HTML. "
        f"{_AUTH_NOTICE}"
    )
)
async def detect_cookie_consent(url: str) -> dict[str, Any]:
    """Audit cookie consent banners and pre-consent tracking scripts."""
    try:
        clean_url = validate_input_url(url)
        res = await _detect_cookie_consent(clean_url)
        return res.model_dump()
    except (SecurityError, ValueError) as exc:
        return ToolResult(
            status="error",
            tool_name="detect_cookie_consent",
            error_message=str(exc),
            disclaimer=LEGAL_DISCLAIMER,
        ).model_dump()
    except Exception as exc:  # noqa: BLE001 - Deliberate MCP tool wrapper boundary to prevent stdio server crashes
        logger.error("detect_cookie_consent unexpected error: %s", exc)
        return ToolResult(
            status="error",
            tool_name="detect_cookie_consent",
            error_message=f"Cookie consent audit failed: {exc}",
            disclaimer=LEGAL_DISCLAIMER,
        ).model_dump()


@mcp.tool(
    description=(
        "Audit web forms for personal/sensitive data, GET submissions, and pre-ticked consent. "
        f"{_AUTH_NOTICE}"
    )
)
async def find_personal_data_forms(target: str) -> dict[str, Any]:
    """Audit forms for personal data handling, sensitive fields, and security."""
    try:
        is_url = target.startswith("http://") or target.startswith("https://")
        clean_target = validate_input_url(target) if is_url else validate_input_path(target)
        res = await _find_personal_data_forms(clean_target)
        return res.model_dump()
    except (SecurityError, ValueError) as exc:
        return ToolResult(
            status="error",
            tool_name="find_personal_data_forms",
            error_message=str(exc),
            disclaimer=LEGAL_DISCLAIMER,
        ).model_dump()
    except Exception as exc:  # noqa: BLE001 - Deliberate MCP tool wrapper boundary to prevent stdio server crashes
        logger.error("find_personal_data_forms unexpected error: %s", exc)
        return ToolResult(
            status="error",
            tool_name="find_personal_data_forms",
            error_message=f"Form audit failed: {exc}",
            disclaimer=LEGAL_DISCLAIMER,
        ).model_dump()


@mcp.tool(
    description=(
        "Scan local project files for data models, deletion logic, PII logging, and SDKs. "
        f"{_AUTH_NOTICE}"
    )
)
async def scan_project_files(path: str) -> dict[str, Any]:
    """Analyze a local project directory for personal data models, logging, and SDKs."""
    try:
        clean_path = validate_input_path(path)
        res = await _scan_project_files(clean_path)
        return res.model_dump()
    except (SecurityError, ValueError) as exc:
        return ToolResult(
            status="error",
            tool_name="scan_project_files",
            error_message=str(exc),
            disclaimer=LEGAL_DISCLAIMER,
        ).model_dump()
    except Exception as exc:  # noqa: BLE001 - Deliberate MCP tool wrapper boundary to prevent stdio server crashes
        logger.error("scan_project_files unexpected error: %s", exc)
        return ToolResult(
            status="error",
            tool_name="scan_project_files",
            error_message=f"Project scan failed: {exc}",
            disclaimer=LEGAL_DISCLAIMER,
        ).model_dump()


@mcp.tool(
    description=(
        "Audit repository documentation for breach response readiness and security contacts. "
        f"{_AUTH_NOTICE}"
    )
)
async def check_breach_readiness(path: str) -> dict[str, Any]:
    """Evaluate repository documentation for incident response and breach readiness."""
    try:
        clean_path = validate_input_path(path)
        res = await _check_breach_readiness(clean_path)
        return res.model_dump()
    except (SecurityError, ValueError) as exc:
        return ToolResult(
            status="error",
            tool_name="check_breach_readiness",
            error_message=str(exc),
            disclaimer=LEGAL_DISCLAIMER,
        ).model_dump()
    except Exception as exc:  # noqa: BLE001 - Deliberate MCP tool wrapper boundary to prevent stdio server crashes
        logger.error("check_breach_readiness unexpected error: %s", exc)
        return ToolResult(
            status="error",
            tool_name="check_breach_readiness",
            error_message=f"Breach readiness check failed: {exc}",
            disclaimer=LEGAL_DISCLAIMER,
        ).model_dump()


@mcp.tool(
    description=(
        "Detect third-party analytics/tracking/payment domains and cross-border disclosures. "
        f"{_AUTH_NOTICE}"
    )
)
async def detect_third_party_transfers(url: str, policy_text: str | None = None) -> dict[str, Any]:
    """Audit external resource domains and cross-border transfer disclosures."""
    try:
        clean_url = validate_input_url(url)
        res = await _detect_third_party_transfers(clean_url, policy_text=policy_text)
        return res.model_dump()
    except (SecurityError, ValueError) as exc:
        return ToolResult(
            status="error",
            tool_name="detect_third_party_transfers",
            error_message=str(exc),
            disclaimer=LEGAL_DISCLAIMER,
        ).model_dump()
    except Exception as exc:  # noqa: BLE001 - Deliberate MCP tool wrapper boundary to prevent stdio server crashes
        logger.error("detect_third_party_transfers unexpected error: %s", exc)
        return ToolResult(
            status="error",
            tool_name="detect_third_party_transfers",
            error_message=f"Transfer audit failed: {exc}",
            disclaimer=LEGAL_DISCLAIMER,
        ).model_dump()


@mcp.tool(
    description=(
        "Execute a full technical readiness audit against Sri Lanka PDPA No. 9 of 2022. "
        f"{_AUTH_NOTICE}"
    )
)
async def run_full_audit(
    url: str | None = None,
    project_path: str | None = None,
) -> dict[str, Any]:
    """Run full technical audit across web and/or project targets."""
    try:
        report = await _run_full_audit(url=url, project_path=project_path)
        return report.model_dump()
    except (SecurityError, ValueError) as exc:
        return Report(
            status="error",
            target=f"URL={url}, Path={project_path}",
            timestamp="",
            summary=calculate_readiness_score([]),
            error_message=str(exc),
            disclaimer=LEGAL_DISCLAIMER,
        ).model_dump()
    except Exception as exc:  # noqa: BLE001 - Deliberate MCP tool wrapper boundary to prevent stdio server crashes
        logger.error("run_full_audit unexpected error: %s", exc)
        return Report(
            status="error",
            target=f"URL={url}, Path={project_path}",
            timestamp="",
            summary=calculate_readiness_score([]),
            error_message=f"Full audit failed: {exc}",
            disclaimer=LEGAL_DISCLAIMER,
        ).model_dump()


@mcp.tool(
    description=(
        "Generate a formatted gap analysis report (Markdown or JSON) from an audit result. "
        f"{_AUTH_NOTICE}"
    )
)
def generate_gap_report(
    audit_result: dict[str, Any],
    format: Literal["markdown", "json"] = "markdown",
) -> str:
    """Format full audit results into a structured Markdown or JSON gap report."""
    try:
        return _generate_gap_report(audit_result, format=format)
    except Exception as exc:  # noqa: BLE001 - Deliberate MCP tool wrapper boundary to prevent stdio server crashes
        logger.error("generate_gap_report unexpected error: %s", exc)
        return f"# Audit Report Generation Error\n\nFailed to format audit result: {exc}"


@mcp.tool(
    description=(
        "List technical readiness checklist rules and indicators for Sri Lanka PDPA. "
        f"{_AUTH_NOTICE}"
    )
)
def list_checklist(category: str | None = None) -> dict[str, Any]:
    """List checklist rules optionally filtered by category."""
    try:
        res = _list_checklist(category=category)
        return res.model_dump()
    except Exception as exc:  # noqa: BLE001 - Deliberate MCP tool wrapper boundary to prevent stdio server crashes
        logger.error("list_checklist unexpected error: %s", exc)
        return ToolResult(
            status="error",
            tool_name="list_checklist",
            error_message=f"Listing checklist rules failed: {exc}",
            disclaimer=LEGAL_DISCLAIMER,
        ).model_dump()


def main() -> None:
    """Start FastMCP server on standard input/output transport."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
