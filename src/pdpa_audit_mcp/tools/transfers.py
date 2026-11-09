"""Third-party resource detection and cross-border data transfer audit tool."""

from __future__ import annotations

from urllib.parse import urljoin, urlsplit

import httpx
from bs4 import BeautifulSoup

from pdpa_audit_mcp.checklist import get_rule_by_id, match_rule_indicators
from pdpa_audit_mcp.config import DEFENSIVE_USE_NOTICE, LEGAL_DISCLAIMER
from pdpa_audit_mcp.fetcher import SafeFetcher
from pdpa_audit_mcp.models import (
    CheckTypeEnum,
    ConfidenceEnum,
    Finding,
    RuleFindingStatus,
    ToolResult,
)
from pdpa_audit_mcp.safety import SecurityError, sanitize_evidence_snippet
from pdpa_audit_mcp.tools.constants import VENDOR_CATEGORIES

TOOL_DESCRIPTION: str = (
    "Detect external third-party domains and verify cross-border transfer disclosures "
    "under Sri Lanka PDPA No. 9 of 2022. "
    f"{DEFENSIVE_USE_NOTICE}"
)


def _categorize_domain(domain: str) -> str:
    """Classify external domain into functional vendor categories."""
    d_lower = domain.lower()
    for category, pattern_list in VENDOR_CATEGORIES.items():
        for pat in pattern_list:
            if pat in d_lower:
                return category
    return "other"


def _extract_external_domains(
    base_url: str, soup: BeautifulSoup
) -> dict[str, list[dict[str, str]]]:
    """Extract all third-party external domains referenced in HTML elements."""
    page_netloc = urlsplit(base_url).netloc.lower()
    # Strip port if present
    page_domain = page_netloc.split(":")[0]

    elements_to_check = [
        ("script", "src", "script"),
        ("iframe", "src", "iframe"),
        ("link", "href", "stylesheet/font"),
        ("img", "src", "image"),
        ("form", "action", "form_action"),
    ]

    domains_map: dict[str, list[dict[str, str]]] = {}

    for tag_name, attr, resource_type in elements_to_check:
        for tag in soup.find_all(tag_name, **{attr: True}):
            raw_val = tag[attr].strip()
            if not raw_val or raw_val.startswith(("data:", "javascript:", "#")):
                continue

            full_url = urljoin(base_url, raw_val)
            parsed = urlsplit(full_url)
            netloc = parsed.netloc.lower().split(":")[0]

            if not netloc:
                continue

            # Compare against primary domain and subdomains
            if netloc != page_domain and not netloc.endswith("." + page_domain):
                category = _categorize_domain(netloc)
                if netloc not in domains_map:
                    domains_map[netloc] = []
                domains_map[netloc].append(
                    {
                        "category": category,
                        "resource_type": resource_type,
                        "url": full_url,
                        "vendor_classification": "third-party processor, location unverified",
                    }
                )

    return domains_map


async def _detect_third_party_transfers_impl(
    url: str,
    fetcher: SafeFetcher,
    policy_text: str | None = None,
) -> ToolResult:
    try:
        res = await fetcher.fetch(url)
    except SecurityError as exc:
        return ToolResult(
            status="error",
            tool_name="detect_third_party_transfers",
            error_message=str(exc),
            disclaimer=LEGAL_DISCLAIMER,
        )
    except (TimeoutError, httpx.TimeoutException) as exc:
        return ToolResult(
            status="error",
            tool_name="detect_third_party_transfers",
            error_message=f"Request to '{url}' timed out: {exc}",
            disclaimer=LEGAL_DISCLAIMER,
        )
    except (httpx.HTTPError, OSError) as exc:
        return ToolResult(
            status="error",
            tool_name="detect_third_party_transfers",
            error_message=f"Failed to fetch '{url}': {exc}",
            disclaimer=LEGAL_DISCLAIMER,
        )

    if res.status_code != 200 or not res.text or res.error_message:
        return ToolResult(
            status="error",
            tool_name="detect_third_party_transfers",
            error_message=(
                res.error_message or f"HTTP request to '{url}' returned status {res.status_code}."
            ),
            disclaimer=LEGAL_DISCLAIMER,
        )

    soup = BeautifulSoup(res.text, "html.parser")
    external_domains = _extract_external_domains(res.final_url, soup)

    # Group domains by category
    categorized_vendors: dict[str, list[str]] = {}
    for d, entries in external_domains.items():
        cat = entries[0]["category"]
        if cat not in categorized_vendors:
            categorized_vendors[cat] = []
        categorized_vendors[cat].append(d)

    # If policy text was not supplied, check if the current page has transfer indicators
    rule = get_rule_by_id("transfer_cross_border_disclosed")
    text_to_check = policy_text if policy_text else soup.get_text(separator=" ", strip=True)

    transfer_disclosed = False
    disclosure_evidence = ""
    transfer_terms: list[str] = []
    if rule:
        matched, snippet, transfer_terms = match_rule_indicators(rule, text_to_check)
        if matched:
            transfer_disclosed = True
            disclosure_evidence = snippet

    findings: list[Finding] = []
    total_external_count = len(external_domains)

    if total_external_count > 0:
        domain_list = sorted(external_domains.keys())
        summary_str = ", ".join(domain_list[:5])
        if len(domain_list) > 5:
            summary_str += f" (+{len(domain_list) - 5} more)"

        if transfer_disclosed:
            status = RuleFindingStatus.PASSED
            evidence = (
                f"Cross-border transfer disclosed: {disclosure_evidence} (vendors: {summary_str})"
            )
            rec = (
                "Continue disclosing third-party processors and cross-border safeguards in policy."
            )
        else:
            status = RuleFindingStatus.FAILED
            evidence = (
                f"Page loads {total_external_count} external domains ({summary_str}) but no "
                "cross-border transfer disclosure was found in policy text."
            )
            rec = (
                "Update privacy policy to disclose third-party data processors, hosting providers, "
                "and whether personal data is processed outside Sri Lanka."
            )

        findings.append(
            Finding(
                rule_id="transfer_cross_border_disclosed",
                category="Cross-Border Transfers",
                title=rule.title if rule else "Cross-Border Transfers Disclosed",
                severity=rule.severity if rule else "medium",
                status=status,
                confidence=ConfidenceEnum.HIGH,
                evidence=sanitize_evidence_snippet(evidence),
                matched_terms=domain_list[:5],
                recommendation=rec,
                legal_ref="TODO_VERIFY",
                check_type=CheckTypeEnum.TRANSFER,
                details={
                    "total_external_domains": total_external_count,
                    "categories": categorized_vendors,
                    "external_domains": domain_list,
                    "location_disclaimer": (
                        "Vendors labeled 'third-party processor, location unverified'."
                    ),
                },
            )
        )
    else:
        findings.append(
            Finding(
                rule_id="transfer_cross_border_disclosed",
                category="Cross-Border Transfers",
                title=rule.title if rule else "Cross-Border Transfers Disclosed",
                severity=rule.severity if rule else "medium",
                status=RuleFindingStatus.NOT_APPLICABLE,
                confidence=ConfidenceEnum.HIGH,
                evidence="No external third-party domains detected in HTML markup.",
                recommendation=(
                    "If adding third-party CDNs, fonts, or analytics, update policy disclosures."
                ),
                legal_ref="TODO_VERIFY",
                check_type=CheckTypeEnum.TRANSFER,
            )
        )

    return ToolResult(
        status="ok",
        tool_name="detect_third_party_transfers",
        findings=findings,
        data={
            "external_domains_count": total_external_count,
            "categories": categorized_vendors,
            "domains": external_domains,
            "policy_transfer_disclosed": transfer_disclosed,
        },
        disclaimer=LEGAL_DISCLAIMER,
    )


async def detect_third_party_transfers(
    url: str,
    fetcher: SafeFetcher | None = None,
    client: httpx.AsyncClient | None = None,
    policy_text: str | None = None,
) -> ToolResult:
    """Audit third-party external scripts/domains and check cross-border transfer disclosures.

    Use only on sites/projects you own or are authorised to audit.
    """
    owns_fetcher = fetcher is None
    if fetcher is None:
        fetcher = SafeFetcher(client=client)

    try:
        return await _detect_third_party_transfers_impl(url, fetcher, policy_text=policy_text)
    finally:
        if owns_fetcher:
            await fetcher.aclose()
