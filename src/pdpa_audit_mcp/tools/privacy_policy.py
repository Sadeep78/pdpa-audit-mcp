"""Privacy policy scanner auditing transparency and data subject rights against Sri Lanka PDPA."""

from __future__ import annotations

from urllib.parse import urljoin

import httpx
from bs4 import BeautifulSoup

from pdpa_audit_mcp.checklist import get_rules_by_check_type, match_rule_indicators
from pdpa_audit_mcp.config import DEFENSIVE_USE_NOTICE, LEGAL_DISCLAIMER
from pdpa_audit_mcp.fetcher import SafeFetcher
from pdpa_audit_mcp.models import (
    CheckTypeEnum,
    ConfidenceEnum,
    Finding,
    RuleFindingStatus,
    ToolResult,
)
from pdpa_audit_mcp.safety import SecurityError, normalize_text

TOOL_DESCRIPTION: str = (
    "Scan a website's privacy policy for technical transparency and data subject rights readiness "
    "under Sri Lanka PDPA No. 9 of 2022. "
    f"{DEFENSIVE_USE_NOTICE}"
)

PRIVACY_LINK_KEYWORDS: list[str] = [
    "privacy",
    "privacy policy",
    "privacy notice",
    "privacy statement",
    "data protection",
    "පෞද්ගලිකත්ව",
    "දත්ත ආරක්ෂණ",
    "தனியுரிமை",
    "தரவு பாதுகாப்பு",
]


def _find_privacy_policy_url(base_url: str, html: str) -> str | None:
    """Search HTML for a link pointing to the privacy policy page."""
    soup = BeautifulSoup(html, "html.parser")
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        link_text = normalize_text(a.get_text())
        href_lower = href.lower()

        for kw in PRIVACY_LINK_KEYWORDS:
            norm_kw = normalize_text(kw)
            if norm_kw in link_text or norm_kw in href_lower:
                return urljoin(base_url, href)

    return None


async def _scan_privacy_policy_impl(url: str, fetcher: SafeFetcher) -> ToolResult:
    try:
        initial_res = await fetcher.fetch(url)
    except SecurityError as exc:
        return ToolResult(
            status="error",
            tool_name="scan_privacy_policy",
            error_message=str(exc),
            disclaimer=LEGAL_DISCLAIMER,
        )
    except (TimeoutError, httpx.TimeoutException) as exc:
        return ToolResult(
            status="error",
            tool_name="scan_privacy_policy",
            error_message=f"Request to '{url}' timed out: {exc}",
            disclaimer=LEGAL_DISCLAIMER,
        )
    except (httpx.HTTPError, OSError) as exc:
        return ToolResult(
            status="error",
            tool_name="scan_privacy_policy",
            error_message=f"Failed to fetch target URL '{url}': {exc}",
            disclaimer=LEGAL_DISCLAIMER,
        )

    if initial_res.status_code != 200 or not initial_res.text or initial_res.error_message:
        return ToolResult(
            status="error",
            tool_name="scan_privacy_policy",
            error_message=(
                initial_res.error_message
                or f"HTTP request to '{url}' returned status {initial_res.status_code}."
            ),
            disclaimer=LEGAL_DISCLAIMER,
        )

    # Check if the initial page is already a privacy policy or find the link
    policy_url = initial_res.final_url
    policy_html = initial_res.text

    url_lower = initial_res.final_url.lower()
    is_already_policy = any(kw in url_lower for kw in ("privacy", "පෞද්ගලිකත්ව", "தனியுரிமை"))

    if not is_already_policy:
        found_link = _find_privacy_policy_url(initial_res.final_url, initial_res.text)
        if found_link:
            policy_url = found_link
            # Enforce robots.txt permissions on discovered policy page
            allowed = await fetcher.can_fetch_url(found_link)
            if not allowed:
                return ToolResult(
                    status="error",
                    tool_name="scan_privacy_policy",
                    error_message=(
                        f"Robots.txt disallows crawling privacy policy at '{found_link}'."
                    ),
                    disclaimer=LEGAL_DISCLAIMER,
                )

            try:
                policy_res = await fetcher.fetch(found_link)
                if policy_res.status_code == 200 and policy_res.text:
                    policy_html = policy_res.text
                else:
                    return ToolResult(
                        status="error",
                        tool_name="scan_privacy_policy",
                        error_message=(
                            policy_res.error_message
                            or (
                                f"Discovered privacy policy at '{found_link}' "
                                f"returned HTTP status {policy_res.status_code}."
                            )
                        ),
                        disclaimer=LEGAL_DISCLAIMER,
                    )
            except SecurityError as exc:
                return ToolResult(
                    status="error",
                    tool_name="scan_privacy_policy",
                    error_message=str(exc),
                    disclaimer=LEGAL_DISCLAIMER,
                )
            except (TimeoutError, httpx.TimeoutException) as exc:
                return ToolResult(
                    status="error",
                    tool_name="scan_privacy_policy",
                    error_message=f"Request to privacy policy at '{found_link}' timed out: {exc}",
                    disclaimer=LEGAL_DISCLAIMER,
                )
            except (httpx.HTTPError, OSError) as exc:
                return ToolResult(
                    status="error",
                    tool_name="scan_privacy_policy",
                    error_message=f"Failed to fetch privacy policy at '{found_link}': {exc}",
                    disclaimer=LEGAL_DISCLAIMER,
                )
        else:
            # Privacy policy link could not be found from static HTML
            rules = get_rules_by_check_type(CheckTypeEnum.PRIVACY_POLICY)
            primary_rule = rules[0] if rules else None
            rule_id = primary_rule.id if primary_rule else "transparency_purpose"
            category = primary_rule.category if primary_rule else "Transparency / Privacy Notice"

            missing_finding = Finding(
                rule_id=rule_id,
                category=category,
                title="Privacy Notice / Policy Link Not Found",
                severity=primary_rule.severity if primary_rule else "high",
                status=RuleFindingStatus.FAILED,
                confidence=ConfidenceEnum.MEDIUM,
                evidence="No link to a privacy policy was found in the homepage HTML markup.",
                recommendation=(
                    "Publish an accessible privacy policy linked in website header/footer."
                ),
                legal_ref="TODO_VERIFY",
                legal_ref_verified=False,
                check_type=CheckTypeEnum.PRIVACY_POLICY,
                details={
                    "target_url": url,
                    "note": "Static analysis cannot detect JS-rendered links.",
                },
            )

            other_findings: list[Finding] = []
            for r in rules[1:]:
                other_findings.append(
                    Finding(
                        rule_id=r.id,
                        category=r.category,
                        title=r.title,
                        severity=r.severity,
                        status=RuleFindingStatus.NOT_EVALUATED,
                        confidence=ConfidenceEnum.MEDIUM,
                        evidence="Privacy policy page could not be located to assess this rule.",
                        recommendation=r.recommendation,
                        legal_ref=r.legal_ref,
                        legal_ref_verified=r.legal_ref_verified,
                        check_type=r.check_type,
                    )
                )

            return ToolResult(
                status="ok",
                tool_name="scan_privacy_policy",
                findings=[missing_finding, *other_findings],
                data={"policy_url": None, "policy_found": False},
                disclaimer=LEGAL_DISCLAIMER,
            )

    # Parse and extract visible text from the policy page
    soup = BeautifulSoup(policy_html, "html.parser")
    # Remove script and style tags to avoid false indicator matches
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()

    page_text = soup.get_text(separator="\n\n", strip=True)
    words = page_text.split()
    is_substantial_policy = len(words) >= 50 and len(page_text) >= 300

    rules = get_rules_by_check_type(CheckTypeEnum.PRIVACY_POLICY)
    findings: list[Finding] = []

    for rule in rules:
        matched, evidence_snippet, matched_terms = match_rule_indicators(rule, page_text)
        if matched:
            findings.append(
                Finding(
                    rule_id=rule.id,
                    category=rule.category,
                    title=rule.title,
                    severity=rule.severity,
                    status=RuleFindingStatus.PASSED,
                    confidence=ConfidenceEnum.HIGH,
                    evidence=evidence_snippet,
                    matched_terms=matched_terms[:5],
                    recommendation=rule.recommendation,
                    legal_ref=rule.legal_ref,
                    legal_ref_verified=rule.legal_ref_verified,
                    check_type=rule.check_type,
                )
            )
        else:
            if is_substantial_policy:
                status = RuleFindingStatus.FAILED
                evidence = (
                    "No indicators matching this requirement were detected in the policy text."
                )
                confidence = ConfidenceEnum.HIGH
            else:
                status = RuleFindingStatus.NEEDS_REVIEW
                evidence = (
                    "Policy text is very brief; manual review recommended to confirm coverage."
                )
                confidence = ConfidenceEnum.MEDIUM

            findings.append(
                Finding(
                    rule_id=rule.id,
                    category=rule.category,
                    title=rule.title,
                    severity=rule.severity,
                    status=status,
                    confidence=confidence,
                    evidence=evidence,
                    recommendation=rule.recommendation,
                    legal_ref=rule.legal_ref,
                    legal_ref_verified=rule.legal_ref_verified,
                    check_type=rule.check_type,
                )
            )

    return ToolResult(
        status="ok",
        tool_name="scan_privacy_policy",
        findings=findings,
        data={
            "policy_url": policy_url,
            "policy_found": True,
            "word_count": len(words),
            "is_substantial": is_substantial_policy,
        },
        disclaimer=LEGAL_DISCLAIMER,
    )


async def scan_privacy_policy(
    url: str,
    fetcher: SafeFetcher | None = None,
    client: httpx.AsyncClient | None = None,
) -> ToolResult:
    """Fetch and audit the privacy policy of a target website against PDPA readiness rules.

    Use only on sites/projects you own or are authorised to audit.
    """
    owns_fetcher = fetcher is None
    if fetcher is None:
        fetcher = SafeFetcher(client=client)

    try:
        return await _scan_privacy_policy_impl(url, fetcher)
    finally:
        if owns_fetcher:
            await fetcher.aclose()
