"""Cookie consent and third-party tracker detection tool for PDPA compliance auditing."""

from __future__ import annotations

import httpx
from bs4 import BeautifulSoup

from pdpa_audit_mcp.checklist import get_rule_by_id
from pdpa_audit_mcp.config import DEFENSIVE_USE_NOTICE, LEGAL_DISCLAIMER
from pdpa_audit_mcp.fetcher import SafeFetcher
from pdpa_audit_mcp.models import (
    CheckTypeEnum,
    ConfidenceEnum,
    Finding,
    RuleFindingStatus,
    ToolResult,
)
from pdpa_audit_mcp.safety import (
    SecurityError,
    normalize_text,
    sanitize_evidence_snippet,
)
from pdpa_audit_mcp.tools.constants import (
    ACCEPT_KEYWORDS,
    CMP_SELECTORS,
    MANAGE_KEYWORDS,
    REJECT_KEYWORDS,
    TRACKER_DOMAINS,
)

TOOL_DESCRIPTION: str = (
    "Detect cookie consent banners, CMP markup, and third-party tracking scripts in static HTML "
    "under Sri Lanka PDPA No. 9 of 2022. "
    f"{DEFENSIVE_USE_NOTICE}"
)


def _detect_cmp_markup(soup: BeautifulSoup) -> tuple[bool, str | None]:
    """Detect whether cookie consent banner markup exists in HTML."""
    # Check elements matching common CMP classes, IDs, or attributes
    for el in soup.find_all(True):
        el_id = el.get("id", "")
        el_class = " ".join(el.get("class", [])) if el.get("class") else ""
        combined = f"{el_id} {el_class}".lower()

        for sel in CMP_SELECTORS:
            if sel in combined:
                snippet = f"<{el.name} id='{el_id}' class='{el_class}'>"
                return True, sanitize_evidence_snippet(snippet)

    # Check for text in buttons or dialogs mentioning cookies
    for tag in soup.find_all(["div", "section", "aside", "dialog"]):
        text_lower = normalize_text(tag.get_text()[:200])
        if "cookie" in text_lower and any(
            kw in text_lower for kw in ("agree", "accept", "consent")
        ):
            return True, sanitize_evidence_snippet(text_lower[:100])

    return False, None


def _detect_button_types(soup: BeautifulSoup) -> dict[str, bool]:
    """Detect whether accept, reject, and manage buttons exist in the page/banner."""
    has_accept = False
    has_reject = False
    has_manage = False

    for tag in soup.find_all(["button", "a", "input"]):
        text = normalize_text(tag.get_text() or tag.get("value", ""))
        tag_attrs = " ".join(
            f"{k}='{v}'" for k, v in tag.attrs.items() if isinstance(v, str)
        ).lower()
        combined = f"{text} {tag_attrs}"

        if not has_accept and any(kw in combined for kw in ACCEPT_KEYWORDS):
            has_accept = True
        if not has_reject and any(kw in combined for kw in REJECT_KEYWORDS):
            has_reject = True
        if not has_manage and any(kw in combined for kw in MANAGE_KEYWORDS):
            has_manage = True

    return {
        "has_accept": has_accept,
        "has_reject": has_reject,
        "has_manage": has_manage,
    }


def _detect_trackers(soup: BeautifulSoup) -> list[dict[str, str]]:
    """Detect third-party analytics and tracking scripts in static HTML markup."""
    detected: list[dict[str, str]] = []

    # Check script src attributes
    for script in soup.find_all("script", src=True):
        src = script["src"]
        src_lower = src.lower()
        for domain, name in TRACKER_DOMAINS.items():
            if domain in src_lower:
                detected.append({"type": "script", "tracker": name, "source": src})
                break

    # Check iframes
    for iframe in soup.find_all("iframe", src=True):
        src = iframe["src"]
        src_lower = src.lower()
        for domain, name in TRACKER_DOMAINS.items():
            if domain in src_lower:
                detected.append({"type": "iframe", "tracker": name, "source": src})
                break

    # Check inline scripts for tracking invocations (gtag, fbq, _hjSettings, etc.)
    inline_signatures = {
        "gtag(": "Google Analytics (gtag)",
        "fbq(": "Meta Pixel (fbq)",
        "_hjSettings": "Hotjar",
        "clarity(": "Microsoft Clarity",
        "mixpanel.": "Mixpanel",
        "amplitude.": "Amplitude",
    }
    for script in soup.find_all("script", src=False):
        content = script.string or ""
        for sig, name in inline_signatures.items():
            if sig in content:
                detected.append({"type": "inline", "tracker": name, "source": f"inline {sig}"})

    return detected


async def _detect_cookie_consent_impl(url: str, fetcher: SafeFetcher) -> ToolResult:
    try:
        res = await fetcher.fetch(url)
    except SecurityError as exc:
        return ToolResult(
            status="error",
            tool_name="detect_cookie_consent",
            error_message=str(exc),
            disclaimer=LEGAL_DISCLAIMER,
        )
    except (TimeoutError, httpx.TimeoutException) as exc:
        return ToolResult(
            status="error",
            tool_name="detect_cookie_consent",
            error_message=f"Request to '{url}' timed out: {exc}",
            disclaimer=LEGAL_DISCLAIMER,
        )
    except (httpx.HTTPError, OSError) as exc:
        return ToolResult(
            status="error",
            tool_name="detect_cookie_consent",
            error_message=f"Failed to fetch '{url}': {exc}",
            disclaimer=LEGAL_DISCLAIMER,
        )

    if res.status_code != 200 or not res.text or res.error_message:
        return ToolResult(
            status="error",
            tool_name="detect_cookie_consent",
            error_message=(
                res.error_message or f"HTTP request to '{url}' returned status {res.status_code}."
            ),
            disclaimer=LEGAL_DISCLAIMER,
        )

    soup = BeautifulSoup(res.text, "html.parser")

    banner_found, banner_evidence = _detect_cmp_markup(soup)
    buttons = _detect_button_types(soup)
    trackers = _detect_trackers(soup)

    findings: list[Finding] = []

    # Rule 1: consent_before_tracking
    rule_before = get_rule_by_id("consent_before_tracking")
    if trackers and not banner_found:
        tracker_names = list({t["tracker"] for t in trackers})
        evidence = f"Found trackers {tracker_names[:3]} with no consent banner in static HTML."
        findings.append(
            Finding(
                rule_id="consent_before_tracking",
                category="Consent",
                title=rule_before.title if rule_before else "Consent Prior to Trackers",
                severity=rule_before.severity if rule_before else "high",
                status=RuleFindingStatus.FAILED,
                confidence=ConfidenceEnum.HIGH,
                evidence=sanitize_evidence_snippet(evidence),
                matched_terms=tracker_names[:5],
                recommendation=(
                    "Install a consent management banner and block trackers until user opt-in."
                ),
                legal_ref="TODO_VERIFY",
                check_type=CheckTypeEnum.COOKIE_CONSENT,
                details={"trackers_detected": tracker_names},
            )
        )
    elif trackers and banner_found:
        tracker_names = list({t["tracker"] for t in trackers})
        evidence = f"Found consent banner ({banner_evidence}) and trackers {tracker_names[:2]}."
        findings.append(
            Finding(
                rule_id="consent_before_tracking",
                category="Consent",
                title=rule_before.title if rule_before else "Consent Prior to Trackers",
                severity=rule_before.severity if rule_before else "high",
                status=RuleFindingStatus.NEEDS_REVIEW,
                confidence=ConfidenceEnum.MEDIUM,
                evidence=sanitize_evidence_snippet(evidence),
                matched_terms=tracker_names[:5],
                recommendation=(
                    "Cannot verify trackers are blocked before consent from static HTML. "
                    "Verify client-side."
                ),
                legal_ref="TODO_VERIFY",
                check_type=CheckTypeEnum.COOKIE_CONSENT,
                details={
                    "note": "cannot verify trackers are blocked before consent from static HTML"
                },
            )
        )
    else:
        evidence = "No pre-consent third-party tracking scripts detected in initial HTML."
        findings.append(
            Finding(
                rule_id="consent_before_tracking",
                category="Consent",
                title=rule_before.title if rule_before else "Consent Prior to Trackers",
                severity=rule_before.severity if rule_before else "high",
                status=RuleFindingStatus.NOT_APPLICABLE,
                confidence=ConfidenceEnum.HIGH,
                evidence=evidence,
                recommendation=(
                    "Maintain policy of not loading non-essential trackers prior to consent."
                ),
                legal_ref="TODO_VERIFY",
                check_type=CheckTypeEnum.COOKIE_CONSENT,
            )
        )

    # Rule 2: consent_easy_withdrawal
    rule_withdraw = get_rule_by_id("consent_easy_withdrawal")
    if banner_found:
        if buttons["has_reject"]:
            status = RuleFindingStatus.PASSED
            evidence = "Consent banner markup includes an explicit reject/decline button."
            rec = "Continue offering an explicit reject option."
        else:
            status = RuleFindingStatus.FAILED
            evidence = (
                "Consent banner detected with accept option but missing an explicit reject option."
            )
            rec = (
                "Provide an equally prominent 'Reject All' or 'Decline' button on the "
                "cookie banner."
            )

        findings.append(
            Finding(
                rule_id="consent_easy_withdrawal",
                category="Consent",
                title=rule_withdraw.title if rule_withdraw else "Withdrawal of Consent",
                severity=rule_withdraw.severity if rule_withdraw else "medium",
                status=status,
                confidence=ConfidenceEnum.HIGH,
                evidence=evidence,
                recommendation=rec,
                legal_ref="TODO_VERIFY",
                check_type=CheckTypeEnum.COOKIE_CONSENT,
                details=buttons,
            )
        )
    else:
        findings.append(
            Finding(
                rule_id="consent_easy_withdrawal",
                category="Consent",
                title=rule_withdraw.title if rule_withdraw else "Withdrawal of Consent",
                severity=rule_withdraw.severity if rule_withdraw else "medium",
                status=RuleFindingStatus.NEEDS_REVIEW,
                confidence=ConfidenceEnum.LOW,
                evidence=(
                    "No cookie consent banner detected in static HTML to evaluate reject button."
                ),
                recommendation=(
                    "If using cookies, add a banner with both accept and reject options."
                ),
                legal_ref="TODO_VERIFY",
                check_type=CheckTypeEnum.COOKIE_CONSENT,
            )
        )

    # Rule 3: security_secure_cookie_flags (inspect Set-Cookie headers from fetch response)
    set_cookie_header = res.headers.get("set-cookie", "")
    rule_cookie_sec = get_rule_by_id("security_secure_cookie_flags")
    if set_cookie_header:
        cookie_lower = set_cookie_header.lower()
        has_secure = "secure" in cookie_lower
        has_httponly = "httponly" in cookie_lower
        has_samesite = "samesite" in cookie_lower

        if has_secure and has_httponly and has_samesite:
            status = RuleFindingStatus.PASSED
            evidence = "Cookies set with Secure, HttpOnly, and SameSite attributes."
        else:
            status = RuleFindingStatus.NEEDS_REVIEW
            evidence = (
                f"Cookies present: Secure={has_secure}, HttpOnly={has_httponly}, "
                f"SameSite={has_samesite}."
            )

        findings.append(
            Finding(
                rule_id="security_secure_cookie_flags",
                category="Security Safeguards",
                title=rule_cookie_sec.title if rule_cookie_sec else "Secure Cookie Flags",
                severity=rule_cookie_sec.severity if rule_cookie_sec else "medium",
                status=status,
                confidence=ConfidenceEnum.HIGH,
                evidence=evidence,
                recommendation=(
                    "Ensure all session cookies feature Secure, HttpOnly, and SameSite flags."
                ),
                legal_ref="TODO_VERIFY",
                check_type=CheckTypeEnum.COOKIE_CONSENT,
            )
        )
    else:
        findings.append(
            Finding(
                rule_id="security_secure_cookie_flags",
                category="Security Safeguards",
                title=rule_cookie_sec.title if rule_cookie_sec else "Secure Cookie Flags",
                severity=rule_cookie_sec.severity if rule_cookie_sec else "medium",
                status=RuleFindingStatus.NOT_APPLICABLE,
                confidence=ConfidenceEnum.HIGH,
                evidence="No cookies set on initial page response.",
                recommendation="If session cookies are added, enforce Secure and HttpOnly flags.",
                legal_ref="TODO_VERIFY",
                check_type=CheckTypeEnum.COOKIE_CONSENT,
            )
        )

    return ToolResult(
        status="ok",
        tool_name="detect_cookie_consent",
        findings=findings,
        data={
            "banner_detected": banner_found,
            "banner_evidence": banner_evidence,
            "buttons": buttons,
            "trackers_count": len(trackers),
            "trackers": trackers,
            "static_analysis_limitation": (
                "Static HTML analysis only; JS-rendered banners may not be visible."
            ),
        },
        disclaimer=LEGAL_DISCLAIMER,
    )


async def detect_cookie_consent(
    url: str,
    fetcher: SafeFetcher | None = None,
    client: httpx.AsyncClient | None = None,
) -> ToolResult:
    """Audit cookie consent banners and pre-consent tracking scripts.

    Use only on sites/projects you own or are authorised to audit.
    """
    owns_fetcher = fetcher is None
    if fetcher is None:
        fetcher = SafeFetcher(client=client)

    try:
        return await _detect_cookie_consent_impl(url, fetcher)
    finally:
        if owns_fetcher:
            await fetcher.aclose()
