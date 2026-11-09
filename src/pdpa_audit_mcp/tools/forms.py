"""Audit web forms for personal data handling, sensitive fields, and security."""

from __future__ import annotations

import ipaddress
from typing import Any
from urllib.parse import urlsplit

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
    is_ip_private_or_restricted,
    is_safe_file_path,
    is_safe_file_size,
    normalize_text,
    parse_alternative_ipv4,
    sanitize_evidence_snippet,
    validate_project_path,
)
from pdpa_audit_mcp.tools.constants import (
    CONSENT_CHECKBOX_KEYWORDS,
    FORM_FILE_EXTENSIONS,
    PERSONAL_FIELD_NAMES,
    SENSITIVE_FIELD_NAMES,
)

TOOL_DESCRIPTION: str = (
    "Audit web forms (live URL or local project directory) for personal data collection, "
    "sensitive special category fields, insecure GET submissions, pre-checked consent, "
    "and password autocomplete configurations under Sri Lanka PDPA No. 9 of 2022. "
    f"{DEFENSIVE_USE_NOTICE}"
)

MAX_FORM_FILES: int = 2000


def _is_private_or_loopback_target(host: str) -> bool:
    """Check whether a hostname/IP represents a local dev or private server."""
    if not host:
        return False
    h = host.strip().lower().strip("[]")
    if h in ("localhost", "127.0.0.1", "::1") or h.endswith(".localhost"):
        return True
    try:
        ip = ipaddress.ip_address(h)
        return is_ip_private_or_restricted(str(ip))
    except ValueError:
        alt_ip = parse_alternative_ipv4(h)
        if alt_ip is not None:
            return is_ip_private_or_restricted(str(alt_ip))
        return False


def _classify_field_name(name_or_id: str, field_type: str) -> tuple[str, bool, bool]:
    """Classify a field as sensitive, personal, or non-personal.

    Returns: (category, is_sensitive, is_personal)
    NEVER inspects or returns field values or placeholders.
    """
    clean_name = normalize_text(name_or_id).lower()

    # Check sensitive indicators
    is_sensitive = any(term in clean_name for term in SENSITIVE_FIELD_NAMES)
    if is_sensitive:
        return "sensitive_personal_data", True, True

    # Check personal data indicators
    is_personal = field_type in ("email", "tel") or any(
        term in clean_name for term in PERSONAL_FIELD_NAMES
    )
    if is_personal:
        return "personal_data", False, True

    return "non_personal", False, False


def _is_consent_checkbox(tag: Any) -> bool:
    """Determine whether a checkbox corresponds to consent, terms, or marketing."""
    name_or_id = f"{tag.get('name', '')} {tag.get('id', '')}".lower()
    if any(kw in name_or_id for kw in CONSENT_CHECKBOX_KEYWORDS):
        return True

    # Check parent label or surrounding container text
    parent = tag.find_parent(["label", "div", "p", "span"])
    if parent:
        parent_text = normalize_text(parent.get_text()[:150]).lower()
        if any(kw in parent_text for kw in CONSENT_CHECKBOX_KEYWORDS):
            return True

    return False


def _parse_forms_from_html(html_content: str, source_label: str) -> list[dict[str, Any]]:
    """Extract and analyze <form> elements from raw HTML markup.

    NEVER extracts field values, placeholders, or user data.
    """
    soup = BeautifulSoup(html_content, "html.parser")
    form_nodes = soup.find_all("form")
    parsed_forms: list[dict[str, Any]] = []

    for idx, form in enumerate(form_nodes):
        method = form.get("method", "GET").upper().strip()
        action = form.get("action", "").strip()

        fields: list[dict[str, Any]] = []
        has_preticked_consent = False
        preticked_field_names: list[str] = []
        password_missing_autocomplete = False

        for tag in form.find_all(["input", "select", "textarea"]):
            tag_name = tag.name
            tag_type = tag.get("type", "text").lower().strip() if tag_name == "input" else tag_name
            name = tag.get("name") or tag.get("id") or f"unnamed_{tag_type}"

            cat, is_sens, is_pers = _classify_field_name(name, tag_type)

            # Check pre-ticked consent checkboxes
            if tag_type == "checkbox":
                if _is_consent_checkbox(tag) and tag.has_attr("checked"):
                    has_preticked_consent = True
                    preticked_field_names.append(name)

            # Check password autocomplete
            if tag_type == "password":
                autocomplete = tag.get("autocomplete", "").lower().strip()
                if not autocomplete or autocomplete in ("off", "false"):
                    password_missing_autocomplete = True

            fields.append(
                {
                    "name": name,
                    "type": tag_type,
                    "classification": cat,
                    "is_sensitive": is_sens,
                    "is_personal": is_pers,
                }
            )

        parsed_forms.append(
            {
                "source": source_label,
                "form_index": idx,
                "method": method,
                "action": action,
                "fields": fields,
                "has_preticked_consent": has_preticked_consent,
                "preticked_fields": preticked_field_names,
                "password_missing_autocomplete": password_missing_autocomplete,
                "has_password": any(f["type"] == "password" for f in fields),
                "sensitive_fields": [f["name"] for f in fields if f["is_sensitive"]],
                "personal_fields": [f["name"] for f in fields if f["is_personal"]],
            }
        )

    return parsed_forms


async def _find_personal_data_forms_impl(
    target: str,
    fetcher: SafeFetcher | None = None,
) -> ToolResult:
    is_url = target.startswith("http://") or target.startswith("https://")
    all_forms: list[dict[str, Any]] = []

    if is_url:
        if fetcher is None:
            fetcher = SafeFetcher()

        try:
            res = await fetcher.fetch(target)
        except SecurityError as exc:
            return ToolResult(
                status="error",
                tool_name="find_personal_data_forms",
                error_message=str(exc),
                disclaimer=LEGAL_DISCLAIMER,
            )
        except (TimeoutError, httpx.TimeoutException) as exc:
            return ToolResult(
                status="error",
                tool_name="find_personal_data_forms",
                error_message=f"Request to '{target}' timed out: {exc}",
                disclaimer=LEGAL_DISCLAIMER,
            )
        except (httpx.HTTPError, OSError) as exc:
            return ToolResult(
                status="error",
                tool_name="find_personal_data_forms",
                error_message=f"Failed to fetch target URL '{target}': {exc}",
                disclaimer=LEGAL_DISCLAIMER,
            )

        if res.status_code != 200 or not res.text or res.error_message:
            return ToolResult(
                status="error",
                tool_name="find_personal_data_forms",
                error_message=(
                    res.error_message
                    or f"HTTP request to '{target}' returned status {res.status_code}."
                ),
                disclaimer=LEGAL_DISCLAIMER,
            )

        all_forms = _parse_forms_from_html(res.text, source_label=res.final_url)
    else:
        # Local project path
        try:
            base_dir = validate_project_path(target)
        except (SecurityError, ValueError) as exc:
            return ToolResult(
                status="error",
                tool_name="find_personal_data_forms",
                error_message=f"Invalid or unsafe project path: {exc}",
                disclaimer=LEGAL_DISCLAIMER,
            )

        scanned_count = 0
        for path in base_dir.rglob("*"):
            if scanned_count >= MAX_FORM_FILES:
                break
            if not path.is_file():
                continue
            if path.suffix.lower() not in FORM_FILE_EXTENSIONS:
                continue
            if not is_safe_file_path(base_dir, path):
                continue
            if not is_safe_file_size(path):
                continue

            scanned_count += 1
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
                forms = _parse_forms_from_html(
                    content, source_label=str(path.relative_to(base_dir))
                )
                all_forms.extend(forms)
            except (OSError, UnicodeDecodeError):
                continue

    # Evaluate findings against PDPA structural detector rules
    findings: list[Finding] = []
    has_forms = len(all_forms) > 0

    # 1. minimisation_sensitive_fields
    rule_min = get_rule_by_id("minimisation_sensitive_fields")
    all_sens_fields = sorted({f_name for frm in all_forms for f_name in frm["sensitive_fields"]})
    if not has_forms:
        findings.append(
            Finding(
                rule_id="minimisation_sensitive_fields",
                category="Data Minimisation",
                title=rule_min.title if rule_min else "Sensitive Personal Data Justification",
                severity=rule_min.severity if rule_min else "high",
                status=RuleFindingStatus.NOT_APPLICABLE,
                confidence=ConfidenceEnum.HIGH,
                evidence="No web forms detected in audited target.",
                recommendation="Ensure future data collection forms enforce strict minimisation.",
                legal_ref="TODO_VERIFY",
                check_type=CheckTypeEnum.FORMS,
            )
        )
    elif all_sens_fields:
        findings.append(
            Finding(
                rule_id="minimisation_sensitive_fields",
                category="Data Minimisation",
                title=rule_min.title if rule_min else "Sensitive Personal Data Justification",
                severity=rule_min.severity if rule_min else "high",
                status=RuleFindingStatus.FAILED,
                confidence=ConfidenceEnum.HIGH,
                evidence=sanitize_evidence_snippet(
                    f"Forms collect sensitive data fields: {all_sens_fields}"
                ),
                matched_terms=all_sens_fields[:5],
                recommendation=(
                    "Assess whether collecting special category data (e.g. NIC, health, biometric) "
                    "is strictly justified under applicable legal grounds."
                ),
                legal_ref="TODO_VERIFY",
                check_type=CheckTypeEnum.FORMS,
                details={"sensitive_fields_detected": all_sens_fields},
            )
        )
    else:
        findings.append(
            Finding(
                rule_id="minimisation_sensitive_fields",
                category="Data Minimisation",
                title=rule_min.title if rule_min else "Sensitive Personal Data Justification",
                severity=rule_min.severity if rule_min else "high",
                status=RuleFindingStatus.PASSED,
                confidence=ConfidenceEnum.HIGH,
                evidence="No sensitive special category fields detected in audited forms.",
                recommendation="Continue maintaining strict minimisation for special categories.",
                legal_ref="TODO_VERIFY",
                check_type=CheckTypeEnum.FORMS,
            )
        )

    # 2. security_https_enforced (page URL scheme + form action URLs)
    rule_https = get_rule_by_id("security_https_enforced")
    insecure_actions: list[str] = []
    for frm in all_forms:
        act = frm["action"]
        if act.lower().startswith("http://"):
            insecure_actions.append(act)
        elif (
            is_url
            and target.lower().startswith("http://")
            and not act.lower().startswith("https://")
        ):
            insecure_actions.append(act or target)

    if is_url:
        parsed_url = urlsplit(target)
        target_scheme = parsed_url.scheme.lower()
        target_host = parsed_url.hostname or ""

        if target_scheme == "http":
            if _is_private_or_loopback_target(target_host):
                findings.append(
                    Finding(
                        rule_id="security_https_enforced",
                        category="Security Safeguards",
                        title=rule_https.title if rule_https else "HTTPS Encryption Enforced",
                        severity=rule_https.severity if rule_https else "high",
                        status=RuleFindingStatus.NOT_EVALUATED,
                        confidence=ConfidenceEnum.HIGH,
                        evidence="local http server",
                        recommendation=(
                            "Enforce HTTPS with TLS certificates before deploying to production."
                        ),
                        legal_ref="TODO_VERIFY",
                        check_type=CheckTypeEnum.FORMS,
                        details={
                            "note": "local http server",
                            "form_actions": "not_applicable" if not has_forms else "uninspected",
                        },
                    )
                )
            else:
                findings.append(
                    Finding(
                        rule_id="security_https_enforced",
                        category="Security Safeguards",
                        title=rule_https.title if rule_https else "HTTPS Encryption Enforced",
                        severity=rule_https.severity if rule_https else "high",
                        status=RuleFindingStatus.FAILED,
                        confidence=ConfidenceEnum.HIGH,
                        evidence=sanitize_evidence_snippet(
                            f"Page URL scheme is insecure HTTP: {target}"
                        ),
                        recommendation="Enforce HTTPS with TLS encryption for all web endpoints.",
                        legal_ref="TODO_VERIFY",
                        check_type=CheckTypeEnum.FORMS,
                        details={
                            "insecure_action_endpoints": [target],
                            "form_actions": "not_applicable" if not has_forms else "insecure_page",
                        },
                    )
                )
        else:
            if insecure_actions:
                findings.append(
                    Finding(
                        rule_id="security_https_enforced",
                        category="Security Safeguards",
                        title=rule_https.title if rule_https else "HTTPS Encryption Enforced",
                        severity=rule_https.severity if rule_https else "high",
                        status=RuleFindingStatus.FAILED,
                        confidence=ConfidenceEnum.HIGH,
                        evidence=sanitize_evidence_snippet(
                            f"Form submits over insecure HTTP endpoint: {insecure_actions[0]}"
                        ),
                        recommendation="Enforce HTTPS across all form action endpoints with TLS.",
                        legal_ref="TODO_VERIFY",
                        check_type=CheckTypeEnum.FORMS,
                        details={"insecure_action_endpoints": insecure_actions},
                    )
                )
            else:
                findings.append(
                    Finding(
                        rule_id="security_https_enforced",
                        category="Security Safeguards",
                        title=rule_https.title if rule_https else "HTTPS Encryption Enforced",
                        severity=rule_https.severity if rule_https else "high",
                        status=RuleFindingStatus.PASSED,
                        confidence=ConfidenceEnum.HIGH,
                        evidence=(
                            "All form submission endpoints enforce secure HTTPS transmission."
                            if has_forms
                            else "Target URL enforces secure HTTPS encryption."
                        ),
                        recommendation=(
                            "Continue enforcing TLS encryption on all transmission endpoints."
                        ),
                        legal_ref="TODO_VERIFY",
                        check_type=CheckTypeEnum.FORMS,
                        details={
                            "form_actions": "not_applicable" if not has_forms else "secure",
                        },
                    )
                )
    else:
        # Project scan
        if not has_forms:
            findings.append(
                Finding(
                    rule_id="security_https_enforced",
                    category="Security Safeguards",
                    title=rule_https.title if rule_https else "HTTPS Encryption Enforced",
                    severity=rule_https.severity if rule_https else "high",
                    status=RuleFindingStatus.NOT_APPLICABLE,
                    confidence=ConfidenceEnum.HIGH,
                    evidence="No web forms detected in audited project.",
                    recommendation=(
                        "Ensure any newly created web forms submit exclusively over HTTPS."
                    ),
                    legal_ref="TODO_VERIFY",
                    check_type=CheckTypeEnum.FORMS,
                )
            )
        elif insecure_actions:
            findings.append(
                Finding(
                    rule_id="security_https_enforced",
                    category="Security Safeguards",
                    title=rule_https.title if rule_https else "HTTPS Encryption Enforced",
                    severity=rule_https.severity if rule_https else "high",
                    status=RuleFindingStatus.FAILED,
                    confidence=ConfidenceEnum.HIGH,
                    evidence=sanitize_evidence_snippet(
                        f"Form submits over insecure HTTP endpoint: {insecure_actions[0]}"
                    ),
                    recommendation="Enforce HTTPS across all form action endpoints with TLS.",
                    legal_ref="TODO_VERIFY",
                    check_type=CheckTypeEnum.FORMS,
                    details={"insecure_action_endpoints": insecure_actions},
                )
            )
        else:
            findings.append(
                Finding(
                    rule_id="security_https_enforced",
                    category="Security Safeguards",
                    title=rule_https.title if rule_https else "HTTPS Encryption Enforced",
                    severity=rule_https.severity if rule_https else "high",
                    status=RuleFindingStatus.PASSED,
                    confidence=ConfidenceEnum.HIGH,
                    evidence="All form submission endpoints enforce secure HTTPS transmission.",
                    recommendation=(
                        "Continue enforcing TLS encryption on all transmission endpoints."
                    ),
                    legal_ref="TODO_VERIFY",
                    check_type=CheckTypeEnum.FORMS,
                )
            )

    # 3. security_no_pii_in_urls (GET method with personal data fields)
    rule_get = get_rule_by_id("security_no_pii_in_urls")
    get_pii_fields: list[str] = []
    for frm in all_forms:
        if frm["method"] == "GET" and (frm["personal_fields"] or frm["sensitive_fields"]):
            get_pii_fields.extend(frm["personal_fields"] + frm["sensitive_fields"])

    if not has_forms:
        findings.append(
            Finding(
                rule_id="security_no_pii_in_urls",
                category="Security Safeguards",
                title=rule_get.title if rule_get else "No Personal Data in Query Parameters",
                severity=rule_get.severity if rule_get else "high",
                status=RuleFindingStatus.NOT_APPLICABLE,
                confidence=ConfidenceEnum.HIGH,
                evidence="No web forms detected in audited target.",
                recommendation="Maintain policy of using POST for personal data submissions.",
                legal_ref="TODO_VERIFY",
                check_type=CheckTypeEnum.FORMS,
            )
        )
    elif get_pii_fields:
        unique_pii = sorted(set(get_pii_fields))
        findings.append(
            Finding(
                rule_id="security_no_pii_in_urls",
                category="Security Safeguards",
                title=rule_get.title if rule_get else "No Personal Data in Query Parameters",
                severity=rule_get.severity if rule_get else "high",
                status=RuleFindingStatus.FAILED,
                confidence=ConfidenceEnum.HIGH,
                evidence=sanitize_evidence_snippet(
                    f"GET form transmits personal fields in query strings: {unique_pii}"
                ),
                matched_terms=unique_pii[:5],
                recommendation=(
                    "Use POST requests with encrypted request bodies for personal data submissions."
                ),
                legal_ref="TODO_VERIFY",
                check_type=CheckTypeEnum.FORMS,
                details={"exposed_param_names": unique_pii},
            )
        )
    else:
        findings.append(
            Finding(
                rule_id="security_no_pii_in_urls",
                category="Security Safeguards",
                title=rule_get.title if rule_get else "No Personal Data in Query Parameters",
                severity=rule_get.severity if rule_get else "high",
                status=RuleFindingStatus.PASSED,
                confidence=ConfidenceEnum.HIGH,
                evidence="No GET forms submitting personal data detected.",
                recommendation="Maintain policy of using POST for personal data submissions.",
                legal_ref="TODO_VERIFY",
                check_type=CheckTypeEnum.FORMS,
            )
        )

    # 4. consent_not_preticked
    rule_preticked = get_rule_by_id("consent_not_preticked")
    all_preticked = sorted({p for frm in all_forms for p in frm["preticked_fields"]})
    if not has_forms:
        findings.append(
            Finding(
                rule_id="consent_not_preticked",
                category="Consent",
                title=rule_preticked.title if rule_preticked else "Consent Not Pre-Ticked",
                severity=rule_preticked.severity if rule_preticked else "high",
                status=RuleFindingStatus.NOT_APPLICABLE,
                confidence=ConfidenceEnum.HIGH,
                evidence="No web forms detected in audited target.",
                recommendation="Ensure any future consent checkboxes require explicit user opt-in.",
                legal_ref="TODO_VERIFY",
                check_type=CheckTypeEnum.FORMS,
            )
        )
    elif all_preticked:
        findings.append(
            Finding(
                rule_id="consent_not_preticked",
                category="Consent",
                title=rule_preticked.title if rule_preticked else "Consent Not Pre-Ticked",
                severity=rule_preticked.severity if rule_preticked else "high",
                status=RuleFindingStatus.FAILED,
                confidence=ConfidenceEnum.HIGH,
                evidence=sanitize_evidence_snippet(
                    f"Pre-checked consent checkboxes detected: {all_preticked}"
                ),
                matched_terms=all_preticked[:5],
                recommendation=(
                    "Ensure consent checkboxes are unchecked by default for affirmative opt-in."
                ),
                legal_ref="TODO_VERIFY",
                check_type=CheckTypeEnum.FORMS,
                details={"preticked_fields": all_preticked},
            )
        )
    else:
        findings.append(
            Finding(
                rule_id="consent_not_preticked",
                category="Consent",
                title=rule_preticked.title if rule_preticked else "Consent Not Pre-Ticked",
                severity=rule_preticked.severity if rule_preticked else "high",
                status=RuleFindingStatus.PASSED,
                confidence=ConfidenceEnum.HIGH,
                evidence="Consent and marketing checkboxes are unchecked by default.",
                recommendation="Maintain default opt-in standards across all user interfaces.",
                legal_ref="TODO_VERIFY",
                check_type=CheckTypeEnum.FORMS,
            )
        )

    # 5. security_password_autocomplete
    rule_pwd = get_rule_by_id("security_password_autocomplete")
    pwd_missing = any(frm["password_missing_autocomplete"] for frm in all_forms)
    has_pwd = any(frm["has_password"] for frm in all_forms)
    if pwd_missing:
        findings.append(
            Finding(
                rule_id="security_password_autocomplete",
                category="Security Safeguards",
                title=rule_pwd.title if rule_pwd else "Password Autocomplete Attributes",
                severity=rule_pwd.severity if rule_pwd else "low",
                status=RuleFindingStatus.FAILED,
                confidence=ConfidenceEnum.HIGH,
                evidence="Password field missing standard autocomplete attribute or set to 'off'.",
                matched_terms=["password"],
                recommendation="Set autocomplete='current-password' or 'new-password' on inputs.",
                legal_ref="TODO_VERIFY",
                check_type=CheckTypeEnum.FORMS,
            )
        )
    elif has_pwd:
        findings.append(
            Finding(
                rule_id="security_password_autocomplete",
                category="Security Safeguards",
                title=rule_pwd.title if rule_pwd else "Password Autocomplete Attributes",
                severity=rule_pwd.severity if rule_pwd else "low",
                status=RuleFindingStatus.PASSED,
                confidence=ConfidenceEnum.HIGH,
                evidence="Password fields feature valid autocomplete attributes.",
                recommendation="Continue supporting password manager autocomplete attributes.",
                legal_ref="TODO_VERIFY",
                check_type=CheckTypeEnum.FORMS,
            )
        )
    else:
        findings.append(
            Finding(
                rule_id="security_password_autocomplete",
                category="Security Safeguards",
                title=rule_pwd.title if rule_pwd else "Password Autocomplete Attributes",
                severity=rule_pwd.severity if rule_pwd else "low",
                status=RuleFindingStatus.NOT_APPLICABLE,
                confidence=ConfidenceEnum.HIGH,
                evidence="No password fields detected in audited forms.",
                recommendation="Ensure future credential fields permit password autocomplete.",
                legal_ref="TODO_VERIFY",
                check_type=CheckTypeEnum.FORMS,
            )
        )

    return ToolResult(
        status="ok",
        tool_name="find_personal_data_forms",
        findings=findings,
        data={
            "target": target,
            "forms_count": len(all_forms),
            "forms_summary": [
                {
                    "source": f["source"],
                    "method": f["method"],
                    "action": f["action"],
                    "fields_count": len(f["fields"]),
                    "field_names": [x["name"] for x in f["fields"]],
                }
                for f in all_forms
            ],
        },
        disclaimer=LEGAL_DISCLAIMER,
    )


async def find_personal_data_forms(
    target: str,
    fetcher: SafeFetcher | None = None,
    client: httpx.AsyncClient | None = None,
) -> ToolResult:
    """Audit web forms for personal data handling, sensitive fields, and security.

    Use only on sites/projects you own or are authorised to audit.
    """
    is_url = target.startswith("http://") or target.startswith("https://")
    owns_fetcher = is_url and (fetcher is None)
    if is_url and fetcher is None:
        fetcher = SafeFetcher(client=client)

    try:
        return await _find_personal_data_forms_impl(target, fetcher=fetcher)
    finally:
        if owns_fetcher and fetcher is not None:
            await fetcher.aclose()
