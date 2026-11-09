# Security Policy & Threat Model

`pdpa-audit-mcp` is a defensive technical readiness audit utility. Security and strict defensive constraints are built into its core architecture.

> [!IMPORTANT]
> **Defensive Use Notice**: Use this tool only on websites, endpoints, or local repositories that you own or have explicit written authorization to audit. Exploitation, scanning of unauthorized ports, fuzzing, or credential brute-forcing are strictly out of scope and prohibited.

---

## 1. Threat Model & Mitigations

The table below outlines identified threats, implemented mitigations, and corresponding automated tests verifying defense effectiveness:

| Threat Category | Specific Attack Vector | Mitigation in Code | Automated Test Covering Defense |
|---|---|---|---|
| **SSRF** | Target URL pointing to localhost, private networks, cloud metadata, or alternative IP formats | Strict validation in `validate_url`: only `http`/`https` schemes; userinfo credentials rejected; decimal/octal/hex IPs resolved to canonical IPv4/IPv6; blocks loopback (`127.0.0.0/8`, `::1`), RFC 1918, CGNAT (`100.64.0.0/10`), link-local/cloud metadata (`169.254.169.254`), 6to4 (`2002::/16`), and NAT64 (`64:ff9b::/96`). | `tests/test_safety.py::TestIsIpPrivateOrRestricted`, `TestURLValidationSSRF` |
| **DNS Rebinding** | Hostname resolves to public IP on first check, but rebinds to `127.0.0.1` during HTTP connection | `SSRFProtectedTransport` overrides httpcore network backend and pins the resolved IP before connection. Re-resolution is blocked, guaranteeing socket connects to pre-validated IP. | `tests/test_fetcher.py::TestDNSRebindingProtection::test_dns_rebinding_default_constructor_ip_pinning` |
| **Redirect Re-validation** | HTTP redirect (301/302/307/308) forwarding to an internal or restricted endpoint | Redirect locations are inspected before hop traversal via `validate_redirect`. Redirect count is strictly capped (default max 3); unsafe redirects raise `SecurityError`. | `tests/test_safety.py::TestRedirectValidation::test_redirect_to_private_ip_blocked`, `test_redirect_limit_enforced` |
| **Path Traversal & UNC Escapes** | Malicious path input navigating via `..`, Windows UNC network shares, alternative drive letters, or prefix tricks | `validate_project_path` canonicalizes paths using `Path.resolve()`, enforces boundary within `PDPA_AUDIT_ALLOWED_ROOTS` (default `Path.cwd()`), and rejects UNC prefixes (`\\`, `//`). | `tests/test_safety.py::TestWindowsPathGuard::test_unc_paths_rejected`, `test_parent_traversal_rejected`, `test_drive_letter_switch_rejected` |
| **Symlink & Junction Escapes** | Symlinks or NTFS directory junctions inside the project pointing outside the allowed root | `is_safe_file_path` inspects resolved file and directory targets. If a symlink or junction escapes the project boundary, it is skipped. | `tests/test_safety.py::TestWindowsPathGuard::test_junction_escaping_root_rejected`, `tests/test_project_scan.py::TestProjectScan::test_symlink_or_junction_escaping_root_not_followed` |
| **Decompression Bombs & Slow Servers** | Gzip/deflate zip bombs or dripping/infinite HTTP streams | Responses are streamed in 64 KB chunks up to 1 MB decompressed limit. The entire redirect chain and streaming body download is bounded by `asyncio.timeout(settings.fetch_deadline_seconds)`. | `tests/test_fetcher.py::TestDeadlineAndResourceLimits::test_decompression_bomb_truncated_safely`, `test_fetch_deadline_exceeded_raises_timeout` |
| **Prompt & Markdown Injection** | Malicious content in audited web pages attempting prompt injection or UI defacement | Evidence strings extracted from HTML/code are sanitized via `sanitize_evidence_snippet`: control chars stripped, length truncated to <= 120 chars, and wrapped in code spans in Markdown. | `tests/test_report.py::TestUntrustedContentHardening::test_malicious_evidence_rendered_inert` |
| **Localhost Bridge CSRF & Rebinding** | Attacker web page attempting CSRF or DNS rebinding against local bridge (`127.0.0.1:8765`) | Bridge checks `Host` header (421 Misdirected Request if foreign), blocks foreign `Origin` headers (403 Forbidden), requires per-run random `X-Bridge-Token` header (401 Unauthorized), and enforces 64 KB request body limit. | `tests/test_bridge.py::TestBridgeSecurity::test_host_header_validation_blocks_rebinding`, `test_foreign_origin_rejected_and_no_cors_headers`, `test_bridge_token_protection` |
| **Dashboard DOM Injection (XSS)** | Audit findings containing XSS payloads rendered into web dashboard | Single-page dashboard uses zero unsafe sinks (`.innerHTML`, `.outerHTML`, `insertAdjacentHTML`, `document.write`, `eval`). Renders all dynamic text with `document.createTextNode` and `.textContent`. Emits strict CSP with per-response dynamic nonces. | `tests/test_bridge.py::TestDashboardHtmlInvariants::test_no_inner_html_or_dangerous_sinks_in_dashboard`, `test_no_unsafe_dom_injection_methods` |
| **Personal Data Handling** | User credentials or personal data accidentally logged or surfaced in reports | The scanner extracts field *names* and structural patterns only. Field values, form submissions, placeholder values, and log statement payloads are NEVER recorded, stored, or output. | `tests/test_forms.py::TestFormScanner::test_hard_rule_never_outputs_field_values_or_placeholders`, `tests/test_project_scan.py::TestProjectScan::test_pii_logging_reports_file_line_only_and_no_content_leak` |

---

## 2. What Is Out of Scope

To prevent dual-use misuse, the following capabilities are explicitly out of scope and intentionally omitted:
1. **Network Port Scanning & Fuzzing**: The tool audits only targeted HTTP/HTTPS URLs and local repository files. Port scanning, protocol discovery, and parameter fuzzing are prohibited.
2. **Credential Testing & Brute Forcing**: The scanner does not attempt authentication, login brute-forcing, or credential cracking.
3. **Active Exploitation**: The scanner does not submit payloads, test for SQL injection, or exploit vulnerabilities.
4. **Legal Compliance Certification**: Technical indicators assess technical hygiene and static readiness only; they do not guarantee or certify formal compliance under Sri Lanka PDPA No. 9 of 2022.
