# Changelog

All notable changes to `pdpa-audit-mcp` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-09

### Added
- **FastMCP Stdio Server**: 9 tools exposing Sri Lanka Personal Data Protection Act No. 9 of 2022 technical readiness indicators:
  - `scan_privacy_policy`: Analyzes transparency, data subject rights (access, correction, erasure, withdrawal of consent), retention, and DPO contacts.
  - `detect_cookie_consent`: Identifies CMP banners, opt-in/reject buttons, and tracking scripts (Google Analytics, Meta Pixel, Hotjar, TikTok, etc.).
  - `find_personal_data_forms`: Audits HTML forms for sensitive categories (NIC, passport, biometric, health), insecure GET submissions, pre-checked checkboxes, and password autocomplete attributes.
  - `scan_project_files`: Scans codebases for personal data model schemas, erasure/retention implementations, third-party SDK dependencies, and personal data logging.
  - `check_breach_readiness`: Evaluates repositories for incident response plans (`BREACH_RESPONSE.md`), security contact files (`security.txt`), and escalation procedures.
  - `detect_third_party_transfers`: Audits external domain assets and cross-border data transfer disclosures.
  - `run_full_audit`: Orchestrates simultaneous web and repository scans, isolating errors and deduplicating findings across tools.
  - `generate_gap_report`: Renders structured Markdown and JSON reports complete with executive summaries, categorised breakdowns, prioritised findings, and legal disclaimers.
  - `list_checklist`: Enumerates technical readiness indicators with filtering by category.
- **REST Bridge & Web Dashboard**:
  - FastAPI server running on `127.0.0.1:8765` (`pdpa-audit-bridge`) with Host header validation, per-run token authentication (`X-Bridge-Token`), and concurrency locking.
  - Single-page vanilla HTML/CSS/JS dashboard (`dashboard/index.html`) using strict text APIs (zero DOM injection sinks, zero external dependencies).
  - One-click report download as Markdown blob.
- **Security & Safety Guardrails**:
  - Full SSRF protection blocking private, loopback, link-local, carrier-grade NAT, 6to4, NAT64, and cloud metadata IPs (`169.254.169.254`).
  - DNS rebinding prevention via `SSRFProtectedTransport` pinning resolved IP addresses before connection.
  - Path traversal and boundary guard preventing access outside `PDPA_AUDIT_ALLOWED_ROOTS` (UNC, symlinks, Windows junction escapes, path prefixes).
  - Decompression bomb guard streaming up to 1 MB decompressed payloads.
  - Untrusted content sanitization preventing prompt and markdown injection in reports.
  - Ruff `BLE` enforcement confining catch-all exception handlers exclusively to deliberate system boundaries (stdio wrapper, bridge endpoints, middleware, full audit orchestrator).
  - Coverage metric reporting rule coverage and weight coverage alongside scores, qualifying partial audits under 60% coverage as `(partial assessment)`.
  - Added `not_applicable` status for rules where target elements were not present (e.g. no cookies set, no password fields, no external domains, no web forms), excluding them from score denominators and coverage numerators.
  - Added dedicated `erasure_mechanism_in_code` rule for project schema analysis, keeping `rights_erasure` strictly as a privacy policy text rule.
  - Added dedicated `no_pii_in_logs` project rule for logging analysis (reporting file:line only, zero content/value leakage), keeping `security_no_pii_in_urls` strictly for GET query strings and link hrefs.
  - Added `matched_terms` (up to 5 matched indicators, fields, or tracker names) on `Finding`, displayed in Markdown/JSON reports, web dashboard, and demo summary tables.
  - Added `scripts/evaluate.py` evaluation sheet generator with required `--confirm-authorised` gate for real-world labeling and human verification.
  - Defined explicit multi-source merge precedence hierarchy (failed > needs_review > passed > not_evaluated > not_applicable).
  - End-to-end browser test with Playwright verifying strict CSP and DOM XSS immunity.
