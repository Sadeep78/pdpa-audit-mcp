# pdpa-audit-mcp

> [!WARNING]
> **LEGAL DISCLAIMER**: This tool provides technical readiness indicators and gap analysis only. It does **NOT** constitute legal advice or formal certification of compliance with Sri Lanka's Personal Data Protection Act, No. 9 of 2022 (PDPA). Organizations must verify all legal references against the official gazetted Act at [dpa.gov.lk](https://dpa.gov.lk) and consult qualified legal counsel. Check [dpa.gov.lk](https://dpa.gov.lk) for the current commencement status.

> [!IMPORTANT]
> **DEFENSIVE USE ONLY**: Use this tool only on websites, endpoints, or local repositories that you own or have explicit written authorization to audit. Never use this tool for port scanning, network exploitation, fuzzing, or credential brute-forcing.

`pdpa-audit-mcp` is an open-source technical readiness audit utility and FastMCP server. It empowers developers and technical leads to evaluate their web properties and codebases against technical hygiene indicators aligned with Sri Lanka's Personal Data Protection Act, No. 9 of 2022. It features an MCP stdio server for AI assistants (such as Claude Desktop), a local REST bridge, and a standalone single-page web dashboard.

---

## Features

- **9 Specialized MCP Tools**: Expose granular readiness audits for privacy policies, cookie consent, personal data forms, local repository files, breach readiness, and third-party data transfers.
- **SSRF & DNS Rebinding Immunity**: Validates IP addresses, disallowing private, loopback, link-local, carrier-grade NAT, 6to4, NAT64, and cloud metadata (`169.254.169.254`). Employs socket-level IP pinning on initial hops.
- **Path Guard**: Blocks directory traversal (`..`), UNC network shares, alternative drive letters, and symlink/junction escapes outside allowed roots.
- **Multilingual Support**: Supports indicator detection and text normalization in **English**, **Sinhala** (සිංහල), and **Tamil** (தமிழ்).
- **Zero-Storage Personal Data Guarantee**: Extracts structural metadata and field *names* only. Field values, user input, sample data, and log payloads are never stored, logged, or emitted in audit reports.
- **Single-Page Local Dashboard**: Zero external requests, zero vulnerable DOM sinks (`innerHTML`, `eval`), strict CSP with per-response nonces, and instant Markdown gap report export.
- **Offline Capable**: Functions seamlessly without internet access when auditing local directories and offline test fixtures.

---

## Installation

### With `uv` (Recommended)

```bash
# Clone the repository
git clone https://github.com/your-org/pdpa-audit-mcp.git
cd pdpa-audit-mcp

# Install dependencies and sync virtual environment
uv sync
```

### With `pip` and virtualenv

```bash
python -m venv .venv

# Windows
.venv\Scripts\activate
# Linux / macOS
source .venv/bin/activate

pip install -e .
```

---

## Running the Servers

### 1. FastMCP Server (stdio)

Run the server directly via standard input/output (for integration with MCP clients):

```bash
# Using uv
uv run pdpa-audit-mcp

# Using virtualenv
pdpa-audit-mcp
```

### 2. REST Bridge & Web Dashboard

Start the local REST bridge and web UI:

```bash
# Using uv
uv run pdpa-audit-bridge

# Custom port
uv run pdpa-audit-bridge --port 8765
```

Once started, open **`http://127.0.0.1:8765/`** in your browser to access the interactive audit dashboard.

---

## Claude Desktop Configuration

To use `pdpa-audit-mcp` in Claude Desktop on Windows, configure your `claude_desktop_config.json` (located at `%APPDATA%\Claude\claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "pdpa-audit": {
      "command": "uv",
      "args": [
        "run",
        "--directory",
        "C:\\Users\\DELL\\Desktop\\pdpa-audit-mcp",
        "pdpa-audit-mcp"
      ],
      "env": {
        "PDPA_AUDIT_ALLOWED_ROOTS": "C:\\Users\\DELL\\projects;C:\\Users\\DELL\\Desktop\\my-site",
        "PDPA_AUDIT_ALLOW_PRIVATE": "false"
      }
    }
  }
}
```

### Environment Variables Explained

- **`PDPA_AUDIT_ALLOWED_ROOTS`**: Semicolon-delimited on Windows (colon-delimited on Linux/macOS) list of allowed project root directories. If unset, it strictly defaults to the **current working directory** (`Path.cwd()`), preventing an AI assistant or client from wandering the filesystem.
- **`PDPA_AUDIT_ALLOW_PRIVATE`**: Defaults to `false`. Set to `true` **only** when auditing a local development server (e.g. `http://localhost:3000` or `http://127.0.0.1:8000`).
- **`PDPA_AUDIT_TIMEOUT_SECONDS`**: Per-request HTTP timeout in seconds (default: `10.0`).
- **`PDPA_AUDIT_FETCH_DEADLINE_SECONDS`**: Overall deadline for complete crawl/redirect chain (default: `20.0`).

---

## Tool Reference Table

All tools include the defensive use notice: *"Use only on sites/projects you own or are authorised to audit."*

| Tool Name | Target Scope | Primary Indicators Audited |
|---|---|---|
| `scan_privacy_policy` | Web URL | Data processing purpose, retention period, categories collected, contact info, and data subject rights (access, correction, erasure, withdrawal of consent). |
| `detect_cookie_consent` | Web URL | Cookie banners/CMPs, affirmative opt-in buttons, reject options, and tracking scripts executed prior to consent. |
| `find_personal_data_forms` | URL or Local Path | HTML form fields collecting sensitive data (NIC, passport, biometrics, health), insecure GET submissions, pre-checked consent checkboxes, and password autocomplete attributes. |
| `scan_project_files` | Local Path | Repository schemas, code-level erasure mechanisms (`erasure_mechanism_in_code`), hardcoded personal data logging, and cross-border vendor SDKs. |
| `check_breach_readiness` | Local Path | Presence of `BREACH_RESPONSE.md`, incident response guidelines, internal notification procedures, and `security.txt`. |
| `detect_third_party_transfers` | Web URL | External CDN domains, analytics, tag managers, and cross-border data transfer disclosures in policy text. |
| `run_full_audit` | URL and/or Path | Orchestrates all applicable tools, isolates tool errors, deduplicates findings, and calculates readiness index scores. |
| `generate_gap_report` | Audit Result | Formats audit findings into structured Markdown or JSON gap reports with executive summaries and legal disclaimers. |
| `list_checklist` | None | Enumerates all bundled checklist rules, optionally filtered by category. |

---

## How Scoring Works

The readiness score is calculated as a **weighted heuristic percentage (0–100%)** accompanied by comprehensive coverage metrics:

1. **Heuristic Weights**:
   - Each checklist rule carries a severity weight: `critical` (weight 5), `high` (weight 3), `medium` (weight 2), `low` (weight 1).
2. **Evaluated vs Excluded Rules**:
   - Rules with status `passed` earn 100% of their weight.
   - Rules with status `failed` earn 0% of their weight.
   - Rules with status `needs_review` or `not_evaluated` are **excluded from the scored denominator**, preventing unassessed rules from dragging down the readiness score.
   - Rules with status `not_applicable` (e.g. no cookies set, no password fields, no external domains, no web forms) are **excluded from both the score denominator and coverage calculations**, and listed in a dedicated "Not Applicable" report section and dashboard card. Only rules where target elements were actually inspected may be marked `passed`.
3. **Coverage Metrics & Anti-False-Confidence Safeguards**:
   - **Rule Coverage**: Assessed rules (`passed + failed`) / applicable rules (`passed + failed + needs_review`).
   - **Weight Coverage**: Scored weight / total applicable weight.
   - **Partial Assessment Suffix**: Whenever weight coverage is under 60%, the readiness label is automatically qualified as `<Label> (partial assessment)` and explicitly reports how many rules require manual human review.
   - **No Bare 100% Scores**: The report, dashboard, and demo outputs always display coverage alongside the score (e.g., `100.0% (Mostly Ready | Coverage: 96.0%)`), preventing misleading representations of compliance.
4. **Insufficient Data Handling**:
   - If no evaluable rules run in an audit (or all tools encounter network timeouts/errors), both category and overall scores are returned as `None` with the label **"Insufficient data"**, never a misleading 0% or 100%.
5. **Readiness Labels**:
   - **80.0% – 100%**: *Mostly Ready*
   - **50.0% – 79.9%**: *Partially Ready*
   - **0.0% – 49.9%**: *Not Ready*
   - **Score is None**: *Insufficient data*
6. **Multi-Source Merge Precedence**:
   When multiple tools evaluate the same rule (e.g. `forms(url)`, `forms(project)`, `privacy_policy`, `project_scan`), findings are merged using a strict conservative precedence hierarchy:
   $$\text{failed} > \text{needs\_review} > \text{passed} > \text{not\_evaluated} > \text{not\_applicable}$$
   - Any identified compliance failure (`failed`) or ambiguity requiring human inspection (`needs_review`) is never masked by a clean result from another target.
   - An inspected `passed` beats a source that could not run (`not_evaluated`) or found nothing to inspect (`not_applicable`). For example, if a privacy policy states cross-border transfer details (`passed`), that inspected disclosure takes precedence over a project scan detecting no third-party cloud SDKs (`not_applicable`).
   - A source that could not run due to an error or timeout (`not_evaluated`) beats a rule that was completely inapplicable (`not_applicable`), ensuring that unassessed scope remains visible.

---

## Validation & Evaluation

The automated test suite in `tests/test_rule_matrix.py` is a table-driven **synthetic regression suite** verifying keyword combinations, multilingual text indicators (English, Sinhala, Tamil), and structural detectors against controlled test fixtures. It serves as a regression prevention harness, not an empirical accuracy measurement.

Real-world accuracy, precision, and recall are measured through systematic manual verification of production websites and open-source codebases documented in [`docs/EVALUATION.md`](docs/EVALUATION.md).

To generate a structured evaluation labeling sheet for an authorized target:
```bash
python scripts/evaluate.py --url https://your-site.lk --confirm-authorised --out docs/evaluation_sheet.md
```

---

## Defensive Architecture & Exception Handling

To ensure reliability without masking errors:
- **Ruff `BLE` Rules Enforced**: Core logic throughout tools, safety guards, and fetchers catches specific exception types (`httpx.HTTPError`, `OSError`, `TimeoutError`, `ValueError`, `SecurityError`).
- **Deliberate Boundary Catch-Alls**: Blind exception handlers (`except Exception`) are strictly restricted to four deliberate system boundaries:
  1. *MCP tool wrappers* (`server.py`): Prevents stdio JSON-RPC crashes.
  2. *Bridge endpoints* (`api/bridge.py`): Returns HTTP 500 JSON without crashing the server.
  3. *Bridge ASGI middleware* (`api/bridge.py`): Injects security headers on unexpected pipeline errors.
  4. *Tool isolation in `run_full_audit`* (`report.py`): Isolates single-tool failures so remaining checks continue.
  Each boundary handler is annotated with `# noqa: BLE001` and an explanatory comment.

---

## Browser End-to-End Testing

An optional Playwright browser test suite is provided in `tests/test_dashboard_browser.py`:
- Automatically runs when Playwright is installed (`pytest tests/test_dashboard_browser.py`) and cleanly skips when missing.
- Verifies strict Content Security Policy (zero console errors, zero CSP report events).
- Asserts score gauge and coverage gauge are rendered correctly.
- Confirms that untrusted evidence containing HTML injection payloads (such as `<img src=x onerror=alert(1)>`) is rendered as inert plain text with zero alert dialogs.

---

## How to Extend the Checklist

The checklist is stored in `src/pdpa_audit_mcp/data/pdpa_checklist.yaml`.

```yaml
rules:
  - id: "custom_rule_id"
    category: "Transparency"
    title: "Explicit Purpose Specification"
    severity: "high"
    check_type: "privacy_policy"
    # To maintain audit integrity, legal_ref must be "TODO_VERIFY" by default
    legal_ref: "TODO_VERIFY"
    legal_ref_verified: false
    # Once human legal counsel verifies against official gazette, update as follows:
    # legal_ref: "Section X"
    # legal_ref_verified: true
    # source_url: "https://dpa.gov.lk/..."
    recommendation: "Clearly state specific, legitimate purposes for processing."
    all_of:
      - en: ["purpose of processing", "processing purposes"]
        si: ["දත්ත සැකසීමේ අරමුණ"]
        ta: ["செயலாக்கத்தின் நோக்கம்"]
```

> [!NOTE]
> The checklist loader strictly validates that if `legal_ref_verified: true`, a valid, non-empty `source_url` pointing to an official reference must be supplied. Whenever `legal_ref_verified` is `false`, reports display `"legal reference: to be verified"`. Do not invent section numbers or commencement dates; consult [dpa.gov.lk](https://dpa.gov.lk).

---

## Limitations

1. **Static HTML Only**: Scans static HTML responses only; single-page applications (SPAs) that render dynamically in client-side JavaScript will show little content and may omit unrendered elements.
2. **Keyword Heuristics**: Textual analysis relies on normalized keyword indicators across English, Sinhala, and Tamil. Complex legal drafting nuances require human expert verification.
3. **No Proof of Runtime Behaviour**: Static analysis does not monitor runtime network egress, live database write operations, or actual backend retention cron jobs.
4. **Chunk-Level Decompression**: Response decompression is capped at 1 MB after each chunk is received. While payloads exceeding 1 MB are truncated safely, a single compressed chunk with an extreme compression ratio can cause a brief memory spike before truncation.
5. **CDN & Font Domains**: External CDN and web font domains are reported as third-party processors with unverified locations, which may produce false fails for cross-border transfer disclosures when such assets do not process personal data.

---

## Roadmap

- [ ] Headless browser rendering option (e.g. Playwright) for client-side rendered SPAs.
- [ ] Export formats for formal executive audit presentations (PDF, SARIF).
- [ ] Direct GitHub Action for automated pull request readiness checks.
- [ ] Domain classification updates for regional South Asian cloud providers.

---

## License

This project is licensed under the [MIT License](LICENSE).
