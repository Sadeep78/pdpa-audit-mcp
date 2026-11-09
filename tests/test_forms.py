"""Unit tests for find_personal_data_forms tool against good/bad forms, URLs, and safety guards."""

from pathlib import Path
from unittest.mock import patch

import httpx
import pytest

from pdpa_audit_mcp.models import RuleFindingStatus
from pdpa_audit_mcp.tools.forms import find_personal_data_forms

SAMPLE_PROJECT_DIR = Path(__file__).parent / "fixtures" / "sample_project"


class TestFindPersonalDataForms:
    """Test suite for form scanning across local directories and URLs."""

    @pytest.mark.asyncio
    async def test_good_form_passes_all_rules(self):
        good_dir = SAMPLE_PROJECT_DIR / "good"
        result = await find_personal_data_forms(str(good_dir))

        assert result.status == "ok"
        assert result.data["forms_count"] >= 1

        findings = {f.rule_id: f for f in result.findings}

        # 1. Minimisation: No sensitive fields
        assert findings["minimisation_sensitive_fields"].status == RuleFindingStatus.PASSED

        # 2. HTTPS enforced: Uses HTTPS action
        assert findings["security_https_enforced"].status == RuleFindingStatus.PASSED

        # 3. No PII in URLs: Uses POST
        assert findings["security_no_pii_in_urls"].status == RuleFindingStatus.PASSED

        # 4. Consent not pre-ticked: Checkbox is unchecked
        assert findings["consent_not_preticked"].status == RuleFindingStatus.PASSED

        # 5. Password autocomplete: Uses new-password
        assert findings["security_password_autocomplete"].status == RuleFindingStatus.PASSED

    @pytest.mark.asyncio
    async def test_bad_form_fails_all_rules(self):
        bad_dir = SAMPLE_PROJECT_DIR / "bad"
        result = await find_personal_data_forms(str(bad_dir))

        assert result.status == "ok"
        assert result.data["forms_count"] >= 1

        findings = {f.rule_id: f for f in result.findings}

        # 1. Minimisation: Sensitive NIC field detected
        assert findings["minimisation_sensitive_fields"].status == RuleFindingStatus.FAILED
        assert "nic" in findings["minimisation_sensitive_fields"].evidence

        # 2. HTTPS enforced: Insecure http:// action
        assert findings["security_https_enforced"].status == RuleFindingStatus.FAILED
        assert "http://" in findings["security_https_enforced"].evidence

        # 3. No PII in URLs: GET method with personal fields
        assert findings["security_no_pii_in_urls"].status == RuleFindingStatus.FAILED

        # 4. Consent pre-ticked: Checked attribute present
        assert findings["consent_not_preticked"].status == RuleFindingStatus.FAILED

        # 5. Password autocomplete: autocomplete='off'
        assert findings["security_password_autocomplete"].status == RuleFindingStatus.FAILED

    @pytest.mark.asyncio
    async def test_url_form_audit_with_mock_client(self):
        form_html = """
        <html>
        <body>
          <form method="POST" action="https://example.com/login">
            <input type="text" name="username">
            <input type="password" name="password" autocomplete="current-password">
            <button type="submit">Log in</button>
          </form>
        </body>
        </html>
        """

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, headers={"Content-Type": "text/html"}, text=form_html)

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        with patch(
            "pdpa_audit_mcp.fetcher.validate_url", return_value=(True, None, "93.184.216.34")
        ):
            result = await find_personal_data_forms("https://example.com/login", client=client)

        assert result.status == "ok"
        assert result.data["forms_count"] == 1
        findings = {f.rule_id: f for f in result.findings}
        assert findings["security_password_autocomplete"].status == RuleFindingStatus.PASSED
        assert findings["security_https_enforced"].status == RuleFindingStatus.PASSED

    @pytest.mark.asyncio
    async def test_path_traversal_rejected(self):
        result = await find_personal_data_forms("../../non_existent_folder_xyz")
        assert result.status == "error"
        assert "Invalid or unsafe project path" in (result.error_message or "")

    @pytest.mark.asyncio
    async def test_hard_rule_never_outputs_field_values_or_placeholders(
        self, tmp_path, monkeypatch
    ):
        """Verify field values, sample data, and placeholders are never leaked."""
        monkeypatch.setenv("PDPA_AUDIT_ALLOWED_ROOTS", str(tmp_path))
        form_file = tmp_path / "leak_test.html"
        form_file.write_text(
            """
            <html>
            <body>
              <form method="POST" action="https://example.com/submit">
                <input type="text" name="secret_code"
                       value="LEAKED_SECRET_VALUE_12345"
                       placeholder="Sample Secret Placeholder">
              </form>
            </body>
            </html>
            """,
            encoding="utf-8",
        )

        result = await find_personal_data_forms(str(tmp_path))
        assert result.status == "ok"

        # Convert entire serialized result to string and assert secrets are NOT present
        serialized = result.model_dump_json()
        assert "LEAKED_SECRET_VALUE_12345" not in serialized
        assert "Sample Secret Placeholder" not in serialized
        assert "secret_code" in serialized

    @pytest.mark.asyncio
    async def test_security_https_enforced_public_http_fails(self):
        """Public http:// URL must result in FAILED for security_https_enforced."""
        html = (
            "<html><body><form method='POST' action='/submit'>"
            "<input name='user'></form></body></html>"
        )

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, headers={"Content-Type": "text/html"}, text=html)

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        with patch(
            "pdpa_audit_mcp.fetcher.validate_url", return_value=(True, None, "93.184.216.34")
        ):
            result = await find_personal_data_forms("http://example.com/form", client=client)

        assert result.status == "ok"
        findings = {f.rule_id: f for f in result.findings}
        assert findings["security_https_enforced"].status == RuleFindingStatus.FAILED
        assert "insecure HTTP" in findings["security_https_enforced"].evidence

    @pytest.mark.asyncio
    async def test_security_https_enforced_local_http_is_not_evaluated(self):
        """Loopback/private http:// must be NOT_EVALUATED with 'local http server' note."""
        html = (
            "<html><body><form method='POST' action='/submit'>"
            "<input name='user'></form></body></html>"
        )

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, headers={"Content-Type": "text/html"}, text=html)

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        with patch("pdpa_audit_mcp.fetcher.validate_url", return_value=(True, None, "127.0.0.1")):
            result = await find_personal_data_forms("http://127.0.0.1:8000/form", client=client)

        assert result.status == "ok"
        findings = {f.rule_id: f for f in result.findings}
        assert findings["security_https_enforced"].status == RuleFindingStatus.NOT_EVALUATED
        assert "local http server" in findings["security_https_enforced"].evidence
        assert findings["security_https_enforced"].details.get("note") == "local http server"

    @pytest.mark.asyncio
    async def test_no_forms_yields_not_applicable(self, tmp_path, monkeypatch):
        """When no forms exist in audited project, form rules must be NOT_APPLICABLE."""
        monkeypatch.setenv("PDPA_AUDIT_ALLOWED_ROOTS", str(tmp_path))
        empty_dir = tmp_path / "empty_proj"
        empty_dir.mkdir()
        dummy_file = empty_dir / "index.html"
        dummy_file.write_text(
            "<html><body><h1>Hello World without forms</h1></body></html>", encoding="utf-8"
        )

        result = await find_personal_data_forms(str(empty_dir))
        assert result.status == "ok"
        assert result.data["forms_count"] == 0

        findings = {f.rule_id: f for f in result.findings}
        assert findings["minimisation_sensitive_fields"].status == RuleFindingStatus.NOT_APPLICABLE
        assert findings["security_no_pii_in_urls"].status == RuleFindingStatus.NOT_APPLICABLE
        assert findings["consent_not_preticked"].status == RuleFindingStatus.NOT_APPLICABLE
        assert findings["security_password_autocomplete"].status == RuleFindingStatus.NOT_APPLICABLE
        assert findings["security_https_enforced"].status == RuleFindingStatus.NOT_APPLICABLE

    @pytest.mark.asyncio
    async def test_form_without_password_yields_password_not_applicable(
        self, tmp_path, monkeypatch
    ):
        """When forms exist without password fields, password autocomplete is NOT_APPLICABLE."""
        monkeypatch.setenv("PDPA_AUDIT_ALLOWED_ROOTS", str(tmp_path))
        proj_dir = tmp_path / "contact_proj"
        proj_dir.mkdir()
        contact_file = proj_dir / "contact.html"
        contact_file.write_text(
            """
            <html><body>
              <form method="POST" action="https://api.example.com/contact">
                <input type="text" name="name">
                <input type="email" name="email">
                <textarea name="message"></textarea>
                <button type="submit">Send</button>
              </form>
            </body></html>
            """,
            encoding="utf-8",
        )

        result = await find_personal_data_forms(str(proj_dir))
        assert result.status == "ok"
        findings = {f.rule_id: f for f in result.findings}
        assert findings["security_password_autocomplete"].status == RuleFindingStatus.NOT_APPLICABLE
        assert findings["security_https_enforced"].status == RuleFindingStatus.PASSED

    @pytest.mark.asyncio
    async def test_security_https_enforced_scheme_and_form_action_cases(self):
        """Always evaluate URL scheme even with no forms; form-action part is not_applicable.

        Covers all four canonical cases:
        1. Public https:// with no forms -> PASSED
        2. Public http:// with no forms -> FAILED
        3. Local/private http:// with no forms -> NOT_EVALUATED ('local http server')
        4. Public https:// with insecure http:// form action -> FAILED
        """
        no_forms_html = "<html><body><p>Static informative content without forms.</p></body></html>"
        insecure_form_html = (
            "<html><body><form method='POST' action='http://api.example.com/login'>"
            "<input name='u'></form></body></html>"
        )

        # Case 1: Public https:// URL with no forms -> PASSED
        c1 = httpx.AsyncClient(
            transport=httpx.MockTransport(lambda req: httpx.Response(200, text=no_forms_html))
        )
        with patch(
            "pdpa_audit_mcp.fetcher.validate_url", return_value=(True, None, "93.184.216.34")
        ):
            res1 = await find_personal_data_forms("https://example.com/info", client=c1)
        f1 = {f.rule_id: f for f in res1.findings}["security_https_enforced"]
        assert f1.status == RuleFindingStatus.PASSED
        assert f1.details.get("form_actions") == "not_applicable"

        # Case 2: Public http:// URL with no forms -> FAILED
        c2 = httpx.AsyncClient(
            transport=httpx.MockTransport(lambda req: httpx.Response(200, text=no_forms_html))
        )
        with patch(
            "pdpa_audit_mcp.fetcher.validate_url", return_value=(True, None, "93.184.216.34")
        ):
            res2 = await find_personal_data_forms("http://example.com/info", client=c2)
        f2 = {f.rule_id: f for f in res2.findings}["security_https_enforced"]
        assert f2.status == RuleFindingStatus.FAILED
        assert "insecure HTTP" in f2.evidence
        assert f2.details.get("form_actions") == "not_applicable"

        # Case 3: Local/private http:// URL with no forms -> NOT_EVALUATED
        c3 = httpx.AsyncClient(
            transport=httpx.MockTransport(lambda req: httpx.Response(200, text=no_forms_html))
        )
        with patch("pdpa_audit_mcp.fetcher.validate_url", return_value=(True, None, "127.0.0.1")):
            res3 = await find_personal_data_forms("http://127.0.0.1:8000/info", client=c3)
        f3 = {f.rule_id: f for f in res3.findings}["security_https_enforced"]
        assert f3.status == RuleFindingStatus.NOT_EVALUATED
        assert "local http server" in f3.evidence
        assert f3.details.get("form_actions") == "not_applicable"

        # Case 4: Public https:// URL with insecure http:// form action -> FAILED
        c4 = httpx.AsyncClient(
            transport=httpx.MockTransport(lambda req: httpx.Response(200, text=insecure_form_html))
        )
        with patch(
            "pdpa_audit_mcp.fetcher.validate_url", return_value=(True, None, "93.184.216.34")
        ):
            res4 = await find_personal_data_forms("https://example.com/login", client=c4)
        f4 = {f.rule_id: f for f in res4.findings}["security_https_enforced"]
        assert f4.status == RuleFindingStatus.FAILED
        assert "insecure HTTP endpoint" in f4.evidence
