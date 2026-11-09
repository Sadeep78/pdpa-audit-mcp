"""Optional end-to-end browser test for the Single-Page Dashboard using Playwright.

Automatically skipped if playwright is not installed or browser binaries are missing.
Verifies:
1. Zero console errors and zero CSP report events.
2. Score gauge and coverage metric are rendered.
3. Malicious evidence payload (<img src=x onerror=alert(1)>) renders inertly with no alert dialog.
"""

from __future__ import annotations

import http.server
import os
import threading
import time
from pathlib import Path
from typing import Any

import pytest


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        pass


def test_dashboard_browser_audit_execution_and_xss_immunity(tmp_path: Path):
    """End-to-end browser test verifying strict CSP, dual gauges, and XSS immunity."""
    # Skip test if playwright is not installed
    pytest.importorskip("playwright")
    from playwright.sync_api import sync_playwright

    # Create test fixture site with malicious evidence payload
    site_dir = tmp_path / "xss_site"
    site_dir.mkdir()
    index_file = site_dir / "index.html"
    index_file.write_text(
        """<!DOCTYPE html>
<html>
<head><title>Test Site</title></head>
<body>
  <h1>Test Site</h1>
  <form action="http://insecure.test/submit" method="GET">
    <input type="text" name="email" value="<img src=x onerror=alert(1)>">
    <button type="submit">Submit</button>
  </form>
</body>
</html>""",
        encoding="utf-8",
    )

    # 1. Start test fixture HTTP server
    port_site = 8995
    site_handler = lambda *args, **kwargs: QuietHandler(*args, directory=str(site_dir), **kwargs)  # noqa: E731
    site_server = http.server.ThreadingHTTPServer(("127.0.0.1", port_site), site_handler)
    site_thread = threading.Thread(target=site_server.serve_forever, daemon=True)
    site_thread.start()

    # 2. Start bridge server in thread
    import uvicorn

    from pdpa_audit_mcp.api.bridge import app

    old_allow = os.environ.get("PDPA_AUDIT_ALLOW_PRIVATE")
    old_port = os.environ.get("PDPA_AUDIT_PORT")

    os.environ["PDPA_AUDIT_ALLOW_PRIVATE"] = "true"
    os.environ["PDPA_AUDIT_PORT"] = "8996"

    config = uvicorn.Config(app, host="127.0.0.1", port=8996, log_level="error")
    bridge_server = uvicorn.Server(config)
    bridge_thread = threading.Thread(target=bridge_server.run, daemon=True)
    bridge_thread.start()

    # Wait for bridge to be ready
    import httpx

    ready = False
    for _ in range(50):
        try:
            r = httpx.get("http://127.0.0.1:8996/health", timeout=1.0)
            if r.status_code == 200:
                ready = True
                break
        except Exception:  # noqa: BLE001
            time.sleep(0.1)

    if not ready:
        site_server.shutdown()
        pytest.fail("Failed to start bridge server for browser test")

    try:
        with sync_playwright() as p:
            try:
                browser = p.chromium.launch(headless=True)
            except Exception as exc:  # noqa: BLE001
                pytest.skip(f"Chromium browser could not be launched: {exc}")

            context = browser.new_context()
            page = context.new_page()

            console_errors: list[str] = []
            dialog_alerts: list[str] = []

            # Track console errors & CSP events
            page.on(
                "console",
                lambda msg: console_errors.append(msg.text) if msg.type == "error" else None,
            )

            # Fail immediately if an alert dialog is triggered (XSS proof)
            page.on("dialog", lambda dialog: dialog_alerts.append(dialog.message))

            # Navigate to Dashboard
            page.goto("http://127.0.0.1:8996/")

            # Fill in URL to audit
            page.fill("#audit-url", f"http://127.0.0.1:{port_site}")

            # Click Run Audit
            page.click("#btn-run")

            # Wait for results to render
            page.wait_for_selector("#results-section:not(.hidden)", timeout=15000)

            # Assert score and coverage gauges rendered
            score_text = page.inner_text("#overall-score-val")
            cov_text = page.inner_text("#overall-coverage-val")
            label_text = page.inner_text("#overall-label")

            assert score_text != "--"
            assert cov_text != "--"
            assert len(label_text) > 0

            # Assert no XSS alert was ever triggered
            assert len(dialog_alerts) == 0, f"XSS alert dialog was triggered: {dialog_alerts}"

            # Assert zero console errors and zero CSP events
            csp_errors = [e for e in console_errors if "Content Security Policy" in e or "CSP" in e]
            assert len(csp_errors) == 0, f"CSP report events detected: {csp_errors}"
            assert len(console_errors) == 0, f"Console errors detected: {console_errors}"

            browser.close()
    finally:
        bridge_server.should_exit = True
        site_server.shutdown()
        site_server.server_close()
        if old_allow is not None:
            os.environ["PDPA_AUDIT_ALLOW_PRIVATE"] = old_allow
        else:
            os.environ.pop("PDPA_AUDIT_ALLOW_PRIVATE", None)
        if old_port is not None:
            os.environ["PDPA_AUDIT_PORT"] = old_port
        else:
            os.environ.pop("PDPA_AUDIT_PORT", None)
