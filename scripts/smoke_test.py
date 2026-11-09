"""Comprehensive smoke test for pdpa-audit-mcp.

1. Executes scripts/demo.py (offline fixture audits).
2. Runs MCP server via stdio and invokes list_checklist, scan_privacy_policy, and run_full_audit.
3. Launches REST bridge on a test port and executes an audit through the HTTP REST API with token.
"""

from __future__ import annotations

import asyncio
import http.server
import json
import os
import subprocess
import sys
import threading
import time
from functools import partial
from pathlib import Path

import httpx

PROJECT_ROOT = Path(__file__).parent.parent.resolve()
os.environ["PDPA_AUDIT_ALLOW_PRIVATE"] = "true"
os.environ["PDPA_AUDIT_ALLOWED_ROOTS"] = str(PROJECT_ROOT)


def _start_http_server(directory: Path, port: int) -> http.server.ThreadingHTTPServer:
    handler = partial(http.server.SimpleHTTPRequestHandler, directory=str(directory))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


async def run_mcp_client_test(fixture_url: str):
    """Run JSON-RPC calls over stdio against the FastMCP server."""
    print("\n--- STEP 2: FASTMCP STDIO PROTOCOL CLIENT CALLS ---")
    proc = subprocess.Popen(
        [sys.executable, "-m", "pdpa_audit_mcp"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    try:
        # 1. Initialize
        init_req = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "smoke-test", "version": "1.0.0"},
            },
        }
        proc.stdin.write(json.dumps(init_req) + "\n")
        proc.stdin.flush()
        init_resp = json.loads(proc.stdout.readline())
        print(f"[*] MCP Server Initialized: {init_resp['result']['serverInfo']}")

        # 2. Initialized notification
        init_notif = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        proc.stdin.write(json.dumps(init_notif) + "\n")
        proc.stdin.flush()

        # 3. Call list_checklist
        list_req = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "list_checklist", "arguments": {"category": "Transparency"}},
        }
        proc.stdin.write(json.dumps(list_req) + "\n")
        proc.stdin.flush()
        list_resp = json.loads(proc.stdout.readline())
        list_data = json.loads(list_resp["result"]["content"][0]["text"])
        rules_cnt = list_data["data"]["rules_count"]
        print(f"[*] Tool 'list_checklist' (Transparency): {rules_cnt} rules returned")

        # 4. Call scan_privacy_policy
        priv_req = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "scan_privacy_policy", "arguments": {"url": fixture_url}},
        }
        proc.stdin.write(json.dumps(priv_req) + "\n")
        proc.stdin.flush()
        priv_resp = json.loads(proc.stdout.readline())
        priv_data = json.loads(priv_resp["result"]["content"][0]["text"])
        f_count = len(priv_data.get("findings", []))
        print(f"[*] Tool 'scan_privacy_policy': status={priv_data['status']}, findings={f_count}")

        # 5. Call run_full_audit
        full_req = {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "run_full_audit", "arguments": {"url": fixture_url}},
        }
        proc.stdin.write(json.dumps(full_req) + "\n")
        proc.stdin.flush()
        full_resp = json.loads(proc.stdout.readline())
        full_data = json.loads(full_resp["result"]["content"][0]["text"])
        score = full_data["summary"]["overall_score"]
        label = full_data["summary"]["readiness_label"]
        print(f"[*] Tool 'run_full_audit': status={full_data['status']}, score={score}% ({label})")

    finally:
        if proc.stdin:
            proc.stdin.close()
        if proc.stdout:
            proc.stdout.close()
        if proc.stderr:
            proc.stderr.close()
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()


async def run_rest_bridge_test(fixture_url: str):
    """Start REST bridge and invoke audit over HTTP with token."""
    print("\n--- STEP 3: REST BRIDGE HTTP API AUDIT ---")
    bridge_port = 8795
    proc = subprocess.Popen(
        [sys.executable, "-m", "pdpa_audit_mcp.api.bridge", "--port", str(bridge_port)],
        env={
            **os.environ,
            "PDPA_AUDIT_PORT": str(bridge_port),
            "PDPA_AUDIT_ALLOW_PRIVATE": "true",
            "PDPA_AUDIT_ALLOWED_ROOTS": str(PROJECT_ROOT),
        },
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    try:
        # Wait for bridge to become ready
        ready = False
        for _ in range(30):
            try:
                r = httpx.get(f"http://127.0.0.1:{bridge_port}/health", timeout=1.0)
                if r.status_code == 200:
                    ready = True
                    break
            except Exception:
                time.sleep(0.2)

        assert ready, "Bridge failed to become ready"
        print(f"[*] Bridge server live at http://127.0.0.1:{bridge_port}")

        # Fetch dashboard to retrieve per-run token
        dash_res = httpx.get(f"http://127.0.0.1:{bridge_port}/")
        import re

        m = re.search(r'<meta name="bridge-token" content="([^"]+)">', dash_res.text)
        assert m, "Bridge token meta tag not found in dashboard"
        token = m.group(1)
        print(f"[*] Extracted bridge token (length {len(token)})")

        # Execute POST /audit/full
        headers = {
            "Content-Type": "application/json",
            "X-Bridge-Token": token,
        }
        payload = {"url": fixture_url}
        audit_res = httpx.post(
            f"http://127.0.0.1:{bridge_port}/audit/full",
            headers=headers,
            json=payload,
            timeout=15.0,
        )
        assert audit_res.status_code == 200
        result_json = audit_res.json()
        print(f"[*] POST /audit/full responded: status={result_json['status']}")
        print(f"    Target:           {result_json['target']}")
        print(f"    Overall Score:    {result_json['summary']['overall_score']}%")
        print(f"    Readiness Label:  {result_json['summary']['readiness_label']}")
        print(f"    Passed Count:     {result_json['summary']['total_passed']}")
        print(f"    Failed Count:     {result_json['summary']['total_failed']}")
        print(f"    Needs Review:     {result_json['summary']['total_needs_review']}")

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()


def main():
    # 1. Run demo.py
    print("--- STEP 1: RUNNING SCRIPTS/DEMO.PY ---")
    res_demo = subprocess.run(
        [sys.executable, "scripts/demo.py"], cwd=PROJECT_ROOT, capture_output=True, text=True
    )
    print(res_demo.stdout)

    # 2. Host local fixture server for MCP & Bridge tests
    fixtures_dir = PROJECT_ROOT / "tests" / "fixtures" / "good_site"
    port_fix = 8995
    fixture_server = _start_http_server(fixtures_dir, port_fix)
    fixture_url = f"http://127.0.0.1:{port_fix}"

    try:
        # Run MCP stdio client tests
        asyncio.run(run_mcp_client_test(fixture_url))

        # Run REST bridge test
        asyncio.run(run_rest_bridge_test(fixture_url))

        print("\n" + "=" * 70)
        print("ALL SMOKE TESTS COMPLETED SUCCESSFULLY!")
        print("=" * 70)
    finally:
        fixture_server.shutdown()


if __name__ == "__main__":
    main()
