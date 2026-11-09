"""Unit tests for FastMCP server tool registration, defensive notices, and stdio execution."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from pdpa_audit_mcp.scoring import calculate_readiness_score
from pdpa_audit_mcp.server import (
    check_breach_readiness,
    detect_cookie_consent,
    detect_third_party_transfers,
    mcp,
    run_full_audit,
    scan_privacy_policy,
    scan_project_files,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"
SAMPLE_PROJECT_DIR = FIXTURES_DIR / "sample_project"

EXPECTED_TOOLS = {
    "scan_privacy_policy",
    "detect_cookie_consent",
    "find_personal_data_forms",
    "scan_project_files",
    "check_breach_readiness",
    "detect_third_party_transfers",
    "run_full_audit",
    "generate_gap_report",
    "list_checklist",
}


@pytest.mark.asyncio
async def test_all_nine_tools_registered_with_defensive_notice():
    """Verify that exactly the 9 required tools are registered in FastMCP and include the notice."""
    tools = await mcp.list_tools()
    tool_map = {t.name: t for t in tools}

    assert EXPECTED_TOOLS.issubset(set(tool_map.keys()))
    assert len(tool_map) == 9

    for tool_name in EXPECTED_TOOLS:
        tool_obj = tool_map[tool_name]
        desc = tool_obj.description or ""
        assert "Use only on sites/projects you own or are authorised to audit" in desc, (
            f"Tool {tool_name} description missing defensive authorization notice: {desc}"
        )


@pytest.mark.asyncio
async def test_server_list_checklist_execution():
    """Verify list_checklist works via FastMCP and filters categories."""
    res_all = await mcp.call_tool("list_checklist", {})
    # FastMCP ToolResult has content list with TextContent
    assert res_all.is_error is False
    content_text = res_all.content[0].text
    data = json.loads(content_text)
    assert data["status"] == "ok"
    assert data["data"]["rules_count"] >= 15

    res_transp = await mcp.call_tool("list_checklist", {"category": "Transparency"})
    data_transp = json.loads(res_transp.content[0].text)
    assert data_transp["status"] == "ok"
    assert data_transp["data"]["rules_count"] >= 4


@pytest.mark.asyncio
async def test_server_generate_gap_report_execution():
    """Verify generate_gap_report works via FastMCP call."""
    score = calculate_readiness_score([])
    res = await mcp.call_tool(
        "generate_gap_report",
        {
            "audit_result": {
                "status": "ok",
                "target": "https://example.com",
                "timestamp": "2026-11-09T00:00:00Z",
                "summary": score.model_dump(),
                "findings": [],
            },
            "format": "markdown",
        },
    )
    assert res.is_error is False
    text = res.content[0].text
    assert "LEGAL DISCLAIMER" in text
    assert "## Executive Summary" in text


@pytest.mark.asyncio
async def test_server_tool_handles_restricted_url_gracefully():
    """Verify server tools catch SecurityError and return status error without throwing."""
    res = await scan_privacy_policy("http://127.0.0.1/privacy")
    assert res["status"] == "error"
    err = res["error_message"].lower()
    assert "loopback" in err or "restricted" in err

    res_consent = await detect_cookie_consent("http://169.254.169.254/cookies")
    assert res_consent["status"] == "error"

    res_transfers = await detect_third_party_transfers("http://10.0.0.1/")
    assert res_transfers["status"] == "error"


@pytest.mark.asyncio
async def test_server_tool_handles_invalid_path_gracefully():
    """Verify server tools catch SecurityError on path traversal and return status: error."""
    res = await scan_project_files("../../some_secret_dir")
    assert res["status"] == "error"

    res_breach = await check_breach_readiness("C:/nonexistent/directory/12345")
    assert res_breach["status"] == "error"


@pytest.mark.asyncio
async def test_server_tool_enforces_allowed_roots(tmp_path: Path, monkeypatch):
    """Verify server tool scan_project_files blocks paths outside PDPA_AUDIT_ALLOWED_ROOTS."""
    root_a = tmp_path / "root_a"
    root_b = tmp_path / "root_b"
    root_a.mkdir()
    root_b.mkdir()

    monkeypatch.setenv("PDPA_AUDIT_ALLOWED_ROOTS", str(root_a))

    # Path inside root_a should succeed validation
    res_a = await scan_project_files(str(root_a))
    assert res_a["status"] == "ok"

    # Path outside root_a should return error
    res_b = await scan_project_files(str(root_b))
    assert res_b["status"] == "error"
    assert "pdpa_audit_allowed_roots" in res_b["error_message"].lower()


@pytest.mark.asyncio
async def test_server_run_full_audit_validation_error():
    """Verify run_full_audit returns an error report when neither url nor path is supplied."""
    res = await run_full_audit()
    assert res["status"] == "error"
    assert "at least one of" in res["error_message"].lower()


def test_stdio_jsonrpc_handshake():
    """Verify launching server as subprocess communicates via clean JSON-RPC over stdio."""
    proc = subprocess.Popen(
        [sys.executable, "-m", "pdpa_audit_mcp"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    try:
        # Step 1: Send initialize request
        init_req = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "test-client", "version": "1.0.0"},
            },
        }
        proc.stdin.write(json.dumps(init_req) + "\n")
        proc.stdin.flush()

        stdout_line = proc.stdout.readline()
        assert stdout_line, "Server did not respond on stdout"
        init_resp = json.loads(stdout_line)
        assert init_resp.get("jsonrpc") == "2.0"
        assert init_resp.get("id") == 1
        assert "result" in init_resp
        assert init_resp["result"]["serverInfo"]["name"] == "pdpa-audit-mcp"
        assert init_resp["result"]["serverInfo"]["version"] == "0.1.0"

        # Step 2: Send initialized notification
        init_notif = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        proc.stdin.write(json.dumps(init_notif) + "\n")
        proc.stdin.flush()

        # Step 3: Send tools/list request
        tools_req = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
        proc.stdin.write(json.dumps(tools_req) + "\n")
        proc.stdin.flush()

        tools_line = proc.stdout.readline()
        tools_resp = json.loads(tools_line)
        assert tools_resp.get("id") == 2
        tool_names = [t["name"] for t in tools_resp["result"]["tools"]]
        assert EXPECTED_TOOLS.issubset(set(tool_names))

    finally:
        if proc.stdin:
            proc.stdin.close()
        if proc.stdout:
            proc.stdout.close()
        if proc.stderr:
            proc.stderr.close()
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        assert stdout_line.startswith("{")
