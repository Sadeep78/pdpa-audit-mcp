"""Packaging tests verifying wheel contents and entry points in a clean venv."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
import zipfile
from pathlib import Path

import httpx
import pytest

UV_BIN = shutil.which("uv") or "uv"

REQUIRED_WHEEL_FILES = {
    "pdpa_audit_mcp/dashboard/index.html",
    "pdpa_audit_mcp/data/pdpa_checklist.yaml",
}

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


def test_wheel_contents_include_all_runtime_assets(tmp_path: Path):
    """Verify built wheel contains HTML dashboard, checklist YAML, and license."""
    dist_dir = tmp_path / "dist"
    dist_dir.mkdir()
    project_root = Path(__file__).parent.parent

    # Build wheel to tmp dist
    res = subprocess.run(
        [UV_BIN, "build", "--wheel", "--out-dir", str(dist_dir)],
        cwd=project_root,
        capture_output=True,
        text=True,
    )
    if res.returncode != 0:
        pytest.fail(
            f"uv build failed with code {res.returncode}:\n"
            f"STDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}"
        )

    whls = list(dist_dir.glob("*.whl"))
    assert len(whls) == 1
    whl_path = whls[0]

    with zipfile.ZipFile(whl_path, "r") as z:
        names = set(z.namelist())

    for req in REQUIRED_WHEEL_FILES:
        assert req in names, f"Required asset {req} missing from wheel archive"


def test_installed_wheel_stdio_and_bridge_execution(tmp_path: Path):
    """Install wheel into a clean temporary virtual environment and verify CLI tools."""
    dist_dir = tmp_path / "dist"
    dist_dir.mkdir()
    venv_dir = tmp_path / "test_venv"
    project_root = Path(__file__).parent.parent

    # Build wheel
    res = subprocess.run(
        [UV_BIN, "build", "--wheel", "--out-dir", str(dist_dir)],
        cwd=project_root,
        capture_output=True,
        text=True,
    )
    if res.returncode != 0:
        pytest.fail(f"uv build failed: {res.stderr}")
    whl_path = list(dist_dir.glob("*.whl"))[0]

    # Create temporary virtualenv
    res_venv = subprocess.run(
        [UV_BIN, "venv", str(venv_dir)],
        cwd=project_root,
        capture_output=True,
        text=True,
    )
    if res_venv.returncode != 0:
        pytest.fail(f"uv venv failed: {res_venv.stderr}")

    if sys.platform == "win32":
        venv_python = venv_dir / "Scripts" / "python.exe"
    else:
        venv_python = venv_dir / "bin" / "python"

    # Install wheel into clean venv
    subprocess.run(
        [UV_BIN, "pip", "install", str(whl_path), "--python", str(venv_python)],
        check=True,
        capture_output=True,
        text=True,
    )

    # 1. Test stdio JSON-RPC MCP server
    mcp_proc = subprocess.Popen(
        [str(venv_python), "-m", "pdpa_audit_mcp"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    try:
        init_req = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "pack-test", "version": "1.0"},
            },
        }
        mcp_proc.stdin.write(json.dumps(init_req) + "\n")
        mcp_proc.stdin.flush()
        out1 = mcp_proc.stdout.readline()
        res1 = json.loads(out1)
        assert res1["result"]["serverInfo"]["name"] == "pdpa-audit-mcp"
        assert res1["result"]["serverInfo"]["version"] == "0.1.0"

        init_notif = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        mcp_proc.stdin.write(json.dumps(init_notif) + "\n")
        mcp_proc.stdin.flush()

        tools_req = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
        mcp_proc.stdin.write(json.dumps(tools_req) + "\n")
        mcp_proc.stdin.flush()
        out2 = mcp_proc.stdout.readline()
        res2 = json.loads(out2)
        tool_names = {t["name"] for t in res2["result"]["tools"]}
        assert EXPECTED_TOOLS.issubset(tool_names)
        assert len(tool_names) == 9
    finally:
        if mcp_proc.stdin:
            mcp_proc.stdin.close()
        if mcp_proc.stdout:
            mcp_proc.stdout.close()
        if mcp_proc.stderr:
            mcp_proc.stderr.close()
        try:
            mcp_proc.terminate()
            mcp_proc.wait(timeout=5)
        except Exception:
            mcp_proc.kill()

    # 2. Test REST bridge serves dashboard HTML
    port = 8799
    bridge_proc = subprocess.Popen(
        [str(venv_python), "-m", "pdpa_audit_mcp.api.bridge", "--port", str(port)],
        env={**os.environ, "PDPA_AUDIT_PORT": str(port)},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    try:
        # Wait for bridge to become ready
        ready = False
        for _ in range(30):
            try:
                r = httpx.get(f"http://127.0.0.1:{port}/health", timeout=1.0)
                if r.status_code == 200:
                    ready = True
                    break
            except Exception:
                time.sleep(0.2)

        assert ready, "Bridge failed to start in clean venv"

        # Verify dashboard is served
        dash_res = httpx.get(f"http://127.0.0.1:{port}/", timeout=2.0)
        assert dash_res.status_code == 200
        assert "text/html" in dash_res.headers["content-type"]
        assert '<meta name="bridge-token"' in dash_res.text
        assert "Personal Data Protection Act" in dash_res.text
    finally:
        if bridge_proc.stdout:
            bridge_proc.stdout.close()
        if bridge_proc.stderr:
            bridge_proc.stderr.close()
        bridge_proc.terminate()
        try:
            bridge_proc.wait(timeout=5)
        except Exception:
            bridge_proc.kill()
