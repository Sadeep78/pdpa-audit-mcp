"""REST API bridge and dashboard server for Sri Lanka PDPA readiness audits."""

from __future__ import annotations

import asyncio
import ipaddress
import os
import secrets
import sys
import traceback
from functools import wraps
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel
from starlette.types import ASGIApp, Receive, Scope, Send

from pdpa_audit_mcp.config import get_settings
from pdpa_audit_mcp.report import (
    generate_gap_report as _generate_gap_report,
)
from pdpa_audit_mcp.report import (
    list_checklist as _list_checklist,
)
from pdpa_audit_mcp.report import (
    run_full_audit as _run_full_audit,
)
from pdpa_audit_mcp.safety import (
    SecurityError,
    validate_input_path,
    validate_input_url,
)
from pdpa_audit_mcp.tools.breach_readiness import check_breach_readiness as _check_breach_readiness
from pdpa_audit_mcp.tools.cookie_consent import detect_cookie_consent as _detect_cookie_consent
from pdpa_audit_mcp.tools.forms import find_personal_data_forms as _find_personal_data_forms
from pdpa_audit_mcp.tools.privacy_policy import scan_privacy_policy as _scan_privacy_policy
from pdpa_audit_mcp.tools.project_scan import scan_project_files as _scan_project_files
from pdpa_audit_mcp.tools.transfers import (
    detect_third_party_transfers as _detect_third_party_transfers,
)

MAX_BODY_BYTES = 65_536  # 64 KB request body limit
ERR_CONCURRENT_AUDIT = "Another audit is currently in progress. Only one audit may run at a time."

# Generate per-run random security token for the bridge
BRIDGE_TOKEN: str = secrets.token_urlsafe(32)

# Single concurrent audit lock
_AUDIT_LOCK = asyncio.Lock()

DASHBOARD_PATH = Path(__file__).parent.parent / "dashboard" / "index.html"


def _is_loopback_host(host_str: str) -> bool:
    """Check if host string is a valid loopback host ('localhost', 127.0.0.1, ::1)."""
    h = host_str.strip().lower().strip("[]")
    if h == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(h)
        return ip.is_loopback
    except ValueError:
        return False


def verify_bind_host(host: str) -> None:
    """Refuse binding non-local hosts unless PDPA_BRIDGE_ALLOW_NON_LOCAL=true."""
    allow_non_local = os.getenv("PDPA_BRIDGE_ALLOW_NON_LOCAL", "false").strip().lower() in (
        "true",
        "1",
        "yes",
    )
    if not _is_loopback_host(host) and not allow_non_local:
        raise ValueError(
            f"Refusing to bind to non-local host '{host}'. "
            "Set PDPA_BRIDGE_ALLOW_NON_LOCAL=true to explicitly override."
        )


def _add_security_headers(response: Response, nonce: str) -> None:
    """Attach standard defensive HTTP headers and CSP nonce to all bridge responses."""
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        f"default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; "
        "connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; "
        "frame-ancestors 'none'"
    )


def _make_security_response(status_code: int, error_message: str, nonce: str) -> JSONResponse:
    """Create a JSON error response with full security headers attached."""
    resp = JSONResponse(
        status_code=status_code,
        content={"status": "error", "error_message": error_message},
    )
    _add_security_headers(resp, nonce)
    return resp


class BridgeSecurityMiddleware:
    """Pure ASGI middleware enforcing Host/Origin allowlists, token auth, and body limits."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        settings = get_settings()
        port = settings.port
        nonce = secrets.token_urlsafe(16)
        scope["csp_nonce"] = nonce

        headers_dict: dict[str, str] = {}
        for k, v in scope.get("headers", []):
            headers_dict[k.decode("latin-1").lower()] = v.decode("latin-1")

        # 1. Host header validation (blocks DNS rebinding)
        raw_host = headers_dict.get("host", "")
        host_clean = raw_host.lower().strip()
        allowed_hosts = {
            f"127.0.0.1:{port}",
            f"localhost:{port}",
            f"[::1]:{port}",
        }
        if host_clean not in allowed_hosts:
            resp = _make_security_response(421, f"Misdirected Host header: '{raw_host}'", nonce)
            await resp(scope, receive, send)
            return

        # 2. Origin header validation (same-origin only, no foreign cross-origin)
        origin = headers_dict.get("origin")
        if origin:
            origin_clean = origin.lower().strip()
            allowed_origins = {f"http://{h}" for h in allowed_hosts}
            if origin_clean not in allowed_origins:
                resp = _make_security_response(
                    403, f"Forbidden cross-origin request from '{origin}'.", nonce
                )
                await resp(scope, receive, send)
                return

        # 3. Token authentication (exempt /health and GET /)
        path = scope.get("path", "")
        method = scope.get("method", "")
        if path != "/health" and not (path == "/" and method == "GET"):
            token_hdr = headers_dict.get("x-bridge-token", "")
            token_bytes = token_hdr.encode("latin-1")
            bridge_bytes = BRIDGE_TOKEN.encode("utf-8")
            if not token_bytes or not secrets.compare_digest(token_bytes, bridge_bytes):
                resp = _make_security_response(
                    401, "Invalid or missing X-Bridge-Token header.", nonce
                )
                await resp(scope, receive, send)
                return

        # 4. POST Content-Type and Body size checks
        new_receive = receive
        if method == "POST":
            content_type = headers_dict.get("content-type", "").lower()
            if not content_type.startswith("application/json"):
                resp = _make_security_response(
                    415,
                    "Unsupported Media Type: Content-Type must be application/json.",
                    nonce,
                )
                await resp(scope, receive, send)
                return

            chunks: list[bytes] = []
            total_bytes = 0
            exceeded = False

            while True:
                message = await receive()
                if message["type"] == "http.request":
                    body_chunk = message.get("body", b"")
                    total_bytes += len(body_chunk)
                    if total_bytes > MAX_BODY_BYTES:
                        exceeded = True
                        break
                    chunks.append(body_chunk)
                    if not message.get("more_body", False):
                        break
                elif message["type"] == "http.disconnect":
                    return

            if exceeded:
                resp = _make_security_response(
                    413,
                    f"Payload Too Large: body exceeds {MAX_BODY_BYTES} byte limit.",
                    nonce,
                )
                await resp(scope, receive, send)
                return

            full_body = b"".join(chunks)
            has_sent_body = False

            async def buffered_receive() -> dict[str, Any]:
                nonlocal has_sent_body
                if not has_sent_body:
                    has_sent_body = True
                    return {"type": "http.request", "body": full_body, "more_body": False}
                return {"type": "http.request", "body": b"", "more_body": False}

            new_receive = buffered_receive

        response_started = False

        async def send_with_security_headers(message: dict[str, Any]) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
                raw_hdrs = list(message.get("headers", []))
                extra_hdrs = [
                    (b"cache-control", b"no-store"),
                    (b"x-content-type-options", b"nosniff"),
                    (b"referrer-policy", b"no-referrer"),
                    (
                        b"content-security-policy",
                        (
                            f"default-src 'none'; script-src 'nonce-{nonce}'; "
                            f"style-src 'nonce-{nonce}'; connect-src 'self'; "
                            "img-src 'self' data:; base-uri 'none'; form-action 'none'; "
                            "frame-ancestors 'none'"
                        ).encode("latin-1"),
                    ),
                ]
                existing_keys = {h[0].lower() for h in extra_hdrs}
                clean_hdrs = [h for h in raw_hdrs if h[0].lower() not in existing_keys]
                clean_hdrs.extend(extra_hdrs)
                message["headers"] = clean_hdrs
            await send(message)

        try:
            await self.app(scope, new_receive, send_with_security_headers)
        except Exception as exc:  # noqa: BLE001 - Deliberate bridge boundary for unhandled server exceptions
            sys.stderr.write(f"Unexpected bridge error in ASGI pipeline: {exc}\n")
            traceback.print_exc(file=sys.stderr)
            if not response_started:
                err_resp = _make_security_response(
                    500,
                    "An unexpected internal server error occurred.",
                    nonce,
                )
                await err_resp(scope, receive, send)


def with_audit_lock(func: Any) -> Any:
    """Decorator ensuring single-audit concurrency and centralized error handling."""

    @wraps(func)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        if _AUDIT_LOCK.locked():
            return JSONResponse(
                status_code=429,
                content={
                    "status": "error",
                    "error_message": ERR_CONCURRENT_AUDIT,
                },
            )
        async with _AUDIT_LOCK:
            try:
                result = await func(*args, **kwargs)
                if hasattr(result, "model_dump"):
                    return result.model_dump()
                return result
            except (SecurityError, ValueError) as exc:
                return {
                    "status": "error",
                    "error_message": str(exc),
                }
            except Exception as exc:  # noqa: BLE001 - Deliberate bridge boundary for unhandled tool exceptions
                sys.stderr.write(f"Unexpected bridge error in {func.__name__}: {exc}\n")
                traceback.print_exc(file=sys.stderr)
                return JSONResponse(
                    status_code=500,
                    content={
                        "status": "error",
                        "error_message": (
                            "An unexpected internal error occurred during audit execution."
                        ),
                    },
                )

    return wrapper


app = FastAPI(
    title="Sri Lanka PDPA Technical Audit Bridge",
    description="Local REST bridge for PDPA technical readiness audit tools",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
app.add_middleware(BridgeSecurityMiddleware)


# Input schemas
class UrlAuditRequest(BaseModel):
    url: str


class TargetAuditRequest(BaseModel):
    target: str


class PathAuditRequest(BaseModel):
    path: str


class TransfersAuditRequest(BaseModel):
    url: str
    policy_text: str | None = None


class FullAuditRequest(BaseModel):
    url: str | None = None
    project_path: str | None = None


class ReportFormatRequest(BaseModel):
    audit_result: dict[str, Any]
    format: Literal["markdown", "json"] = "markdown"


# Endpoints


@app.get("/health")
async def health_check() -> dict[str, str]:
    """Health check endpoint accessible without token."""
    return {"status": "ok", "service": "pdpa-audit-bridge"}


@app.get("/", response_class=HTMLResponse)
async def serve_dashboard(request: Request) -> HTMLResponse:
    """Serve the single-page vanilla JS audit dashboard with injected token and nonce."""
    nonce = request.scope.get("csp_nonce", secrets.token_urlsafe(16))
    if not DASHBOARD_PATH.exists():
        raise HTTPException(status_code=404, detail="Dashboard template not found.")

    raw_html = DASHBOARD_PATH.read_text(encoding="utf-8")
    rendered = raw_html.replace("__BRIDGE_TOKEN__", BRIDGE_TOKEN).replace("__CSP_NONCE__", nonce)
    return HTMLResponse(content=rendered, status_code=200)


@app.get("/checklist")
async def get_checklist(category: str | None = None) -> dict[str, Any]:
    """List PDPA readiness checklist rules."""
    res = _list_checklist(category=category)
    return res.model_dump()


@app.post("/audit/privacy-policy")
@with_audit_lock
async def audit_privacy_policy(req: UrlAuditRequest) -> Any:
    """Audit website privacy policy."""
    clean_url = validate_input_url(req.url)
    return await _scan_privacy_policy(clean_url)


@app.post("/audit/cookies")
@with_audit_lock
async def audit_cookies(req: UrlAuditRequest) -> Any:
    """Audit cookie consent banners and tracking scripts."""
    clean_url = validate_input_url(req.url)
    return await _detect_cookie_consent(clean_url)


@app.post("/audit/forms")
@with_audit_lock
async def audit_forms(req: TargetAuditRequest) -> Any:
    """Audit web forms for personal data handling."""
    is_url = req.target.startswith("http://") or req.target.startswith("https://")
    clean_target = validate_input_url(req.target) if is_url else validate_input_path(req.target)
    return await _find_personal_data_forms(clean_target)


@app.post("/audit/project")
@with_audit_lock
async def audit_project(req: PathAuditRequest) -> Any:
    """Scan local repository project files."""
    clean_path = validate_input_path(req.path)
    return await _scan_project_files(clean_path)


@app.post("/audit/breach")
@with_audit_lock
async def audit_breach(req: PathAuditRequest) -> Any:
    """Audit repository for breach response readiness."""
    clean_path = validate_input_path(req.path)
    return await _check_breach_readiness(clean_path)


@app.post("/audit/transfers")
@with_audit_lock
async def audit_transfers(req: TransfersAuditRequest) -> Any:
    """Detect third-party transfers and disclosures."""
    clean_url = validate_input_url(req.url)
    return await _detect_third_party_transfers(clean_url, policy_text=req.policy_text)


@app.post("/audit/full")
@with_audit_lock
async def audit_full(req: FullAuditRequest) -> Any:
    """Execute full technical readiness audit combining web and project checks."""
    return await _run_full_audit(url=req.url, project_path=req.project_path)


@app.post("/report")
async def generate_report_endpoint(req: ReportFormatRequest) -> Response:
    """Format audit results into structured Markdown or JSON report."""
    try:
        formatted = _generate_gap_report(req.audit_result, format=req.format)
        if req.format.lower() == "markdown":
            return PlainTextResponse(content=formatted, media_type="text/markdown")
        return Response(content=formatted, media_type="application/json")
    except (SecurityError, ValueError) as exc:
        return JSONResponse(
            status_code=400,
            content={"status": "error", "error_message": str(exc)},
        )
    except Exception as exc:  # noqa: BLE001 - Deliberate bridge boundary for unhandled report exceptions
        sys.stderr.write(f"Unexpected error formatting report: {exc}\n")
        traceback.print_exc(file=sys.stderr)
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "error_message": "An unexpected error occurred while generating the report.",
            },
        )


def main() -> None:
    """Run REST bridge server using uvicorn on local interface."""
    import uvicorn

    settings = get_settings()
    host = settings.host
    port = settings.port

    verify_bind_host(host)

    # Print security token to stderr at startup
    sys.stderr.write(
        f"\n====================================================================\n"
        f"[pdpa-audit-bridge] Security Token: {BRIDGE_TOKEN}\n"
        f"[pdpa-audit-bridge] Listening on http://{host}:{port}/\n"
        f"====================================================================\n\n"
    )
    sys.stderr.flush()

    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
