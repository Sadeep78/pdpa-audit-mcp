"""Configuration handling and system constants for pdpa-audit-mcp."""

from __future__ import annotations

import os
from dataclasses import dataclass

LEGAL_DISCLAIMER: str = (
    "LEGAL DISCLAIMER: This tool provides technical readiness indicators and gap analysis only. "
    "It does NOT constitute legal advice or certify legal compliance with Sri Lanka's "
    "Personal Data Protection Act, No. 9 of 2022 (PDPA). Organizations must verify all legal "
    "references against the official Act (dpa.gov.lk) and consult qualified legal counsel."
)

DEFENSIVE_USE_NOTICE: str = (
    "Defensive use only. Use this tool only on websites, endpoints, or local projects that you own "
    "or have explicit written authorization to audit."
)

LEGAL_REF_PENDING: str = "legal reference: to be verified"


def _get_bool(key: str, default: bool = False) -> bool:
    val = os.getenv(key)
    if val is None:
        return default
    return val.strip().lower() in ("true", "1", "yes", "on")


def _get_float(key: str, default: float) -> float:
    val = os.getenv(key)
    if val is None:
        return default
    try:
        return float(val.strip())
    except ValueError:
        return default


def _get_int(key: str, default: int) -> int:
    val = os.getenv(key)
    if val is None:
        return default
    try:
        return int(val.strip())
    except ValueError:
        return default


def _get_allowed_roots() -> tuple[str, ...]:
    val = os.getenv("PDPA_AUDIT_ALLOWED_ROOTS")
    if not val:
        return ()
    return tuple(r.strip() for r in val.split(os.pathsep) if r.strip())


@dataclass(frozen=True)
class Settings:
    allow_private: bool = _get_bool("PDPA_AUDIT_ALLOW_PRIVATE", default=False)
    timeout_seconds: float = _get_float("PDPA_AUDIT_TIMEOUT_SECONDS", default=10.0)
    max_response_bytes: int = _get_int("PDPA_AUDIT_MAX_RESPONSE_BYTES", default=1_048_576)
    max_redirects: int = _get_int("PDPA_AUDIT_MAX_REDIRECTS", default=3)
    max_crawl_pages: int = _get_int("PDPA_AUDIT_MAX_CRAWL_PAGES", default=10)
    fetch_deadline_seconds: float = _get_float("PDPA_AUDIT_FETCH_DEADLINE_SECONDS", default=20.0)
    user_agent: str = os.getenv("PDPA_AUDIT_USER_AGENT", "pdpa-audit-mcp/0.1 (+self-audit)")
    host: str = os.getenv("PDPA_AUDIT_HOST", "127.0.0.1")
    port: int = _get_int("PDPA_AUDIT_PORT", default=8765)
    allowed_roots: tuple[str, ...] = _get_allowed_roots()


def get_settings() -> Settings:
    """Return the current runtime settings (reading fresh environment variables)."""
    return Settings(
        allow_private=_get_bool("PDPA_AUDIT_ALLOW_PRIVATE", default=False),
        timeout_seconds=_get_float("PDPA_AUDIT_TIMEOUT_SECONDS", default=10.0),
        max_response_bytes=_get_int("PDPA_AUDIT_MAX_RESPONSE_BYTES", default=1_048_576),
        max_redirects=_get_int("PDPA_AUDIT_MAX_REDIRECTS", default=3),
        max_crawl_pages=_get_int("PDPA_AUDIT_MAX_CRAWL_PAGES", default=10),
        fetch_deadline_seconds=_get_float("PDPA_AUDIT_FETCH_DEADLINE_SECONDS", default=20.0),
        user_agent=os.getenv("PDPA_AUDIT_USER_AGENT", "pdpa-audit-mcp/0.1 (+self-audit)"),
        host=os.getenv("PDPA_AUDIT_HOST", "127.0.0.1"),
        port=_get_int("PDPA_AUDIT_PORT", default=8765),
        allowed_roots=_get_allowed_roots(),
    )
