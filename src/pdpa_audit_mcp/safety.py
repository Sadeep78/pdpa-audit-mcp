"""Security guardrails: SSRF protection, path traversal protection, and data sanitization."""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import unicodedata
from pathlib import Path, PureWindowsPath
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpcore
import httpx

EXCLUDED_DIR_NAMES: set[str] = {
    "node_modules",
    ".git",
    "venv",
    ".venv",
    "dist",
    "build",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".egg-info",
}

MAX_FILE_BYTES: int = 1_048_576  # 1 MB
MAX_SNIPPET_LENGTH: int = 120

# Regex patterns for sanitizing personal data snippets
_EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
_NIC_REGEX = re.compile(r"\b(?:\d{9}[vVxX]|\d{12})\b")
_PHONE_REGEX = re.compile(r"(?<!\w)(?:\+94|0094|0)?(?:7\d{8}|[1-9]\d{7,9})\b")
_CARD_REGEX = re.compile(r"\b(?:\d{4}[ -]?){3}\d{1,4}\b")


class SecurityError(Exception):
    """Raised when an operation breaches SSRF or path traversal constraints."""


def is_unc_path(path_input: str | Path) -> bool:
    """Check if a path string or Path object is a Windows UNC network path."""
    if not path_input:
        return False
    s = str(path_input).strip()
    if s.startswith(("\\\\", "//", "\\??\\UNC", "\\\\?\\UNC")):
        return True
    try:
        if PureWindowsPath(s).drive.startswith(("\\\\", "//")):
            return True
    except (ValueError, TypeError):
        pass
    return False


def _parse_c_style_int(s: str) -> int:
    """Parse integer literal supporting C-style decimal, hex (0x), and octal (0) formats."""
    s = s.strip()
    if s.startswith(("0x", "0X")):
        return int(s, 16)
    if s.startswith(("0o", "0O")):
        return int(s, 8)
    if s.startswith("0") and len(s) > 1 and s.isdigit():
        return int(s, 8)
    return int(s, 10)


def parse_alternative_ipv4(host: str) -> ipaddress.IPv4Address | None:
    """Parse alternative IPv4 formats (decimal integer, hex, octal, dotted 1-4 parts)."""
    if not host:
        return None
    h = host.strip("[]").strip()
    try:
        return ipaddress.IPv4Address(h)
    except ValueError:
        pass

    parts = h.split(".")
    if 1 <= len(parts) <= 4:
        try:
            parsed_parts = [_parse_c_style_int(p) for p in parts]
        except (ValueError, OverflowError):
            return None

        if len(parsed_parts) == 4:
            if all(0 <= p <= 255 for p in parsed_parts):
                val = (
                    (parsed_parts[0] << 24)
                    | (parsed_parts[1] << 16)
                    | (parsed_parts[2] << 8)
                    | parsed_parts[3]
                )
                return ipaddress.IPv4Address(val)
        elif len(parsed_parts) == 1:
            if 0 <= parsed_parts[0] <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(parsed_parts[0])
        elif len(parsed_parts) == 2:
            if (0 <= parsed_parts[0] <= 255) and (0 <= parsed_parts[1] <= 0xFFFFFF):
                val = (parsed_parts[0] << 24) | parsed_parts[1]
                return ipaddress.IPv4Address(val)
        elif len(parsed_parts) == 3:
            if (
                (0 <= parsed_parts[0] <= 255)
                and (0 <= parsed_parts[1] <= 255)
                and (0 <= parsed_parts[2] <= 0xFFFF)
            ):
                val = (parsed_parts[0] << 24) | (parsed_parts[1] << 16) | parsed_parts[2]
                return ipaddress.IPv4Address(val)
    return None


def is_ip_private_or_restricted(ip_str: str) -> bool:
    """Check whether an IP address belongs to private, loopback, link-local, or metadata ranges."""
    try:
        ip = ipaddress.ip_address(ip_str.strip("[]").strip())
    except ValueError:
        # Check alternative IPv4 formats (decimal, hex, octal)
        alt_ip = parse_alternative_ipv4(ip_str)
        if alt_ip is not None:
            ip = alt_ip
        else:
            return True  # If unparseable as IP, treat as unsafe

    # IPv6-mapped IPv4, NAT64, and 6to4 embedded IPv4 extraction
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        elif ip in ipaddress.ip_network("64:ff9b::/96"):
            ip = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
        elif ip in ipaddress.ip_network("2002::/16"):
            ip = ipaddress.IPv4Address((int(ip) >> 80) & 0xFFFFFFFF)

    # Allowlist-style check: any non-global address is restricted
    if not ip.is_global:
        return True

    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    ):
        return True

    restricted_networks = [
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("169.254.0.0/16"),
        ipaddress.ip_network("0.0.0.0/8"),
        ipaddress.ip_network("::1/128"),
        ipaddress.ip_network("fc00::/7"),
        ipaddress.ip_network("fe80::/10"),
    ]

    for net in restricted_networks:
        if ip in net:
            return True

    return False


def validate_url(
    url: str,
    allow_private: bool = False,
) -> tuple[bool, str | None, str | None]:
    """Validate a URL against SSRF rules:

    - Only http/https schemes allowed.
    - Embedded userinfo / credentials in authority are blocked.
    - Alternative IP representations (decimal, hex, octal) are normalized and checked.
    - Resolves hostname and blocks private, loopback, link-local, and metadata IP ranges
      unless allow_private is True.
    Returns: (is_valid, error_message, resolved_ip)
    """
    if not url or not isinstance(url, str):
        return False, "Target URL must be a non-empty string.", None

    url = url.strip()
    try:
        parsed = urlsplit(url)
    except ValueError as exc:
        return False, f"Failed to parse URL: {exc}", None

    if parsed.scheme.lower() not in ("http", "https"):
        return (
            False,
            f"Invalid scheme '{parsed.scheme}'. Only 'http' and 'https' are allowed.",
            None,
        )

    # Block userinfo tricks (e.g. http://example.com@127.0.0.1 or http://user:pass@host)
    if parsed.username or parsed.password or ("@" in (parsed.netloc or "")):
        return (
            False,
            "URLs containing embedded credentials/userinfo are not permitted.",
            None,
        )

    hostname = parsed.hostname
    if not hostname:
        return False, "URL must contain a valid hostname.", None

    # Handle alternative IP formats (decimal, hex, octal)
    alt_ip = parse_alternative_ipv4(hostname)
    if alt_ip is not None:
        ip_str = str(alt_ip)
        if not allow_private and is_ip_private_or_restricted(ip_str):
            return (
                False,
                f"Access to private/restricted IP address '{hostname}' ({ip_str}) is blocked.",
                None,
            )
        return True, None, ip_str

    # Direct IP address check (standard IPv4 / IPv6)
    try:
        ip = ipaddress.ip_address(hostname.strip("[]"))
        ip_str = str(ip)
        if not allow_private and is_ip_private_or_restricted(ip_str):
            return False, f"Access to private/restricted IP address '{hostname}' is blocked.", None
        return True, None, ip_str
    except ValueError:
        pass  # It is a domain name, resolve below

    # Handle 'localhost'
    if hostname.lower() == "localhost":
        if not allow_private:
            return (
                False,
                "Access to 'localhost' is blocked (set PDPA_AUDIT_ALLOW_PRIVATE=true to allow).",
                None,
            )
        return True, None, "127.0.0.1"

    # Resolve hostname via DNS
    try:
        addr_infos = socket.getaddrinfo(
            hostname, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
        )
    except (socket.gaierror, socket.herror, OSError) as exc:
        return False, f"DNS resolution failed for hostname '{hostname}': {exc}", None

    if not addr_infos:
        return False, f"No IP addresses resolved for hostname '{hostname}'.", None

    resolved_ips: list[str] = []
    for info in addr_infos:
        ip_addr = info[4][0]
        resolved_ips.append(ip_addr)
        if not allow_private and is_ip_private_or_restricted(ip_addr):
            return (
                False,
                f"Hostname '{hostname}' resolved to private IP '{ip_addr}', which is blocked.",
                None,
            )

    # Return primary safe resolved IP for connection pinning
    return True, None, resolved_ips[0]


def validate_redirect(
    current_url: str,
    location_header: str,
    redirect_count: int,
    max_redirects: int = 3,
    allow_private: bool = False,
) -> tuple[bool, str | None, str | None, str | None]:
    """Validate an HTTP redirect destination against SSRF rules and redirect limits.

    Returns: (is_valid, error_message, target_url, resolved_ip)
    """
    if redirect_count >= max_redirects:
        return (
            False,
            f"Redirect limit exceeded ({max_redirects} redirects maximum).",
            None,
            None,
        )

    if not location_header:
        return False, "Empty Location header in redirect.", None, None

    target_url = urljoin(current_url, location_header.strip())
    valid, err, ip = validate_url(target_url, allow_private=allow_private)
    if not valid:
        return False, f"Redirect to unsafe destination blocked: {err}", None, None

    return True, None, target_url, ip


class SSRFProtectedBackend(httpcore.AnyIOBackend):
    """Network backend that connects strictly to pre-validated IP addresses,

    preventing DNS rebinding (TOCTOU) attacks.
    """

    def __init__(self, pinned_ips: dict[str, str] | None = None, allow_private: bool = False):
        self.pinned_ips = dict(pinned_ips or {})
        self.allow_private = allow_private

    def pin_host(self, host: str, ip: str) -> None:
        self.pinned_ips[host] = ip

    async def connect_tcp(
        self,
        host: str,
        port: int,
        *args: Any,
        **kwargs: Any,
    ) -> httpcore.AsyncNetworkStream:
        target_ip = self.pinned_ips.get(host)
        if target_ip is None:
            loop = asyncio.get_running_loop()
            try:
                addr_infos = await loop.getaddrinfo(
                    host, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
                )
            except (socket.gaierror, socket.herror, OSError) as exc:
                raise SecurityError(f"DNS resolution failed for '{host}': {exc}") from exc

            if not addr_infos:
                raise SecurityError(f"No IP addresses resolved for '{host}'")

            resolved_ip = addr_infos[0][4][0]
            if not self.allow_private and is_ip_private_or_restricted(resolved_ip):
                raise SecurityError(
                    f"SSRF guard blocked connection: '{host}' resolved to private IP "
                    f"'{resolved_ip}'"
                )
            target_ip = resolved_ip
            self.pinned_ips[host] = target_ip

        # Connect directly to target_ip while TLS SNI and HTTP Host header retain host
        return await super().connect_tcp(target_ip, port, *args, **kwargs)


class SSRFProtectedTransport(httpx.AsyncHTTPTransport):
    """HTTPX Async Transport with DNS-rebinding protection and SSRF enforcement."""

    def __init__(
        self,
        pinned_ips: dict[str, str] | None = None,
        allow_private: bool = False,
        **kwargs: Any,
    ):
        super().__init__(**kwargs)
        self.backend = SSRFProtectedBackend(pinned_ips=pinned_ips, allow_private=allow_private)
        self._pool = httpcore.AsyncConnectionPool(
            network_backend=self.backend,
            ssl_context=self._pool._ssl_context,
            retries=0,
        )

    def pin_host(self, host: str, ip: str) -> None:
        self.backend.pin_host(host, ip)


def validate_input_url(url: Any) -> str:
    """Validate tool input URL: must be string, <= 2048 chars, no control characters."""
    if not isinstance(url, str):
        raise ValueError(f"URL must be a string, got {type(url).__name__}")
    if len(url) > 2048:
        raise ValueError("URL exceeds maximum length of 2048 characters.")
    if any(ord(c) < 32 or (127 <= ord(c) <= 159) for c in url):
        raise ValueError("URL contains prohibited control characters.")
    return url.strip()


def validate_input_path(path: Any) -> str:
    """Validate tool input path: must be string, no control characters."""
    if not isinstance(path, (str, Path)):
        raise ValueError(f"Path must be a string or Path, got {type(path).__name__}")
    path_str = str(path)
    if any(ord(c) < 32 or (127 <= ord(c) <= 159) for c in path_str):
        raise ValueError("Path contains prohibited control characters.")
    return path_str.strip()


def validate_project_path(path_str: str | Path) -> Path:
    """Validate and resolve a project directory path.

    Blocks Windows UNC paths, non-existent directories, non-directory targets,
    and enforces PDPA_AUDIT_ALLOWED_ROOTS when configured.
    """
    if not path_str:
        raise ValueError("Project path must not be empty.")

    validate_input_path(path_str)

    if is_unc_path(path_str):
        raise ValueError(f"UNC network paths are not permitted: '{path_str}'")

    p = Path(path_str).resolve()
    if not p.exists():
        raise ValueError(f"Project path does not exist: {p}")
    if not p.is_dir():
        raise ValueError(f"Project path is not a directory: {p}")

    # Check PDPA_AUDIT_ALLOWED_ROOTS
    from pdpa_audit_mcp.config import get_settings

    allowed_roots = get_settings().allowed_roots
    resolved_p = p.resolve()

    if allowed_roots:
        is_allowed = False
        for root in allowed_roots:
            try:
                resolved_root = Path(root).resolve()
                if resolved_p.is_relative_to(resolved_root):
                    is_allowed = True
                    break
            except (ValueError, OSError):
                continue
        if not is_allowed:
            raise SecurityError(
                f"Access to path '{p}' is not permitted by PDPA_AUDIT_ALLOWED_ROOTS."
            )
    else:
        # When unset, defaults to current working directory
        cwd = Path.cwd().resolve()
        if not resolved_p.is_relative_to(cwd):
            raise SecurityError(
                f"Access to path '{p}' is outside the working directory. "
                "Set PDPA_AUDIT_ALLOWED_ROOTS to the folder that contains your project."
            )

    return p


def is_safe_file_path(base_dir: Path, target_path: Path) -> bool:
    """Ensure target_path is strictly within base_dir, does not escape via symlinks or junctions,

    does not cross drives, is not a UNC path, and does not enter excluded directories.
    """
    try:
        if is_unc_path(base_dir) or is_unc_path(target_path):
            return False

        resolved_base = Path(base_dir).resolve()
        resolved_target = Path(target_path).resolve()

        # Check drive matching (Windows different drive letters)
        if resolved_target.drive.lower() != resolved_base.drive.lower():
            return False

        # Check path containment (prevents prefix confusion and directory traversal)
        if not resolved_target.is_relative_to(resolved_base):
            return False

        # Check parent folder components for excluded directories or .egg-info
        rel_parts = resolved_target.relative_to(resolved_base).parts
        for part in rel_parts:
            if part in EXCLUDED_DIR_NAMES or part.endswith(".egg-info"):
                return False

        # If the target file itself is a symlink, verify its resolved destination
        if target_path.is_symlink():
            link_target = target_path.resolve()
            if not link_target.is_relative_to(resolved_base):
                return False

        return True
    except (ValueError, RuntimeError):
        return False


def is_safe_file_size(file_path: Path, max_bytes: int = MAX_FILE_BYTES) -> bool:
    """Check if file size does not exceed the allowed maximum."""
    try:
        return file_path.stat().st_size <= max_bytes
    except (OSError, ValueError):
        return False


def normalize_text(text: str) -> str:
    """Normalize text: Unicode NFC, lowercasing, whitespace collapse, and zero-width stripping."""
    if not text:
        return ""
    norm = unicodedata.normalize("NFC", text).lower()
    for zw in ("\u200b", "\u200c", "\u200d"):
        norm = norm.replace(zw, "")
    return " ".join(norm.split())


def sanitize_evidence_snippet(text: str, max_chars: int = MAX_SNIPPET_LENGTH) -> str:
    """Normalize whitespace, strip control/zero-width chars, redact PII, truncate."""
    if not text:
        return ""

    # Strip control characters (ord < 32 or 127..159) and zero-width chars
    clean_chars: list[str] = []
    for c in text:
        code = ord(c)
        if code < 32 or (127 <= code <= 159):
            clean_chars.append(" ")
        elif c in ("\u200b", "\u200c", "\u200d", "\ufeff"):
            continue
        else:
            clean_chars.append(c)

    cleaned = "".join(clean_chars)
    normalized = " ".join(cleaned.split())

    sanitized = _EMAIL_REGEX.sub("[EMAIL]", normalized)
    sanitized = _NIC_REGEX.sub("[NIC]", sanitized)
    sanitized = _PHONE_REGEX.sub("[PHONE]", sanitized)
    sanitized = _CARD_REGEX.sub("[CARD]", sanitized)

    if len(sanitized) > max_chars:
        cutoff = max_chars - 3
        last_space = sanitized.rfind(" ", 0, cutoff)
        if last_space > (cutoff // 2):
            return sanitized[:last_space].rstrip() + "..."
        return sanitized[:cutoff] + "..."
    return sanitized


def extract_centered_snippet(
    text: str,
    match_start: int,
    match_end: int,
    target_len: int = MAX_SNIPPET_LENGTH,
) -> str:
    """Extract a sanitized snippet centered around a match window with clean word boundaries.

    Ensures no mid-word cuts and stays within target_len.
    """
    if not text:
        return ""

    text_len = len(text)
    if text_len <= target_len:
        return sanitize_evidence_snippet(text, max_chars=target_len)

    match_start = max(0, min(match_start, text_len))
    match_end = max(match_start, min(match_end, text_len))
    center = (match_start + match_end) // 2

    half = target_len // 2
    raw_start = max(0, center - half)
    raw_end = min(text_len, center + half)

    if raw_start == 0:
        raw_end = min(text_len, target_len)
    elif raw_end == text_len:
        raw_start = max(0, text_len - target_len)

    # Snap inward to nearest whitespace to avoid mid-word cuts
    start = raw_start
    if start > 0:
        space_after = text.find(" ", start)
        if space_after != -1 and space_after < match_start:
            start = space_after + 1
        else:
            space_before = text.rfind(" ", 0, start)
            if space_before != -1:
                start = space_before + 1

    end = raw_end
    if end < text_len:
        space_before = text.rfind(" ", start, end)
        if space_before != -1 and space_before > match_end:
            end = space_before
        else:
            space_after = text.find(" ", end)
            if space_after != -1 and (space_after - start) <= target_len + 10:
                end = space_after

    snippet = text[start:end].strip()
    prefix = "... " if start > 0 else ""
    suffix = " ..." if end < text_len else ""
    full_snippet = f"{prefix}{snippet}{suffix}"

    return sanitize_evidence_snippet(full_snippet, max_chars=target_len)
