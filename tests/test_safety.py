"""Unit tests for safety guardrails: SSRF protection, path validation, and data sanitization."""

import socket
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpcore
import pytest

from pdpa_audit_mcp.safety import (
    SSRFProtectedTransport,
    is_ip_private_or_restricted,
    is_safe_file_path,
    is_safe_file_size,
    is_unc_path,
    parse_alternative_ipv4,
    sanitize_evidence_snippet,
    validate_project_path,
    validate_redirect,
    validate_url,
)


class TestIPVerification:
    """Tests for private, loopback, and restricted IP detection."""

    @pytest.mark.parametrize(
        "ip_str",
        [
            "127.0.0.1",
            "127.0.0.2",
            "10.0.0.1",
            "10.255.255.255",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.0.1",
            "192.168.1.100",
            "169.254.169.254",  # AWS/Cloud metadata
            "169.254.1.1",  # Link-local
            "0.0.0.0",
            "::1",  # IPv6 loopback
            "fc00::1",  # IPv6 ULA
            "fd00::1234",  # IPv6 ULA
            "fe80::1",  # IPv6 link-local
            "::ffff:127.0.0.1",  # IPv6 mapped IPv4 loopback
            "::ffff:10.0.0.1",  # IPv6 mapped IPv4 private
            "::ffff:7f00:1",  # IPv6 mapped IPv4 hex loopback
            "::ffff:169.254.169.254",  # IPv6 mapped IPv4 metadata
            "100.64.0.1",  # CGNAT (RFC 6598)
            "100.100.100.200",  # CGNAT (RFC 6598)
            "198.18.0.1",  # Benchmark network (RFC 2544)
            "192.0.0.1",  # IETF Protocol Assignments (RFC 6890)
            "64:ff9b::7f00:1",  # NAT64 embedded loopback
            "2002:7f00:1::",  # 6to4 embedded loopback
        ],
    )
    def test_restricted_ips_blocked(self, ip_str: str):
        assert is_ip_private_or_restricted(ip_str) is True

    @pytest.mark.parametrize(
        "ip_str",
        [
            "8.8.8.8",
            "1.1.1.1",
            "93.184.216.34",
            "2606:4700:4700::1111",
            "::ffff:8.8.8.8",
        ],
    )
    def test_public_ips_allowed(self, ip_str: str):
        assert is_ip_private_or_restricted(ip_str) is False


class TestURLValidation:
    """Tests for URL scheme and SSRF guard validation."""

    def test_empty_or_invalid_url(self):
        valid, err, ip = validate_url("")
        assert valid is False
        assert "non-empty string" in err

    @pytest.mark.parametrize(
        "bad_url",
        [
            "ftp://example.com/file.txt",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "data:text/html;base64,PHNjcmlwdD4=",
            "gopher://127.0.0.1:70",
        ],
    )
    def test_invalid_schemes_blocked(self, bad_url: str):
        valid, err, ip = validate_url(bad_url)
        assert valid is False
        assert "Invalid scheme" in err

    def test_private_ip_url_blocked_by_default(self):
        valid, err, ip = validate_url("http://127.0.0.1:8080/dashboard")
        assert valid is False
        assert "blocked" in err

        valid, err, ip = validate_url("http://169.254.169.254/latest/meta-data")
        assert valid is False
        assert "blocked" in err

        valid, err, ip = validate_url("http://0.0.0.0:8000")
        assert valid is False
        assert "blocked" in err

    def test_ipv4_mapped_ipv6_url_blocked(self):
        valid, err, ip = validate_url("http://[::ffff:127.0.0.1]/status")
        assert valid is False
        assert "blocked" in err

        valid, err, ip = validate_url("http://[::ffff:169.254.169.254]/latest")
        assert valid is False
        assert "blocked" in err

        valid, err, ip = validate_url("http://[64:ff9b::7f00:1]/status")
        assert valid is False
        assert "blocked" in err

        valid, err, ip = validate_url("http://[2002:7f00:1::]/status")
        assert valid is False
        assert "blocked" in err

    def test_private_ip_url_allowed_with_flag(self):
        valid, err, ip = validate_url("http://127.0.0.1:8080/dashboard", allow_private=True)
        assert valid is True
        assert err is None
        assert ip == "127.0.0.1"

    def test_localhost_blocked_by_default(self):
        valid, err, ip = validate_url("http://localhost:3000/app")
        assert valid is False
        assert "localhost" in err

    def test_localhost_allowed_with_flag(self):
        valid, err, ip = validate_url("http://localhost:3000/app", allow_private=True)
        assert valid is True
        assert err is None

    def test_dns_resolving_to_private_ip_blocked(self):
        with patch("socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.55", 80))
            ]
            valid, err, ip = validate_url("http://internal-portal.example.org")
            assert valid is False
            assert "blocked" in err

    def test_dns_resolving_to_public_ip_allowed(self):
        with patch("socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))
            ]
            valid, err, ip = validate_url("https://example.com")
            assert valid is True
            assert err is None
            assert ip == "93.184.216.34"


class TestAlternativeIPForms:
    """Tests for decimal, hex, and octal integer IP representations."""

    @pytest.mark.parametrize(
        ("host_str", "expected_ip"),
        [
            ("2130706433", "127.0.0.1"),  # Decimal 32-bit int
            ("0x7f000001", "127.0.0.1"),  # Hex 32-bit int
            ("0177.0.0.1", "127.0.0.1"),  # Octal first octet
            ("0x7f.0.0.1", "127.0.0.1"),  # Hex first octet
            ("0x7f.1", "127.0.0.1"),  # Hex 2-part BSD socket style
            ("127.1", "127.0.0.1"),  # Decimal 2-part BSD style
            ("017700000001", "127.0.0.1"),  # Octal 32-bit int
            ("2886729729", "172.16.0.1"),  # Decimal private
            ("3232235521", "192.168.0.1"),  # Decimal private
            ("2852039166", "169.254.169.254"),  # Decimal cloud metadata
        ],
    )
    def test_parse_alternative_ipv4(self, host_str: str, expected_ip: str):
        parsed = parse_alternative_ipv4(host_str)
        assert parsed is not None
        assert str(parsed) == expected_ip

    @pytest.mark.parametrize(
        "bad_url",
        [
            "http://2130706433/admin",
            "http://0x7f000001/status",
            "http://0177.0.0.1/console",
            "http://0x7f.1/",
            "http://017700000001/",
            "http://2852039166/latest/meta-data",
        ],
    )
    def test_alternative_ip_urls_blocked(self, bad_url: str):
        valid, err, ip = validate_url(bad_url)
        assert valid is False
        assert "blocked" in err


class TestUserinfoGuard:
    """Tests preventing userinfo / credential bypass tricks in URLs."""

    def test_userinfo_targeting_private_ip_blocked(self):
        # http://example.com@127.0.0.1 has hostname 127.0.0.1
        valid, err, ip = validate_url("http://example.com@127.0.0.1")
        assert valid is False
        assert "blocked" in err or "credentials" in err

    def test_embedded_credentials_blocked(self):
        valid, err, ip = validate_url("http://user:secret@127.0.0.1:8080/path")
        assert valid is False
        assert "blocked" in err or "credentials" in err

        # Even with public domain, userinfo in audit target should be rejected
        valid, err, ip = validate_url("http://admin:secret@example.com")
        assert valid is False
        assert "credentials" in err


class TestRedirectValidation:
    """Tests for re-validating redirect destinations and redirect limits."""

    def test_redirect_to_private_ip_blocked(self):
        valid, err, target, ip = validate_redirect(
            current_url="https://example.com/login",
            location_header="http://169.254.169.254/latest/meta-data",
            redirect_count=1,
            max_redirects=3,
        )
        assert valid is False
        assert "blocked" in err

    def test_redirect_exceeding_max_limit_blocked(self):
        valid, err, target, ip = validate_redirect(
            current_url="https://example.com/step3",
            location_header="https://example.com/step4",
            redirect_count=3,
            max_redirects=3,
        )
        assert valid is False
        assert "limit exceeded" in err

    def test_relative_redirect_to_safe_url_allowed(self):
        with patch("socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
            ]
            valid, err, target, ip = validate_redirect(
                current_url="https://example.com/old-page",
                location_header="/new-page",
                redirect_count=0,
                max_redirects=3,
            )
            assert valid is True
            assert err is None
            assert target == "https://example.com/new-page"
            assert ip == "93.184.216.34"


class TestDNSRebindingProtection:
    """Tests guaranteeing that connections pin the validated IP against rebinding."""

    def test_transport_replaces_pool_with_ssrf_backend(self):
        import httpcore

        transport = SSRFProtectedTransport()
        assert isinstance(transport.backend, httpcore.AnyIOBackend)
        assert transport._pool._network_backend is transport.backend

    @pytest.mark.asyncio
    async def test_ssrf_transport_pins_validated_ip(self):
        transport = SSRFProtectedTransport(pinned_ips={"example.com": "93.184.216.34"})
        assert transport.backend.pinned_ips["example.com"] == "93.184.216.34"

        # Dynamically pinning a host
        transport.pin_host("audit-target.lk", "198.51.100.1")
        assert transport.backend.pinned_ips["audit-target.lk"] == "198.51.100.1"

    @pytest.mark.asyncio
    async def test_dns_rebinding_simulation_pins_connection(self):
        """Truly simulate DNS rebinding: DNS returns public IP on call 1 and 127.0.0.1 later.

        Assert the connection goes to the public IP and no second resolution occurs.
        """
        call_count = 0

        def rebinding_dns(host, port, *args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))]
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80))]

        with patch("socket.getaddrinfo", side_effect=rebinding_dns):
            valid, err, pinned_ip = validate_url("http://rebinding-target.com")
            assert valid is True
            assert pinned_ip == "93.184.216.34"
            assert call_count == 1

            transport = SSRFProtectedTransport(pinned_ips={"rebinding-target.com": pinned_ip})

            with patch.object(
                httpcore.AnyIOBackend, "connect_tcp", new_callable=AsyncMock
            ) as mock_connect:
                mock_connect.return_value = MagicMock()
                await transport.backend.connect_tcp("rebinding-target.com", 80)

                mock_connect.assert_awaited_once_with("93.184.216.34", 80)
                assert call_count == 1


class TestWindowsPathGuard:
    """Tests for Windows-specific path guard: UNC paths, drive letters, symlinks,

    casing, and prefix confusion.
    """

    def test_unc_paths_detected(self):
        assert is_unc_path(r"\\attacker.com\share") is True
        assert is_unc_path("//attacker.com/share") is True
        assert is_unc_path(r"\\192.168.1.1\c$") is True
        assert is_unc_path("C:/project/src") is False
        assert is_unc_path(r"C:\project\src") is False

    def test_validate_project_path_rejects_unc(self):
        with pytest.raises(ValueError, match="UNC network paths are not permitted"):
            validate_project_path(r"\\evil-server\share")

        with pytest.raises(ValueError, match="UNC network paths are not permitted"):
            validate_project_path("//evil-server/share")

    def test_is_safe_file_path_rejects_unc(self, tmp_path: Path):
        assert is_safe_file_path(tmp_path, Path(r"\\evil-server\share\file.txt")) is False

    def test_is_safe_file_path_different_drive(self, tmp_path: Path):
        target = Path("D:/secret_data/credentials.txt")
        assert is_safe_file_path(tmp_path, target) is False

    def test_prefix_confusion_rejected(self, tmp_path: Path):
        # Base dir is tmp_path / "proj"
        base_dir = tmp_path / "proj"
        base_dir.mkdir()
        # Evil dir is tmp_path / "proj-evil" (starts with string "proj")
        evil_dir = tmp_path / "proj-evil"
        evil_dir.mkdir()
        evil_file = evil_dir / "secret.txt"
        evil_file.write_text("compromised")

        # Must reject evil_file even though str(evil_file) starts with str(base_dir)
        assert is_safe_file_path(base_dir, evil_file) is False

    def test_mixed_slashes_and_case_differences(self, tmp_path: Path):
        sub_dir = tmp_path / "SubFolder"
        sub_dir.mkdir()
        test_file = sub_dir / "TestFile.html"
        test_file.write_text("<p>Hello</p>")

        mixed_path = Path(str(tmp_path).lower() + "/subfolder\\testfile.html")
        assert is_safe_file_path(tmp_path, mixed_path) is True

    @pytest.mark.skipif(sys.platform != "win32", reason="NTFS directory junctions are Windows-only")
    def test_junction_escaping_root_rejected(self, tmp_path: Path):
        """Test Windows NTFS directory junction escaping root without requiring admin rights."""
        import _winapi

        base_dir = tmp_path / "project"
        base_dir.mkdir()
        outside_dir = tmp_path / "outside_dir"
        outside_dir.mkdir()
        secret_file = outside_dir / "secret.env"
        secret_file.write_text("DATABASE_URL=postgres://...")

        junction_inside_base = base_dir / "junction_escape"
        try:
            _winapi.CreateJunction(str(outside_dir), str(junction_inside_base))
        except (AttributeError, OSError) as exc:
            pytest.skip(f"NTFS Junctions not supported on this platform: {exc}")

        target_file = junction_inside_base / "secret.env"
        assert is_safe_file_path(base_dir, target_file) is False

    def test_symlink_escaping_mocked(self, tmp_path: Path):
        from unittest.mock import MagicMock

        base_dir = tmp_path / "project"
        base_dir.mkdir()
        mock_symlink = MagicMock(spec=Path)
        mock_symlink.is_symlink.return_value = True
        mock_symlink.resolve.return_value = Path("C:/Windows/System32/cmd.exe")

        assert is_safe_file_path(base_dir, mock_symlink) is False

    def test_symlink_escaping_root_rejected(self, tmp_path: Path):
        outside_dir = tmp_path / "outside"
        outside_dir.mkdir()
        outside_file = outside_dir / "sensitive.env"
        outside_file.write_text("API_KEY=12345")

        project_dir = tmp_path / "my_project"
        project_dir.mkdir()

        symlink_target = project_dir / "link_to_outside.env"
        try:
            symlink_target.symlink_to(outside_file)
        except (OSError, NotImplementedError):
            pytest.skip("Symlink creation requires privileges on this OS")

        assert is_safe_file_path(project_dir, symlink_target) is False

    def test_validate_project_path_nonexistent(self, tmp_path: Path):
        nonexistent = tmp_path / "does_not_exist"
        with pytest.raises(ValueError, match="does not exist"):
            validate_project_path(nonexistent)

    def test_validate_project_path_file_instead_of_dir(self, tmp_path: Path):
        file_path = tmp_path / "file.txt"
        file_path.write_text("sample")
        with pytest.raises(ValueError, match="not a directory"):
            validate_project_path(file_path)

    def test_validate_project_path_valid(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("PDPA_AUDIT_ALLOWED_ROOTS", str(tmp_path))
        resolved = validate_project_path(tmp_path)
        assert resolved == tmp_path.resolve()

    def test_is_safe_file_path_egg_info_directories(self, tmp_path: Path):
        egg_dir = tmp_path / "my_custom_package.egg-info"
        egg_dir.mkdir()
        target = egg_dir / "PKG-INFO"
        target.write_text("Metadata")
        assert is_safe_file_path(tmp_path, target) is False

    def test_is_safe_file_path_excluded_directories(self, tmp_path: Path):
        node_modules = tmp_path / "node_modules" / "pkg"
        node_modules.mkdir(parents=True)
        target = node_modules / "index.js"
        target.write_text("console.log('hi')")
        assert is_safe_file_path(tmp_path, target) is False

        git_dir = tmp_path / ".git" / "hooks"
        git_dir.mkdir(parents=True)
        git_target = git_dir / "pre-commit"
        git_target.write_text("#!/bin/sh")
        assert is_safe_file_path(tmp_path, git_target) is False

    def test_is_safe_file_size(self, tmp_path: Path):
        small_file = tmp_path / "small.txt"
        small_file.write_bytes(b"A" * 1024)
        assert is_safe_file_size(small_file, max_bytes=2048) is True

        large_file = tmp_path / "large.txt"
        large_file.write_bytes(b"A" * 5000)
        assert is_safe_file_size(large_file, max_bytes=2048) is False


class TestSnippetSanitization:
    """Tests for redacting personal data and limiting snippet length."""

    def test_redacts_email_addresses(self):
        text = "Please reach out to privacy-officer@company.lk for corrections."
        sanitized = sanitize_evidence_snippet(text)
        assert "privacy-officer@company.lk" not in sanitized
        assert "[EMAIL]" in sanitized

    def test_redacts_nic_numbers(self):
        old_nic = "National ID number: 912345678V submitted."
        sanitized_old = sanitize_evidence_snippet(old_nic)
        assert "912345678V" not in sanitized_old
        assert "[NIC]" in sanitized_old

        new_nic = "New NIC format: 200012345678 entered."
        sanitized_new = sanitize_evidence_snippet(new_nic)
        assert "200012345678" not in sanitized_new
        assert "[NIC]" in sanitized_new

    def test_redacts_phone_numbers(self):
        text = "Call customer support at +94771234567 or 0712345678."
        sanitized = sanitize_evidence_snippet(text)
        assert "+94771234567" not in sanitized
        assert "0712345678" not in sanitized
        assert "[PHONE]" in sanitized

    def test_truncates_long_snippets(self):
        long_text = "This is a very long policy sentence " * 10
        sanitized = sanitize_evidence_snippet(long_text, max_chars=50)
        assert len(sanitized) <= 50
        assert sanitized.endswith("...")
