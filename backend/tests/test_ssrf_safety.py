import pytest
import socket
from unittest.mock import MagicMock, patch
import requests

import net_guard
from net_guard import resolve_public_ips, assert_public_host, SsrfBlocked, _ip_is_disallowed
from schemas import ScanRequest, normalize_domain


class TestIPClassification:
    def test_public_ipv4_allowed(self):
        assert not _ip_is_disallowed("93.184.216.34")
        assert not _ip_is_disallowed("8.8.8.8")
        assert not _ip_is_disallowed("1.1.1.1")

    def test_private_ipv4_blocked(self):
        assert _ip_is_disallowed("10.0.0.1")
        assert _ip_is_disallowed("172.16.0.1")
        assert _ip_is_disallowed("172.31.255.255")
        assert _ip_is_disallowed("192.168.1.1")

    def test_loopback_blocked(self):
        assert _ip_is_disallowed("127.0.0.1")
        assert _ip_is_disallowed("127.0.0.2")
        assert _ip_is_disallowed("::1")

    def test_link_local_blocked(self):
        assert _ip_is_disallowed("169.254.169.254")  # AWS/GCP metadata
        assert _ip_is_disallowed("fe80::1")

    def test_ipv6_unique_local_blocked(self):
        assert _ip_is_disallowed("fc00::1")
        assert _ip_is_disallowed("fd12:3456:789a::1")

    def test_ipv4_mapped_ipv6(self):
        # Private embedded IPv4 must be blocked
        assert _ip_is_disallowed("::ffff:10.0.0.1")
        assert _ip_is_disallowed("::ffff:127.0.0.1")
        assert _ip_is_disallowed("::ffff:169.254.169.254")
        assert _ip_is_disallowed("::ffff:192.168.1.5")
        # Public embedded IPv4 must be allowed
        assert not _ip_is_disallowed("::ffff:8.8.8.8")
        assert not _ip_is_disallowed("::ffff:93.184.216.34")

    def test_nat64_prefix_unwrapping(self):
        # 64:ff9b::/96 with private embedded IPv4 (e.g. 10.0.0.1 -> 0a000001)
        assert _ip_is_disallowed("64:ff9b::a00:1")
        assert _ip_is_disallowed("64:ff9b::7f00:1")      # 127.0.0.1
        assert _ip_is_disallowed("64:ff9b::c0a8:101")    # 192.168.1.1
        # Public embedded IPv4 (e.g. 8.8.8.8 -> 08080808)
        assert not _ip_is_disallowed("64:ff9b::808:808")
        assert not _ip_is_disallowed("64:ff9b::5db8:d822") # 93.184.216.34


class TestHostResolutionAndPinning:
    def test_resolve_public_ips_success(self, monkeypatch):
        mock_info = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 0))]
        monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: mock_info)
        ips = resolve_public_ips("example.com")
        assert ips == ["93.184.216.34"]

    def test_resolve_public_ips_rejects_private(self, monkeypatch):
        mock_info = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('10.0.0.1', 0))]
        monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: mock_info)
        with pytest.raises(SsrfBlocked):
            resolve_public_ips("internal.corp")

    def test_resolve_public_ips_rejects_mixed_records(self, monkeypatch):
        # If any A/AAAA record points to private IP, it must be rejected (defense against rebinding/round-robin)
        mock_info = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 0)),
        ]
        monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: mock_info)
        with pytest.raises(SsrfBlocked):
            resolve_public_ips("mixed.example.com")

    def test_assert_public_host_blocks_private(self, monkeypatch):
        monkeypatch.setattr(net_guard, "resolve_public_ips", MagicMock(side_effect=SsrfBlocked("private IP")))
        with pytest.raises(SsrfBlocked):
            assert_public_host("bad.example.com")


class TestSchemaValidationSSRF:
    def test_normalize_domain_allows_valid_public_domain(self):
        assert normalize_domain("example.com") == "example.com"
        assert normalize_domain("https://scan.target.com/path") == "scan.target.com"

    def test_normalize_domain_blocks_private_ip_literals(self):
        with pytest.raises(ValueError, match="private/internal IP"):
            normalize_domain("127.0.0.1")
        with pytest.raises(ValueError, match="private/internal IP"):
            normalize_domain("10.0.0.1")
        with pytest.raises(ValueError, match="private/internal IP"):
            normalize_domain("192.168.1.1")
        with pytest.raises(ValueError, match="private/internal IP"):
            normalize_domain("169.254.169.254")

    def test_normalize_domain_blocks_ipv4_mapped_ipv6(self):
        with pytest.raises(ValueError, match="private/internal IP"):
            normalize_domain("::ffff:127.0.0.1")
        with pytest.raises(ValueError, match="private/internal IP"):
            normalize_domain("::ffff:10.0.0.1")

    def test_normalize_domain_blocks_nat64_private(self):
        with pytest.raises(ValueError, match="private/internal IP"):
            normalize_domain("64:ff9b::7f00:1")
        with pytest.raises(ValueError, match="private/internal IP"):
            normalize_domain("64:ff9b::a00:1")

    def test_normalize_domain_rejects_malformed_hostnames(self):
        with pytest.raises(ValueError):
            normalize_domain("foo..bar")
        with pytest.raises(ValueError):
            normalize_domain("-invalid.com")
        with pytest.raises(ValueError):
            normalize_domain("invalid-.com")
        with pytest.raises(ValueError):
            normalize_domain("http://")


class TestRedirectRevalidation:
    def test_redirect_to_private_ip_blocked(self):
        # _PinnedPoolAdapter inspects every hop (including redirects) in get_connection
        adapter = net_guard._PinnedPoolAdapter()
        with pytest.raises(SsrfBlocked, match="non-public address"):
            adapter.get_connection("http://169.254.169.254/latest/meta-data/")

        with pytest.raises(SsrfBlocked, match="non-public address"):
            adapter.get_connection("http://127.0.0.1:8080/admin")

        with pytest.raises(SsrfBlocked, match="non-public address"):
            adapter.get_connection("http://[::ffff:10.0.0.1]/secret")
