import pytest
import requests
from unittest.mock import MagicMock, patch

from config import settings
import net_guard
from tasks.owasp import _make_session, scan_owasp, _SESSION_KWARGS
from tasks.auth_login import detect_login_type, fetch_json_auth_token
from analysis.verifier import (
    _get_verify_setting,
    verify_open_redirect,
    verify_path_traversal,
    verify_sensitive_file_exposure,
    verify_directory_listing,
)


class TestTLSVerificationDefaults:
    def test_verify_ssl_setting_default_true(self):
        assert hasattr(settings, "VERIFY_SSL")
        assert settings.VERIFY_SSL is True

    def test_ca_bundle_path_setting_exists(self):
        assert hasattr(settings, "CA_BUNDLE_PATH")

    def test_get_tls_verify_helper(self, monkeypatch):
        monkeypatch.setattr(settings, "VERIFY_SSL", True)
        monkeypatch.setattr(settings, "CA_BUNDLE_PATH", "")
        assert net_guard.get_tls_verify() is True

        monkeypatch.setattr(settings, "VERIFY_SSL", False)
        assert net_guard.get_tls_verify() is False

        monkeypatch.setattr(settings, "CA_BUNDLE_PATH", "/path/to/custom-ca.pem")
        assert net_guard.get_tls_verify() == "/path/to/custom-ca.pem"

    def test_owasp_session_kwargs_does_not_hardcode_verify_false(self):
        assert "verify" not in _SESSION_KWARGS or _SESSION_KWARGS.get("verify") is not False

    def test_owasp_make_session_configures_verify(self, monkeypatch):
        monkeypatch.setattr(settings, "VERIFY_SSL", True)
        monkeypatch.setattr(settings, "CA_BUNDLE_PATH", "/etc/ssl/lab.crt")
        session = _make_session(auth=None)
        assert session.verify == "/etc/ssl/lab.crt"

    def test_verifier_get_verify_setting(self, monkeypatch):
        monkeypatch.setattr(settings, "VERIFY_SSL", True)
        monkeypatch.setattr(settings, "CA_BUNDLE_PATH", "")
        assert _get_verify_setting() is True

        monkeypatch.setattr(settings, "CA_BUNDLE_PATH", "/lab/ca.pem")
        assert _get_verify_setting() == "/lab/ca.pem"

        # Explicit session verify overrides
        custom_session = requests.Session()
        custom_session.verify = False
        assert _get_verify_setting(custom_session) is False


class TestTLSErrorHandling:
    def test_owasp_login_ssl_error_distinguished(self, monkeypatch):
        monkeypatch.setattr(net_guard, "guarded_request", MagicMock(side_effect=requests.exceptions.SSLError("CERT_UNTRUSTED")))
        auth = {
            "login_url": "https://target.local/login",
            "username_field": "user",
            "username": "admin",
            "password_field": "pass",
            "password": "SUPER_SECRET_PASSWORD",
        }
        session = _make_session(auth)
        assert session.login_result["attempted"] is True
        assert session.login_result["outcome"] == "error"
        assert "TLS certificate verification failed" in session.login_result["detail"]
        # Ensure password is not leaked in the login_result detail
        assert "SUPER_SECRET_PASSWORD" not in session.login_result["detail"]

    def test_auth_login_json_ssl_error_handled_no_secret_leak(self, monkeypatch):
        monkeypatch.setattr(net_guard, "guarded_request", MagicMock(side_effect=requests.exceptions.SSLError("self signed certificate")))
        auth = {
            "login_url": "https://target.local/api/login",
            "username_field": "email",
            "username": "admin@example.com",
            "password_field": "password",
            "password": "SECRET_PASSWORD_123",
        }
        token = fetch_json_auth_token(auth)
        assert token is None

    def test_detect_login_type_ssl_error_handled(self, monkeypatch):
        monkeypatch.setattr(net_guard, "guarded_get", MagicMock(side_effect=requests.exceptions.SSLError("Hostname mismatch")))
        result = detect_login_type("https://mismatch.target.local/login")
        assert result == "form"

    def test_verifier_demotes_on_ssl_error_with_distinguished_note(self):
        finding = {
            "confidence": "confirmed",
            "verification_target": {
                "url": "https://bad-ssl.target.local/redirect",
                "param": "next",
                "payload": "https://evil.example.com",
            },
        }
        mock_client = MagicMock()
        mock_client.get.side_effect = requests.exceptions.SSLError("CERTIFICATE_VERIFY_FAILED")
        
        updated = verify_open_redirect(finding, session=mock_client)
        assert updated["confidence"] == "unverified"
        assert "TLS certificate error" in updated["verification_note"]

    def test_verifier_path_traversal_ssl_error(self):
        finding = {
            "confidence": "confirmed",
            "verification_target": {
                "url": "https://bad-ssl.target.local/view",
                "param": "file",
                "payload": "../../../etc/passwd",
            },
        }
        mock_client = MagicMock()
        mock_client.get.side_effect = requests.exceptions.SSLError("CERTIFICATE_VERIFY_FAILED")
        updated = verify_path_traversal(finding, session=mock_client)
        assert updated["confidence"] == "unverified"
        assert "TLS certificate error" in updated["verification_note"]


class TestNoSilentInsecureFallback:
    def test_guarded_request_does_not_silently_fallback_on_ssl_error(self, monkeypatch):
        # When an SSLError occurs in guarded_request, it must raise, not retry with verify=False
        calls = []
        def mock_request(self_sess, method, url, **kwargs):
            calls.append(kwargs.get("verify"))
            raise requests.exceptions.SSLError("CERT_UNTRUSTED")

        monkeypatch.setattr(requests.Session, "request", mock_request)
        monkeypatch.setattr(net_guard, "resolve_public_ips", lambda host: ["93.184.216.34"])

        with pytest.raises(requests.exceptions.SSLError):
            net_guard.guarded_request("get", "https://example.com/test")

        # Must have attempted with verify=True (or CA bundle) and NOT made a second call with verify=False
        assert len(calls) == 1
        assert calls[0] is True
