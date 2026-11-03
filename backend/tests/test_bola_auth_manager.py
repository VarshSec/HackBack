"""
Tests for Two-Identity Authentication Architecture (Milestone P2.2).
Proves session isolation, independent cookie jars, header segregation,
controlled session refresh, and credential redaction.
"""

import json
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock
import pytest
import requests

from tasks.bola.auth_manager import (
    SessionIdentityManager,
    IDENTITY_PRIMARY,
    IDENTITY_SECONDARY,
    IDENTITY_ANONYMOUS,
    AuthOutcome,
    IdentityAuthState,
)
from tasks.auth_store import (
    store_scan_auth,
    get_scan_auth,
    get_scan_auth_both,
    delete_scan_auth,
    touch_scan_auth,
    get_scan_auth_ttl,
    DEFAULT_AUTH_TTL_SECONDS,
)
from schemas import ScanRequest, AuthConfig


class TestSessionIsolationAndState:
    """Verifies that Identity A, Identity B, and Anonymous are strictly isolated."""

    @pytest.fixture
    def primary_auth(self):
        return {
            "login_url": "https://target.test/api/login",
            "username": "user_a",
            "password": "secret_password_a",
            "login_type": "json",
            "token_json_path": "token",
        }

    @pytest.fixture
    def secondary_auth(self):
        return {
            "login_url": "https://target.test/api/login",
            "username": "user_b",
            "password": "secret_password_b",
            "login_type": "json",
            "token_json_path": "token",
        }

    def test_different_session_objects(self, primary_auth, secondary_auth):
        """1. Identity A and B have completely different session objects."""
        mgr = SessionIdentityManager(primary_auth, secondary_auth)
        sess_a = mgr.get_session(IDENTITY_PRIMARY, auto_authenticate=False)
        sess_b = mgr.get_session(IDENTITY_SECONDARY, auto_authenticate=False)
        sess_anon = mgr.get_session(IDENTITY_ANONYMOUS, auto_authenticate=False)

        assert sess_a is not sess_b
        assert sess_a is not sess_anon
        assert sess_b is not sess_anon

    def test_independent_cookie_jars(self, primary_auth, secondary_auth):
        """2. Identity A and B have independent cookie jars (no cookie bleeding)."""
        mgr = SessionIdentityManager(primary_auth, secondary_auth)
        sess_a = mgr.get_session(IDENTITY_PRIMARY, auto_authenticate=False)
        sess_b = mgr.get_session(IDENTITY_SECONDARY, auto_authenticate=False)

        sess_a.cookies.set("session_cookie_a", "val_a", domain="target.test")
        sess_b.cookies.set("session_cookie_b", "val_b", domain="target.test")

        assert sess_a.cookies.get("session_cookie_a") == "val_a"
        assert sess_a.cookies.get("session_cookie_b") is None, "Identity B cookie leaked to Identity A"

        assert sess_b.cookies.get("session_cookie_b") == "val_b"
        assert sess_b.cookies.get("session_cookie_a") is None, "Identity A cookie leaked to Identity B"

    def test_authorization_header_isolation(self, primary_auth, secondary_auth):
        """3 & 4. Identity A's token never appears in Identity B's requests, and vice-versa."""
        def mock_fetch_token(auth):
            if auth["username"] == "user_a":
                return "jwt_token_for_user_a"
            elif auth["username"] == "user_b":
                return "jwt_token_for_user_b"
            return None

        with patch("tasks.bola.auth_manager.fetch_json_auth_token", side_effect=mock_fetch_token):
            mgr = SessionIdentityManager(primary_auth, secondary_auth)
            auth_results = mgr.authenticate_all()

            assert auth_results[IDENTITY_PRIMARY] is True
            assert auth_results[IDENTITY_SECONDARY] is True

            sess_a = mgr.get_session(IDENTITY_PRIMARY)
            sess_b = mgr.get_session(IDENTITY_SECONDARY)
            sess_anon = mgr.get_session(IDENTITY_ANONYMOUS)

            assert sess_a.headers.get("Authorization") == "Bearer jwt_token_for_user_a"
            assert sess_b.headers.get("Authorization") == "Bearer jwt_token_for_user_b"
            assert "Authorization" not in sess_anon.headers, "Anonymous session must not have Authorization header"

            # Cross-verify tokens are mutually exclusive
            assert "jwt_token_for_user_b" not in sess_a.headers.get("Authorization", "")
            assert "jwt_token_for_user_a" not in sess_b.headers.get("Authorization", "")

    def test_auth_failure_identity_b_does_not_invalidate_identity_a(self, primary_auth, secondary_auth):
        """5. Authentication failure for Identity B does not invalidate Identity A."""
        def mock_fetch_token(auth):
            if auth["username"] == "user_a":
                return "valid_token_a"
            # User B fails authentication
            return None

        with patch("tasks.bola.auth_manager.fetch_json_auth_token", side_effect=mock_fetch_token):
            mgr = SessionIdentityManager(primary_auth, secondary_auth)
            mgr.authenticate(IDENTITY_PRIMARY)
            mgr.authenticate(IDENTITY_SECONDARY)

            st_a = mgr.get_state(IDENTITY_PRIMARY)
            st_b = mgr.get_state(IDENTITY_SECONDARY)

            assert st_a.outcome == AuthOutcome.CONFIRMED
            assert st_b.outcome == AuthOutcome.FAILED

            sess_a = mgr.get_session(IDENTITY_PRIMARY)
            assert sess_a.headers.get("Authorization") == "Bearer valid_token_a"

            # Proves two-identity readiness is correctly false without corrupting User A
            assert mgr.is_two_identity_ready() is False

    def test_missing_secondary_credentials_produces_inconclusive_two_identity_state(self, primary_auth):
        """6. Missing secondary credentials produce an explicit unsupported/inconclusive state."""
        # Only primary auth provided
        mgr = SessionIdentityManager(primary_auth=primary_auth, secondary_auth=None)
        assert mgr.is_identity_configured(IDENTITY_PRIMARY) is True
        assert mgr.is_identity_configured(IDENTITY_SECONDARY) is False
        assert mgr.has_two_identities() is False
        assert mgr.is_two_identity_ready() is False

        st_b = mgr.get_state(IDENTITY_SECONDARY)
        assert st_b.configured is False
        assert st_b.outcome == AuthOutcome.NOT_ATTEMPTED

        # Attempting to authenticate unconfigured secondary sets UNCONFIGURED
        success = mgr.authenticate(IDENTITY_SECONDARY)
        assert success is False
        st_b_after = mgr.get_state(IDENTITY_SECONDARY)
        assert st_b_after.outcome == AuthOutcome.UNCONFIGURED

    def test_session_cleanup(self, primary_auth, secondary_auth):
        """7. Session cleanup safely closes sessions and clears headers and cookies."""
        mgr = SessionIdentityManager(primary_auth, secondary_auth)
        sess_a = mgr.get_session(IDENTITY_PRIMARY, auto_authenticate=False)
        sess_b = mgr.get_session(IDENTITY_SECONDARY, auto_authenticate=False)

        sess_a.cookies.set("c_a", "1", domain="target.test")
        sess_a.headers["X-Test"] = "A"
        sess_b.cookies.set("c_b", "2", domain="target.test")
        sess_b.headers["X-Test"] = "B"

        mgr.close()

        # Both sessions should be closed and removed from manager
        with mgr._lock:
            assert mgr._sessions[IDENTITY_PRIMARY] is None
            assert mgr._sessions[IDENTITY_SECONDARY] is None
            assert mgr._sessions[IDENTITY_ANONYMOUS] is None

    def test_single_identity_backward_compatibility(self, primary_auth):
        """8. Single-identity authentication works seamlessly and remains backward compatible."""
        with patch("tasks.bola.auth_manager.fetch_json_auth_token", return_value="jwt_single"):
            mgr = SessionIdentityManager(primary_auth=primary_auth)
            sess = mgr.get_session(IDENTITY_PRIMARY)
            assert sess.headers.get("Authorization") == "Bearer jwt_single"
            st_a = mgr.get_state(IDENTITY_PRIMARY)
            assert st_a.outcome == AuthOutcome.CONFIRMED

    def test_session_refresh_cannot_mix_identity_state(self, primary_auth, secondary_auth):
        """9. Session refresh on 401 updates only the expired identity and cannot mix tokens."""
        call_counts = {"user_a": 0, "user_b": 0}

        def mock_fetch_token(auth):
            user = auth["username"]
            call_counts[user] += 1
            return f"token_{user}_v{call_counts[user]}"

        with patch("tasks.bola.auth_manager.fetch_json_auth_token", side_effect=mock_fetch_token):
            mgr = SessionIdentityManager(primary_auth, secondary_auth, max_refreshes=1)
            mgr.authenticate(IDENTITY_PRIMARY)
            mgr.authenticate(IDENTITY_SECONDARY)

            # Both initially authenticated with v1
            assert mgr.get_session(IDENTITY_PRIMARY).headers["Authorization"] == "Bearer token_user_a_v1"
            assert mgr.get_session(IDENTITY_SECONDARY).headers["Authorization"] == "Bearer token_user_b_v1"

            # Simulate 401 on Identity A request
            resp_401 = requests.Response()
            resp_401.status_code = 401

            refreshed = mgr.handle_response_auth_status(IDENTITY_PRIMARY, resp_401)
            assert refreshed is True, "Identity A should be successfully refreshed"

            # Identity A now has v2 token
            assert mgr.get_session(IDENTITY_PRIMARY).headers["Authorization"] == "Bearer token_user_a_v2"
            # Identity B is untouched and still has v1 token
            assert mgr.get_session(IDENTITY_SECONDARY).headers["Authorization"] == "Bearer token_user_b_v1"
            assert call_counts["user_b"] == 1, "Identity B should not have been re-authenticated"

            # Second 401 on Identity A should exceed max_refreshes (1) and be rejected
            refreshed_again = mgr.handle_response_auth_status(IDENTITY_PRIMARY, resp_401)
            assert refreshed_again is False, "Second refresh must be blocked by rate limit"

    def test_secrets_redacted_from_string_representation(self, primary_auth):
        """10. Secrets (passwords, tokens) are never leaked through logs or __repr__."""
        with patch("tasks.bola.auth_manager.fetch_json_auth_token", return_value="super_secret_jwt_token_12345"):
            mgr = SessionIdentityManager(primary_auth=primary_auth)
            mgr.authenticate(IDENTITY_PRIMARY)

            state = mgr.get_state(IDENTITY_PRIMARY)
            mgr_repr = repr(mgr)
            state_repr = repr(state)

            assert "super_secret_jwt_token_12345" not in mgr_repr
            assert "secret_password_a" not in mgr_repr
            assert "super_secret_jwt_token_12345" not in state_repr
            assert "secret_password_a" not in state_repr


class TestCompleteCredentialCleanup:
    """Verifies that SessionIdentityManager.close() securely erases all sensitive state."""

    @pytest.fixture
    def primary_auth(self):
        return {
            "login_url": "https://target.test/api/login",
            "username": "user_a",
            "password": "secret_password_a",
            "login_type": "json",
            "token_json_path": "token",
        }

    @pytest.fixture
    def secondary_auth(self):
        return {
            "login_url": "https://target.test/api/login",
            "username": "user_b",
            "password": "secret_password_b",
            "login_type": "json",
            "token_json_path": "token",
        }

    def test_primary_and_secondary_credentials_cleared_after_close(self, primary_auth, secondary_auth):
        """1 & 2. Primary and secondary credentials dictionaries are completely wiped after close()."""
        mgr = SessionIdentityManager(primary_auth, secondary_auth)
        assert mgr._auth_configs[IDENTITY_PRIMARY] is not None
        assert mgr._auth_configs[IDENTITY_SECONDARY] is not None

        mgr.close()

        # Both credential dictionaries must be cleared from memory
        assert mgr._auth_configs[IDENTITY_PRIMARY] is None
        assert mgr._auth_configs[IDENTITY_SECONDARY] is None
        assert mgr.is_closed is True

    def test_retained_bearer_tokens_cleared_after_close(self, primary_auth, secondary_auth):
        """3. Retained bearer tokens and authorization header values are cleared from state tracking."""
        with patch("tasks.bola.auth_manager.fetch_json_auth_token", side_effect=lambda a: f"token_for_{a['username']}"):
            mgr = SessionIdentityManager(primary_auth, secondary_auth)
            mgr.authenticate(IDENTITY_PRIMARY)
            mgr.authenticate(IDENTITY_SECONDARY)

            # Before close, tokens are present internally
            assert mgr._states[IDENTITY_PRIMARY]._token_val == "Bearer token_for_user_a"
            assert mgr._states[IDENTITY_SECONDARY]._token_val == "Bearer token_for_user_b"

            mgr.close()

            # After close, tokens must be None
            assert mgr._states[IDENTITY_PRIMARY]._token_val is None
            assert mgr._states[IDENTITY_SECONDARY]._token_val is None
            assert mgr._states[IDENTITY_PRIMARY].token_header is None
            assert mgr._states[IDENTITY_SECONDARY].token_header is None

    def test_session_cookies_and_headers_cleared(self, primary_auth, secondary_auth):
        """4. Active session instances have cookies and headers cleared, and are dereferenced."""
        with patch("tasks.bola.auth_manager.fetch_json_auth_token", return_value="jwt_test"):
            mgr = SessionIdentityManager(primary_auth, secondary_auth)
            sess_a = mgr.get_session(IDENTITY_PRIMARY)
            sess_b = mgr.get_session(IDENTITY_SECONDARY)

            sess_a.cookies.set("auth_cookie_a", "val_a", domain="target.test")
            sess_b.cookies.set("auth_cookie_b", "val_b", domain="target.test")

            mgr.close()

            # Session objects in manager are set to None
            assert mgr._sessions[IDENTITY_PRIMARY] is None
            assert mgr._sessions[IDENTITY_SECONDARY] is None
            assert mgr._sessions[IDENTITY_ANONYMOUS] is None

            # Underlying session cookie jars and headers were purged
            assert len(sess_a.cookies) == 0
            assert len(sess_b.cookies) == 0
            assert "Authorization" not in sess_a.headers
            assert "Authorization" not in sess_b.headers

    def test_calling_close_twice_is_safe_and_idempotent(self, primary_auth, secondary_auth):
        """5. Calling close() twice does not raise an exception."""
        mgr = SessionIdentityManager(primary_auth, secondary_auth)
        mgr.close()
        # Second call must be a safe no-op
        mgr.close()
        assert mgr.is_closed is True

    def test_context_manager_exit_performs_complete_cleanup(self, primary_auth, secondary_auth):
        """6. Context-manager exit triggers full cleanup of credentials, tokens, and sessions."""
        with patch("tasks.bola.auth_manager.fetch_json_auth_token", return_value="token_ctx"):
            with SessionIdentityManager(primary_auth, secondary_auth) as mgr:
                mgr.authenticate(IDENTITY_PRIMARY)
                sess = mgr.get_session(IDENTITY_PRIMARY)
                sess.cookies.set("c", "1", domain="target.test")
                assert mgr.is_closed is False
                assert mgr._auth_configs[IDENTITY_PRIMARY] is not None
                assert mgr._states[IDENTITY_PRIMARY]._token_val is not None

            # Upon exiting with-block, full cleanup has occurred
            assert mgr.is_closed is True
            assert mgr._auth_configs[IDENTITY_PRIMARY] is None
            assert mgr._auth_configs[IDENTITY_SECONDARY] is None
            assert mgr._states[IDENTITY_PRIMARY]._token_val is None
            assert mgr._sessions[IDENTITY_PRIMARY] is None
            assert len(sess.cookies) == 0

    def test_no_credentials_appear_in_diagnostic_output_after_cleanup(self, primary_auth, secondary_auth):
        """7. Diagnostic state inspection after close() exposes no passwords, tokens, or credentials."""
        with patch("tasks.bola.auth_manager.fetch_json_auth_token", return_value="leak_test_secret_token"):
            mgr = SessionIdentityManager(primary_auth, secondary_auth)
            mgr.authenticate(IDENTITY_PRIMARY)
            mgr.close()

            # Diagnostics must still report outcomes for audit logs
            st_a = mgr.get_state(IDENTITY_PRIMARY)
            assert st_a.outcome == AuthOutcome.CONFIRMED
            assert st_a.attempted is True

            # But contain no secrets
            state_str = str(st_a)
            repr_str = repr(st_a)
            mgr_repr = repr(mgr)

            for secret in ("secret_password_a", "secret_password_b", "leak_test_secret_token"):
                assert secret not in state_str
                assert secret not in repr_str
                assert secret not in mgr_repr
                assert secret not in (st_a.detail or "")

    def test_manager_unusable_for_operations_after_close(self, primary_auth, secondary_auth):
        """8. Operational methods raise RuntimeError after manager is closed."""
        mgr = SessionIdentityManager(primary_auth, secondary_auth)
        mgr.close()

        with pytest.raises(RuntimeError, match="SessionIdentityManager has been closed"):
            mgr.get_session(IDENTITY_PRIMARY)

        with pytest.raises(RuntimeError, match="SessionIdentityManager has been closed"):
            mgr.authenticate(IDENTITY_PRIMARY)

        with pytest.raises(RuntimeError, match="SessionIdentityManager has been closed"):
            mgr.authenticate_all()

        with pytest.raises(RuntimeError, match="SessionIdentityManager has been closed"):
            mgr.handle_response_auth_status(IDENTITY_PRIMARY, requests.Response())


class TestAuthStoreRedisCompatibility:
    """Verifies Redis storage compatibility for both single and dual identities."""

    def test_dual_identity_storage_and_retrieval(self):
        scan_id = "test-dual-auth-scan"
        primary = {"login_url": "https://test.com/login", "username": "admin"}
        secondary = {"login_url": "https://test.com/login", "username": "attacker"}

        mock_redis = {}
        with patch("tasks.auth_store._r.setex", side_effect=lambda k, t, val: mock_redis.update({k: val})), \
             patch("tasks.auth_store._r.get", side_effect=lambda k: mock_redis.get(k)), \
             patch("tasks.auth_store._r.delete", side_effect=lambda k: mock_redis.pop(k, None)):

            store_scan_auth(scan_id, auth=primary, auth_secondary=secondary)

            # 1. Fetch primary (backward compatibility)
            p = get_scan_auth(scan_id)
            assert p == primary

            # 2. Fetch secondary
            s = get_scan_auth(scan_id, identity="secondary")
            assert s == secondary

            # 3. Fetch both
            both_p, both_s = get_scan_auth_both(scan_id)
            assert both_p == primary
            assert both_s == secondary

            # 4. Delete wipes both
            delete_scan_auth(scan_id)
            assert get_scan_auth(scan_id) is None
            assert get_scan_auth(scan_id, identity="secondary") is None

    def test_legacy_single_identity_retrieval_compatibility(self):
        """Proves that raw single-identity dictionaries in Redis parse cleanly."""
        scan_id = "test-legacy-auth-scan"
        legacy_data = {"login_url": "https://test.com/login", "username": "legacy_user"}

        # Simulate older single-identity dict in Redis
        mock_redis = {f"scan_auth:{scan_id}": json.dumps(legacy_data)}
        with patch("tasks.auth_store._r.get", side_effect=lambda k: mock_redis.get(k)):
            # Calling get_scan_auth without identity argument returns legacy dict
            assert get_scan_auth(scan_id) == legacy_data
            # Calling for secondary returns None
            assert get_scan_auth(scan_id, identity="secondary") is None
            # get_scan_auth_both returns (legacy_data, None)
            both_p, both_s = get_scan_auth_both(scan_id)
            assert both_p == legacy_data
            assert both_s is None

    def test_store_scan_auth_bounded_ttl_and_touch(self):
        """Verifies that store_scan_auth enforces the bounded 14,400s (4 hours) TTL and touch refreshes it."""
        scan_id = "test-ttl-scan"
        auth = {"login_url": "https://test.com/login", "username": "admin"}

        captured_ttl = {}
        with patch("tasks.auth_store._r.setex", side_effect=lambda k, t, val: captured_ttl.update({k: t})), \
             patch("tasks.auth_store._r.expire", side_effect=lambda k, t: True), \
             patch("tasks.auth_store._r.ttl", return_value=DEFAULT_AUTH_TTL_SECONDS):

            store_scan_auth(scan_id, auth=auth)
            assert captured_ttl[f"scan_auth:{scan_id}"] == DEFAULT_AUTH_TTL_SECONDS
            assert captured_ttl[f"scan_auth:{scan_id}"] == 14400

            # touch_scan_auth refreshes TTL
            assert touch_scan_auth(scan_id) is True
            assert get_scan_auth_ttl(scan_id) == 14400

    def test_reap_stuck_scans_deletes_credentials(self):
        """Stuck-scan reaper deletes scan authentication credentials from Redis."""
        from routers.scan import _reap_stuck_scans
        mock_scan = MagicMock()
        mock_scan.id = "stuck-scan-uuid"
        mock_scan.started_at = None
        mock_scan.created_at = None
        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.all.return_value = [mock_scan]

        with patch("routers.scan._is_waiting", return_value=False), \
             patch("routers.scan.datetime") as mock_dt, \
             patch("tasks.auth_store.delete_scan_auth") as mock_delete:
            mock_dt.utcnow.return_value = datetime(2026, 1, 1, 12, 0, 0)
            mock_scan.created_at = datetime(2026, 1, 1, 10, 0, 0)

            reaped = _reap_stuck_scans(mock_db)
            assert reaped == 1
            mock_delete.assert_called_once_with("stuck-scan-uuid")

    def test_cancel_scan_decision_deletes_credentials(self):
        """Cancelling a scan via submit_scan_decision deletes scan credentials."""
        from routers.scan import submit_scan_decision
        from schemas import ScanDecisionRequest
        mock_scan = MagicMock()
        mock_scan.id = "cancel-scan-uuid"
        mock_scan.domain = "test.domain"
        mock_scan.status = "awaiting_user_decision"
        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.first.return_value = mock_scan
        mock_request = MagicMock()

        req = ScanDecisionRequest(action="cancel")
        with patch("routers.scan.get_owned_scan_or_404", return_value=mock_scan), \
             patch("tasks.auth_store.delete_scan_auth") as mock_delete, \
             patch("routers.scan.get_scan_status"):
            submit_scan_decision("cancel-scan-uuid", req, mock_request, mock_db)
            mock_delete.assert_called_once_with("cancel-scan-uuid")


class TestScanRequestSchemaValidation:
    """Verifies Pydantic validations on ScanRequest for dual authentication."""

    def test_single_auth_valid(self):
        req = ScanRequest(
            domain="target.test",
            authorized=True,
            auth=AuthConfig(login_url="https://target.test/login", username="u1", password="p1"),
        )
        assert req.auth is not None
        assert req.auth_secondary is None

    def test_dual_auth_distinct_users_valid(self):
        req = ScanRequest(
            domain="target.test",
            authorized=True,
            auth=AuthConfig(login_url="https://target.test/login", username="user_a", password="p1"),
            auth_secondary=AuthConfig(login_url="https://target.test/login", username="user_b", password="p2"),
        )
        assert req.auth.username == "user_a"
        assert req.auth_secondary.username == "user_b"

    def test_secondary_without_primary_rejected(self):
        with pytest.raises(ValueError, match="Primary authentication.*must be configured"):
            ScanRequest(
                domain="target.test",
                authorized=True,
                auth=None,
                auth_secondary=AuthConfig(login_url="https://target.test/login", username="u2", password="p2"),
            )

    def test_identical_usernames_rejected(self):
        with pytest.raises(ValueError, match="must represent distinct user identities"):
            ScanRequest(
                domain="target.test",
                authorized=True,
                auth=AuthConfig(login_url="https://target.test/login", username="same_user", password="p1"),
                auth_secondary=AuthConfig(login_url="https://target.test/login", username="same_user", password="p2"),
            )
