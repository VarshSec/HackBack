"""
Unit and integration tests for BOLA Verification Engine (backend/tasks/bola/engine.py).
Tests:
1. Cache interference (suspected cache hit -> INCONCLUSIVE)
2. Redirect handling (allow_redirects=False, auth challenge recognized as AUTHORIZED)
3. Dynamic JSON fields (volatile masking while preserving IDs)
4. Ownership mismatch / silent tenant scoping (safe scoping -> AUTHORIZED)
5. Missing Resource B (strong evidence -> HIGH_PROBABLE_BOLA, weak evidence -> INCONCLUSIVE)
6. Confirmed BOLA (full 4-way corroboration -> CONFIRMED_BOLA, CERTAIN confidence)
7. Proper access control (403 Forbidden -> AUTHORIZED)
8. Public resource (anonymous 200 OK -> PUBLIC_RESOURCE)
9. Soft-404 / empty payload avoidance -> SOFT_404_AUTHORIZED
10. Safety guardrail: side-effecting route/method blocked when allow_state_modification=False
11. Single-identity configuration -> SINGLE_IDENTITY_UNVERIFIED
12. Sanitized reproduction cURL (no credential leakage)
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch
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
from tasks.bola.comparator import CacheInterference
from tasks.bola.models import CandidateEndpoint, IdentifierType, ParameterLocation, SemanticRole
from tasks.bola.engine import (
    AccessPolicy,
    TargetAuthorizationPolicy,
    BOLAVerificationEngine,
    BOLAOutcome,
    ConfidenceLevel,
    VerificationScenario,
    is_potentially_side_effecting,
    is_auth_challenge_redirect,
    is_routing_error,
    resolve_url_resource_identifier,
    check_session_isolation,
    extract_authenticated_principal,
    compare_authenticated_principal,
    build_sanitized_curl,
    CLAIM_CATEGORY_MAP,
    SENSITIVE_RESPONSE_HEADERS,
    SAFE_CACHE_RESPONSE_HEADERS,
    sanitize_response_headers,
)


def make_mock_response(
    status_code: int = 200,
    text: str = "",
    headers: dict | None = None,
) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.headers = headers or {"Content-Type": "application/json"}
    return resp


@pytest.fixture
def dual_auth_manager():
    """Mock SessionIdentityManager configured with primary and secondary identities."""
    mgr = MagicMock(spec=SessionIdentityManager)
    mgr.is_identity_configured.side_effect = lambda ident: ident in (IDENTITY_PRIMARY, IDENTITY_SECONDARY, IDENTITY_ANONYMOUS)
    mgr.has_two_identities.return_value = True

    # Isolated mock sessions for primary, secondary, and anonymous
    sess_a = MagicMock()
    sess_a.headers = {"Authorization": "Bearer primary_token_a"}
    sess_a.cookies = {}

    sess_b = MagicMock()
    sess_b.headers = {"Authorization": "Bearer secondary_token_b"}
    sess_b.cookies = {}

    sess_d = MagicMock()
    sess_d.headers = {}
    sess_d.cookies = {}

    sessions_map = {
        IDENTITY_PRIMARY: sess_a,
        IDENTITY_SECONDARY: sess_b,
        IDENTITY_ANONYMOUS: sess_d,
    }
    mgr.get_session.side_effect = lambda ident, auto_authenticate=True: sessions_map.get(ident, MagicMock())
    mgr.handle_response_auth_status.return_value = False
    mgr.get_state.side_effect = lambda ident: IdentityAuthState(
        identity=ident,
        configured=True,
        attempted=True,
        outcome=AuthOutcome.CONFIRMED,
        detail="Authenticated session",
    )
    return mgr


@pytest.fixture
def single_auth_manager():
    """Mock SessionIdentityManager configured with primary identity only."""
    mgr = MagicMock(spec=SessionIdentityManager)
    mgr.is_identity_configured.side_effect = lambda ident: ident in (IDENTITY_PRIMARY, IDENTITY_ANONYMOUS)
    mgr.has_two_identities.return_value = False
    mgr.get_session.return_value = MagicMock()
    mgr.get_state.side_effect = lambda ident: IdentityAuthState(
        identity=ident,
        configured=(ident == IDENTITY_PRIMARY),
        attempted=True,
        outcome=AuthOutcome.CONFIRMED if ident == IDENTITY_PRIMARY else AuthOutcome.UNCONFIGURED,
        detail="Primary authenticated",
    )
    return mgr


@pytest.fixture
def sample_candidate():
    return CandidateEndpoint(
        candidate_id="cand_test_001",
        scan_id="scan_123",
        target_domain="target.test",
        method="GET",
        original_url="https://target.test/api/v1/orders/105",
        route_template="/api/v1/orders/{order_id}",
        resource_type="orders",
    )


class TestSideEffectingSafetyGate:
    def test_safe_get_passes(self):
        is_bad, _ = is_potentially_side_effecting("GET", "https://target.test/api/v1/orders/105")
        assert is_bad is False

    def test_safe_head_passes(self):
        is_bad, _ = is_potentially_side_effecting("HEAD", "https://target.test/api/v1/orders/105")
        assert is_bad is False

    def test_non_get_head_methods_flagged(self):
        for m in ("POST", "PUT", "DELETE", "PATCH"):
            is_bad, reason = is_potentially_side_effecting(m, "https://target.test/api/v1/orders")
            assert is_bad is True
            assert m in reason

    def test_side_effecting_verbs_in_get_path_flagged(self):
        dangerous_paths = [
            "https://target.test/api/v1/orders/105/cancel",
            "https://target.test/api/v1/users/105/delete",
            "https://target.test/api/v1/auth/logout",
            "https://target.test/api/v1/database/purge",
            "https://target.test/api/v1/accounts/105/terminate",
        ]
        for url in dangerous_paths:
            is_bad, reason = is_potentially_side_effecting("GET", url)
            assert is_bad is True
            assert "side-effecting" in reason

    def test_engine_skips_side_effecting_when_modification_disabled(self, dual_auth_manager, sample_candidate):
        engine = BOLAVerificationEngine(dual_auth_manager, allow_state_modification=False)
        candidate_delete = CandidateEndpoint(
            candidate_id="cand_del",
            scan_id="scan_123",
            target_domain="target.test",
            method="DELETE",
            original_url="https://target.test/api/v1/orders/105",
            route_template="/api/v1/orders/{order_id}",
            resource_type="orders",
        )
        res = engine.verify_candidate(
            candidate_delete,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="105",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "guardrail" in res.explanation.lower()


class TestRedirectInspection:
    def test_auth_challenge_redirect_detected(self):
        assert is_auth_challenge_redirect(302, "https://target.test/login") is True
        assert is_auth_challenge_redirect(302, "/auth/signin") is True
        assert is_auth_challenge_redirect(303, "https://target.test/oauth/authorize") is True
        assert is_auth_challenge_redirect(307, "/session/new") is True
        assert is_auth_challenge_redirect(302, "/unauthorized") is True

    def test_non_auth_redirect_not_treated_as_auth_challenge(self):
        assert is_auth_challenge_redirect(302, "/api/v2/orders/105") is False
        assert is_auth_challenge_redirect(301, "https://target.test/orders/105/") is False
        assert is_auth_challenge_redirect(200, "/login") is False

    @patch("net_guard.guarded_request")
    def test_redirect_to_login_counts_as_authorized(self, mock_guarded, dual_auth_manager, sample_candidate):
        engine = BOLAVerificationEngine(dual_auth_manager)

        data_a = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        # Scenario A: 200 OK
        resp_a = make_mock_response(200, data_a)
        # Scenario B: 302 Redirect to /login
        resp_b = make_mock_response(302, "", {"Location": "https://target.test/login"})

        mock_guarded.side_effect = [resp_a, resp_b]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
        )
        assert res.outcome == BOLAOutcome.AUTHORIZED
        assert res.is_vulnerable is False
        # Assert allow_redirects=False was passed
        for call_args in mock_guarded.call_args_list:
            assert call_args.kwargs.get("allow_redirects") is False


class TestCacheInterference:
    @patch("net_guard.guarded_request")
    def test_cached_hit_triggers_inconclusive(self, mock_guarded, dual_auth_manager, sample_candidate):
        engine = BOLAVerificationEngine(dual_auth_manager)

        data = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        resp_a = make_mock_response(200, data, {"Content-Type": "application/json"})
        # Scenario B returns identical data BUT with proxy cache header HIT
        resp_b = make_mock_response(200, data, {"Content-Type": "application/json", "X-Cache": "HIT from cdn"})

        mock_guarded.side_effect = [resp_a, resp_b]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert res.cache_interference == CacheInterference.SUSPECTED_CACHE_HIT
        assert "cache" in res.explanation.lower()


class TestOwnershipAndSilentTenantScoping:
    @patch("net_guard.guarded_request")
    def test_silent_tenant_scoping_is_authorized(self, mock_guarded, dual_auth_manager, sample_candidate):
        engine = BOLAVerificationEngine(dual_auth_manager)

        data_a = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        # User B requested order 105, but server returned User B's own order 205
        data_b = json.dumps({"order_id": "205", "item": "Widget B", "user_id": "user_B"})

        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_b)

        mock_guarded.side_effect = [resp_a, resp_b]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            user_b_identifier="user_B",
        )
        assert res.outcome == BOLAOutcome.AUTHORIZED
        assert res.is_vulnerable is False
        assert "tenant scoping" in res.explanation.lower()


class TestDecisionMatrixOutcomes:
    @patch("net_guard.guarded_request")
    def test_full_4way_confirmed_bola(self, mock_guarded, dual_auth_manager, sample_candidate):
        engine = BOLAVerificationEngine(dual_auth_manager)

        data_a = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A", "price": 100})
        # Scenario B gets User A's private data!
        data_b = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A", "price": 100, "timestamp": 12345})
        # Scenario C: User B has their own order 205
        data_c = json.dumps({"order_id": "205", "item": "Widget B", "user_id": "user_B", "price": 50})

        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_b)
        resp_d = make_mock_response(401, '{"error": "Unauthorized"}')
        resp_c = make_mock_response(200, data_c)

        # Execution order: Scenario A, Scenario B, Scenario D, Scenario C
        mock_guarded.side_effect = [resp_a, resp_b, resp_d, resp_c]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            target_url_b="https://target.test/api/v1/orders/205",
            user_b_identifier="user_B",
        )
        assert res.outcome == BOLAOutcome.CONFIRMED_BOLA
        assert res.is_vulnerable is True
        assert res.confidence.level == ConfidenceLevel.CERTAIN
        assert res.confidence.score >= 0.95
        assert "401" in res.explanation or "denied" in res.explanation

    @patch("net_guard.guarded_request")
    def test_missing_resource_b_strong_evidence_is_high_probable(self, mock_guarded, dual_auth_manager, sample_candidate):
        engine = BOLAVerificationEngine(dual_auth_manager, default_validation_url="https://target.test/api/user/me")

        data_a = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        data_b = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A", "timestamp": "2026-11-06"})
        data_val = json.dumps({"user_id": "user_B", "role": "user"})

        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_b)
        resp_d = make_mock_response(403, '{"error": "Forbidden"}')
        resp_val = make_mock_response(200, data_val)

        mock_guarded.side_effect = [resp_a, resp_b, resp_d, resp_val]

        # No target_url_b provided (Resource B missing)
        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            target_url_b=None,
            user_b_identifier="user_B",
            user_b_validation_url="https://target.test/api/user/me",
        )
        assert res.outcome == BOLAOutcome.HIGH_PROBABLE_BOLA
        assert res.is_vulnerable is True
        assert res.confidence.level == ConfidenceLevel.HIGH
        assert 0.80 <= res.confidence.score <= 0.94

    @patch("net_guard.guarded_request")
    def test_missing_resource_b_weak_evidence_is_inconclusive(self, mock_guarded, dual_auth_manager, sample_candidate):
        engine = BOLAVerificationEngine(dual_auth_manager)

        data_a = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        # Scenario B has completely different structure / low similarity and missing user_A id
        data_b = json.dumps({"status": "ok", "result": "partial"})

        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_b)
        resp_d = make_mock_response(403, '{"error": "Forbidden"}')

        mock_guarded.side_effect = [resp_a, resp_b, resp_d]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            target_url_b=None,
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False

    @patch("net_guard.guarded_request")
    def test_proper_authorization_403_forbidden(self, mock_guarded, dual_auth_manager, sample_candidate):
        engine = BOLAVerificationEngine(dual_auth_manager)

        data_a = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(403, '{"message": "Forbidden"}')

        mock_guarded.side_effect = [resp_a, resp_b]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
        )
        assert res.outcome == BOLAOutcome.AUTHORIZED
        assert res.is_vulnerable is False

    @patch("net_guard.guarded_request")
    def test_public_resource_when_anonymous_succeeds(self, mock_guarded, dual_auth_manager, sample_candidate):
        engine = BOLAVerificationEngine(dual_auth_manager)

        public_data = json.dumps({"product_id": "prod_105", "name": "Catalog Item", "price": 10})
        resp_a = make_mock_response(200, public_data)
        resp_b = make_mock_response(200, public_data)
        resp_d = make_mock_response(200, public_data)

        mock_guarded.side_effect = [resp_a, resp_b, resp_d]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/products/prod_105",
            user_a_identifier="prod_105",
            expected_access_policy=AccessPolicy.PUBLIC,
        )
        assert res.outcome == BOLAOutcome.PUBLIC_RESOURCE
        assert res.is_vulnerable is False

    @patch("net_guard.guarded_request")
    def test_soft_404_empty_array_avoidance(self, mock_guarded, dual_auth_manager, sample_candidate):
        engine = BOLAVerificationEngine(dual_auth_manager)

        data_a = json.dumps({"order_id": "105", "user_id": "user_A", "items": ["item1", "item2"]})
        # User B gets 200 OK with empty items
        data_b = json.dumps({"order_id": "105", "items": [], "data": []})

        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_b)

        mock_guarded.side_effect = [resp_a, resp_b]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "soft-404" in res.title.lower() or "generic error" in res.title.lower()

    @patch("net_guard.guarded_request")
    def test_user_b_accessing_own_resource_b_is_not_bola(self, mock_guarded, dual_auth_manager):
        """
        Verifies that when a candidate endpoint represents User B accessing their own Resource B,
        it establishes a normal owner baseline and is NEVER classified as CONFIRMED_BOLA.
        """
        engine = BOLAVerificationEngine(dual_auth_manager)
        candidate_b = CandidateEndpoint(
            candidate_id="cand_user_b_res_b",
            scan_id="scan_123",
            target_domain="target.test",
            method="GET",
            original_url="https://target.test/api/v1/orders/205",
            route_template="/api/v1/orders/{order_id}",
            resource_type="orders",
        )
        data_b = json.dumps({"order_id": "205", "user_id": "user_B", "item": "Widget B"})
        resp_b = make_mock_response(200, data_b)

        # In this context, primary identity configured in engine accesses Resource B
        mock_guarded.return_value = resp_b

        # If User B accesses Resource B as Scenario A (owner baseline), it's a valid baseline, not BOLA
        res = engine.verify_candidate(
            candidate_b,
            target_url_a="https://target.test/api/v1/orders/205",
            user_a_identifier="user_B",
        )
        assert res.outcome != BOLAOutcome.CONFIRMED_BOLA

    @patch("net_guard.guarded_request")
    def test_secondary_identity_reverse_control_failure_is_inconclusive(self, mock_guarded, dual_auth_manager, sample_candidate):
        """
        Verifies that if User B accesses Resource A, but fails reverse control on their own Resource B
        (e.g., status 403 or 401), the engine fails closed with INCONCLUSIVE rather than declaring BOLA.
        """
        engine = BOLAVerificationEngine(dual_auth_manager)

        data_a = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_a)
        resp_d = make_mock_response(401, '{"error": "Unauthorized"}')
        # Scenario C fails! User B cannot access their own resource 205
        resp_c_fail = make_mock_response(403, '{"error": "Forbidden for user B"}')

        mock_guarded.side_effect = [resp_a, resp_b, resp_d, resp_c_fail]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            target_url_b="https://target.test/api/v1/orders/205",
            user_b_identifier="user_B",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "reverse control" in res.explanation.lower()

    @patch("net_guard.guarded_request")
    def test_static_mock_identical_responses_across_resources_is_inconclusive(self, mock_guarded, dual_auth_manager, sample_candidate):
        """
        Verifies that if Resource A and Resource B return identical static data without User B's identifier,
        the engine suspects a static mock and marks INCONCLUSIVE.
        """
        engine = BOLAVerificationEngine(dual_auth_manager)

        static_data = json.dumps({"order_id": "static_template", "items": ["item1"]})
        resp_a = make_mock_response(200, static_data)
        resp_b = make_mock_response(200, static_data)
        resp_d = make_mock_response(401, '{"error": "Unauthorized"}')
        resp_c = make_mock_response(200, static_data)

        mock_guarded.side_effect = [resp_a, resp_b, resp_d, resp_c]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="static_template",
            resource_a_identifier="static_template",
            target_url_b="https://target.test/api/v1/orders/205",
            user_b_identifier="user_B",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "undifferentiated" in res.title.lower() or "static" in res.explanation.lower()

    @patch("net_guard.guarded_request")
    def test_anonymous_ambiguous_failure_is_inconclusive(self, mock_guarded, dual_auth_manager, sample_candidate):
        """
        Verifies that if Scenario D returns an unhandled server error (500) rather than a definitive
        authorization challenge (401/403/redirect), the test fails closed as INCONCLUSIVE.
        """
        engine = BOLAVerificationEngine(dual_auth_manager)

        data_a = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_a)
        # Scenario D server crashed
        resp_d_500 = make_mock_response(500, "Internal Server Error")

        mock_guarded.side_effect = [resp_a, resp_b, resp_d_500]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "unauthenticated" in res.explanation.lower()


class TestSingleIdentityAndReproductionCurl:
    def test_single_identity_unverified(self, single_auth_manager, sample_candidate):
        engine = BOLAVerificationEngine(single_auth_manager)

        with patch("net_guard.guarded_request") as mock_guarded:
            mock_guarded.return_value = make_mock_response(200, json.dumps({"order_id": "105"}))
            res = engine.verify_candidate(
                sample_candidate,
                target_url_a="https://target.test/api/v1/orders/105",
                user_a_identifier="105",
            )
            assert res.outcome == BOLAOutcome.SINGLE_IDENTITY_UNVERIFIED
            assert res.is_vulnerable is False
            assert "Secondary credentials not configured" in res.confidence.deductions[0]

    def test_sanitized_reproduction_curl(self):
        curl = build_sanitized_curl("GET", "https://target.test/api/v1/orders?token=SECRET_123")
        assert "SECRET_123" not in curl
        assert "[REDACTED]" in curl
        assert "-X GET" in curl
        assert "Authorization: [REDACTED]" in curl


class TestCriticalSecurityAuditRegressions:
    """
    CRITICAL AUDIT 5 — Dedicated Regression Tests for Source-Level Audit Invariants:
    1. User A receives Resource A but ownership cannot be established.
    2. User B receives Resource A's identifier without sufficient protected business data.
    3. User B receives Resource A with verified ownership evidence.
    4. User B's session is invalid but the endpoint returns HTTP 200.
    5. Three-way fallback with invalid secondary credentials.
    6. Three-way fallback with valid secondary credentials and strong cross-user evidence.
    7. Scenario C succeeds but Scenario B is denied.
    8. Scenario C succeeds but Scenario B receives User B's own resource.
    9. Similar JSON structures with different underlying resources.
    10. Confidence score is high but a mandatory evidence condition is missing.
    """

    @patch("net_guard.guarded_request")
    def test_user_a_receives_resource_a_without_ownership_evidence_is_inconclusive(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """
        Audit 1 / Test 1: User A receives 200 OK with valid JSON, but the payload
        does not contain ownership evidence proving User A owns the resource.
        Verdict must be INCONCLUSIVE.
        """
        engine = BOLAVerificationEngine(dual_auth_manager)
        unowned_payload = json.dumps({"order_id": "105", "item": "Widget A", "price": 99.99})
        mock_guarded.return_value = make_mock_response(200, unowned_payload)

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "ownership evidence missing" in res.title.lower()

    @patch("net_guard.guarded_request")
    def test_user_b_receives_identifier_without_substantive_business_data_is_inconclusive(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """
        Audit 1 / Test 2: User B receives 200 OK containing order_id: 105, but it is a reflected
        stub or minimal response without substantive protected business fields.
        Must not independently establish BOLA -> INCONCLUSIVE.
        """
        engine = BOLAVerificationEngine(dual_auth_manager)
        resp_a = make_mock_response(200, json.dumps({"order_id": "105", "user_id": "user_A", "item": "Widget A"}))
        resp_b_stub = make_mock_response(200, json.dumps({"order_id": "105"}))
        mock_guarded.side_effect = [resp_a, resp_b_stub]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "insufficient protected business data" in res.title.lower()

    @patch("net_guard.guarded_request")
    def test_user_b_receives_resource_a_with_verified_ownership_evidence(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """
        Audit 1 / Test 3: User B receives Resource A's full payload with verified ownership evidence
        confirming it belongs to User A. All 4 scenarios succeed -> CONFIRMED_BOLA.
        """
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "user_id": "user_A", "item": "Widget A", "price": 99.99})
        data_b = json.dumps({"order_id": "205", "user_id": "user_B", "item": "Widget B", "price": 49.99})

        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_a)
        resp_d = make_mock_response(401, '{"error": "Unauthorized"}')
        resp_c = make_mock_response(200, data_b)

        mock_guarded.side_effect = [resp_a, resp_b, resp_d, resp_c]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            target_url_b="https://target.test/api/v1/orders/205",
            user_b_identifier="user_B",
            resource_b_identifier="205",
        )
        assert res.outcome == BOLAOutcome.CONFIRMED_BOLA
        assert res.is_vulnerable is True
        assert res.confidence.level == ConfidenceLevel.CERTAIN
        assert res.reproduction_curl is not None

    @patch("net_guard.guarded_request")
    def test_user_b_session_invalid_but_endpoint_returns_200_is_inconclusive(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """
        Audit 2 / Test 4: User B's authentication failed or expired, but the target endpoint
        returns HTTP 200. Failed/expired authentication cannot be mistaken for cross-user authorization.
        Must fail closed to INCONCLUSIVE.
        """
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "user_id": "user_A", "item": "Widget A"})
        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_a)

        mock_guarded.side_effect = [resp_a, resp_b]

        dual_auth_manager.get_state.side_effect = lambda ident: IdentityAuthState(
            identity=ident,
            configured=True,
            attempted=True,
            outcome=AuthOutcome.CONFIRMED if ident == IDENTITY_PRIMARY else AuthOutcome.FAILED,
            detail="Secondary credentials rejected by login endpoint",
        )

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "secondary identity authentication invalid" in res.title.lower()

    @patch("net_guard.guarded_request")
    def test_three_way_fallback_with_invalid_secondary_credentials_is_inconclusive(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """
        Audit 2 / Test 5: In three-way fallback (Resource B unavailable), secondary credentials
        are invalid. Missing Resource B must not silently imply User B is authenticated.
        Must return INCONCLUSIVE.
        """
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "user_id": "user_A", "item": "Widget A"})
        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_a)

        mock_guarded.side_effect = [resp_a, resp_b]

        dual_auth_manager.get_state.side_effect = lambda ident: IdentityAuthState(
            identity=ident,
            configured=True,
            attempted=True,
            outcome=AuthOutcome.CONFIRMED if ident == IDENTITY_PRIMARY else AuthOutcome.FAILED,
            detail="Secondary session token expired",
        )

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            target_url_b=None,
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False

    @patch("net_guard.guarded_request")
    def test_three_way_fallback_with_valid_credentials_is_high_probable(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """
        Audit 2 / Test 6: Three-way fallback with validated secondary credentials, strong cross-user
        evidence, and anonymous denied -> HIGH_PROBABLE_BOLA.
        """
        engine = BOLAVerificationEngine(dual_auth_manager, default_validation_url="https://target.test/api/user/me")
        data_a = json.dumps({"order_id": "105", "user_id": "user_A", "item": "Widget A", "price": 99.99})
        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_a)
        resp_d = make_mock_response(403, '{"error": "Forbidden"}')
        resp_val = make_mock_response(200, '{"user_id": "user_B", "role": "user"}')

        mock_guarded.side_effect = [resp_a, resp_b, resp_d, resp_val]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            target_url_b=None,
            user_b_identifier="user_B",
            user_b_validation_url="https://target.test/api/user/me",
        )
        assert res.outcome == BOLAOutcome.HIGH_PROBABLE_BOLA
        assert res.is_vulnerable is True
        assert res.confidence.level == ConfidenceLevel.HIGH

    @patch("net_guard.guarded_request")
    def test_scenario_c_succeeds_but_scenario_b_denied_is_authorized(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """
        Audit 5 / Test 7: Scenario C proves User B is authenticated and can access their own Resource B,
        but User B is properly denied access to Resource A (Scenario B 403 Forbidden).
        Verdict must be AUTHORIZED.
        """
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "user_id": "user_A", "item": "Widget A"})
        data_b = json.dumps({"order_id": "205", "user_id": "user_B", "item": "Widget B"})

        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(403, '{"error": "Forbidden for user B"}')
        resp_c = make_mock_response(200, data_b)

        mock_guarded.side_effect = [resp_a, resp_b, resp_c]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            target_url_b="https://target.test/api/v1/orders/205",
            user_b_identifier="user_B",
            resource_b_identifier="205",
        )
        assert res.outcome == BOLAOutcome.AUTHORIZED
        assert res.is_vulnerable is False
        assert "scenario_c" in res.scenario_results
        assert res.scenario_results["scenario_c"].status_code == 200

    @patch("net_guard.guarded_request")
    def test_scenario_c_succeeds_and_scenario_b_receives_user_b_own_resource(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """
        Audit 5 / Test 8: User B requests Resource A (/orders/105), but the server silently returns
        User B's own record (/orders/205 with user_id: user_B). Scenario C also succeeds.
        Verdict must be AUTHORIZED (Server-Side Tenant Scoping).
        """
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "user_id": "user_A", "item": "Widget A"})
        data_b = json.dumps({"order_id": "205", "user_id": "user_B", "item": "Widget B"})

        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_b)
        resp_c = make_mock_response(200, data_b)

        mock_guarded.side_effect = [resp_a, resp_b, resp_c]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            target_url_b="https://target.test/api/v1/orders/205",
            user_b_identifier="user_B",
            resource_b_identifier="205",
        )
        assert res.outcome == BOLAOutcome.AUTHORIZED
        assert res.is_vulnerable is False
        assert "tenant scoping" in res.title.lower() or "tenant scoping" in res.explanation.lower()

    @patch("net_guard.guarded_request")
    def test_similar_json_structure_with_different_underlying_resources_is_not_bola(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """
        Audit 1 & 5 / Test 9: User A and User B receive payloads with identical JSON keys/schema,
        but the resource identifiers and ownership fields belong to different entities.
        Identical JSON structure alone cannot establish BOLA -> INCONCLUSIVE.
        """
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "user_id": "user_A", "total": 100, "status": "shipped"})
        data_b = json.dumps({"order_id": "999", "user_id": "user_C", "total": 100, "status": "shipped"})

        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_b)

        mock_guarded.side_effect = [resp_a, resp_b]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "resource identity evidence missing" in res.title.lower()

    @patch("net_guard.guarded_request")
    def test_high_confidence_signals_cannot_promote_verdict_when_mandatory_evidence_missing(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """
        Audit 4 & 5 / Test 10: Response B is 200 OK and matches Response A, but Scenario D unauthenticated
        access also succeeds (returns 200 OK). Even if heuristic score is positive, the mandatory
        evidence failure (endpoint is public) forces PUBLIC_RESOURCE (not BOLA). Confidence cannot promote verdict.
        """
        engine = BOLAVerificationEngine(dual_auth_manager)
        public_data = json.dumps({"order_id": "105", "user_id": "user_A", "item": "Public Catalog Item"})

        resp_a = make_mock_response(200, public_data)
        resp_b = make_mock_response(200, public_data)
        resp_d = make_mock_response(200, public_data)

        mock_guarded.side_effect = [resp_a, resp_b, resp_d]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            expected_access_policy=AccessPolicy.PUBLIC,
        )
        assert res.outcome == BOLAOutcome.PUBLIC_RESOURCE
        assert res.is_vulnerable is False
        assert res.outcome != BOLAOutcome.CONFIRMED_BOLA
        assert res.outcome != BOLAOutcome.HIGH_PROBABLE_BOLA


class TestIssue1ThreeWayFallbackAuthValidation:
    """
    CORRECTION 1 — Three-Way Fallback Authentication Validation Tests:
    - Expired Authorization token with header present.
    - Invalid cookie with cookie present.
    - Credentials present but authentication state unverified.
    - Valid independently verified User B session.
    - Authentication validation endpoint unavailable or ambiguous.
    """

    @patch("net_guard.guarded_request")
    def test_expired_authorization_token_with_header_present(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """Expired bearer token with header present in session returns INCONCLUSIVE when validation endpoint rejects it."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "user_id": "user_A", "item": "Widget A", "price": 99.99})
        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_a)
        resp_d = make_mock_response(401, '{"error": "Unauthorized"}')
        resp_val_401 = make_mock_response(401, '{"error": "Token expired"}')

        mock_guarded.side_effect = [resp_a, resp_b, resp_d, resp_val_401]

        mock_session_b = MagicMock()
        mock_session_b.headers = {"Authorization": "Bearer expired_token"}
        mock_session_b.cookies = {}
        dual_auth_manager.get_session.side_effect = lambda ident, auto_authenticate=True: mock_session_b if ident == IDENTITY_SECONDARY else MagicMock()

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            target_url_b=None,
            user_b_identifier="user_B",
            user_b_validation_url="https://target.test/api/user/me",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "unverified in 3-way fallback" in res.title.lower() or "credentials" in res.explanation.lower()

    @patch("net_guard.guarded_request")
    def test_invalid_cookie_with_cookie_present(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """Invalid cookie present in session returns INCONCLUSIVE when validation endpoint returns 403 or redirect."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "user_id": "user_A", "item": "Widget A", "price": 99.99})
        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_a)
        resp_d = make_mock_response(401, '{"error": "Unauthorized"}')
        resp_val_302 = make_mock_response(302, "", headers={"Location": "/login"})

        mock_guarded.side_effect = [resp_a, resp_b, resp_d, resp_val_302]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            target_url_b=None,
            user_b_identifier="user_B",
            user_b_validation_url="https://target.test/api/user/me",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "unauthenticated" in res.explanation.lower() or "unverified" in res.title.lower()

    @patch("net_guard.guarded_request")
    def test_credentials_present_but_authentication_state_unverified(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """Credentials are present in session, but no validation endpoint was configured -> INCONCLUSIVE."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "user_id": "user_A", "item": "Widget A", "price": 99.99})
        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_a)
        resp_d = make_mock_response(401, '{"error": "Unauthorized"}')

        mock_guarded.side_effect = [resp_a, resp_b, resp_d]

        # No validation endpoint configured or passed
        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            target_url_b=None,
            user_b_validation_url=None,
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "credential presence alone cannot establish trust" in res.explanation.lower()

    @patch("net_guard.guarded_request")
    def test_valid_independently_verified_user_b_session(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """Validation endpoint succeeds (200 OK) with User B identity -> HIGH_PROBABLE_BOLA."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "user_id": "user_A", "item": "Widget A", "price": 99.99})
        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_a)
        resp_d = make_mock_response(401, '{"error": "Unauthorized"}')
        resp_val_200 = make_mock_response(200, json.dumps({"user_id": "user_B", "email": "user_b@test.com"}))

        mock_guarded.side_effect = [resp_a, resp_b, resp_d, resp_val_200]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            target_url_b=None,
            user_b_identifier="user_B",
            user_b_validation_url="https://target.test/api/user/me",
        )
        assert res.outcome == BOLAOutcome.HIGH_PROBABLE_BOLA
        assert res.is_vulnerable is True
        assert res.confidence.level == ConfidenceLevel.HIGH

    @patch("net_guard.guarded_request")
    def test_authentication_validation_endpoint_unavailable_or_ambiguous(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """Validation endpoint returns 500 Internal Server Error -> INCONCLUSIVE."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "user_id": "user_A", "item": "Widget A", "price": 99.99})
        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_a)
        resp_d = make_mock_response(401, '{"error": "Unauthorized"}')
        resp_val_500 = make_mock_response(500, "Internal Server Error")

        mock_guarded.side_effect = [resp_a, resp_b, resp_d, resp_val_500]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            target_url_b=None,
            user_b_identifier="user_B",
            user_b_validation_url="https://target.test/api/user/me",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "ambiguous" in res.explanation.lower() or "500" in res.explanation


class TestIssue2PublicResourceResourceIdentityValidation:
    """
    CORRECTION 2 — Public Resource Resource Identity Validation Tests:
    - Anonymous receives the same Resource A -> PUBLIC_RESOURCE.
    - Anonymous receives a different resource with identical JSON structure -> not PUBLIC_RESOURCE.
    - Anonymous receives a generic 200 response -> INCONCLUSIVE.
    - Anonymous receives Resource A identifier without sufficient resource evidence -> INCONCLUSIVE.
    """

    @patch("net_guard.guarded_request")
    def test_anonymous_receives_the_same_resource_a(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """Anonymous receives full Resource A with verified ownership and substantive data -> PUBLIC_RESOURCE."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        resource_data = json.dumps({"order_id": "105", "user_id": "user_A", "item": "Widget A", "price": 99.99})

        resp_a = make_mock_response(200, resource_data)
        resp_b = make_mock_response(200, resource_data)
        resp_d = make_mock_response(200, resource_data)

        mock_guarded.side_effect = [resp_a, resp_b, resp_d]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            expected_access_policy=AccessPolicy.PUBLIC,
        )
        assert res.outcome == BOLAOutcome.PUBLIC_RESOURCE
        assert res.is_vulnerable is False

    @patch("net_guard.guarded_request")
    def test_anonymous_receives_different_resource_with_identical_json_structure(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """Anonymous receives a different resource (order_id 999) with identical JSON structure -> not PUBLIC_RESOURCE (INCONCLUSIVE)."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "user_id": "user_A", "item": "Widget A", "price": 99.99})
        # Anonymous gets order 999, not 105!
        data_d = json.dumps({"order_id": "999", "user_id": "user_anon", "item": "Widget A", "price": 99.99})

        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_a)
        resp_d = make_mock_response(200, data_d)

        mock_guarded.side_effect = [resp_a, resp_b, resp_d]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
        )
        assert res.outcome != BOLAOutcome.PUBLIC_RESOURCE
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "resource a identity" in res.title.lower()

    @patch("net_guard.guarded_request")
    def test_anonymous_receives_generic_200_response(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """Anonymous receives a generic 200 OK wrapper (e.g. {"status": "ok"}) -> INCONCLUSIVE."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "user_id": "user_A", "item": "Widget A", "price": 99.99})
        data_d_generic = json.dumps({"status": "ok", "message": "hello"})

        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_a)
        resp_d = make_mock_response(200, data_d_generic)

        mock_guarded.side_effect = [resp_a, resp_b, resp_d]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "substantive resource data" in res.title.lower()

    @patch("net_guard.guarded_request")
    def test_anonymous_receives_resource_a_identifier_without_sufficient_resource_evidence(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """Anonymous receives reflected order_id: 105 but without substantive fields or ownership -> INCONCLUSIVE."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "user_id": "user_A", "item": "Widget A", "price": 99.99})
        data_d_stub = json.dumps({"order_id": "105"})

        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_a)
        resp_d = make_mock_response(200, data_d_stub)

        mock_guarded.side_effect = [resp_a, resp_b, resp_d]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "substantive resource data" in res.title.lower() or "ownership" in res.title.lower()


class TestIssue3AuthorizedVsAccessNotDemonstrated:
    """
    CORRECTION 3 — Authorized vs. Access Not Demonstrated Tests:
    - Explicit 403 denial.
    - Explicit authentication challenge.
    - 404 with insufficient resource-existence evidence.
    - 404 with independently established resource existence.
    - Silent tenant scoping to User B's own resource.
    """

    @patch("net_guard.guarded_request")
    def test_explicit_403_denial(self, mock_guarded, dual_auth_manager, sample_candidate):
        """Explicit 403 Forbidden denial -> AUTHORIZED with explicit title."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "user_id": "user_A", "item": "Widget A"})
        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(403, '{"error": "Forbidden"}')

        mock_guarded.side_effect = [resp_a, resp_b]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
        )
        assert res.outcome == BOLAOutcome.AUTHORIZED
        assert res.is_vulnerable is False
        assert "403 forbidden" in res.title.lower() or "properly enforced" in res.title.lower()

    @patch("net_guard.guarded_request")
    def test_explicit_authentication_challenge(self, mock_guarded, dual_auth_manager, sample_candidate):
        """Explicit 401 Unauthorized or redirect to /login -> AUTHORIZED."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "user_id": "user_A", "item": "Widget A"})
        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(302, "", headers={"Location": "https://target.test/auth/login"})

        mock_guarded.side_effect = [resp_a, resp_b]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
        )
        assert res.outcome == BOLAOutcome.AUTHORIZED
        assert res.is_vulnerable is False
        assert "authentication challenge" in res.title.lower()

    @patch("net_guard.guarded_request")
    def test_404_with_insufficient_resource_existence_evidence(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """Scenario B returns 404, but Scenario A did not establish verified existence/ownership -> ACCESS_NOT_DEMONSTRATED."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        unowned_a = json.dumps({"order_id": "105", "item": "Widget A"})
        resp_a = make_mock_response(200, unowned_a)

        mock_guarded.return_value = resp_a

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
        )
        assert res.outcome in (BOLAOutcome.INCONCLUSIVE, BOLAOutcome.ACCESS_NOT_DEMONSTRATED)
        assert res.is_vulnerable is False

    @patch("net_guard.guarded_request")
    def test_404_with_independently_established_resource_existence(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """Scenario A established that Resource A exists and is owned by User A. Scenario B returns 404 -> AUTHORIZED (concealment)."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "user_id": "user_A", "item": "Widget A", "price": 99.99})
        resp_a = make_mock_response(200, data_a)
        resp_b_404 = make_mock_response(404, '{"error": "Order not found"}')

        mock_guarded.side_effect = [resp_a, resp_b_404]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
        )
        assert res.outcome == BOLAOutcome.RESOURCE_EXISTENCE_CONCEALED
        assert res.is_vulnerable is False
        assert "404" in res.title
        assert "concealed" in res.title.lower() or "enumeration" in res.explanation.lower()

    @patch("net_guard.guarded_request")
    def test_silent_tenant_scoping_to_user_b_own_resource(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """User B requests Resource A (/orders/105) but server silently returns User B's own record -> AUTHORIZED."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "user_id": "user_A", "item": "Widget A"})
        data_b = json.dumps({"order_id": "205", "user_id": "user_B", "item": "Widget B"})

        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_b)

        mock_guarded.side_effect = [resp_a, resp_b]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            target_url_b="https://target.test/api/v1/orders/205",
            user_b_identifier="user_B",
            resource_b_identifier="205",
        )
        assert res.outcome == BOLAOutcome.AUTHORIZED
        assert res.is_vulnerable is False
        assert "tenant scoping" in res.title.lower()


class TestPrincipalValidation:
    """
    ISSUE 1 — Principal Validation in _validate_secondary_authentication:
    a. Public validation endpoint returns 200 without identity.
    b. Validation endpoint returns another user's identity.
    c. Validation endpoint returns User B's exact identity.
    d. User B's invalid credentials receive a public 200 response.
    e. Validation response contains incomplete identity attributes.
    f. Validation request accidentally uses the primary identity session.
    """

    @patch("net_guard.guarded_request")
    def test_public_validation_endpoint_returns_200_without_identity(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """Public validation endpoint returns 200 without principal identity attributes -> INCONCLUSIVE."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "user_id": "user_A", "item": "Widget A", "price": 99.99})
        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_a)
        resp_d = make_mock_response(401, '{"error": "Unauthorized"}')
        # Public landing/health endpoint returning 200 with no user identity
        resp_val_pub = make_mock_response(200, '{"status": "ok", "app": "HackBack", "version": "1.0"}')

        mock_guarded.side_effect = [resp_a, resp_b, resp_d, resp_val_pub]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            target_url_b=None,
            user_b_identifier="user_B",
            user_b_validation_url="https://target.test/api/health",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "lacks authenticated principal" in res.explanation.lower()

    @patch("net_guard.guarded_request")
    def test_validation_endpoint_returns_another_users_identity(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """Validation endpoint returns a different user's principal (e.g. user_A/alice instead of user_B) -> INCONCLUSIVE."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "user_id": "user_A", "item": "Widget A", "price": 99.99})
        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_a)
        resp_d = make_mock_response(401, '{"error": "Unauthorized"}')
        # Returns another user's identity!
        resp_val_wrong = make_mock_response(200, json.dumps({"user_id": "user_A", "username": "alice"}))

        mock_guarded.side_effect = [resp_a, resp_b, resp_d, resp_val_wrong]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            target_url_b=None,
            user_b_identifier="user_B",
            user_b_validation_url="https://target.test/api/user/me",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "principal mismatch" in res.explanation.lower()

    @patch("net_guard.guarded_request")
    def test_validation_endpoint_returns_user_b_exact_identity(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """Validation endpoint returns exact User B principal -> HIGH_PROBABLE_BOLA."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "user_id": "user_A", "item": "Widget A", "price": 99.99})
        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_a)
        resp_d = make_mock_response(401, '{"error": "Unauthorized"}')
        # Valid principal matching user_B
        resp_val_ok = make_mock_response(200, json.dumps({"user_id": "user_B", "email": "bob@test.com"}))

        mock_guarded.side_effect = [resp_a, resp_b, resp_d, resp_val_ok]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            target_url_b=None,
            user_b_identifier="user_B",
            user_b_validation_url="https://target.test/api/user/me",
        )
        assert res.outcome == BOLAOutcome.HIGH_PROBABLE_BOLA
        assert res.is_vulnerable is True
        assert res.confidence.level == ConfidenceLevel.HIGH

    @patch("net_guard.guarded_request")
    def test_user_b_invalid_credentials_receive_public_200_response(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """User B's invalid/unauthenticated credentials receive a generic public 200 response -> INCONCLUSIVE."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "user_id": "user_A", "item": "Widget A", "price": 99.99})
        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_a)
        resp_d = make_mock_response(401, '{"error": "Unauthorized"}')
        # Public guest fallback 200 response
        resp_val_guest = make_mock_response(200, json.dumps({"status": "guest", "public": True, "user": None}))

        mock_guarded.side_effect = [resp_a, resp_b, resp_d, resp_val_guest]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            target_url_b=None,
            user_b_identifier="user_B",
            user_b_validation_url="https://target.test/api/profile",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "lacks authenticated principal" in res.explanation.lower()

    @patch("net_guard.guarded_request")
    def test_validation_response_contains_incomplete_identity_attributes(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """Validation response returns 200 OK but lacks concrete principal keys (e.g. only {"authenticated": true}) -> INCONCLUSIVE."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "user_id": "user_A", "item": "Widget A", "price": 99.99})
        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_a)
        resp_d = make_mock_response(401, '{"error": "Unauthorized"}')
        # Incomplete identity attributes
        resp_val_inc = make_mock_response(200, json.dumps({"authenticated": True, "session_active": True}))

        mock_guarded.side_effect = [resp_a, resp_b, resp_d, resp_val_inc]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            target_url_b=None,
            user_b_identifier="user_B",
            user_b_validation_url="https://target.test/api/auth/status",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "incomplete identity attributes" in res.explanation.lower()

    @patch("net_guard.guarded_request")
    def test_validation_request_accidentally_uses_primary_identity_session(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """Validation request uses User A session or shares credentials -> session isolation violation -> INCONCLUSIVE."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "user_id": "user_A", "item": "Widget A", "price": 99.99})
        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_a)
        resp_d = make_mock_response(401, '{"error": "Unauthorized"}')

        mock_guarded.side_effect = [resp_a, resp_b, resp_d]

        # Force dual_auth_manager to return the same session object for primary and secondary
        shared_session = MagicMock()
        shared_session.headers = {"Authorization": "Bearer shared_token"}
        shared_session.cookies = {}
        dual_auth_manager.get_session.side_effect = lambda ident, auto_authenticate=True: shared_session

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            target_url_b=None,
            user_b_identifier="user_B",
            user_b_validation_url="https://target.test/api/user/me",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "session isolation violation" in res.explanation.lower()


class TestRefined404VerdictSemantics:
    """
    ISSUE 2 — Refined 404 Verdict Semantics Tests:
    - Explicit authorization denial (403 / 401 redirect) -> AUTHORIZED
    - Verified silent tenant scoping -> AUTHORIZED
    - Existing resource concealed through 404 -> RESOURCE_EXISTENCE_CONCEALED
    - 404 without independently verified resource existence -> ACCESS_NOT_DEMONSTRATED
    - Ambiguous routing error on 404 -> INCONCLUSIVE
    - Ambiguous server error (500) on Scenario B -> INCONCLUSIVE
    """

    @patch("net_guard.guarded_request")
    def test_explicit_authorization_denial_403(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """Explicit 403 Forbidden denial -> AUTHORIZED."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "user_id": "user_A", "item": "Widget A"})
        resp_a = make_mock_response(200, data_a)
        resp_b_403 = make_mock_response(403, '{"error": "Access denied"}')

        mock_guarded.side_effect = [resp_a, resp_b_403]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
        )
        assert res.outcome == BOLAOutcome.AUTHORIZED
        assert res.is_vulnerable is False
        assert "properly enforced" in res.title.lower()

    @patch("net_guard.guarded_request")
    def test_verified_silent_tenant_scoping(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """User B requests Resource A (/orders/105), server silently scopes and returns User B's own data -> AUTHORIZED."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "user_id": "user_A", "item": "Widget A"})
        data_b_own = json.dumps({"order_id": "205", "user_id": "user_B", "item": "Widget B"})

        resp_a = make_mock_response(200, data_a)
        resp_b_scoped = make_mock_response(200, data_b_own)

        mock_guarded.side_effect = [resp_a, resp_b_scoped]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            target_url_b="https://target.test/api/v1/orders/205",
            user_b_identifier="user_B",
            resource_b_identifier="205",
        )
        assert res.outcome == BOLAOutcome.AUTHORIZED
        assert res.is_vulnerable is False
        assert "tenant scoping" in res.title.lower()

    @patch("net_guard.guarded_request")
    def test_existing_resource_concealed_through_404(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """Scenario A established Resource A exists and belongs to User A. Scenario B returns 404 -> RESOURCE_EXISTENCE_CONCEALED."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "user_id": "user_A", "item": "Widget A", "price": 99.99})
        resp_a = make_mock_response(200, data_a)
        resp_b_404 = make_mock_response(404, '{"error": "Resource not found"}')

        mock_guarded.side_effect = [resp_a, resp_b_404]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
        )
        assert res.outcome == BOLAOutcome.RESOURCE_EXISTENCE_CONCEALED
        assert res.is_vulnerable is False
        assert "concealed" in res.title.lower()

    @patch("net_guard.guarded_request")
    def test_404_without_independently_verified_resource_existence(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """Scenario A did not establish verified existence/ownership. Scenario B returns 404 -> ACCESS_NOT_DEMONSTRATED."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        unowned_a = json.dumps({"order_id": "105", "item": "Widget A"})
        resp_a = make_mock_response(200, unowned_a)

        mock_guarded.return_value = resp_a

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
        )
        assert res.outcome in (BOLAOutcome.INCONCLUSIVE, BOLAOutcome.ACCESS_NOT_DEMONSTRATED)
        assert res.is_vulnerable is False

    @patch("net_guard.guarded_request")
    def test_ambiguous_routing_error_on_404(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """Scenario B returns 404 with generic web framework / gateway routing error -> INCONCLUSIVE."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "user_id": "user_A", "item": "Widget A", "price": 99.99})
        resp_a = make_mock_response(200, data_a)
        resp_b_route_err = make_mock_response(404, "Cannot GET /api/v1/orders/105")

        mock_guarded.side_effect = [resp_a, resp_b_route_err]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "routing error" in res.title.lower()

    @patch("net_guard.guarded_request")
    def test_ambiguous_server_error_500_on_scenario_b(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """Scenario B triggers 500 Internal Server Error -> INCONCLUSIVE."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "user_id": "user_A", "item": "Widget A", "price": 99.99})
        resp_a = make_mock_response(200, data_a)
        resp_b_500 = make_mock_response(500, "Internal Server Error")

        mock_guarded.side_effect = [resp_a, resp_b_500]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "server error" in res.title.lower()


class TestPublicVsUnexpectedAnonymousAccess:
    """
    ISSUE 3 — Public Resource vs. Unexpected Anonymous Access Tests:
    - Explicitly public resource -> PUBLIC_RESOURCE (not vulnerable).
    - Anonymous access to independently established private resource -> UNEXPECTED_ANONYMOUS_ACCESS (critical exposure).
    - Ambiguous access policy -> INCONCLUSIVE (not vulnerable, qualified).
    """

    @patch("net_guard.guarded_request")
    def test_explicitly_public_resource_returns_public_resource(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """Explicitly configured public policy + anonymous retrieves data -> PUBLIC_RESOURCE (is_vulnerable=False)."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "user_id": "user_A", "item": "Public Catalog Item", "price": 10.0})

        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_a)
        resp_d = make_mock_response(200, data_a)

        mock_guarded.side_effect = [resp_a, resp_b, resp_d]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            expected_access_policy=AccessPolicy.PUBLIC,
        )
        assert res.outcome == BOLAOutcome.PUBLIC_RESOURCE
        assert res.is_vulnerable is False
        assert "explicitly public resource" in res.title.lower()

    @patch("net_guard.guarded_request")
    def test_anonymous_access_to_private_resource_is_unexpected_anonymous_access(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """Configured PRIVATE policy + anonymous retrieves private data -> UNEXPECTED_ANONYMOUS_ACCESS (is_vulnerable=True)."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "user_id": "user_A", "item": "Confidential Medical Record", "diagnosis": "Secret"})

        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_a)
        resp_d = make_mock_response(200, data_a)

        mock_guarded.side_effect = [resp_a, resp_b, resp_d]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            expected_access_policy=AccessPolicy.PRIVATE,
        )
        assert res.outcome == BOLAOutcome.UNEXPECTED_ANONYMOUS_ACCESS
        assert res.is_vulnerable is True
        assert "critical exposure" in res.title.lower()
        assert res.reproduction_curl is not None

    @patch("net_guard.guarded_request")
    def test_ambiguous_access_policy_anonymous_access_is_inconclusive(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """Unknown policy + anonymous retrieves data -> INCONCLUSIVE (is_vulnerable=False, qualified)."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "user_id": "user_A", "item": "Widget A", "price": 99.99})

        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_a)
        resp_d = make_mock_response(200, data_a)

        mock_guarded.side_effect = [resp_a, resp_b, resp_d]

        # No policy provided, candidate authentication_context is None -> UNKNOWN
        sample_candidate.authentication_context = None

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            expected_access_policy=AccessPolicy.UNKNOWN,
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "policy unknown" in res.title.lower() or "inconclusive" in res.title.lower()

    @patch("net_guard.guarded_request")
    def test_discovery_anonymous_context_alone_does_not_imply_public_policy(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """
        Finding 3: Discovery authentication context alone must not be treated as
        authoritative policy evidence. When expected policy is UNKNOWN, candidate.authentication_context='anonymous'
        must NOT produce PUBLIC_RESOURCE; it must remain INCONCLUSIVE.
        """
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "user_id": "user_A", "item": "Widget A", "price": 99.99})

        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_a)
        resp_d = make_mock_response(200, data_a)

        mock_guarded.side_effect = [resp_a, resp_b, resp_d]

        # Discovery context was anonymous, but expected_access_policy is UNKNOWN
        sample_candidate.authentication_context = "anonymous"

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            expected_access_policy=AccessPolicy.UNKNOWN,
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "policy unknown" in res.title.lower() or "inconclusive" in res.title.lower()


class TestPrincipalAttributeMatchingAndSessionIsolation:
    """
    CRITICAL CORRECTION — Principal Attribute Matching & Session Isolation Tests:
    1. Expected User B ID matches response ID -> accepted.
    2. Expected User B ID matches username but response ID belongs to User A -> rejected.
    3. Expected User B email matches another unrelated claim -> rejected.
    4. Canonical ID and username conflict -> rejected.
    5. Two explicitly configured claims agree -> accepted.
    6. Two explicitly configured claims conflict -> rejected.
    7. Shared cookie jar between primary and secondary sessions -> INCONCLUSIVE.
    """

    @patch("net_guard.guarded_request")
    def test_expected_user_b_id_matches_response_id_accepted(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """Expected User B ID matches response ID -> accepted (HIGH_PROBABLE_BOLA)."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "user_id": "user_A", "item": "Widget A", "price": 99.99})
        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_a)
        resp_d = make_mock_response(401, '{"error": "Unauthorized"}')
        resp_val = make_mock_response(200, json.dumps({"id": "user-B", "username": "bob"}))

        mock_guarded.side_effect = [resp_a, resp_b, resp_d, resp_val]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            target_url_b=None,
            expected_user_b_claims={"id": "user-B"},
            user_b_validation_url="https://target.test/api/user/me",
        )
        assert res.outcome == BOLAOutcome.HIGH_PROBABLE_BOLA
        assert res.is_vulnerable is True

    @patch("net_guard.guarded_request")
    def test_expected_user_b_id_matches_username_but_response_id_belongs_to_user_a_rejected(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """Expected User B ID matches username but canonical ID belongs to User A -> rejected (INCONCLUSIVE)."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "user_id": "user_A", "item": "Widget A", "price": 99.99})
        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_a)
        resp_d = make_mock_response(401, '{"error": "Unauthorized"}')
        # Vulnerability probe: ID belongs to user-A, but username happens to be user-B
        resp_val_wrong = make_mock_response(200, json.dumps({"id": "user-A", "username": "user-B", "email": "userA@example.com"}))

        mock_guarded.side_effect = [resp_a, resp_b, resp_d, resp_val_wrong]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            target_url_b=None,
            expected_user_b_claims={"id": "user-B"},
            user_b_validation_url="https://target.test/api/user/me",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "principal mismatch for claim 'id'" in res.explanation.lower()

    @patch("net_guard.guarded_request")
    def test_expected_user_b_email_matches_another_unrelated_claim_rejected(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """Expected email matches an unrelated attribute (e.g. support_contact) but canonical email is different -> rejected."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "user_id": "user_A", "item": "Widget A", "price": 99.99})
        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_a)
        resp_d = make_mock_response(401, '{"error": "Unauthorized"}')
        resp_val_unrelated = make_mock_response(200, json.dumps({
            "id": "user-B",
            "email": "userA@example.com",
            "support_contact": "userB@example.com"
        }))

        mock_guarded.side_effect = [resp_a, resp_b, resp_d, resp_val_unrelated]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            target_url_b=None,
            expected_user_b_claims={"email": "userB@example.com"},
            user_b_validation_url="https://target.test/api/user/me",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "principal mismatch for claim 'email'" in res.explanation.lower()

    @patch("net_guard.guarded_request")
    def test_canonical_id_and_username_conflict_rejected(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """Canonical ID and username in validation response conflict with configured expected claims -> rejected."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "user_id": "user_A", "item": "Widget A", "price": 99.99})
        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_a)
        resp_d = make_mock_response(401, '{"error": "Unauthorized"}')
        # Response has ID for user-A and username for user-B
        resp_val_conflict = make_mock_response(200, json.dumps({"id": "user-A", "username": "user-B"}))

        mock_guarded.side_effect = [resp_a, resp_b, resp_d, resp_val_conflict]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            target_url_b=None,
            expected_user_b_claims={"id": "user-B", "username": "user-B"},
            user_b_validation_url="https://target.test/api/user/me",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "principal mismatch for claim 'id'" in res.explanation.lower()

    @patch("net_guard.guarded_request")
    def test_two_explicitly_configured_claims_agree_accepted(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """Two explicitly configured claims (id and username) both match validation response -> accepted."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "user_id": "user_A", "item": "Widget A", "price": 99.99})
        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_a)
        resp_d = make_mock_response(401, '{"error": "Unauthorized"}')
        resp_val_agree = make_mock_response(200, json.dumps({"id": "user-B", "username": "bob"}))

        mock_guarded.side_effect = [resp_a, resp_b, resp_d, resp_val_agree]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            target_url_b=None,
            expected_user_b_claims={"id": "user-B", "username": "bob"},
            user_b_validation_url="https://target.test/api/user/me",
        )
        assert res.outcome == BOLAOutcome.HIGH_PROBABLE_BOLA
        assert res.is_vulnerable is True

    @patch("net_guard.guarded_request")
    def test_two_explicitly_configured_claims_conflict_rejected(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """Two explicitly configured claims conflict (id matches, but username belongs to someone else) -> rejected."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "user_id": "user_A", "item": "Widget A", "price": 99.99})
        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_a)
        resp_d = make_mock_response(401, '{"error": "Unauthorized"}')
        resp_val_conflict = make_mock_response(200, json.dumps({"id": "user-B", "username": "mallory"}))

        mock_guarded.side_effect = [resp_a, resp_b, resp_d, resp_val_conflict]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            target_url_b=None,
            expected_user_b_claims={"id": "user-B", "username": "bob"},
            user_b_validation_url="https://target.test/api/user/me",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "principal mismatch for claim 'username'" in res.explanation.lower()

    @patch("net_guard.guarded_request")
    def test_shared_cookie_jar_between_primary_and_secondary_sessions_is_inconclusive(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """Primary and secondary sessions share the same CookieJar instance -> session isolation violation -> INCONCLUSIVE."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "user_id": "user_A", "item": "Widget A", "price": 99.99})
        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_a)
        resp_d = make_mock_response(401, '{"error": "Unauthorized"}')

        mock_guarded.side_effect = [resp_a, resp_b, resp_d]

        # Configure shared CookieJar instance between session A and session B
        shared_jar = MagicMock()
        sess_a = MagicMock()
        sess_a.headers = {"Authorization": "Bearer token_a"}
        sess_a.cookies = shared_jar

        sess_b = MagicMock()
        sess_b.headers = {"Authorization": "Bearer token_b"}
        sess_b.cookies = shared_jar  # Shared mutable CookieJar!

        sessions_map = {
            IDENTITY_PRIMARY: sess_a,
            IDENTITY_SECONDARY: sess_b,
            IDENTITY_ANONYMOUS: MagicMock(),
        }
        dual_auth_manager.get_session.side_effect = lambda ident, auto_authenticate=True: sessions_map.get(ident, MagicMock())

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            target_url_b=None,
            expected_user_b_claims={"id": "user-B"},
            user_b_validation_url="https://target.test/api/user/me",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "session isolation violation" in res.explanation.lower()
        assert "cookiejar" in res.explanation.lower()


class TestSessionIsolationRules:
    """
    Finding 2: Missing sessions must never count as isolated.
    Verifies that check_session_isolation:
    - Returns False when both sessions are None.
    - Returns False when primary session is None.
    - Returns False when secondary session is None.
    - Returns True when both sessions are independently initialized.
    - Returns False when both sessions reference the same session object.
    - Returns False when both sessions share a CookieJar instance.
    - Causes engine to produce INCONCLUSIVE when either required identity session is unavailable.
    """

    def test_both_sessions_missing_fails_closed(self):
        ok, msg = check_session_isolation(None, None)
        assert ok is False
        assert "both primary and secondary sessions are None" in msg

    def test_primary_session_missing_fails_closed(self):
        sess_b = requests.Session()
        ok, msg = check_session_isolation(None, sess_b)
        assert ok is False
        assert "primary session is None" in msg

    def test_secondary_session_missing_fails_closed(self):
        sess_a = requests.Session()
        ok, msg = check_session_isolation(sess_a, None)
        assert ok is False
        assert "secondary session is None" in msg

    def test_both_sessions_independently_initialized_accepted(self):
        sess_a = requests.Session()
        sess_b = requests.Session()
        ok, msg = check_session_isolation(sess_a, sess_b)
        assert ok is True
        assert "strictly isolated" in msg

    def test_same_session_object_rejected(self):
        sess = requests.Session()
        ok, msg = check_session_isolation(sess, sess)
        assert ok is False
        assert "identical instance" in msg

    def test_shared_cookie_jar_rejected(self):
        sess_a = requests.Session()
        sess_b = requests.Session()
        sess_b.cookies = sess_a.cookies
        ok, msg = check_session_isolation(sess_a, sess_b)
        assert ok is False
        assert "CookieJar" in msg

    @patch("net_guard.guarded_request")
    def test_engine_produces_inconclusive_when_primary_session_missing(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        engine = BOLAVerificationEngine(dual_auth_manager)
        # Mock get_session returning None for primary
        dual_auth_manager.get_session.side_effect = lambda ident, auto_authenticate=True: (
            None if ident == IDENTITY_PRIMARY else requests.Session()
        )

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "session isolation" in res.explanation.lower()
        assert "primary session is none" in res.explanation.lower()

    @patch("net_guard.guarded_request")
    def test_engine_produces_inconclusive_when_secondary_session_missing(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        engine = BOLAVerificationEngine(dual_auth_manager)
        # Mock get_session returning None for secondary
        dual_auth_manager.get_session.side_effect = lambda ident, auto_authenticate=True: (
            requests.Session() if ident == IDENTITY_PRIMARY else None
        )

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "session isolation" in res.explanation.lower()
        assert "secondary session is none" in res.explanation.lower()


class TestSessionIdentityManagerAudit:
    """
    Finding 4: Complete session isolation audit.
    Audits SessionIdentityManager session construction and lifecycle:
    - Session object identity.
    - Mutable headers.
    - Cookie jars.
    - Authentication objects.
    - HTTP adapters and transport state.
    - Shared mutable configuration.
    - Authentication cleanup and lifecycle.
    - Cross-identity credential leakage.
    - Distinguishes immutable configuration from mutable state.
    """

    def test_session_construction_separate_instances_and_state(self):
        """Verify that newly created sessions have distinct identity, headers, cookies, adapters."""
        sess_a = requests.Session()
        sess_b = requests.Session()

        # Session object identity
        assert sess_a is not sess_b

        # Mutable headers
        assert sess_a.headers is not sess_b.headers

        # Cookie jars
        assert sess_a.cookies is not sess_b.cookies

        # Adapters
        assert sess_a.adapters is not sess_b.adapters

        # Mutable hooks
        assert sess_a.hooks is not sess_b.hooks

        # Full isolation check
        ok, msg = check_session_isolation(sess_a, sess_b)
        assert ok is True

    def test_safe_shared_immutable_configuration_accepted(self):
        """Safe shared configuration (like Boolean verify=True or string CA path) does not fail isolation."""
        sess_a = requests.Session()
        sess_b = requests.Session()
        sess_a.verify = True
        sess_b.verify = True  # Same immutable boolean

        ok, msg = check_session_isolation(sess_a, sess_b)
        assert ok is True
        assert "strictly isolated" in msg

    def test_shared_mutable_adapters_dict_fails_closed(self):
        """If two sessions share mutable adapters dictionary, check_session_isolation rejects."""
        sess_a = requests.Session()
        sess_b = requests.Session()
        sess_b.adapters = sess_a.adapters  # Shared mutable adapters dict

        ok, msg = check_session_isolation(sess_a, sess_b)
        assert ok is False
        assert "adapters dict" in msg

    def test_shared_mutable_params_dict_fails_closed(self):
        """If two sessions share mutable params dictionary, check_session_isolation rejects."""
        sess_a = requests.Session()
        sess_b = requests.Session()
        shared_params = {"mode": "test"}
        sess_a.params = shared_params
        sess_b.params = shared_params

        ok, msg = check_session_isolation(sess_a, sess_b)
        assert ok is False
        assert "params dict" in msg

    def test_shared_mutable_hooks_dict_fails_closed(self):
        """If two sessions share mutable hooks dictionary, check_session_isolation rejects."""
        sess_a = requests.Session()
        sess_b = requests.Session()
        sess_b.hooks = sess_a.hooks

        ok, msg = check_session_isolation(sess_a, sess_b)
        assert ok is False
        assert "hooks dict" in msg

    def test_shared_authorization_header_fails_closed(self):
        """If two sessions share the exact same Authorization header, check_session_isolation rejects."""
        sess_a = requests.Session()
        sess_b = requests.Session()
        sess_a.headers["Authorization"] = "Bearer leaked_shared_token_xyz"
        sess_b.headers["Authorization"] = "Bearer leaked_shared_token_xyz"

        ok, msg = check_session_isolation(sess_a, sess_b)
        assert ok is False
        assert "Authorization header" in msg

    def test_shared_sensitive_cookie_fails_closed(self):
        """If two sessions share an identical sensitive cookie, check_session_isolation rejects."""
        sess_a = requests.Session()
        sess_b = requests.Session()
        sess_a.cookies.set("sessionid", "shared_token_12345", domain="target.test", path="/")
        sess_b.cookies.set("sessionid", "shared_token_12345", domain="target.test", path="/")

        ok, msg = check_session_isolation(sess_a, sess_b)
        assert ok is False
        assert "sensitive cookie 'sessionid'" in msg

    def test_session_identity_manager_close_lifecycle(self):
        """SessionIdentityManager.close() clears sessions, cookies, headers, and prevents reuse."""
        sim = SessionIdentityManager(primary_auth={"type": "bearer", "token": "tok_a"})
        # Authenticate anonymous baseline session
        sim.authenticate(IDENTITY_ANONYMOUS)
        sess = sim.get_session(IDENTITY_ANONYMOUS)
        assert sess is not None

        # Close manager
        sim.close()
        assert sim.is_closed is True

        # Reusing closed manager raises RuntimeError
        with pytest.raises(RuntimeError, match="closed and cannot be reused"):
            sim.authenticate(IDENTITY_ANONYMOUS)


class TestPrincipalIdentityCategorySeparation:
    """
    Finding 1: Principal identity category separation.
    Verifies that:
    - User ID and Account ID are separated; account_id cannot satisfy user_id without explicit mapping.
    - user_id cannot satisfy account_id without explicit mapping.
    - Cross-category mapping requires explicit configuration (claim_mappings).
    - Intra-category contradictions in extracted claims fail closed.
    - Intra-category contradictions in configured expected claims fail closed.
    - Tenant ID and Profile ID are separated from user_id.
    """

    def test_account_id_cannot_satisfy_user_id_without_explicit_mapping(self):
        extracted = {"account_id": "user-A", "username": "alice"}
        expected = {"user_id": "user-A"}
        ok, msg = compare_authenticated_principal(extracted, expected)
        assert ok is False
        assert "Required identity claim 'user_id' (category 'user_id') was not found" in msg

    def test_user_id_cannot_satisfy_account_id_without_explicit_mapping(self):
        extracted = {"user_id": "acc-100", "username": "alice"}
        expected = {"account_id": "acc-100"}
        ok, msg = compare_authenticated_principal(extracted, expected)
        assert ok is False
        assert "Required identity claim 'account_id' (category 'account_id') was not found" in msg

    def test_account_id_satisfies_user_id_with_explicit_mapping(self):
        extracted = {"account_id": "user-A", "username": "alice"}
        expected = {"user_id": "user-A"}
        ok, msg = compare_authenticated_principal(
            extracted,
            expected,
            claim_mappings={"account_id": "user_id"}
        )
        assert ok is True
        assert "Principal identity verified" in msg

    def test_intra_category_contradiction_in_extracted_claims_fails_closed(self):
        # Both 'id' and 'user_id' belong to canonical user_id category
        extracted = {"id": "user-1", "user_id": "user-2"}
        expected = {"user_id": "user-1"}
        ok, msg = compare_authenticated_principal(extracted, expected)
        assert ok is False
        assert "conflicting 'user_id' claims" in msg

    def test_intra_category_contradiction_in_expected_claims_fails_closed(self):
        extracted = {"user_id": "user-1"}
        expected = {"id": "user-1", "user_id": "user-2"}
        ok, msg = compare_authenticated_principal(extracted, expected)
        assert ok is False
        assert "internal contradiction for category 'user_id'" in msg

    def test_tenant_id_and_profile_id_separation(self):
        extracted = {"tenant_id": "tenant-corp", "profile_id": "prof-99"}
        expected = {"user_id": "tenant-corp"}
        ok, msg = compare_authenticated_principal(extracted, expected)
        assert ok is False
        assert "category 'user_id'" in msg


class TestScenarioCReverseControlHardening:
    """
    Finding 2: Hardened Scenario C reverse-control verification.
    Verifies that:
    - User B appearing in response without Resource B returns INCONCLUSIVE.
    - Resource B appearing but belonging to another user returns INCONCLUSIVE.
    - Resource B identical to Resource A returns INCONCLUSIVE.
    - Soft-404 or empty response on Resource B returns INCONCLUSIVE.
    - Missing substantive business data on Resource B returns INCONCLUSIVE.
    """

    @patch("net_guard.guarded_request")
    def test_scenario_c_user_b_appears_but_resource_b_does_not_is_inconclusive(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A", "price": 100})
        data_b = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A", "price": 100})
        data_d = json.dumps({"error": "Unauthorized"})
        # Scenario C has user_B but lacks order_id 205 (only generic response)
        data_c = json.dumps({"item": "Widget B", "user_id": "user_B", "price": 50})

        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_b)
        resp_d = make_mock_response(401, data_d)
        resp_c = make_mock_response(200, data_c)
        mock_guarded.side_effect = [resp_a, resp_b, resp_d, resp_c]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            target_url_b="https://target.test/api/v1/orders/205",
            user_b_identifier="user_B",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "Resource B Identifier Missing" in res.title
        assert "205" in res.explanation

    @patch("net_guard.guarded_request")
    def test_scenario_c_resource_b_appears_but_ownership_belongs_to_other_user_is_inconclusive(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A", "price": 100})
        data_b = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A", "price": 100})
        data_d = json.dumps({"error": "Unauthorized"})
        # Resource B has order_id 205 but owner is user_attacker, NOT user_B!
        data_c = json.dumps({"order_id": "205", "item": "Widget B", "user_id": "user_attacker", "price": 50})

        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_b)
        resp_d = make_mock_response(401, data_d)
        resp_c = make_mock_response(200, data_c)
        mock_guarded.side_effect = [resp_a, resp_b, resp_d, resp_c]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            target_url_b="https://target.test/api/v1/orders/205",
            user_b_identifier="user_B",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "Ownership Evidence Missing or Invalid" in res.title

    @patch("net_guard.guarded_request")
    def test_scenario_c_resource_b_identical_to_resource_a_is_inconclusive(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A", "price": 100})
        data_b = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A", "price": 100})
        data_d = json.dumps({"error": "Unauthorized"})

        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_b)
        resp_d = make_mock_response(401, data_d)
        mock_guarded.side_effect = [resp_a, resp_b, resp_d]

        # Pass target_url_b identical to target_url_a
        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            target_url_b="https://target.test/api/v1/orders/105",
            user_b_identifier="user_B",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "Resource B Identical to Resource A" in res.title

    @patch("net_guard.guarded_request")
    def test_scenario_c_soft_404_on_resource_b_is_inconclusive(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A", "price": 100})
        data_b = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A", "price": 100})
        data_d = json.dumps({"error": "Unauthorized"})
        data_c = json.dumps({"status": 404, "message": "Order not found"})

        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_b)
        resp_d = make_mock_response(401, data_d)
        resp_c = make_mock_response(200, data_c)
        mock_guarded.side_effect = [resp_a, resp_b, resp_d, resp_c]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            target_url_b="https://target.test/api/v1/orders/205",
            user_b_identifier="user_B",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "Resource B Soft-404" in res.title

    @patch("net_guard.guarded_request")
    def test_scenario_c_missing_resource_a_id_is_inconclusive(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """Scenario C requires Resource A ID; missing Resource A ID returns INCONCLUSIVE."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"item": "Widget A", "user_id": "user_A", "price": 100})
        data_b = json.dumps({"item": "Widget A", "user_id": "user_A", "price": 100})
        data_d = json.dumps({"error": "Unauthorized"})

        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_b)
        resp_d = make_mock_response(401, data_d)
        mock_guarded.side_effect = [resp_a, resp_b, resp_d]

        # URL has no ID and resource_a_identifier is empty
        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders",
            user_a_identifier="user_A",
            resource_a_identifier="",
            target_url_b="https://target.test/api/v1/orders/205",
            user_b_identifier="user_B",
            resource_b_identifier="205",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "Resource A Identifier Missing" in res.title

    @patch("net_guard.guarded_request")
    def test_scenario_c_missing_resource_b_id_is_inconclusive(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """Scenario C requires Resource B ID; missing Resource B ID returns INCONCLUSIVE."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A", "price": 100})
        data_b = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A", "price": 100})
        data_d = json.dumps({"error": "Unauthorized"})

        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_b)
        resp_d = make_mock_response(401, data_d)
        mock_guarded.side_effect = [resp_a, resp_b, resp_d]

        # URL B has no ID and resource_b_identifier is empty
        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            target_url_b="https://target.test/api/v1/orders",
            user_b_identifier="user_B",
            resource_b_identifier="",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "Resource B Identifier Missing" in res.title

    @patch("net_guard.guarded_request")
    def test_scenario_c_different_urls_same_resource_id_is_inconclusive(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """Different URLs with identical resource identifiers (URL alias/duplicate) returns INCONCLUSIVE."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A", "price": 100})
        data_b = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A", "price": 100})
        data_d = json.dumps({"error": "Unauthorized"})

        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_b)
        resp_d = make_mock_response(401, data_d)
        mock_guarded.side_effect = [resp_a, resp_b, resp_d]

        # Different URLs, but both have resource ID "105"
        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            target_url_b="https://target.test/api/v2/orders/105",
            user_b_identifier="user_B",
            resource_b_identifier="105",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "Resource B Identical to Resource A" in res.title

    @patch("net_guard.guarded_request")
    def test_scenario_c_url_alias_returning_resource_a_is_inconclusive(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """Scenario C URL unexpectedly returns Resource A data -> INCONCLUSIVE."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A", "price": 100})
        data_b = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A", "price": 100})
        data_d = json.dumps({"error": "Unauthorized"})
        # Scenario C returns Resource A's ID 105
        data_c = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_B", "price": 100})

        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_b)
        resp_d = make_mock_response(401, data_d)
        resp_c = make_mock_response(200, data_c)
        mock_guarded.side_effect = [resp_a, resp_b, resp_d, resp_c]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            target_url_b="https://target.test/api/v1/orders/alias-205",
            user_b_identifier="user_B",
            resource_b_identifier="205",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "Scenario C Contains Resource A Identifier" in res.title

    @patch("net_guard.guarded_request")
    def test_scenario_c_distinct_resource_ids_confirmed_bola(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """Independently established distinct Resource A (105) and B (205) yields CONFIRMED_BOLA."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A", "price": 100})
        data_b = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A", "price": 100})
        data_d = json.dumps({"error": "Unauthorized"})
        data_c = json.dumps({"order_id": "205", "item": "Widget B", "user_id": "user_B", "price": 50})

        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_b)
        resp_d = make_mock_response(401, data_d)
        resp_c = make_mock_response(200, data_c)
        mock_guarded.side_effect = [resp_a, resp_b, resp_d, resp_c]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            target_url_b="https://target.test/api/v1/orders/205",
            user_b_identifier="user_B",
            resource_b_identifier="205",
        )
        assert res.outcome == BOLAOutcome.CONFIRMED_BOLA
        assert res.is_vulnerable is True
        assert res.confidence.level == ConfidenceLevel.CERTAIN

    @patch("net_guard.guarded_request")
    def test_scenario_c_with_expected_user_b_claims_none(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """Scenario C operates cleanly when expected_user_b_claims=None using expected_user_b_identifier."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A", "price": 100})
        data_b = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A", "price": 100})
        data_d = json.dumps({"error": "Unauthorized"})
        data_c = json.dumps({"order_id": "205", "item": "Widget B", "user_id": "user_B_special", "price": 50})

        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_b)
        resp_d = make_mock_response(401, data_d)
        resp_c = make_mock_response(200, data_c)
        mock_guarded.side_effect = [resp_a, resp_b, resp_d, resp_c]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            target_url_b="https://target.test/api/v1/orders/205",
            user_b_identifier="user_B_fallback",
            expected_user_b_identifier="user_B_special",
            expected_user_b_claims=None,
            resource_b_identifier="205",
        )
        assert res.outcome == BOLAOutcome.CONFIRMED_BOLA
        assert res.is_vulnerable is True

    @patch("net_guard.guarded_request")
    def test_three_way_fallback_with_expected_user_b_claims_none(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """Three-way fallback operates cleanly when expected_user_b_claims=None."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A", "price": 100})
        data_b = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A", "price": 100})
        data_d = json.dumps({"error": "Unauthorized"})
        data_val = json.dumps({"id": "user_B", "email": "user_b@test.com"})

        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_b)
        resp_d = make_mock_response(401, data_d)
        resp_val = make_mock_response(200, data_val)
        mock_guarded.side_effect = [resp_a, resp_b, resp_d, resp_val]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            target_url_b=None,  # Triggers 3-way fallback
            user_b_identifier="user_B",
            expected_user_b_identifier="user_B",
            expected_user_b_claims=None,
            user_b_validation_url="https://target.test/api/v1/user/me",
        )
        assert res.outcome == BOLAOutcome.HIGH_PROBABLE_BOLA
        assert res.is_vulnerable is True


class TestScenarioDAnonymous404Classification:
    """
    Finding 1 & 2: Trust-Boundary and Secure Anonymous 404 classification in Scenario D.
    Verifies that:
    - Caller-supplied boolean masking policy is rejected as untrusted (fails closed).
    - Untrusted provenance or scope-mismatched policy is rejected.
    - Verified TargetAuthorizationPolicy enables 404 acceptance and records provenance.
    - Cross-origin nonexistent probe URLs are rejected as out of scope.
    - Nonexistent probe scheme mismatches are rejected.
    - SSRF guard blocks non-public IPs (localhost, private, link-local).
    - Nonexistent probe redirects are strictly rejected.
    - Response body and content-type mismatches between Scenario D and probe fail closed.
    - Empty probe response bodies fail closed.
    - Nonexistent probe enforces anonymous context isolation without credentials.
    - Generic gateway or framework routing error on Scenario D produces INCONCLUSIVE.
    """

    @patch("net_guard.guarded_request")
    def test_authenticated_access_succeeds_anonymous_produces_verified_authorization_masking_404(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """1. Authenticated access succeeds, anonymous access produces verified authorization-masking 404."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        data_b = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        data_c = json.dumps({"order_id": "205", "item": "Widget B", "user_id": "user_B"})
        data_d = json.dumps({"error": "Resource not found or unauthorized"})

        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_b)
        resp_d = make_mock_response(404, data_d)
        resp_c = make_mock_response(200, data_c)
        mock_guarded.side_effect = [resp_a, resp_b, resp_d, resp_c]

        policy = TargetAuthorizationPolicy.create_trusted_policy(
            target_domain="target.test",
            masks_404=True,
            provenance="verified_target_profile",
        )

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            target_url_b="https://target.test/api/v1/orders/205",
            user_b_identifier="user_B",
            resource_b_identifier="205",
            authorization_masking_policy=policy,
        )
        assert res.outcome == BOLAOutcome.CONFIRMED_BOLA
        assert res.is_vulnerable is True
        assert any("verified_target_profile" in sig for sig in res.confidence.signals)

    @patch("net_guard.guarded_request")
    def test_forged_policy_is_trusted_true_without_valid_signature_rejected(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """Caller attempting to instantiate TargetAuthorizationPolicy with is_trusted=True fails closed."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        data_b = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        data_d = json.dumps({"error": "Not found"})

        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_b)
        resp_d = make_mock_response(404, data_d)
        mock_guarded.side_effect = [resp_a, resp_b, resp_d]

        # Forged policy instantiated directly with is_trusted=True but without valid HMAC trust token
        forged_policy = TargetAuthorizationPolicy(
            target_domain="target.test",
            masks_404=True,
            provenance="verified_target_profile",
            is_trusted=True,
            trust_token=None,  # Missing trust token
        )

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            authorization_masking_policy=forged_policy,
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "Untrusted Authorization Masking Policy" in res.title
        assert "missing cryptographic trust token" in res.explanation

    @patch("net_guard.guarded_request")
    def test_tampered_policy_domain_or_route_invalidates_signature(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """A validly created trusted policy whose domain or parameters are tampered with fails closed."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        data_b = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        data_d = json.dumps({"error": "Not found"})

        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_b)
        resp_d = make_mock_response(404, data_d)
        mock_guarded.side_effect = [resp_a, resp_b, resp_d]

        # Validly created policy
        policy = TargetAuthorizationPolicy.create_trusted_policy(
            target_domain="target.test",
            masks_404=True,
            provenance="verified_target_profile",
        )
        # Tamper with the policy's target domain
        tampered_policy = policy.model_copy(update={"target_domain": "tampered.test"})

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            authorization_masking_policy=tampered_policy,
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "Untrusted Authorization Masking Policy" in res.title
        assert "Forged policy detected" in res.explanation

    @patch("net_guard.guarded_request")
    def test_ordinary_dict_or_scan_input_cannot_forge_trusted_policy(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """Dictionary supplied from scan input cannot establish trusted masking policy -> INCONCLUSIVE."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        data_b = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        data_d = json.dumps({"error": "Not found"})

        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_b)
        resp_d = make_mock_response(404, data_d)
        mock_guarded.side_effect = [resp_a, resp_b, resp_d]

        # Ordinary scan input dictionary
        dict_policy = {
            "target_domain": "target.test",
            "masks_404": True,
            "is_trusted": True,
            "provenance": "verified_target_profile",
        }

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            authorization_masking_policy=dict_policy,
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "Untrusted Authorization Masking Policy" in res.title

    @patch("net_guard.guarded_request")
    def test_caller_supplied_raw_boolean_masking_policy_rejected_as_untrusted(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """Caller-supplied raw boolean True cannot establish trusted masking policy -> INCONCLUSIVE."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        data_b = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        data_d = json.dumps({"error": "Not found"})

        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_b)
        resp_d = make_mock_response(404, data_d)
        mock_guarded.side_effect = [resp_a, resp_b, resp_d]

        # Pass raw boolean True without trusted TargetAuthorizationPolicy
        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            authorization_masking_policy=True,
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "Untrusted Authorization Masking Policy" in res.title
        assert "untrusted boolean flags cannot establish authorization masking" in res.explanation

    @patch("net_guard.guarded_request")
    def test_untrusted_masking_policy_provenance_rejected(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """TargetAuthorizationPolicy with is_trusted=False or untrusted provenance fails closed."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        data_b = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        data_d = json.dumps({"error": "Not found"})

        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_b)
        resp_d = make_mock_response(404, data_d)
        mock_guarded.side_effect = [resp_a, resp_b, resp_d]

        untrusted_policy = TargetAuthorizationPolicy(
            target_domain="target.test",
            masks_404=True,
            provenance="untrusted_request_param",
            is_trusted=False,
        )

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            authorization_masking_policy=untrusted_policy,
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "Untrusted Authorization Masking Policy" in res.title

    @patch("net_guard.guarded_request")
    def test_scope_mismatched_masking_policy_rejected(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """TargetAuthorizationPolicy targeting a different domain than candidate fails closed."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        data_b = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        data_d = json.dumps({"error": "Not found"})

        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_b)
        resp_d = make_mock_response(404, data_d)
        mock_guarded.side_effect = [resp_a, resp_b, resp_d]

        mismatched_policy = TargetAuthorizationPolicy.create_trusted_policy(
            target_domain="different-domain.test",
            masks_404=True,
            provenance="target_config",
        )

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            authorization_masking_policy=mismatched_policy,
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "Untrusted Authorization Masking Policy" in res.title
        assert "does not match candidate target_domain" in res.explanation

    @patch("net_guard.guarded_request")
    def test_anonymous_404_with_no_evidence_establishing_authorization_semantics_is_inconclusive(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """2. Anonymous 404 with no evidence establishing authorization semantics -> INCONCLUSIVE."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        data_b = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        data_d = json.dumps({"error": "Not found"})

        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_b)
        resp_d = make_mock_response(404, data_d)
        mock_guarded.side_effect = [resp_a, resp_b, resp_d]

        # No authorization_masking_policy and no nonexistent_resource_url
        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "Ambiguous Anonymous 404 Response" in res.title
        assert "authorization-masking policy" in res.explanation

    @patch("net_guard.assert_public_host")
    @patch("net_guard.guarded_request")
    def test_nonexistent_resource_control_validates_authorization_masking_404(
        self, mock_guarded, mock_assert_public, dual_auth_manager, sample_candidate
    ):
        """3. A nonexistent resource returning 404 verifies masking semantics -> CONFIRMED_BOLA."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        data_b = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        data_d = json.dumps({"error": "Resource not found"})
        data_nonexistent = json.dumps({"error": "Resource not found"})
        data_c = json.dumps({"order_id": "205", "item": "Widget B", "user_id": "user_B"})

        resp_a = make_mock_response(200, data_a, headers={"Content-Type": "application/json"})
        resp_b = make_mock_response(200, data_b, headers={"Content-Type": "application/json"})
        resp_d = make_mock_response(404, data_d, headers={"Content-Type": "application/json"})
        resp_nonexistent = make_mock_response(404, data_nonexistent, headers={"Content-Type": "application/json"})
        resp_c = make_mock_response(200, data_c, headers={"Content-Type": "application/json"})
        mock_guarded.side_effect = [resp_a, resp_b, resp_d, resp_nonexistent, resp_c]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            target_url_b="https://target.test/api/v1/orders/205",
            user_b_identifier="user_B",
            resource_b_identifier="205",
            nonexistent_resource_url="https://target.test/api/v1/orders/nonexistent_999999",
        )
        assert res.outcome == BOLAOutcome.CONFIRMED_BOLA
        assert res.is_vulnerable is True

    @patch("net_guard.assert_public_host")
    @patch("net_guard.guarded_request")
    def test_nonexistent_resource_control_mismatch_returns_inconclusive(
        self, mock_guarded, mock_assert_public, dual_auth_manager, sample_candidate
    ):
        """3b. Nonexistent resource returning non-404 fails masking verification -> INCONCLUSIVE."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        data_b = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        data_d = json.dumps({"error": "Resource not found"})
        data_nonexistent = json.dumps({"message": "Welcome anonymous"})

        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_b)
        resp_d = make_mock_response(404, data_d)
        # Nonexistent returns 200 instead of 404
        resp_nonexistent = make_mock_response(200, data_nonexistent)
        mock_guarded.side_effect = [resp_a, resp_b, resp_d, resp_nonexistent]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            target_url_b="https://target.test/api/v1/orders/205",
            user_b_identifier="user_B",
            resource_b_identifier="205",
            nonexistent_resource_url="https://target.test/api/v1/orders/nonexistent_999999",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "Nonexistent Resource Control Mismatch" in res.title

    @patch("net_guard.guarded_request")
    def test_nonexistent_probe_cross_origin_rejected_as_out_of_scope(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """Cross-origin nonexistent probe URL is rejected as out of scope -> INCONCLUSIVE."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        data_b = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        data_d = json.dumps({"error": "Resource not found"})

        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_b)
        resp_d = make_mock_response(404, data_d)
        mock_guarded.side_effect = [resp_a, resp_b, resp_d]

        # Probe targets untrusted external domain evil.test
        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            nonexistent_resource_url="https://evil.test/api/v1/orders/nonexistent",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "Nonexistent Control Probe Out of Scope" in res.title
        assert "violates target scope boundary" in res.explanation

    @patch("net_guard.guarded_request")
    def test_nonexistent_probe_scheme_mismatch_rejected(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """Nonexistent probe URL with scheme mismatch (http vs https) is rejected -> INCONCLUSIVE."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        data_b = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        data_d = json.dumps({"error": "Resource not found"})

        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_b)
        resp_d = make_mock_response(404, data_d)
        mock_guarded.side_effect = [resp_a, resp_b, resp_d]

        # Probe has http scheme while target has https
        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            nonexistent_resource_url="http://target.test/api/v1/orders/nonexistent",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "Nonexistent Control Probe Scheme Mismatch" in res.title

    @patch("net_guard.assert_public_host")
    @patch("net_guard.guarded_request")
    def test_nonexistent_probe_private_ip_blocked_by_ssrf_guard(
        self, mock_guarded, mock_assert_public, dual_auth_manager, sample_candidate
    ):
        """Nonexistent probe targeting private IP (127.0.0.1, 169.254.x) is blocked by SSRF defense."""
        import net_guard
        mock_assert_public.side_effect = net_guard.SsrfBlocked("127.0.0.1 is a non-public address")

        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        data_b = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        data_d = json.dumps({"error": "Resource not found"})

        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_b)
        resp_d = make_mock_response(404, data_d)
        mock_guarded.side_effect = [resp_a, resp_b, resp_d]

        # Candidate target is 127.0.0.1
        sample_candidate.target_domain = "127.0.0.1"
        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://127.0.0.1/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            nonexistent_resource_url="https://127.0.0.1/api/v1/orders/nonexistent",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "Nonexistent Control Probe SSRF Blocked" in res.title
        assert "blocked by SSRF defense" in res.explanation

    @patch("net_guard.assert_public_host")
    @patch("net_guard.guarded_request")
    def test_nonexistent_probe_redirect_rejected(
        self, mock_guarded, mock_assert_public, dual_auth_manager, sample_candidate
    ):
        """Nonexistent probe returning 302 redirect is rejected -> INCONCLUSIVE."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        data_b = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        data_d = json.dumps({"error": "Resource not found"})

        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_b)
        resp_d = make_mock_response(404, data_d)
        resp_probe = make_mock_response(302, "", headers={"Location": "https://target.test/login"})
        mock_guarded.side_effect = [resp_a, resp_b, resp_d, resp_probe]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            nonexistent_resource_url="https://target.test/api/v1/orders/nonexistent",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "Nonexistent Control Probe Redirect Rejected" in res.title

    @patch("net_guard.assert_public_host")
    @patch("net_guard.guarded_request")
    def test_nonexistent_probe_mismatched_content_type_fails_closed(
        self, mock_guarded, mock_assert_public, dual_auth_manager, sample_candidate
    ):
        """Scenario D 404 is JSON while probe 404 is text/html -> INCONCLUSIVE."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        data_b = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        data_d = json.dumps({"error": "Resource not found"})

        resp_a = make_mock_response(200, data_a, headers={"Content-Type": "application/json"})
        resp_b = make_mock_response(200, data_b, headers={"Content-Type": "application/json"})
        resp_d = make_mock_response(404, data_d, headers={"Content-Type": "application/json"})
        resp_probe = make_mock_response(404, "<html>Not Found</html>", headers={"Content-Type": "text/html"})
        mock_guarded.side_effect = [resp_a, resp_b, resp_d, resp_probe]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            nonexistent_resource_url="https://target.test/api/v1/orders/nonexistent",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "Nonexistent Resource Control Response Mismatch" in res.title
        assert "Content-Type mismatch" in res.confidence.deductions[0]

    @patch("net_guard.assert_public_host")
    @patch("net_guard.guarded_request")
    def test_nonexistent_probe_mismatched_error_envelopes_fails_closed(
        self, mock_guarded, mock_assert_public, dual_auth_manager, sample_candidate
    ):
        """Scenario D and probe return completely disjoint JSON error keys -> INCONCLUSIVE."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        data_b = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        data_d = json.dumps({"error": "Resource not found"})
        data_probe = json.dumps({"status_code": 404, "timestamp": 123456})

        resp_a = make_mock_response(200, data_a, headers={"Content-Type": "application/json"})
        resp_b = make_mock_response(200, data_b, headers={"Content-Type": "application/json"})
        resp_d = make_mock_response(404, data_d, headers={"Content-Type": "application/json"})
        resp_probe = make_mock_response(404, data_probe, headers={"Content-Type": "application/json"})
        mock_guarded.side_effect = [resp_a, resp_b, resp_d, resp_probe]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            nonexistent_resource_url="https://target.test/api/v1/orders/nonexistent",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "Nonexistent Resource Control Response Mismatch" in res.title
        assert "JSON error envelopes" in res.confidence.deductions[0]

    @patch("net_guard.assert_public_host")
    @patch("net_guard.guarded_request")
    def test_nonexistent_probe_empty_body_fails_closed(
        self, mock_guarded, mock_assert_public, dual_auth_manager, sample_candidate
    ):
        """Nonexistent probe returning empty body fails closed -> INCONCLUSIVE."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        data_b = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        data_d = json.dumps({"error": "Resource not found"})

        resp_a = make_mock_response(200, data_a, headers={"Content-Type": "application/json"})
        resp_b = make_mock_response(200, data_b, headers={"Content-Type": "application/json"})
        resp_d = make_mock_response(404, data_d, headers={"Content-Type": "application/json"})
        resp_probe = make_mock_response(404, "", headers={"Content-Type": "application/json"})
        mock_guarded.side_effect = [resp_a, resp_b, resp_d, resp_probe]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            nonexistent_resource_url="https://target.test/api/v1/orders/nonexistent",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "Nonexistent Resource Control Response Mismatch" in res.title

    @patch("net_guard.assert_public_host")
    @patch("net_guard.guarded_request")
    def test_nonexistent_probe_conflicting_error_code_returns_inconclusive(
        self, mock_guarded, mock_assert_public, dual_auth_manager, sample_candidate
    ):
        """Scenario D and control probe with conflicting error codes fail closed -> INCONCLUSIVE."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        data_b = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        data_d = json.dumps({"code": "NOT_FOUND", "message": "Order 105 not found"})
        data_probe = json.dumps({"code": "INVALID_QUERY_PARAM", "message": "Order 105 not found"})

        resp_a = make_mock_response(200, data_a, headers={"Content-Type": "application/json"})
        resp_b = make_mock_response(200, data_b, headers={"Content-Type": "application/json"})
        resp_d = make_mock_response(404, data_d, headers={"Content-Type": "application/json"})
        resp_probe = make_mock_response(404, data_probe, headers={"Content-Type": "application/json"})
        mock_guarded.side_effect = [resp_a, resp_b, resp_d, resp_probe]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            nonexistent_resource_url="https://target.test/api/v1/orders/nonexistent",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "Nonexistent Resource Control Response Mismatch" in res.title
        assert "Conflicting error code" in res.confidence.deductions[0]

    @patch("net_guard.assert_public_host")
    @patch("net_guard.guarded_request")
    def test_nonexistent_probe_semantic_error_conflict_validation_vs_not_found(
        self, mock_guarded, mock_assert_public, dual_auth_manager, sample_candidate
    ):
        """One response indicating validation/syntax error while the other indicates not-found fails closed."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        data_b = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        data_d = json.dumps({"error": "Resource does not exist or unauthorized"})
        data_probe = json.dumps({"error": "Validation error: invalid param syntax for id"})

        resp_a = make_mock_response(200, data_a, headers={"Content-Type": "application/json"})
        resp_b = make_mock_response(200, data_b, headers={"Content-Type": "application/json"})
        resp_d = make_mock_response(404, data_d, headers={"Content-Type": "application/json"})
        resp_probe = make_mock_response(404, data_probe, headers={"Content-Type": "application/json"})
        mock_guarded.side_effect = [resp_a, resp_b, resp_d, resp_probe]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            nonexistent_resource_url="https://target.test/api/v1/orders/nonexistent",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "Nonexistent Resource Control Response Mismatch" in res.title
        assert "Semantic error conflict" in res.confidence.deductions[0]

    @patch("net_guard.assert_public_host")
    @patch("net_guard.guarded_request")
    def test_nonexistent_probe_non_json_dissimilar_below_085_returns_inconclusive(
        self, mock_guarded, mock_assert_public, dual_auth_manager, sample_candidate
    ):
        """Non-JSON 404 responses with semantic similarity below 0.85 fail closed -> INCONCLUSIVE."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        data_b = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        body_d = "Custom Application Error: The requested entity 105 could not be found in active tenant scope."
        body_probe = "General Resource Notice: No database entry matches the requested resource key."

        resp_a = make_mock_response(200, data_a, headers={"Content-Type": "text/plain"})
        resp_b = make_mock_response(200, data_b, headers={"Content-Type": "text/plain"})
        resp_d = make_mock_response(404, body_d, headers={"Content-Type": "text/plain"})
        resp_probe = make_mock_response(404, body_probe, headers={"Content-Type": "text/plain"})
        mock_guarded.side_effect = [resp_a, resp_b, resp_d, resp_probe]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            nonexistent_resource_url="https://target.test/api/v1/orders/nonexistent",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "Nonexistent Resource Control Response Mismatch" in res.title
        assert "similarity" in res.confidence.deductions[0].lower()

    @patch("net_guard.assert_public_host")
    @patch("net_guard.guarded_request")
    def test_nonexistent_probe_empty_json_container_returns_inconclusive(
        self, mock_guarded, mock_assert_public, dual_auth_manager, sample_candidate
    ):
        """404 response returning an empty JSON object {} fails closed -> INCONCLUSIVE."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        data_b = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})

        resp_a = make_mock_response(200, data_a, headers={"Content-Type": "application/json"})
        resp_b = make_mock_response(200, data_b, headers={"Content-Type": "application/json"})
        resp_d = make_mock_response(404, "{}", headers={"Content-Type": "application/json"})
        resp_probe = make_mock_response(404, "{}", headers={"Content-Type": "application/json"})
        mock_guarded.side_effect = [resp_a, resp_b, resp_d, resp_probe]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            nonexistent_resource_url="https://target.test/api/v1/orders/nonexistent",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "Nonexistent Resource Control Response Mismatch" in res.title
        assert "empty JSON container" in res.confidence.deductions[0]

    @patch("net_guard.guarded_request")
    def test_ambiguous_application_level_404_is_inconclusive(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """4. An ambiguous application-level 404 without verification -> INCONCLUSIVE."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        data_b = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        data_d = json.dumps({"status": "failed", "detail": "Item not found in current session context"})

        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_b)
        resp_d = make_mock_response(404, data_d)
        mock_guarded.side_effect = [resp_a, resp_b, resp_d]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            authorization_masking_policy=None,
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "Ambiguous Anonymous 404 Response" in res.title

    @patch("net_guard.guarded_request")
    def test_generic_gateway_or_framework_routing_404_is_inconclusive(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """5. Generic gateway/framework 404 (Express, Nginx) on Scenario D returns INCONCLUSIVE."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_a)
        resp_d = make_mock_response(404, "<pre>Cannot GET /api/v1/orders/105</pre>")
        mock_guarded.side_effect = [resp_a, resp_b, resp_d]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "Ambiguous Routing Error on Scenario D" in res.title
        assert "routing or gateway error text" in res.explanation

    @patch("net_guard.guarded_request")
    def test_scenario_d_nginx_gateway_routing_404_is_inconclusive(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """Generic Nginx/proxy 404 routing failure on Scenario D returns INCONCLUSIVE."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_a)
        resp_d = make_mock_response(404, "<html><body><center><h1>404 Not Found</h1></center><hr><center>nginx</center></body></html>")
        mock_guarded.side_effect = [resp_a, resp_b, resp_d]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "Ambiguous Routing Error on Scenario D" in res.title

    @patch("net_guard.assert_public_host")
    @patch("net_guard.guarded_request")
    def test_nonexistent_probe_matching_status_and_keys_without_app_semantics_is_inconclusive(
        self, mock_guarded, mock_assert_public, dual_auth_manager, sample_candidate
    ):
        """Status codes and JSON keys without application-specific resource-not-found semantics fail closed."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        data_b = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        # Shared error key 'error', but value is generic without resource-absence markers
        data_d = json.dumps({"error": "operation failed", "status": "failed"})
        data_nonexistent = json.dumps({"error": "operation failed", "status": "failed"})
        mock_guarded.side_effect = [
            make_mock_response(200, data_a, headers={"Content-Type": "application/json"}),
            make_mock_response(200, data_b, headers={"Content-Type": "application/json"}),
            make_mock_response(404, data_d, headers={"Content-Type": "application/json"}),
            make_mock_response(404, data_nonexistent, headers={"Content-Type": "application/json"}),
        ]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            nonexistent_resource_url="https://target.test/api/v1/orders/nonexistent_999999",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "Uncorroborated Authorization Masking Semantics" in res.title
        assert "Matching status codes, JSON keys, and structural similarity alone cannot independently prove" in res.confidence.deductions[0]

    @patch("net_guard.assert_public_host")
    @patch("net_guard.guarded_request")
    def test_nonexistent_probe_corroborates_with_trusted_masking_policy(
        self, mock_guarded, mock_assert_public, dual_auth_manager, sample_candidate
    ):
        """Nonexistent probe corroborates authorization denial when accompanied by trusted TargetAuthorizationPolicy."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        data_b = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        data_d = json.dumps({"error": "unspecified failure", "code": "ERR_OPAQUE"})
        data_nonexistent = json.dumps({"error": "unspecified failure", "code": "ERR_OPAQUE"})
        data_c = json.dumps({"order_id": "205", "item": "Widget B", "user_id": "user_B"})
        mock_guarded.side_effect = [
            make_mock_response(200, data_a, headers={"Content-Type": "application/json"}),
            make_mock_response(200, data_b, headers={"Content-Type": "application/json"}),
            make_mock_response(404, data_d, headers={"Content-Type": "application/json"}),
            make_mock_response(404, data_nonexistent, headers={"Content-Type": "application/json"}),
            make_mock_response(200, data_c, headers={"Content-Type": "application/json"}),
        ]

        policy = TargetAuthorizationPolicy.create_trusted_policy(
            target_domain="target.test",
            masks_404=True,
            provenance="verified_target_profile",
        )

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            target_url_b="https://target.test/api/v1/orders/205",
            user_b_identifier="user_B",
            resource_b_identifier="205",
            authorization_masking_policy=policy,
            nonexistent_resource_url="https://target.test/api/v1/orders/nonexistent_999999",
        )
        assert res.outcome == BOLAOutcome.CONFIRMED_BOLA
        assert res.is_vulnerable is True

    @patch("net_guard.assert_public_host")
    @patch("net_guard.guarded_request")
    def test_nonexistent_probe_non_json_without_resource_semantics_is_inconclusive(
        self, mock_guarded, mock_assert_public, dual_auth_manager, sample_candidate
    ):
        """Non-JSON responses with high text similarity but generic error text fail closed to INCONCLUSIVE."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        data_b = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        html_d = "<html><body><h1>System Notice: Requested operation unavailable</h1><p>Contact support if needed.</p></body></html>"
        html_probe = "<html><body><h1>System Notice: Requested operation unavailable</h1><p>Contact support if needed.</p></body></html>"
        mock_guarded.side_effect = [
            make_mock_response(200, data_a, headers={"Content-Type": "text/html"}),
            make_mock_response(200, data_b, headers={"Content-Type": "text/html"}),
            make_mock_response(404, html_d, headers={"Content-Type": "text/html"}),
            make_mock_response(404, html_probe, headers={"Content-Type": "text/html"}),
        ]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            nonexistent_resource_url="https://target.test/api/v1/orders/nonexistent_999999",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "Uncorroborated Authorization Masking Semantics" in res.title


class TestEvidenceSanitization:
    """
    Finding 4: Stored evidence sanitization.
    Verifies that:
    - Set-Cookie, Authorization, and sensitive headers are redacted.
    - Safe cache headers (Age, X-Cache, CF-Cache-Status) are preserved.
    - URLs with userinfo or sensitive parameters are sanitized.
    - Exceptions are sanitized for credential leakage.
    - Serialized verification results contain no raw secrets or tokens.
    """

    def test_sensitive_headers_redacted_and_cache_headers_preserved(self):
        raw = {
            "Set-Cookie": "session_id=secret_cookie_val; HttpOnly",
            "Authorization": "Bearer secret_bearer_token",
            "X-Api-Key": "super_secret_api_key",
            "Age": "120",
            "X-Cache": "HIT",
            "CF-Cache-Status": "HIT",
            "X-Varnish": "9876543",
            "Content-Type": "application/json",
        }
        sanitized = sanitize_response_headers(raw)
        assert sanitized["Set-Cookie"] == "[REDACTED]"
        assert sanitized["Authorization"] == "[REDACTED]"
        assert sanitized["X-Api-Key"] == "[REDACTED]"
        assert sanitized["Age"] == "120"
        assert sanitized["X-Cache"] == "HIT"
        assert sanitized["CF-Cache-Status"] == "HIT"
        assert sanitized["X-Varnish"] == "9876543"
        assert sanitized["Content-Type"] == "application/json"

    @patch("net_guard.guarded_request")
    def test_serialized_verification_result_contains_no_secrets(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A", "price": 100})
        data_b = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A", "price": 100})
        data_c = json.dumps({"order_id": "205", "item": "Widget B", "user_id": "user_B", "price": 50})

        headers_with_secret = {
            "Content-Type": "application/json",
            "Set-Cookie": "auth_token=super_secret_session_token_12345; Path=/",
            "Authorization": "Bearer super_secret_jwt_token_99999",
            "X-Cache": "HIT",
        }

        resp_a = make_mock_response(200, data_a, headers=headers_with_secret)
        resp_b = make_mock_response(200, data_b, headers=headers_with_secret)
        resp_d = make_mock_response(401, '{"error": "Unauthorized"}')
        resp_c = make_mock_response(200, data_c, headers=headers_with_secret)
        mock_guarded.side_effect = [resp_a, resp_b, resp_d, resp_c]

        # URL containing userinfo and sensitive query param
        dirty_url_a = "https://admin:pass123@target.test/api/v1/orders/105?token=raw_api_secret_777"
        dirty_url_b = "https://target.test/api/v1/orders/205?api_key=raw_key_888"

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a=dirty_url_a,
            user_a_identifier="user_A",
            target_url_b=dirty_url_b,
            user_b_identifier="user_B",
        )

        serialized = json.dumps(res.to_dict())
        # Assert no sensitive secrets appear anywhere in the serialized evidence
        assert "super_secret_session_token_12345" not in serialized
        assert "super_secret_jwt_token_99999" not in serialized
        assert "pass123" not in serialized
        assert "raw_api_secret_777" not in serialized
        assert "raw_key_888" not in serialized
        # Assert cache header is preserved
        assert '"X-Cache": "HIT"' in serialized


class TestScenarioAServerErrorClassification:
    """
    Finding 5: Correct Scenario A error classification according to decision table.
    Verifies that:
    - 5xx responses (500, 502, 503, 504) return INCONCLUSIVE (upstream failure, not authorization failure).
    - Network and timeout errors return INCONCLUSIVE.
    - 401 and 403 authorization denials return BASELINE_FAILED.
    - 404 resource not found returns BASELINE_FAILED.
    """

    @patch("net_guard.guarded_request")
    def test_scenario_a_500_server_error_is_inconclusive(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        engine = BOLAVerificationEngine(dual_auth_manager)
        mock_guarded.return_value = make_mock_response(500, '{"error": "Internal Server Error"}')

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "Server Error on Baseline" in res.title
        assert "500" in res.explanation

    @patch("net_guard.guarded_request")
    def test_scenario_a_502_bad_gateway_is_inconclusive(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        engine = BOLAVerificationEngine(dual_auth_manager)
        mock_guarded.return_value = make_mock_response(502, "<html>Bad Gateway</html>")

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert "502" in res.explanation

    @patch("net_guard.guarded_request")
    def test_scenario_a_503_service_unavailable_is_inconclusive(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        engine = BOLAVerificationEngine(dual_auth_manager)
        mock_guarded.return_value = make_mock_response(503, "Service Unavailable")

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert "503" in res.explanation

    @patch("net_guard.guarded_request")
    def test_scenario_a_504_gateway_timeout_is_inconclusive(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        engine = BOLAVerificationEngine(dual_auth_manager)
        mock_guarded.return_value = make_mock_response(504, "Gateway Timeout")

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert "504" in res.explanation

    @patch("net_guard.guarded_request")
    def test_scenario_a_connection_error_is_inconclusive(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        engine = BOLAVerificationEngine(dual_auth_manager)
        mock_guarded.side_effect = requests.exceptions.ConnectionError("Connection refused by peer")

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "Network Error on Baseline" in res.title

    @patch("net_guard.guarded_request")
    def test_scenario_a_timeout_is_inconclusive(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        engine = BOLAVerificationEngine(dual_auth_manager)
        mock_guarded.side_effect = requests.exceptions.Timeout("Read operation timed out")

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "Network Error on Baseline" in res.title

    @patch("net_guard.guarded_request")
    def test_scenario_a_401_authorization_denial_is_baseline_failed(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        engine = BOLAVerificationEngine(dual_auth_manager)
        mock_guarded.return_value = make_mock_response(401, '{"error": "Unauthorized"}')

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
        )
        assert res.outcome == BOLAOutcome.BASELINE_FAILED
        assert "Authorization Denial" in res.title
        assert "401" in res.explanation

    @patch("net_guard.guarded_request")
    def test_scenario_a_403_forbidden_is_baseline_failed(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        engine = BOLAVerificationEngine(dual_auth_manager)
        mock_guarded.return_value = make_mock_response(403, '{"error": "Forbidden"}')

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
        )
        assert res.outcome == BOLAOutcome.BASELINE_FAILED
        assert "Authorization Denial" in res.title
        assert "403" in res.explanation

    @patch("net_guard.guarded_request")
    def test_scenario_a_404_not_found_is_baseline_failed(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        engine = BOLAVerificationEngine(dual_auth_manager)
        mock_guarded.return_value = make_mock_response(404, '{"error": "Not Found"}')

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
        )
        assert res.outcome == BOLAOutcome.BASELINE_FAILED
        assert "Resource Not Found" in res.title
        assert "404" in res.explanation

    @patch("net_guard.guarded_request")
    def test_scenario_a_410_gone_is_baseline_failed(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        engine = BOLAVerificationEngine(dual_auth_manager)
        mock_guarded.return_value = make_mock_response(410, '{"error": "Gone"}')

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
        )
        assert res.outcome == BOLAOutcome.BASELINE_FAILED
        assert "Resource Not Found" in res.title
        assert "410" in res.explanation

    @patch("net_guard.guarded_request")
    def test_scenario_a_unexpected_redirect_302_is_inconclusive(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        engine = BOLAVerificationEngine(dual_auth_manager)
        mock_guarded.return_value = make_mock_response(302, "", headers={"Location": "https://target.test/auth/login"})

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "Unexpected Redirect on Baseline" in res.title
        assert "302" in res.explanation

    @patch("net_guard.guarded_request")
    def test_scenario_a_unexpected_redirect_301_is_inconclusive(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        engine = BOLAVerificationEngine(dual_auth_manager)
        mock_guarded.return_value = make_mock_response(301, "", headers={"Location": "https://target.test/api/v2/orders/105"})

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "Unexpected Redirect on Baseline" in res.title
        assert "301" in res.explanation

    @patch("net_guard.guarded_request")
    def test_scenario_a_429_rate_limited_is_inconclusive(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        engine = BOLAVerificationEngine(dual_auth_manager)
        mock_guarded.return_value = make_mock_response(429, '{"error": "Too Many Requests"}')

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "Unexpected Status on Baseline" in res.title
        assert "429" in res.explanation


class TestScenarioBSoft404InconclusiveVerdict:
    """
    Finding 2: Scenario B soft-404 / generic empty error payload handling.
    An empty or generic 200 response must NEVER be treated as proof that authorization is enforced.
    Must fail closed as INCONCLUSIVE unless safe tenant scoping is independently established
    or a definitive authorization denial is received.
    """

    @patch("net_guard.guarded_request")
    def test_scenario_b_empty_json_is_inconclusive(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "user_id": "user_A", "item": "Widget A", "price": 100})
        resp_a = make_mock_response(200, data_a)
        # Empty JSON object {}
        resp_b_empty = make_mock_response(200, "{}")
        mock_guarded.side_effect = [resp_a, resp_b_empty]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "soft-404" in res.title.lower() or "generic error" in res.title.lower()

    @patch("net_guard.guarded_request")
    def test_scenario_b_generic_error_envelope_is_inconclusive(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "user_id": "user_A", "item": "Widget A", "price": 100})
        resp_a = make_mock_response(200, data_a)
        # 200 OK with generic error envelope
        resp_b_err = make_mock_response(200, json.dumps({"error": "Resource not found", "status": "error"}))
        mock_guarded.side_effect = [resp_a, resp_b_err]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "soft-404" in res.title.lower() or "generic error" in res.title.lower()

    @patch("net_guard.guarded_request")
    def test_scenario_b_empty_data_wrapper_is_inconclusive(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "user_id": "user_A", "item": "Widget A", "price": 100})
        resp_a = make_mock_response(200, data_a)
        # 200 OK with empty data wrapper
        resp_b_empty_data = make_mock_response(200, json.dumps({"data": [], "count": 0}))
        mock_guarded.side_effect = [resp_a, resp_b_empty_data]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "soft-404" in res.title.lower() or "generic error" in res.title.lower()

    @patch("net_guard.guarded_request")
    def test_scenario_b_application_level_failure_is_inconclusive(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "user_id": "user_A", "item": "Widget A", "price": 100})
        resp_a = make_mock_response(200, data_a)
        # 200 OK with application level failure flag
        resp_b_fail = make_mock_response(200, json.dumps({"success": False, "message": "Failed to process request"}))
        mock_guarded.side_effect = [resp_a, resp_b_fail]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "soft-404" in res.title.lower() or "generic error" in res.title.lower()


class TestScenarioCHighSimilarityReverseControl:
    """
    Finding 3: Scenario C reverse-control with high semantic similarity.
    Similarity is not resource identity. Distinct resources with independently verified
    ownership must remain valid reverse controls even when their business fields are highly similar.
    """

    @patch("net_guard.guarded_request")
    def test_distinct_resources_with_high_semantic_similarity_confirm_bola(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """
        Resource A (order 105, user_A) and Resource B (order 205, user_B) have identical
        business fields (item, price, status, currency). Semantic similarity >= 0.95.
        Because resource identifiers and ownership are distinct and verified independently,
        Scenario C succeeds and CONFIRMED_BOLA is returned with CERTAIN confidence.
        """
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({
            "order_id": "105",
            "user_id": "user_A",
            "item": "Premium Enterprise Subscription",
            "price": 499.00,
            "status": "active",
            "currency": "USD",
        })
        # Scenario B retrieves User A's private order 105
        data_b = json.dumps({
            "order_id": "105",
            "user_id": "user_A",
            "item": "Premium Enterprise Subscription",
            "price": 499.00,
            "status": "active",
            "currency": "USD",
        })
        # Scenario C: User B retrieves their own order 205 with identical plan/price/status
        data_c = json.dumps({
            "order_id": "205",
            "user_id": "user_B",
            "item": "Premium Enterprise Subscription",
            "price": 499.00,
            "status": "active",
            "currency": "USD",
        })

        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_b)
        resp_d = make_mock_response(401, '{"error": "Unauthorized"}')
        resp_c = make_mock_response(200, data_c)

        mock_guarded.side_effect = [resp_a, resp_b, resp_d, resp_c]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            target_url_b="https://target.test/api/v1/orders/205",
            user_b_identifier="user_B",
            resource_b_identifier="205",
        )
        assert res.outcome == BOLAOutcome.CONFIRMED_BOLA
        assert res.is_vulnerable is True
        assert res.confidence.level == ConfidenceLevel.CERTAIN
        assert res.confidence.score >= 0.95
        # Verify high similarity is recorded as a diagnostic signal without vetoing verdict
        assert any("schema similarity" in sig for sig in res.confidence.signals)

    @patch("net_guard.guarded_request")
    def test_scenario_c_missing_resource_b_identifier_fails_closed(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """Scenario C response lacks Resource B identifier -> INCONCLUSIVE."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "user_id": "user_A", "item": "Widget A", "price": 100})
        data_b = json.dumps({"order_id": "105", "user_id": "user_A", "item": "Widget A", "price": 100})
        # Scenario C has user_B but missing order_id 205
        data_c = json.dumps({"user_id": "user_B", "item": "Widget B", "price": 100})

        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_b)
        resp_d = make_mock_response(401, '{"error": "Unauthorized"}')
        resp_c = make_mock_response(200, data_c)

        mock_guarded.side_effect = [resp_a, resp_b, resp_d, resp_c]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            target_url_b="https://target.test/api/v1/orders/205",
            user_b_identifier="user_B",
            resource_b_identifier="205",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "Resource B Identifier Missing" in res.title

    @patch("net_guard.guarded_request")
    def test_scenario_c_mismatched_resource_b_ownership_fails_closed(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """Scenario C response has Resource B identifier but owner belongs to another user -> INCONCLUSIVE."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "user_id": "user_A", "item": "Widget A", "price": 100})
        data_b = json.dumps({"order_id": "105", "user_id": "user_A", "item": "Widget A", "price": 100})
        # Scenario C has order 205 but owner is user_attacker, NOT user_B
        data_c = json.dumps({"order_id": "205", "user_id": "user_attacker", "item": "Widget B", "price": 100})

        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_b)
        resp_d = make_mock_response(401, '{"error": "Unauthorized"}')
        resp_c = make_mock_response(200, data_c)

        mock_guarded.side_effect = [resp_a, resp_b, resp_d, resp_c]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            target_url_b="https://target.test/api/v1/orders/205",
            user_b_identifier="user_B",
            resource_b_identifier="205",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "Ownership Evidence Missing or Invalid" in res.title


class TestVerifyCandidateSignatureAndIdentitySeparation:
    """
    Finding 1: Public method signature & identity separation verification.
    Verifies that:
    - expected_user_b_identifier is a declared parameter of verify_candidate() with default None.
    - Extended parameters (expected_user_b_claims, endpoint_resource_mapping, etc.) are declared.
    - Four-way reverse control works with expected_user_b_claims=None.
    - Four-way reverse control works with explicitly supplied expected_user_b_claims.
    - Three-way fallback works with expected_user_b_claims=None.
    - Three-way fallback works with explicitly supplied expected_user_b_claims.
    - Owner identity cannot satisfy resource identity (strict separation).
    """

    def test_verify_candidate_signature_declares_expected_user_b_identifier(self):
        """Confirm expected_user_b_identifier is a declared parameter with default None."""
        import inspect

        sig = inspect.signature(BOLAVerificationEngine.verify_candidate)
        assert "expected_user_b_identifier" in sig.parameters
        param = sig.parameters["expected_user_b_identifier"]
        assert param.default is None

    def test_verify_candidate_signature_declares_all_extended_parameters(self):
        """Confirm all extended parameters are declared in verify_candidate signature."""
        import inspect

        sig = inspect.signature(BOLAVerificationEngine.verify_candidate)
        assert "expected_user_b_claims" in sig.parameters
        assert sig.parameters["expected_user_b_claims"].default is None

        assert "endpoint_resource_mapping" in sig.parameters
        assert sig.parameters["endpoint_resource_mapping"].default is None

        assert "authorization_masking_policy" in sig.parameters
        assert sig.parameters["authorization_masking_policy"].default is None

        assert "nonexistent_resource_url" in sig.parameters
        assert sig.parameters["nonexistent_resource_url"].default is None

    @patch("net_guard.guarded_request")
    def test_four_way_reverse_control_with_expected_user_b_claims_none(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """Scenario C executes and confirms BOLA when expected_user_b_claims=None."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        data_b = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        data_c = json.dumps({"order_id": "205", "item": "Widget B", "user_id": "user_B"})

        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_b)
        resp_d = make_mock_response(401, '{"error": "Unauthorized"}')
        resp_c = make_mock_response(200, data_c)
        mock_guarded.side_effect = [resp_a, resp_b, resp_d, resp_c]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            target_url_b="https://target.test/api/v1/orders/205",
            user_b_identifier="user_B",
            resource_b_identifier="205",
            expected_user_b_claims=None,
            expected_user_b_identifier="user_B",
        )
        assert res.outcome == BOLAOutcome.CONFIRMED_BOLA
        assert res.is_vulnerable is True

    @patch("net_guard.guarded_request")
    def test_four_way_reverse_control_with_explicit_expected_user_b_claims(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """Scenario C executes and confirms BOLA when expected_user_b_claims is explicitly supplied."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        data_b = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        data_c = json.dumps({"order_id": "205", "item": "Widget B", "user_id": "user_B"})

        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_b)
        resp_d = make_mock_response(401, '{"error": "Unauthorized"}')
        resp_c = make_mock_response(200, data_c)
        mock_guarded.side_effect = [resp_a, resp_b, resp_d, resp_c]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            target_url_b="https://target.test/api/v1/orders/205",
            user_b_identifier="user_B",
            resource_b_identifier="205",
            expected_user_b_claims={"id": "user_B"},
            expected_claim_type="id",
        )
        assert res.outcome == BOLAOutcome.CONFIRMED_BOLA
        assert res.is_vulnerable is True

    @patch("net_guard.guarded_request")
    def test_three_way_fallback_with_expected_user_b_claims_none(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """3-way fallback executes with expected_user_b_claims=None and validates session via validation URL."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        data_b = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        data_val = json.dumps({"user_id": "user_B", "role": "member"})

        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_b)
        resp_d = make_mock_response(401, '{"error": "Unauthorized"}')
        resp_val = make_mock_response(200, data_val)
        mock_guarded.side_effect = [resp_a, resp_b, resp_d, resp_val]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            target_url_b=None,  # triggers 3-way fallback
            user_b_identifier="user_B",
            user_b_validation_url="https://target.test/api/v1/users/me",
            expected_user_b_claims=None,
            expected_user_b_identifier="user_B",
        )
        assert res.outcome == BOLAOutcome.HIGH_PROBABLE_BOLA
        assert res.is_vulnerable is True

    @patch("net_guard.guarded_request")
    def test_three_way_fallback_with_explicit_expected_user_b_claims(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """3-way fallback executes with explicit expected_user_b_claims and validates session."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        data_b = json.dumps({"order_id": "105", "item": "Widget A", "user_id": "user_A"})
        data_val = json.dumps({"user_id": "user_B", "role": "member"})

        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_b)
        resp_d = make_mock_response(401, '{"error": "Unauthorized"}')
        resp_val = make_mock_response(200, data_val)
        mock_guarded.side_effect = [resp_a, resp_b, resp_d, resp_val]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            target_url_b=None,
            user_b_identifier="user_B",
            user_b_validation_url="https://target.test/api/v1/users/me",
            expected_user_b_claims={"id": "user_B"},
            expected_claim_type="id",
        )
        assert res.outcome == BOLAOutcome.HIGH_PROBABLE_BOLA
        assert res.is_vulnerable is True

    @patch("net_guard.guarded_request")
    def test_owner_identity_cannot_satisfy_resource_identity(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """Owner identity in response payload cannot substitute for missing resource identifier."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        # Payload has user_id 'user_A' but lacks resource_id '105'
        data_a = json.dumps({"user_id": "user_A", "item": "Widget A", "price": 100})
        resp_a = make_mock_response(200, data_a)
        mock_guarded.side_effect = [resp_a]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "Resource A Identifier Missing" in res.title


class TestURLDerivedResourceIdentifierResolution:
    """
    Finding 3: URL-derived resource identifier resolution.
    Verifies that:
    - Multiple candidate identifiers with explicit mapping succeed.
    - Multiple candidate identifiers without mapping fail closed (INCONCLUSIVE).
    - Multiple candidate identifiers with conflicting response data fail closed.
    - Terminal non-identifier segment (/summary) without mapping fails closed.
    - Terminal non-identifier segment with explicit mapping succeeds.
    - Explicitly configured resource identifier takes precedence.
    - Unit helper resolve_url_resource_identifier() handles all path edge cases safely.
    """

    @patch("net_guard.guarded_request")
    def test_url_multiple_candidates_with_explicit_order_mapping_succeeds(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """/api/users/123/orders/456 with endpoint_resource_mapping='orders' resolves 456."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "456", "user_id": "user_A", "item": "Order 456"})
        data_b = json.dumps({"order_id": "456", "user_id": "user_A", "item": "Order 456"})
        data_c = json.dumps({"order_id": "789", "user_id": "user_B", "item": "Order 789"})

        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_b)
        resp_d = make_mock_response(401, '{"error": "Unauthorized"}')
        resp_c = make_mock_response(200, data_c)
        mock_guarded.side_effect = [resp_a, resp_b, resp_d, resp_c]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/users/123/orders/456",
            user_a_identifier="user_A",
            target_url_b="https://target.test/api/v1/users/888/orders/789",
            user_b_identifier="user_B",
            endpoint_resource_mapping="orders",
        )
        assert res.outcome == BOLAOutcome.CONFIRMED_BOLA
        assert res.is_vulnerable is True

    def test_url_multiple_candidates_without_endpoint_mapping_is_inconclusive(
        self, dual_auth_manager, sample_candidate
    ):
        """/api/users/123/orders/456 without endpoint mapping fails closed with INCONCLUSIVE."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/users/123/orders/456",
            user_a_identifier="user_A",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "Ambiguous URL Resource Mapping" in res.title
        assert "Multiple candidate resource identifiers" in res.explanation

    @patch("net_guard.guarded_request")
    def test_multiple_candidate_identifiers_with_conflicting_response_data_fails_closed(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """Multiple candidates where mapped ID (456) is absent from response data fails closed."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        # Response has user 123 and order 999, but NOT the mapped resource 456
        data_a = json.dumps({"user_id": "user_A", "account_id": "123", "order_id": "999"})
        resp_a = make_mock_response(200, data_a)
        mock_guarded.side_effect = [resp_a]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/users/123/orders/456",
            user_a_identifier="user_A",
            endpoint_resource_mapping="orders",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "Resource A Identifier Missing" in res.title

    def test_url_final_segment_not_resource_identifier_without_mapping_is_inconclusive(
        self, dual_auth_manager, sample_candidate
    ):
        """/orders/456/summary without endpoint mapping fails closed with INCONCLUSIVE."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/456/summary",
            user_a_identifier="user_A",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "Ambiguous URL Resource Mapping" in res.title
        assert "is not a resource identifier" in res.explanation

    @patch("net_guard.guarded_request")
    def test_url_final_segment_not_resource_identifier_with_mapping_succeeds(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """/orders/456/summary with endpoint_resource_mapping='orders' resolves 456."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "456", "user_id": "user_A", "summary": "Order 456 Summary"})
        data_b = json.dumps({"order_id": "456", "user_id": "user_A", "summary": "Order 456 Summary"})
        data_c = json.dumps({"order_id": "789", "user_id": "user_B", "summary": "Order 789 Summary"})

        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_b)
        resp_d = make_mock_response(401, '{"error": "Unauthorized"}')
        resp_c = make_mock_response(200, data_c)
        mock_guarded.side_effect = [resp_a, resp_b, resp_d, resp_c]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/456/summary",
            user_a_identifier="user_A",
            target_url_b="https://target.test/api/v1/orders/789/summary",
            user_b_identifier="user_B",
            endpoint_resource_mapping="orders",
        )
        assert res.outcome == BOLAOutcome.CONFIRMED_BOLA
        assert res.is_vulnerable is True

    def test_conflict_between_explicit_identifier_and_mapped_identifier_fails_closed(
        self, dual_auth_manager, sample_candidate
    ):
        """Conflict between caller-supplied explicit identifier and URL path candidate fails closed -> INCONCLUSIVE."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="explicit_999",  # Conflicts with URL candidate '105'
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "Ambiguous URL Resource Mapping" in res.title
        assert "Conflict between explicit resource identifier" in res.explanation

    @patch("net_guard.guarded_request")
    def test_valid_explicitly_configured_resource_identifier_without_conflict_succeeds(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """Explicitly passed resource identifiers matching URL path candidates succeed -> CONFIRMED_BOLA."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "105", "user_id": "user_A", "item": "Widget A"})
        data_b = json.dumps({"order_id": "105", "user_id": "user_A", "item": "Widget A"})
        data_c = json.dumps({"order_id": "205", "user_id": "user_B", "item": "Widget B"})

        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_b)
        resp_d = make_mock_response(401, '{"error": "Unauthorized"}')
        resp_c = make_mock_response(200, data_c)
        mock_guarded.side_effect = [resp_a, resp_b, resp_d, resp_c]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            resource_a_identifier="105",
            target_url_b="https://target.test/api/v1/orders/205",
            user_b_identifier="user_B",
            resource_b_identifier="205",
        )
        assert res.outcome == BOLAOutcome.CONFIRMED_BOLA
        assert res.is_vulnerable is True

    def test_endpoint_mapping_invalid_type_rejected(
        self, dual_auth_manager, sample_candidate
    ):
        """Invalid endpoint_resource_mapping type (not str or dict) fails closed -> INCONCLUSIVE."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            endpoint_resource_mapping=123,  # Invalid type
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "Ambiguous URL Resource Mapping" in res.title
        assert "Invalid endpoint_mapping type" in res.explanation

    def test_endpoint_mapping_action_or_filter_segment_rejected(
        self, dual_auth_manager, sample_candidate
    ):
        """Endpoint mapping specifying an action or filter segment (e.g. 'summary') is rejected."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/105",
            user_a_identifier="user_A",
            endpoint_resource_mapping="summary",  # Disallowed action segment
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "Ambiguous URL Resource Mapping" in res.title
        assert "action, filter, or non-resource" in res.explanation

    def test_endpoint_mapping_duplicate_ambiguous_segments_rejected(
        self, dual_auth_manager, sample_candidate
    ):
        """Endpoint mapping that matches multiple duplicate segments in path fails closed."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/orders/123/items/456/orders/789",
            user_a_identifier="user_A",
            endpoint_resource_mapping="orders",
        )
        assert res.outcome == BOLAOutcome.INCONCLUSIVE
        assert res.is_vulnerable is False
        assert "Ambiguous URL Resource Mapping" in res.title
        assert "multiple duplicate candidate segments" in res.explanation

    @patch("net_guard.guarded_request")
    def test_endpoint_mapping_path_index_support(
        self, mock_guarded, dual_auth_manager, sample_candidate
    ):
        """endpoint_resource_mapping={'path_index': 5} correctly resolves the target segment."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        data_a = json.dumps({"order_id": "456", "user_id": "user_A", "item": "Widget A"})
        data_b = json.dumps({"order_id": "456", "user_id": "user_A", "item": "Widget A"})
        data_c = json.dumps({"order_id": "789", "user_id": "user_B", "item": "Widget B"})

        resp_a = make_mock_response(200, data_a)
        resp_b = make_mock_response(200, data_b)
        resp_d = make_mock_response(401, '{"error": "Unauthorized"}')
        resp_c = make_mock_response(200, data_c)
        mock_guarded.side_effect = [resp_a, resp_b, resp_d, resp_c]

        res = engine.verify_candidate(
            sample_candidate,
            target_url_a="https://target.test/api/v1/users/123/orders/456",
            user_a_identifier="user_A",
            target_url_b="https://target.test/api/v1/users/888/orders/789",
            user_b_identifier="user_B",
            endpoint_resource_mapping={"path_index": 5},
        )
        assert res.outcome == BOLAOutcome.CONFIRMED_BOLA
        assert res.is_vulnerable is True

    def test_direct_resolve_url_resource_identifier_helper_functions(self):
        """Direct unit test of resolve_url_resource_identifier edge cases."""
        # Empty inputs
        assert resolve_url_resource_identifier("", explicit_identifier=None) == (None, "URL is empty")
        assert resolve_url_resource_identifier("https://target.test", explicit_identifier="") == (None, "Explicit resource identifier is empty")
        assert resolve_url_resource_identifier("https://target.test", explicit_identifier="   ") == (None, "Explicit resource identifier is empty")

        # Explicit matching URL candidate succeeds
        assert resolve_url_resource_identifier("https://target.test/api/v1/orders/105", explicit_identifier="105") == ("105", None)

        # Conflict between explicit and URL candidate fails closed
        resolved, err = resolve_url_resource_identifier("https://target.test/api/v1/orders/105", explicit_identifier="res_explicit")
        assert resolved is None
        assert "Conflict between explicit resource identifier" in err

        # Explicit identifier supplied when no candidate in URL path is accepted
        assert resolve_url_resource_identifier("https://target.test/api/v1/orders/active", explicit_identifier="res_explicit") == ("res_explicit", None)

        # No candidate without explicit identifier
        assert resolve_url_resource_identifier("https://target.test/api/v1/orders/active") == (None, "No candidate resource identifiers found in URL path")

        # Single candidate at end
        assert resolve_url_resource_identifier("https://target.test/api/v1/orders/105") == ("105", None)

        # Single candidate with trailing non-identifier
        resolved, err = resolve_url_resource_identifier("https://target.test/api/v1/orders/105/items")
        assert resolved is None
        assert "is not a resource identifier" in err

        # Mapping with dict
        assert resolve_url_resource_identifier(
            "https://target.test/api/v1/users/123/orders/456",
            endpoint_mapping={"resource": "orders"},
        ) == ("456", None)

        # Mapping that does not match
        resolved, err = resolve_url_resource_identifier(
            "https://target.test/api/v1/users/123/orders/456",
            endpoint_mapping="invoices",
        )
        assert resolved is None
        assert "did not match any candidate" in err

        # Mapping with invalid type
        resolved, err = resolve_url_resource_identifier(
            "https://target.test/api/v1/users/123/orders/456",
            endpoint_mapping=999,
        )
        assert resolved is None
        assert "Invalid endpoint_mapping type" in err

        # Mapping with disallowed action segment
        resolved, err = resolve_url_resource_identifier(
            "https://target.test/api/v1/users/123/orders/456",
            endpoint_mapping="summary",
        )
        assert resolved is None
        assert "is an action, filter, or non-resource" in err

    def test_valid_resource_collection_mapping_orders_resolves_resource_id_456(self):
        """Valid resource collection mapping 'orders' on /users/123/orders/456/summary resolves '456'."""
        url = "https://target.test/api/v1/users/123/orders/456/summary"
        resolved, err = resolve_url_resource_identifier(url, endpoint_mapping="orders")
        assert err is None
        assert resolved == "456"

    def test_action_segment_mapping_summary_rejected(self):
        """Action/filter segment 'summary' is rejected as a mapping target on /users/123/orders/456/summary."""
        url = "https://target.test/api/v1/users/123/orders/456/summary"
        resolved, err = resolve_url_resource_identifier(url, endpoint_mapping="summary")
        assert resolved is None
        assert "is an action, filter, or non-resource" in err


class TestConnectionLevelIPPinning:
    """
    Finding 3: Connection-Level IP Pinning & SSRF Verification.
    Verifies that:
    - net_guard._PinnedPoolAdapter resolves and validates public IPs.
    - HTTPSConnectionPool connects directly to the validated IP literal.
    - TLS SNI and certificate validation preserve the original hostname.
    - The connection pool is cached and reused, preventing a second DNS resolution.
    - Host header in requests is set to original hostname, defeating CDN routing failures.
    - allow_redirects=False is strictly enforced across verification requests.
    """

    def test_pinned_pool_adapter_pins_socket_to_validated_ip_and_preserves_sni(self):
        """Connection pool connects directly to validated IP literal while preserving SNI and cert check."""
        import socket
        from net_guard import _PinnedPoolAdapter

        adapter = _PinnedPoolAdapter()
        with patch("socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
            ]
            pool = adapter.get_connection("https://example.com/api/v1/orders/105")

            # 1. Pinned socket connects to the validated IP literal
            assert pool.host == "93.184.216.34"

            # 2. TLS SNI preserves the original hostname
            assert pool.conn_kw.get("server_hostname") == "example.com"

            # 3. Certificate validation asserts the original hostname
            assert pool.assert_hostname == "example.com"

            # 4. Retries are strictly disabled on connection pool
            assert pool.retries is False

    def test_pinned_pool_adapter_reuses_pool_preventing_second_dns_resolution(self):
        """Subsequent requests reuse the cached pool without a second DNS lookup."""
        import socket
        from net_guard import _PinnedPoolAdapter

        adapter = _PinnedPoolAdapter()
        with patch("socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
            ]
            pool1 = adapter.get_connection("https://example.com/api/v1/orders/105")
            pool2 = adapter.get_connection("https://example.com/api/v1/orders/205")

            assert pool1 is pool2
            assert mock_dns.call_count == 1

    def test_pinned_pool_adapter_send_sets_host_header_to_original_hostname(self):
        """_PinnedPoolAdapter.send() injects Host header matching the original hostname."""
        from net_guard import _PinnedPoolAdapter
        from requests.adapters import HTTPAdapter
        from requests.models import PreparedRequest

        adapter = _PinnedPoolAdapter()
        req = PreparedRequest()
        req.url = "https://example.com/api/v1/orders/105"
        req.headers = {}

        with patch.object(HTTPAdapter, "send", return_value=MagicMock()):
            adapter.send(req)
            assert req.headers["Host"] == "example.com"

    @patch("net_guard.guarded_request")
    def test_engine_execute_request_strictly_disables_redirects(
        self, mock_guarded, dual_auth_manager
    ):
        """_execute_request passes allow_redirects=False to guarded_request for strict redirect inspection."""
        engine = BOLAVerificationEngine(dual_auth_manager)
        mock_guarded.return_value = make_mock_response(302, "", headers={"Location": "/login"})

        res = engine._execute_request(IDENTITY_PRIMARY, "GET", "https://target.test/api/v1/orders/105")
        mock_guarded.assert_called_once()
        _, kwargs = mock_guarded.call_args
        assert kwargs.get("allow_redirects") is False
        assert res.is_redirect is True
        assert res.status_code == 302

    def test_socket_connect_receives_pinned_ip_literal_and_preserves_sni_and_cert(self):
        """Low-level socket connection uses the validated IP literal while preserving SNI and cert check."""
        import socket
        from net_guard import _PinnedPoolAdapter

        adapter = _PinnedPoolAdapter()
        with patch("socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
            ]
            pool = adapter.get_connection("https://example.com/api/v1/orders/105")
            conn = pool._new_conn()

            assert conn.host == "93.184.216.34"
            assert conn.port == 443
            assert conn._dns_host == "93.184.216.34"
            assert pool.conn_kw.get("server_hostname") == "example.com"
            assert pool.assert_hostname == "example.com"

            # Mock create_connection to verify socket connection parameters
            with patch("urllib3.util.connection.create_connection") as mock_create_conn:
                fake_sock = MagicMock()
                mock_create_conn.return_value = fake_sock
                sock = conn._new_conn()
                mock_create_conn.assert_called_once()
                args, _ = mock_create_conn.call_args
                # The socket connects directly to (ip, port), NOT the hostname
                assert args[0] == ("93.184.216.34", 443)

    def test_connection_pool_recreation_maintains_ip_pinning(self):
        """Connection recreation across error/close maintains the pinned IP invariant."""
        import socket
        from net_guard import _PinnedPoolAdapter

        adapter = _PinnedPoolAdapter()
        with patch("socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
            ]
            pool = adapter.get_connection("https://example.com/api/v1/orders/105")
            conn1 = pool._new_conn()
            assert conn1.host == "93.184.216.34"

            # Simulate connection error and recreation
            conn1.close()
            conn2 = pool._new_conn()
            assert conn2.host == "93.184.216.34"
            assert mock_dns.call_count == 1


class TestHMACTrustArchitecture:
    """Tests for HMAC cryptographic policy trust architecture, secret lifecycle, and anti-oracle defenses."""

    def test_secret_not_hardcoded_and_derived_from_settings_or_env(self):
        """Trust root secret is resolved dynamically and not exposed in public attributes or models."""
        from tasks.bola.engine import _get_policy_trust_secret, TargetAuthorizationPolicy

        secret = _get_policy_trust_secret()
        assert isinstance(secret, bytes)
        assert len(secret) >= 32

        # Verify secret is NOT exposed on policy model
        policy = TargetAuthorizationPolicy.create_trusted_policy(
            target_domain="secure.test",
            masks_404=True,
            provenance="verified_target_profile",
        )
        assert not hasattr(policy, "secret")
        assert not hasattr(policy, "_secret")
        assert "_POLICY_TRUST_SECRET" not in policy.model_dump()
        assert str(secret) not in repr(policy)

    def test_secret_override_lifecycle_and_rotation(self):
        """Secret override updates token generation and rotates verification keys."""
        from tasks.bola.engine import (
            compute_policy_trust_token,
            set_policy_trust_secret_override,
            clear_policy_trust_secret_override,
        )

        try:
            set_policy_trust_secret_override(b"test_key_epoch_1_0000000000000000000")
            token1 = compute_policy_trust_token("target.test", None, "1.0", True, "verified_target_profile")

            set_policy_trust_secret_override(b"test_key_epoch_2_0000000000000000000")
            token2 = compute_policy_trust_token("target.test", None, "1.0", True, "verified_target_profile")

            assert token1 != token2
        finally:
            clear_policy_trust_secret_override()

    def test_restart_verification_preserves_policy_validity(self, sample_candidate):
        """Policies created before an application restart remain verifiable after restart with matching root."""
        from tasks.bola.engine import (
            set_policy_trust_secret_override,
            clear_policy_trust_secret_override,
        )

        root_key = b"persistent_enterprise_key_root_32b_!"
        try:
            # Epoch 1: before restart
            set_policy_trust_secret_override(root_key)
            policy = TargetAuthorizationPolicy.create_trusted_policy(
                target_domain="target.test",
                route_template="/api/v1/orders/{order_id}",
                masks_404=True,
                provenance="verified_target_profile",
            )
            serialized = policy.model_dump_json()

            # Epoch 2: simulated process restart with same configuration key
            clear_policy_trust_secret_override()
            set_policy_trust_secret_override(root_key)

            restored_policy = TargetAuthorizationPolicy.model_validate_json(serialized)
            valid, reason = restored_policy.validate_for_candidate(
                sample_candidate, "https://target.test/api/v1/orders/105"
            )
            assert valid is True
            assert "verified and trusted" in reason
        finally:
            clear_policy_trust_secret_override()

    def test_unauthorized_factory_access_rejected_for_untrusted_provenance(self):
        """create_trusted_policy raises ValueError when caller passes untrusted provenance."""
        with pytest.raises(ValueError, match="Cannot create trusted policy with untrusted provenance"):
            TargetAuthorizationPolicy.create_trusted_policy(
                target_domain="target.test",
                masks_404=True,
                provenance="scan_input_payload",
            )

        with pytest.raises(ValueError, match="Cannot create trusted policy with untrusted provenance"):
            TargetAuthorizationPolicy.create_trusted_policy(
                target_domain="target.test",
                masks_404=True,
                provenance="untrusted_input",
            )

    def test_signing_oracle_abuse_delimiter_injection_rejected(self):
        """Delimiter injection in target_domain, route_template, or version raises ValueError."""
        with pytest.raises(ValueError, match="delimiters.*forbidden"):
            TargetAuthorizationPolicy.create_trusted_policy(
                target_domain="target.test|fake_route|1.0|True|verified_target_profile",
                masks_404=True,
                provenance="verified_target_profile",
            )

        with pytest.raises(ValueError, match="delimiters.*forbidden"):
            TargetAuthorizationPolicy.create_trusted_policy(
                target_domain="target.test",
                route_template="/api/v1\nmalicious_injection",
                masks_404=True,
                provenance="verified_target_profile",
            )

    def test_forged_deserialized_policy_fails_closed(self, sample_candidate):
        """Untrusted caller deserializing dict claiming is_trusted=True fails closed."""
        forged_dict = {
            "target_domain": "target.test",
            "masks_404": True,
            "provenance": "verified_target_profile",
            "is_trusted": True,
            "trust_token": "forged_invalid_token_9999999999",
        }
        policy = TargetAuthorizationPolicy.model_validate(forged_dict)
        # Root validator demotes is_trusted to False due to token mismatch
        assert policy.is_trusted is False

        valid, reason = policy.validate_for_candidate(
            sample_candidate, "https://target.test/api/v1/orders/105"
        )
        assert valid is False
        assert "untrusted or missing cryptographic trust token" in reason

    def test_tampered_policy_attributes_fail_closed_at_validation(self, sample_candidate):
        """Modifying any attribute of a trusted policy invalidates the HMAC signature."""
        policy = TargetAuthorizationPolicy.create_trusted_policy(
            target_domain="target.test",
            route_template="/api/v1/orders/{order_id}",
            config_version="1.0",
            masks_404=True,
            provenance="verified_target_profile",
        )

        # 1. Tamper masks_404
        t1 = policy.model_copy(update={"masks_404": False})
        valid, reason = t1.validate_for_candidate(sample_candidate, "https://target.test/api/v1/orders/105")
        assert valid is False
        assert "Forged policy detected" in reason

        # 2. Tamper config_version
        t2 = policy.model_copy(update={"config_version": "2.0"})
        valid, reason = t2.validate_for_candidate(sample_candidate, "https://target.test/api/v1/orders/105")
        assert valid is False
        assert "Forged policy detected" in reason

        # 3. Tamper route_template
        t3 = policy.model_copy(update={"route_template": "/api/v1/invoices/{id}"})
        valid, reason = t3.validate_for_candidate(sample_candidate, "https://target.test/api/v1/orders/105")
        assert valid is False
        assert "Forged policy detected" in reason

        # 4. Tamper target_domain
        t4 = policy.model_copy(update={"target_domain": "evil.test"})
        valid, reason = t4.validate_for_candidate(sample_candidate, "https://target.test/api/v1/orders/105")
        assert valid is False
        assert "Forged policy detected" in reason



