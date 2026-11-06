"""
Unit tests for BOLA core extraction models, route normalizer, and resource detector.
"""
import json
import pytest
from tasks.bola.models import (
    CandidateEndpoint,
    CandidateParameter,
    EvidenceRecord,
    IdentifierType,
    ParameterLocation,
    SemanticRole,
)
from tasks.bola.route_normalizer import (
    classify_segment,
    is_static_segment,
    normalize_url_path,
)
from tasks.bola.resource_detector import (
    classify_semantic_role,
    detect_identifier_type,
    extract_json_parameters,
    extract_query_parameters,
)
from tasks.bola.sanitizer import (
    sanitize_url,
    sanitize_snippet,
    sanitize_sample_value,
    sanitize_schema_dict,
)


class TestSecretLeakageWithCanaries:
    """
    Exhaustive regression test suite verifying that secrets and credentials
    never leak across URL sanitization, evidence snippets, query strings,
    parameter extraction, response schemas, and dictionary serialization.
    """
    CANARY_PASSWORD = "CANARY_PASSWORD_998877_SECRET"
    CANARY_AUTH_TOKEN = "CANARY_AUTH_TOKEN_AABBCC_SECRET"
    CANARY_COOKIE = "CANARY_COOKIE_SESSION_112233_SECRET"
    CANARY_USERINFO_PASS = "CANARY_USERINFO_SECRET_4455"
    CANARY_API_KEY = "CANARY_API_KEY_XYZ_9999_SECRET"
    CANARY_FRAG_TOKEN = "CANARY_FRAG_SECRET_776655"
    CANARY_JWT = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )

    def test_url_with_userinfo_and_sensitive_query(self):
        url = (
            f"https://admin:{self.CANARY_USERINFO_PASS}@target.test/api/v1/users"
            f"?token={self.CANARY_AUTH_TOKEN}&apikey={self.CANARY_API_KEY}&name=alice&status=active"
        )
        endpoint = CandidateEndpoint(
            candidate_id="cand-test-01",
            scan_id="scan-01",
            target_domain="target.test",
            method="GET",
            original_url=url,
            route_template="/api/v1/users",
            resource_type="users",
        )

        # 1. Userinfo must be stripped completely
        assert self.CANARY_USERINFO_PASS not in endpoint.original_url
        assert "admin:" not in endpoint.original_url
        assert "@target.test" not in endpoint.original_url

        # 2. Sensitive query values must be redacted to [REDACTED]
        assert self.CANARY_AUTH_TOKEN not in endpoint.original_url
        assert self.CANARY_API_KEY not in endpoint.original_url
        assert "token=%5BREDACTED%5D" in endpoint.original_url or "token=[REDACTED]" in endpoint.original_url
        assert "apikey=%5BREDACTED%5D" in endpoint.original_url or "apikey=[REDACTED]" in endpoint.original_url

        # 3. Non-sensitive query parameters must be preserved
        assert "name=alice" in endpoint.original_url
        assert "status=active" in endpoint.original_url

        # 4. JSON serialization roundtrip must not leak canaries
        dumped = json.dumps(endpoint.to_dict())
        assert self.CANARY_USERINFO_PASS not in dumped
        assert self.CANARY_AUTH_TOKEN not in dumped
        assert self.CANARY_API_KEY not in dumped

    def test_evidence_record_snippet_and_location_redaction(self):
        location = f"https://admin:{self.CANARY_USERINFO_PASS}@target.test/api/v1/login"
        snippet = (
            f"POST /api/v1/login HTTP/1.1\r\n"
            f"Host: target.test\r\n"
            f"Authorization: Bearer {self.CANARY_AUTH_TOKEN}\r\n"
            f"Cookie: session={self.CANARY_COOKIE}; theme=dark\r\n"
            f"Content-Type: application/json\r\n\r\n"
            f'{{"username": "admin", "password": "{self.CANARY_PASSWORD}", "client_secret": "{self.CANARY_API_KEY}"}}'
        )

        ev = EvidenceRecord(
            source="traffic",
            parser="TrafficObserver",
            location=location,
            snippet=snippet,
            confidence_signals=["live_traffic"],
        )

        # Location must have userinfo stripped
        assert self.CANARY_USERINFO_PASS not in ev.location
        assert "admin:" not in ev.location

        # Snippet must have secrets replaced with [REDACTED]
        assert self.CANARY_AUTH_TOKEN not in ev.snippet
        assert self.CANARY_COOKIE not in ev.snippet
        assert self.CANARY_PASSWORD not in ev.snippet
        assert self.CANARY_API_KEY not in ev.snippet

        # Non-sensitive keys and values must remain intact
        assert "username" in ev.snippet
        assert "admin" in ev.snippet
        assert "theme=dark" in ev.snippet
        assert "Authorization: [REDACTED]" in ev.snippet

        dumped = json.dumps(ev.to_dict())
        assert self.CANARY_USERINFO_PASS not in dumped
        assert self.CANARY_AUTH_TOKEN not in dumped
        assert self.CANARY_COOKIE not in dumped
        assert self.CANARY_PASSWORD not in dumped

    def test_url_fragment_secret_redaction(self):
        canary = self.CANARY_FRAG_TOKEN

        # 1. #access_token=CANARY
        url1 = f"https://target.test/oauth/callback#access_token={canary}"
        san1 = sanitize_url(url1)
        assert canary not in san1
        assert "access_token=[REDACTED]" in san1

        # 2. #token=CANARY
        url2 = f"https://target.test/auth#token={canary}"
        san2 = sanitize_url(url2)
        assert canary not in san2
        assert "token=[REDACTED]" in san2

        # 3. #state=normal&access_token=CANARY
        url3 = f"https://target.test/auth#state=normal&access_token={canary}"
        san3 = sanitize_url(url3)
        assert canary not in san3
        assert "state=normal" in san3
        assert "access_token=[REDACTED]" in san3

        # 4. URL-encoded sensitive parameter names (%61ccess_token)
        url4 = f"https://target.test/auth#%61ccess_token={canary}"
        san4 = sanitize_url(url4)
        assert canary not in san4
        assert "[REDACTED]" in san4

        # 5. Preserve harmless fragment parameters and anchors
        url5 = "https://target.test/dashboard#state=normal&tab=overview"
        san5 = sanitize_url(url5)
        assert san5 == url5

        url6 = "https://target.test/docs#section-auth-guide"
        san6 = sanitize_url(url6)
        assert san6 == url6

        # 6. Serialized CandidateEndpoint never leaks fragment canaries
        endpoint = CandidateEndpoint(
            candidate_id="cand-frag-01",
            scan_id="scan-frag",
            target_domain="target.test",
            method="GET",
            original_url=f"https://target.test/callback?user=bob#state=ok&access_token={canary}",
            route_template="/callback",
            resource_type="callback",
        )
        assert canary not in endpoint.original_url
        assert "access_token=[REDACTED]" in endpoint.original_url
        assert "state=ok" in endpoint.original_url

        dumped = json.dumps(endpoint.to_dict())
        assert canary not in dumped

    def test_hardened_evidence_snippet_canaries(self):
        canary_userinfo = "CANARY_SNIP_USERINFO_PASS_1122"
        canary_query = "CANARY_SNIP_QUERY_TOKEN_3344"
        canary_frag = "CANARY_SNIP_FRAG_TOKEN_5566"
        canary_bearer = "CANARY_SNIP_BEARER_7788"
        canary_jwt = self.CANARY_JWT
        canary_cookie = "CANARY_SNIP_COOKIE_9900"
        canary_spaces = "CANARY PASS WITH MULTIPLE SPACES 123"

        raw_snippet = (
            f"Observed request: GET https://admin:{canary_userinfo}@target.test/api/v1/users"
            f"?token={canary_query}&role=admin#access_token={canary_frag} HTTP/1.1\r\n"
            f"Authorization: Bearer {canary_bearer}\r\n"
            f"Cookie: session={canary_cookie}; theme=dark; tracking_id=track_456\r\n"
            f"X-User-Token: {canary_jwt}\r\n"
            f'Body: {{"password": "{canary_spaces}", "client_secret": "CANARY_SNIP_KEY", "items_count": 5}}'
        )

        ev = EvidenceRecord(
            source="traffic",
            parser="TrafficObserver",
            location="https://target.test/api/v1/users",
            snippet=raw_snippet,
            confidence_signals=["live_traffic"],
        )

        endpoint = CandidateEndpoint(
            candidate_id="cand-snip-hardened",
            scan_id="scan-snip",
            target_domain="target.test",
            method="GET",
            original_url="https://target.test/api/v1/users",
            route_template="/api/v1/users",
            resource_type="users",
            evidence=[ev],
        )

        # 1. Assert NONE of the canary values appear in ev.snippet
        assert canary_userinfo not in ev.snippet
        assert canary_query not in ev.snippet
        assert canary_frag not in ev.snippet
        assert canary_bearer not in ev.snippet
        assert canary_jwt not in ev.snippet
        assert canary_cookie not in ev.snippet
        assert canary_spaces not in ev.snippet
        assert "CANARY_SNIP_KEY" not in ev.snippet

        # 2. Assert harmless diagnostic context and non-sensitive values are preserved
        assert "role=admin" in ev.snippet
        assert "theme=dark" in ev.snippet
        assert "tracking_id=track_456" in ev.snippet
        assert "items_count" in ev.snippet
        assert "/api/v1/users" in ev.snippet

        # 3. Assert serialized data does not contain any canary
        dumped = json.dumps(endpoint.to_dict())
        for c in (
            canary_userinfo, canary_query, canary_frag, canary_bearer,
            canary_jwt, canary_cookie, canary_spaces, "CANARY_SNIP_KEY"
        ):
            assert c not in dumped

    def test_candidate_parameter_sample_value_and_nested_json(self):
        param = CandidateParameter(
            name="client_secret",
            location=ParameterLocation.BODY_JSON,
            sample_value=self.CANARY_API_KEY,
        )
        assert param.is_redacted is True
        assert param.sample_value == "[REDACTED]"
        assert self.CANARY_API_KEY not in (param.sample_value or "")

        # Test nested JSON extraction
        nested_body = {
            "auth": {
                "password": self.CANARY_PASSWORD,
                "token": self.CANARY_AUTH_TOKEN,
            },
            "user": {
                "id": 1234,
                "email": "test@target.test",
            }
        }
        params = extract_json_parameters(nested_body)
        for p in params:
            val_str = str(p.sample_value) if p.sample_value is not None else ""
            assert self.CANARY_PASSWORD not in val_str
            assert self.CANARY_AUTH_TOKEN not in val_str
            if "password" in p.name or "token" in p.name:
                assert p.is_redacted is True
                assert p.sample_value == "[REDACTED]"

    def test_response_schema_redaction(self):
        schema = {
            "type": "object",
            "properties": {
                "id": {"type": "integer"},
                "password_hash": {"type": "string", "example": self.CANARY_PASSWORD},
                "api_key": {"type": "string", "default": self.CANARY_API_KEY},
            }
        }
        endpoint = CandidateEndpoint(
            candidate_id="cand-schema-01",
            scan_id="scan-01",
            target_domain="target.test",
            method="GET",
            original_url="/api/users/1",
            route_template="/api/users/{id}",
            resource_type="users",
            response_schema=schema,
        )
        schema_str = json.dumps(endpoint.response_schema)
        assert self.CANARY_PASSWORD not in schema_str
        assert self.CANARY_API_KEY not in schema_str
        assert "[REDACTED]" in schema_str

    def test_authentication_context_validation(self):
        # Valid contexts
        for valid_ctx in ("primary", "secondary", "anonymous", None):
            ep = CandidateEndpoint(
                candidate_id="cand-ctx",
                scan_id="s1",
                target_domain="target.test",
                method="GET",
                original_url="/api/test",
                route_template="/api/test",
                resource_type="test",
                authentication_context=valid_ctx,
            )
            assert ep.authentication_context == valid_ctx

        # Invalid context safely normalizes to anonymous (never stores raw credential)
        ep_bad = CandidateEndpoint(
            candidate_id="cand-ctx-bad",
            scan_id="s1",
            target_domain="target.test",
            method="GET",
            original_url="/api/test",
            route_template="/api/test",
            resource_type="test",
            authentication_context="superadmin_secret_token",
        )
        assert ep_bad.authentication_context == "anonymous"


class TestCandidateModelsAndRedaction:
    def test_sensitive_parameter_values_are_redacted(self):
        param = CandidateParameter(
            name="user_password",
            location=ParameterLocation.BODY_JSON,
            sample_value="SecretPassword123!",
        )
        assert param.is_redacted is True
        assert param.sample_value == "[REDACTED]"
        assert param.semantic_role == SemanticRole.SESSION_TOKEN

    def test_bearer_token_and_cookie_redacted(self):
        for sensitive_name in ["bearer_token", "access_token", "session_id", "api_key", "csrf"]:
            param = CandidateParameter(
                name=sensitive_name,
                location=ParameterLocation.HEADER,
                sample_value="ey...jwt_payload",
            )
            assert param.is_redacted is True
            assert param.sample_value == "[REDACTED]"

    def test_evidence_snippet_redaction(self):
        ev = EvidenceRecord(
            source="openapi",
            parser="OpenAPIParser",
            location="paths/auth",
            snippet="headers: Authorization: Bearer secret_token_xyz; password: my_password",
        )
        assert "[REDACTED]" in ev.snippet
        assert "secret_token_xyz" not in ev.snippet

    def test_candidate_id_is_deterministic(self):
        id1 = CandidateEndpoint.generate_candidate_id("GET", "/api/users/{user_id}", "target.example")
        id2 = CandidateEndpoint.generate_candidate_id("get", "/api/users/{user_id}", "TARGET.example")
        assert id1 == id2
        assert len(id1) == 16


class TestRouteNormalization:
    def test_numeric_path_segment_normalization(self):
        template, resource, params = normalize_url_path("/api/v1/users/123")
        assert template == "/api/v1/users/{user_id}"
        assert resource == "users"
        assert len(params) == 1
        assert params[0].name == "user_id"
        assert params[0].identifier_type == IdentifierType.NUMERIC
        assert params[0].data_type == "integer"
        assert params[0].sample_value == "123"

    def test_uuid_path_segment_normalization(self):
        template, resource, params = normalize_url_path(
            "/api/orders/550e8400-e29b-41d4-a716-446655440000"
        )
        assert template == "/api/orders/{order_uuid}"
        assert resource == "orders"
        assert len(params) == 1
        assert params[0].identifier_type == IdentifierType.UUID

    def test_mongodb_object_id_normalization(self):
        template, resource, params = normalize_url_path(
            "/api/documents/507f1f77bcf86cd799439011"
        )
        assert template == "/api/documents/{document_id}"
        assert resource == "documents"
        assert len(params) == 1
        assert params[0].identifier_type == IdentifierType.OBJECT_ID

    def test_nested_hierarchy_normalization(self):
        template, resource, params = normalize_url_path("/api/users/12/orders/98")
        assert template == "/api/users/{user_id}/orders/{order_id}"
        assert resource == "orders"
        assert len(params) == 2
        assert params[0].name == "user_id"
        assert params[0].semantic_role == SemanticRole.PARENT_RESOURCE_IDENTIFIER
        assert params[1].name == "order_id"
        assert params[1].semantic_role == SemanticRole.RESOURCE_IDENTIFIER

    def test_static_keywords_not_normalized(self):
        template, resource, params = normalize_url_path("/api/v1/users/me")
        assert template == "/api/v1/users/me"
        assert len(params) == 0

        template2, _, params2 = normalize_url_path("/api/v2/auth/login")
        assert template2 == "/api/v2/auth/login"
        assert len(params2) == 0

        template3, _, params3 = normalize_url_path("/admin/dashboard/export")
        assert template3 == "/admin/dashboard/export"
        assert len(params3) == 0


class TestResourceDetectionAndParameters:
    def test_query_parameter_extraction(self):
        qs = "user_id=456&sort=asc&token=secret123"
        params = extract_query_parameters(qs)
        assert len(params) == 3

        p_user = next(p for p in params if p.name == "user_id")
        assert p_user.identifier_type == IdentifierType.NUMERIC
        assert p_user.semantic_role == SemanticRole.USER_IDENTITY
        assert p_user.sample_value == "456"

        p_sort = next(p for p in params if p.name == "sort")
        assert p_sort.semantic_role == SemanticRole.ACTION_FLAG

        p_token = next(p for p in params if p.name == "token")
        assert p_token.is_redacted is True
        assert p_token.sample_value == "[REDACTED]"

    def test_json_parameter_extraction(self):
        body = {
            "account": {
                "account_id": 9876,
                "name": "Acme Corp",
                "api_key": "raw_key_secret",
            },
            "items": [
                {"item_id": "item-001-xyz", "quantity": 5}
            ]
        }
        params = extract_json_parameters(body)
        assert len(params) >= 4

        p_acc = next(p for p in params if p.name == "account.account_id")
        assert p_acc.identifier_type == IdentifierType.NUMERIC
        assert p_acc.semantic_role == SemanticRole.USER_IDENTITY

        p_key = next(p for p in params if p.name == "account.api_key")
        assert p_key.is_redacted is True
        assert p_key.sample_value == "[REDACTED]"

        p_item = next(p for p in params if "item_id" in p.name)
        assert p_item.identifier_type in (IdentifierType.SLUG, IdentifierType.OPAQUE)
        assert p_item.semantic_role == SemanticRole.RESOURCE_IDENTIFIER
