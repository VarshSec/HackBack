"""
Unit tests for BOLA core extraction models, route normalizer, and resource detector.
"""
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
