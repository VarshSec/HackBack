"""
Unit tests for BOLA Semantic Response Comparator (backend/tasks/bola/comparator.py).
Verifies:
- Configurable volatile JSON field masking with identifier protection
- Cache interference detection from response headers
- Soft-404 and 200 OK error payload detection
- Semantic similarity ratio computation
- Silent tenant scoping detection
"""
from __future__ import annotations

import json
import pytest

from tasks.bola.comparator import (
    CacheInterference,
    is_protected_field,
    mask_volatile_fields,
    inspect_cache_interference,
    is_soft_404_or_error,
    compute_semantic_similarity,
    detect_silent_tenant_scoping,
    contains_resource_identifier,
    validate_resource_identifier,
    extract_resource_identifiers,
    DEFAULT_RESOURCE_ID_FIELDS,
    DISALLOWED_RESOURCE_FIELDS,
    check_ownership_evidence,
    validate_ownership_evidence,
    extract_ownership_evidence,
)


class TestVolatileFieldMasking:
    def test_volatile_fields_masked_and_identifiers_preserved(self):
        payload = {
            "id": 105,
            "order_id": "ord_9999",
            "user_id": "usr_alpha_1",
            "account_id": "acc_777",
            "username": "alice",
            "email": "alice@target.test",
            "timestamp": "2026-11-06T16:00:00Z",
            "updated_at": 1730908800,
            "created_at": 1730908700,
            "request_id": "req-xyz-12345",
            "trace_id": "trace-98765",
            "_csrf": "csrf_token_secret_123",
            "items": [
                {
                    "item_id": "item_1",
                    "name": "Widget",
                    "price": 19.99,
                    "date": "2026-11-06",
                }
            ],
            "meta": {
                "server_time": "16:00:05",
                "generation_time_ms": 42,
                "correlation_id": "corr-555",
            },
        }

        masked = mask_volatile_fields(payload)

        # 1. Protected IDs and ownership attributes MUST be preserved
        assert masked["id"] == 105
        assert masked["order_id"] == "ord_9999"
        assert masked["user_id"] == "usr_alpha_1"
        assert masked["account_id"] == "acc_777"
        assert masked["username"] == "alice"
        assert masked["email"] == "alice@target.test"
        assert masked["items"][0]["item_id"] == "item_1"
        assert masked["items"][0]["name"] == "Widget"

        # 2. Volatile fields MUST be masked
        assert masked["timestamp"] == "[VOLATILE]"
        assert masked["updated_at"] == "[VOLATILE]"
        assert masked["created_at"] == "[VOLATILE]"
        assert masked["request_id"] == "[VOLATILE]"
        assert masked["trace_id"] == "[VOLATILE]"
        assert masked["_csrf"] == "[VOLATILE]"
        assert masked["items"][0]["date"] == "[VOLATILE]"
        assert masked["meta"]["server_time"] == "[VOLATILE]"
        assert masked["meta"]["generation_time_ms"] == "[VOLATILE]"
        assert masked["meta"]["correlation_id"] == "[VOLATILE]"

    def test_custom_volatile_and_protected_fields(self):
        payload = {
            "my_custom_token": "secret_nonce",
            "my_custom_id": "cid_123",
        }
        masked = mask_volatile_fields(
            payload,
            volatile_fields={"my_custom_token", "my_custom_id"},
            protected_fields={"my_custom_id"},
        )
        assert masked["my_custom_token"] == "[VOLATILE]"
        assert masked["my_custom_id"] == "cid_123"  # Protected from masking!


class TestCacheInterferenceDetection:
    def test_no_cache_headers(self):
        headers = {
            "Content-Type": "application/json",
            "Content-Length": "120",
        }
        res, reasons = inspect_cache_interference(headers)
        assert res == CacheInterference.NONE
        assert len(reasons) == 0

    def test_age_header_triggers_suspected_cache(self):
        headers = {
            "Content-Type": "application/json",
            "Age": "45",
        }
        res, reasons = inspect_cache_interference(headers)
        assert res == CacheInterference.SUSPECTED_CACHE_HIT
        assert any("Age" in r for r in reasons)

    def test_x_cache_hit_triggers_suspected_cache(self):
        headers = {
            "X-Cache": "HIT from proxy.target.test",
        }
        res, reasons = inspect_cache_interference(headers)
        assert res == CacheInterference.SUSPECTED_CACHE_HIT
        assert any("X-Cache" in r for r in reasons)

    def test_cf_cache_status_hit(self):
        headers = {
            "CF-Cache-Status": "HIT",
        }
        res, reasons = inspect_cache_interference(headers)
        assert res == CacheInterference.SUSPECTED_CACHE_HIT
        assert any("Cloudflare" in r for r in reasons)

    def test_varnish_cache_hit(self):
        headers = {
            "X-Varnish": "1234567 8901234",
        }
        res, reasons = inspect_cache_interference(headers)
        assert res == CacheInterference.SUSPECTED_CACHE_HIT
        assert any("Varnish" in r for r in reasons)


class TestSoft404AndErrorDetection:
    def test_http_error_status_codes(self):
        for code in (401, 403, 404, 500, 502):
            is_err, msg = is_soft_404_or_error(code, '{"message": "failed"}')
            assert is_err is True

    def test_empty_payloads(self):
        for empty_val in ("", "   ", "{}", "[]", "null", '""'):
            is_err, msg = is_soft_404_or_error(200, empty_val)
            assert is_err is True

    def test_json_error_envelopes(self):
        test_payloads = [
            json.dumps({"error": "Resource not found"}),
            json.dumps({"errors": [{"message": "Access denied"}]}),
            json.dumps({"message": "Invalid user ID"}),
            json.dumps({"status": "fail"}),
            json.dumps({"status": "error"}),
            json.dumps({"success": False}),
            json.dumps({"data": []}),
            json.dumps({"data": {}}),
            json.dumps({"detail": "User not found"}),
        ]
        for payload in test_payloads:
            is_err, msg = is_soft_404_or_error(200, payload)
            assert is_err is True, f"Failed to identify error in: {payload}"

    def test_html_access_denied_message(self):
        html_page = "<html><body><h1>Access Denied</h1><p>You do not have permission to view this resource.</p></body></html>"
        is_err, msg = is_soft_404_or_error(200, html_page)
        assert is_err is True

    def test_meaningful_data_payload_is_not_error(self):
        valid_json = json.dumps({
            "order_id": "ord_1001",
            "customer_name": "Bob Smith",
            "amount": 250.00,
            "items": ["laptop", "mouse"],
            "status": "completed",
        })
        is_err, msg = is_soft_404_or_error(200, valid_json)
        assert is_err is False
        assert msg == "Meaningful response payload"


class TestSemanticSimilarity:
    def test_exact_match_after_volatile_masking(self):
        body1 = json.dumps({
            "id": 105,
            "username": "alice",
            "timestamp": "2026-11-06T10:00:00Z",
            "request_id": "req-1",
        })
        body2 = json.dumps({
            "id": 105,
            "username": "alice",
            "timestamp": "2026-11-06T10:05:00Z",
            "request_id": "req-2",
        })
        ratio, is_exact = compute_semantic_similarity(body1, body2)
        assert is_exact is True
        assert ratio == 1.0

    def test_distinct_data_has_lower_similarity(self):
        body_a = json.dumps({"order_id": "ord_A", "user": "alice", "items": ["alpha"]})
        body_b = json.dumps({"order_id": "ord_B", "user": "bob", "items": ["beta", "gamma", "delta"]})
        ratio, is_exact = compute_semantic_similarity(body_a, body_b)
        assert is_exact is False
        assert ratio < 0.90


class TestSilentTenantScoping:
    def test_detects_silent_scoping_to_user_b(self):
        # User B requested Resource A, but response only contains User B's user_id
        body = json.dumps({"order_id": "ord_B", "user_id": "user_B", "data": "private"})
        is_silent_scoping = detect_silent_tenant_scoping(
            body_accessor=body,
            user_a_identifier="user_A",
            user_b_identifier="user_B",
        )
        assert is_silent_scoping is True

    def test_authentic_cross_user_leakage_is_not_silent_scoping(self):
        # Response contains User A's identifier
        body = json.dumps({"order_id": "ord_A", "user_id": "user_A", "data": "private_A"})
        is_silent_scoping = detect_silent_tenant_scoping(
            body_accessor=body,
            user_a_identifier="user_A",
            user_b_identifier="user_B",
        )
        assert is_silent_scoping is False

    def test_contains_resource_identifier(self):
        body = json.dumps({"order_id": "ord_9999", "amount": 50})
        assert contains_resource_identifier(body, "ord_9999") is True
        assert contains_resource_identifier(body, "ord_0000") is False


class TestFieldSpecificOwnershipEvidence:
    """
    Finding 1: Strict field-specific ownership evidence validation.
    Verifies that:
    - Owner ID in actual owner_id field is accepted.
    - Owner ID only in description is strictly rejected.
    - Owner ID only in a message field is strictly rejected.
    - Contradictory owner_id and user_id values fail closed.
    - Nested legitimate ownership fields are correctly extracted.
    - Missing owner field fails closed.
    """

    def test_owner_id_in_actual_owner_id_field_accepted(self):
        payload = json.dumps({
            "order_id": "ord_101",
            "owner_id": "user-A",
            "amount": 150.00,
            "status": "completed",
        })
        ok, msg = validate_ownership_evidence(payload, "user-A")
        assert ok is True
        assert "Ownership verified" in msg
        assert check_ownership_evidence(payload, "user-A") is True

    def test_owner_id_only_in_description_rejected(self):
        payload = json.dumps({
            "order_id": "ord_101",
            "description": "Invoice generated for user-A after checkout",
            "amount": 150.00,
            "status": "completed",
        })
        ok, msg = validate_ownership_evidence(payload, "user-A")
        assert ok is False
        assert "Missing ownership evidence" in msg
        assert check_ownership_evidence(payload, "user-A") is False

    def test_owner_id_only_in_message_field_rejected(self):
        payload = json.dumps({
            "status": "success",
            "message": "Welcome back user-A, your profile is loaded",
            "data": {"profile_name": "My Account"},
        })
        ok, msg = validate_ownership_evidence(payload, "user-A")
        assert ok is False
        assert "Missing ownership evidence" in msg
        assert check_ownership_evidence(payload, "user-A") is False

    def test_contradictory_owner_id_and_user_id_fails_closed(self):
        payload = json.dumps({
            "resource_id": "res_999",
            "owner_id": "user-A",
            "user_id": "user-B",
            "title": "Shared Resource Document",
        })
        ok, msg = validate_ownership_evidence(payload, "user-A")
        assert ok is False
        assert "Conflicting ownership evidence" in msg
        assert "user-A" in msg and "user-B" in msg
        assert check_ownership_evidence(payload, "user-A") is False

    def test_nested_legitimate_ownership_fields_accepted(self):
        payload = json.dumps({
            "data": {
                "item": {
                    "document_id": "doc_555",
                    "owner_id": "user-A",
                    "content": "Confidential Report",
                }
            }
        })
        ok, msg = validate_ownership_evidence(payload, "user-A")
        assert ok is True
        assert "Ownership verified" in msg
        assert check_ownership_evidence(payload, "user-A") is True

        # Test object-valued owner field
        payload_owner_obj = json.dumps({
            "data": {
                "owner": {
                    "id": "user-A",
                    "username": "alice",
                },
                "resource_name": "Financial Data",
            }
        })
        ok2, msg2 = validate_ownership_evidence(payload_owner_obj, "user-A")
        assert ok2 is True
        assert check_ownership_evidence(payload_owner_obj, "user-A") is True

    def test_missing_owner_field_fails_closed(self):
        payload = json.dumps({
            "order_id": "ord_101",
            "status": "active",
            "items": ["widget1", "widget2"],
        })
        ok, msg = validate_ownership_evidence(payload, "user-A")
        assert ok is False
        assert "Missing ownership evidence" in msg
        assert check_ownership_evidence(payload, "user-A") is False


class TestNestedOwnershipIdentityClaims:
    """
    Finding 2: Nested ownership identity claims validation and multi-category checks.
    Requirements:
    - Extract all configured trusted identity claims from nested owner objects.
    - Validate each claim against its explicitly configured identity category.
    - Reject contradictory claims within the same identity category.
    - Do not assume account_id, tenant_id, profile_id and user_id are interchangeable.
    - Use explicit field mappings.
    - Missing or ambiguous ownership evidence must fail closed.
    """

    def test_nested_owner_extracts_all_attributes_and_validates_multiple_categories_positive(self):
        """Positive test: owner object contains id and username matching configured expected claims."""
        payload = json.dumps({
            "resource_id": "doc_101",
            "owner": {
                "id": "user-A",
                "username": "alice",
                "email": "alice@target.test"
            }
        })
        expected_claims = {
            "id": "user-A",
            "username": "alice",
            "email": "alice@target.test"
        }
        ok, msg = validate_ownership_evidence(payload, expected_claims)
        assert ok is True
        assert "owner.id='user-A'" in msg
        assert "owner.username='alice'" in msg
        assert "owner.email='alice@target.test'" in msg
        assert check_ownership_evidence(payload, expected_claims) is True

    def test_nested_owner_contradictory_username_rejected(self):
        """Negative test: owner object has valid id but contradictory username (attacker)."""
        payload = json.dumps({
            "resource_id": "doc_101",
            "owner": {
                "id": "user-A",
                "username": "attacker"
            }
        })
        expected_claims = {
            "id": "user-A",
            "username": "alice"
        }
        ok, msg = validate_ownership_evidence(payload, expected_claims)
        assert ok is False
        assert "Ownership mismatch in field 'owner.username'" in msg
        assert "attacker" in msg
        assert check_ownership_evidence(payload, expected_claims) is False

    def test_nested_owner_contradictory_claims_same_category_fails_closed(self):
        """Negative test: owner object contains contradictory claims in the same identity category (user_id)."""
        payload = json.dumps({
            "resource_id": "doc_101",
            "owner": {
                "id": "user-A",
                "user_id": "attacker_b"
            }
        })
        ok, msg = validate_ownership_evidence(payload, "user-A")
        assert ok is False
        assert "Conflicting ownership evidence" in msg
        assert "user-A" in msg and "attacker_b" in msg
        assert check_ownership_evidence(payload, "user-A") is False

    def test_account_id_and_user_id_not_interchangeable_without_explicit_mapping(self):
        """Negative test: account_id is not treated as user_id without explicit mapping."""
        payload = json.dumps({
            "order_id": "ord_101",
            "account_id": "acc-999",
            "amount": 250.00
        })
        # Searching for expected user_id="acc-999" fails because account_id is distinct category
        ok, msg = validate_ownership_evidence(payload, "acc-999", expected_claim_type="user_id")
        assert ok is False
        assert "Missing ownership evidence" in msg
        assert "category 'user_id'" in msg

    def test_account_id_accepted_with_explicit_field_mapping(self):
        """Positive test: explicit field mapping permits validating account_id as user_id."""
        payload = json.dumps({
            "order_id": "ord_101",
            "account_id": "acc-999",
            "amount": 250.00
        })
        # With explicit mapping, account_id is recognized under the target category
        ok, msg = validate_ownership_evidence(
            payload,
            "acc-999",
            expected_claim_type="user_id",
            field_mappings={"account_id": "user_id"}
        )
        assert ok is True
        assert "account_id='acc-999'" in msg

    def test_tenant_id_validated_against_tenant_category(self):
        """Positive test: tenant_id verified against its own dedicated category."""
        payload = json.dumps({
            "document_id": "doc_777",
            "tenant_id": "tenant-corp-1",
            "user_id": "user-A"
        })
        expected_claims = {
            "user_id": "user-A",
            "tenant_id": "tenant-corp-1"
        }
        ok, msg = validate_ownership_evidence(payload, expected_claims)
        assert ok is True
        assert "tenant_id='tenant-corp-1'" in msg
        assert "user_id='user-A'" in msg

    def test_mismatched_tenant_id_fails_closed(self):
        """Negative test: tenant_id mismatch fails closed even if user_id matches."""
        payload = json.dumps({
            "document_id": "doc_777",
            "tenant_id": "tenant-corp-2",
            "user_id": "user-A"
        })
        expected_claims = {
            "user_id": "user-A",
            "tenant_id": "tenant-corp-1"
        }
        ok, msg = validate_ownership_evidence(payload, expected_claims)
        assert ok is False
        assert "Ownership mismatch in field 'tenant_id'" in msg
        assert "tenant-corp-2" in msg


class TestExactResourceIdentityMatching:
    """
    Finding 3: Strict structured JSON resource identifier verification.
    Verifies that:
    - 105 vs 2105 is strictly rejected (no substring match).
    - 105 vs 1050 is strictly rejected (no prefix/suffix match).
    - Resource IDs appearing only in descriptions are rejected.
    - Resource IDs appearing only in timestamps are rejected.
    - Exact resource ID in recognized field is accepted.
    - Conflicting resource IDs in same response fail closed.
    - Non-structured or invalid JSON fails closed.
    - Type-aware integer and string matching is preserved.
    """

    def test_105_vs_2105_rejected(self):
        """105 must not match 2105 despite substring containment."""
        payload = json.dumps({"order_id": 2105, "item": "Widget"})
        assert contains_resource_identifier(payload, "105") is False
        assert contains_resource_identifier(payload, 105) is False
        ok, msg = validate_resource_identifier(payload, "105")
        assert ok is False
        assert "Resource identifier mismatch" in msg

    def test_105_vs_1050_rejected(self):
        """105 must not match 1050 despite prefix containment."""
        payload = json.dumps({"order_id": 1050, "item": "Widget"})
        assert contains_resource_identifier(payload, "105") is False
        assert contains_resource_identifier(payload, 105) is False
        ok, msg = validate_resource_identifier(payload, "105")
        assert ok is False
        assert "Resource identifier mismatch" in msg

    def test_id_only_in_description_rejected(self):
        """Resource ID appearing only in description or text fields must be rejected."""
        payload = json.dumps({
            "order_id": 9999,
            "description": "Invoice for order 105 was generated successfully",
            "message": "Processed ID: 105"
        })
        assert contains_resource_identifier(payload, "105") is False
        ok, msg = validate_resource_identifier(payload, "105")
        assert ok is False
        assert "Resource identifier mismatch" in msg

    def test_id_only_in_timestamp_rejected(self):
        """Resource ID appearing only in timestamps or dates must be rejected."""
        payload = json.dumps({
            "order_id": 9999,
            "timestamp": 105,
            "created_at": "2026-11-06T10:50:00Z"
        })
        assert contains_resource_identifier(payload, "105") is False
        ok, msg = validate_resource_identifier(payload, "105")
        assert ok is False
        assert "Resource identifier mismatch" in msg

    def test_exact_resource_id_in_correct_field_accepted(self):
        """Exact resource ID in recognized field is accepted."""
        payload = json.dumps({"order_id": "105", "item": "Widget A", "price": 100})
        assert contains_resource_identifier(payload, "105") is True
        assert contains_resource_identifier(payload, 105) is True
        ok, msg = validate_resource_identifier(payload, "105")
        assert ok is True
        assert "confirmed in field 'order_id'" in msg

    def test_exact_resource_id_in_nested_wrapper_accepted(self):
        """Exact resource ID inside data/item wrapper is accepted."""
        payload = json.dumps({"data": {"id": 105, "title": "Report"}})
        assert contains_resource_identifier(payload, 105) is True
        ok, msg = validate_resource_identifier(payload, "105")
        assert ok is True
        assert "confirmed in field 'data.id'" in msg

    def test_conflicting_resource_ids_in_same_response_fails_closed(self):
        """Conflicting resource IDs in primary container must fail closed."""
        payload = json.dumps({"order_id": "105", "id": "205"})
        extracted, conflict_err = extract_resource_identifiers(payload)
        assert conflict_err is not None
        assert "Contradictory resource identifiers" in conflict_err
        assert contains_resource_identifier(payload, "105") is False
        ok, msg = validate_resource_identifier(payload, "105")
        assert ok is False
        assert "Conflicting resource identity evidence" in msg

    def test_non_structured_evidence_fails_closed(self):
        """Non-JSON text or HTML containing the identifier must fail closed."""
        plain_text = "HTTP 200 OK: Order 105 created"
        assert contains_resource_identifier(plain_text, "105") is False
        ok, msg = validate_resource_identifier(plain_text, "105")
        assert ok is False
        assert "no recognized resource ID fields found" in msg

    def test_empty_payload_fails_closed(self):
        """Empty payload fails closed."""
        assert contains_resource_identifier("", "105") is False
        assert contains_resource_identifier("{}", "105") is False


class TestResourceIdentityOwnershipSeparation:
    """
    Finding 3: Resource identity and ownership separation in comparator.
    Verifies that:
    - Responses containing only user_id, owner_id, tenant_id, or account_id return NO resource identifier.
    - contains_resource_identifier() cannot silently reinterpret ownership evidence as resource identity.
    - Explicitly configured endpoint-specific target_field or trusted_fields mapping allows configured ownership fields.
    """

    def test_response_with_only_user_id_fails_resource_identity_validation(self):
        """user_id cannot satisfy resource identity check by default."""
        payload = json.dumps({"user_id": "105", "username": "alice", "status": "active"})
        extracted, err = extract_resource_identifiers(payload)
        assert extracted == {}
        assert err is None
        assert contains_resource_identifier(payload, "105") is False
        ok, msg = validate_resource_identifier(payload, "105")
        assert ok is False
        assert "no recognized resource ID fields found" in msg

    def test_response_with_only_owner_id_fails_resource_identity_validation(self):
        """owner_id cannot satisfy resource identity check by default."""
        payload = json.dumps({"owner_id": "105", "name": "Team Alpha"})
        extracted, err = extract_resource_identifiers(payload)
        assert extracted == {}
        assert contains_resource_identifier(payload, "105") is False
        ok, msg = validate_resource_identifier(payload, "105")
        assert ok is False
        assert "no recognized resource ID fields found" in msg

    def test_response_with_only_tenant_id_fails_resource_identity_validation(self):
        """tenant_id cannot satisfy resource identity check by default."""
        payload = json.dumps({"tenant_id": "tenant-105", "org_name": "Acme Corp"})
        extracted, err = extract_resource_identifiers(payload)
        assert extracted == {}
        assert contains_resource_identifier(payload, "tenant-105") is False
        ok, msg = validate_resource_identifier(payload, "tenant-105")
        assert ok is False
        assert "no recognized resource ID fields found" in msg

    def test_response_with_only_account_id_fails_resource_identity_validation(self):
        """account_id cannot satisfy resource identity check by default."""
        payload = json.dumps({"account_id": "acc-105", "tier": "gold"})
        extracted, err = extract_resource_identifiers(payload)
        assert extracted == {}
        assert contains_resource_identifier(payload, "acc-105") is False
        ok, msg = validate_resource_identifier(payload, "acc-105")
        assert ok is False
        assert "no recognized resource ID fields found" in msg

    def test_explicit_endpoint_target_field_mapping_permits_configured_field(self):
        """Explicitly configured target_field='user_id' permits user_id as resource ID."""
        payload = json.dumps({"user_id": "105", "status": "active"})
        extracted, err = extract_resource_identifiers(payload, target_field="user_id")
        assert "user_id" in extracted
        assert extracted["user_id"] == "105"
        assert contains_resource_identifier(payload, "105", target_field="user_id") is True
        ok, msg = validate_resource_identifier(payload, "105", target_field="user_id")
        assert ok is True
        assert "confirmed in field 'user_id'" in msg

    def test_explicit_trusted_fields_mapping_permits_configured_ownership_field(self):
        """Explicitly configured trusted_fields={'account_id'} permits account_id as resource ID."""
        payload = json.dumps({"account_id": "acc-105", "tier": "enterprise"})
        extracted, err = extract_resource_identifiers(payload, trusted_fields={"account_id"})
        assert "account_id" in extracted
        assert extracted["account_id"] == "acc-105"
        assert contains_resource_identifier(payload, "acc-105", trusted_fields={"account_id"}) is True
        ok, msg = validate_resource_identifier(payload, "acc-105", trusted_fields={"account_id"})
        assert ok is True
        assert "confirmed in field 'account_id'" in msg


class TestStructuredResponseResourceIdentityIntegrity:
    """
    Finding 3: Ensure structured response field represents the actual resource identity.
    Verifies that:
    - Incidental numbers in nested collections (e.g. comments, audit logs) are never accepted as primary resource ID.
    - Child collection IDs (line_items[0].product_id) do not satisfy parent order ID.
    - Configured target_field strictly rejects unrelated _id fields.
    - Disallowed nested sub-resource fields (tax_id, tracking_id, coupon_id) are rejected.
    """

    def test_nested_sub_object_id_rejected_as_primary_resource_id(self):
        """comment_id inside nested comments collection cannot satisfy order resource ID."""
        payload = json.dumps({
            "order_title": "Order Title",
            "comments": [{"comment_id": "105", "text": "Shipment arrived"}],
        })
        extracted, err = extract_resource_identifiers(payload)
        assert extracted == {}
        ok, msg = validate_resource_identifier(payload, "105")
        assert ok is False
        assert "no recognized resource ID fields found" in msg

    def test_incidental_id_in_line_items_rejected_as_order_id(self):
        """product_id in line_items array cannot satisfy order resource ID."""
        payload = json.dumps({
            "status": "shipped",
            "line_items": [{"product_id": "105", "quantity": 2}],
        })
        extracted, err = extract_resource_identifiers(payload)
        assert extracted == {}
        ok, msg = validate_resource_identifier(payload, "105")
        assert ok is False
        assert "no recognized resource ID fields found" in msg

    def test_target_field_rejects_unrelated_id_fields(self):
        """When target_field='order_id' is configured, matching tracking_id does not satisfy resource ID."""
        payload = json.dumps({
            "order_id": "999",
            "tracking_id": "105",
            "status": "delivered",
        })
        ok, msg = validate_resource_identifier(payload, "105", target_field="order_id")
        assert ok is False
        assert "Resource identifier mismatch" in msg

    def test_nested_coupon_or_tax_id_rejected_without_target_field(self):
        """tax_id and coupon_id in pricing sub-object cannot represent primary resource ID."""
        payload = json.dumps({
            "name": "Widget Order",
            "pricing": {"subtotal": 50, "tax_id": "105", "coupon_id": "105"},
        })
        extracted, err = extract_resource_identifiers(payload)
        assert extracted == {}
        assert contains_resource_identifier(payload, "105") is False

