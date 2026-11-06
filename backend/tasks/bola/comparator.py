"""
Semantic Response Comparator for BOLA / IDOR Differential Verification.

Provides fine-grained differential comparison between HTTP responses across
different identity contexts (Owner, Accessor, Reverse-Owner, Anonymous).
Distinguishes between:
- Authentic cross-user data leakage (User B accessing User A's private resource)
- Silent server-side tenant scoping (User B receiving their own data despite requesting A)
- Soft-404 and 200 OK error payloads (empty bodies, generic error messages, JSON error envelopes)
- Public resources (unauthenticated session retrieving identical data)
- Intermediary cache interference (CDN/proxy serving cached User A response)
"""
from __future__ import annotations

import difflib
import enum
import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple

# Default volatile JSON field names (timestamps, nonces, request/trace IDs)
DEFAULT_VOLATILE_FIELDS: Set[str] = {
    "timestamp",
    "updated_at",
    "created_at",
    "last_modified",
    "request_id",
    "trace_id",
    "span_id",
    "correlation_id",
    "server_time",
    "time",
    "date",
    "_csrf",
    "csrf_token",
    "nonce",
    "generation_time_ms",
    "duration_ms",
    "response_time",
}

# Protected resource identifier and ownership fields: NEVER masked even if matching volatile patterns
DEFAULT_PROTECTED_ID_FIELDS: Set[str] = {
    "id",
    "user_id",
    "account_id",
    "order_id",
    "owner_id",
    "tenant_id",
    "username",
    "email",
    "sub",
    "uuid",
    "guid",
    "customer_id",
    "client_id",
    "profile_id",
    "resource_id",
    "document_id",
    "item_id",
    "member_id",
    "owner",
    "user",
    "account",
    "creator",
}

# Common soft-404 / access-denied keywords across web responses
SOFT_404_KEYWORDS_RE = re.compile(
    r"\b(not found|access denied|forbidden|unauthorized|permission denied|"
    r"invalid (user|id|token|session|resource|parameter)|no such (user|item|order|record|resource)|"
    r"does not exist|item not found|record not found|resource not found|"
    r"authentication required|login required)\b",
    re.IGNORECASE,
)


class CacheInterference(str, enum.Enum):
    NONE = "none"
    SUSPECTED_CACHE_HIT = "suspected_cache_hit"
    AMBIGUOUS_CACHE_CONTROL = "ambiguous_cache_control"


# Volatile diagnostic IDs that end in _id but must be masked (NOT resource identifiers)
VOLATILE_ID_FIELDS: Set[str] = {
    "request_id",
    "trace_id",
    "span_id",
    "correlation_id",
    "req_id",
    "transaction_id",
}


def is_protected_field(key: str, custom_protected: Optional[Set[str]] = None) -> bool:
    """
    Returns True if key represents a critical identity or resource identifier
    that must never be masked during volatile field filtering.
    Diagnostic IDs (request_id, trace_id, span_id, correlation_id) are volatile and NOT protected.
    """
    norm_key = key.strip().lower()
    if norm_key in VOLATILE_ID_FIELDS:
        return False
    protected = DEFAULT_PROTECTED_ID_FIELDS | (custom_protected or set())
    if norm_key in protected:
        return True
    if norm_key.endswith("_id") or norm_key.endswith("id"):
        return True
    return False


def mask_volatile_fields(
    data: Any,
    volatile_fields: Optional[Set[str]] = None,
    protected_fields: Optional[Set[str]] = None,
) -> Any:
    """
    Recursively masks volatile fields (timestamps, trace IDs, CSRF tokens)
    in JSON-serializable structures while strictly preserving resource identifiers
    and ownership fields.
    """
    volatile = DEFAULT_VOLATILE_FIELDS | (volatile_fields or set())
    protected = DEFAULT_PROTECTED_ID_FIELDS | (protected_fields or set())

    if isinstance(data, dict):
        masked: Dict[str, Any] = {}
        for k, v in data.items():
            norm_k = str(k).strip().lower()
            if norm_k in volatile and not is_protected_field(norm_k, protected):
                masked[k] = "[VOLATILE]"
            else:
                masked[k] = mask_volatile_fields(v, volatile, protected)
        return masked
    elif isinstance(data, list):
        return [mask_volatile_fields(item, volatile, protected) for item in data]
    return data


def inspect_cache_interference(headers: Dict[str, str]) -> Tuple[CacheInterference, List[str]]:
    """
    Inspects response headers for signs of proxy/CDN caching.
    Returns (CacheInterference, reasons).
    """
    reasons: List[str] = []
    norm_headers = {k.lower(): v for k, v in headers.items()}

    # 1. Check Age header (> 0 implies served from cache)
    age_str = norm_headers.get("age")
    if age_str:
        try:
            age_val = int(age_str.strip())
            if age_val > 0:
                reasons.append(f"Age header > 0 ({age_val}s)")
        except ValueError:
            pass

    # 2. Check X-Cache / CF-Cache-Status / X-Varnish
    x_cache = norm_headers.get("x-cache", "").upper()
    if "HIT" in x_cache:
        reasons.append(f"X-Cache header indicates HIT: {x_cache}")

    cf_cache = norm_headers.get("cf-cache-status", "").upper()
    if cf_cache in ("HIT", "STALE", "UPDATING"):
        reasons.append(f"Cloudflare cache status indicates HIT: {cf_cache}")

    x_varnish = norm_headers.get("x-varnish", "")
    if len(x_varnish.strip().split()) >= 2 or "hit" in x_varnish.lower():
        reasons.append(f"Varnish cache hit: x-varnish={x_varnish.strip()}")

    if reasons:
        return CacheInterference.SUSPECTED_CACHE_HIT, reasons

    # Check for ambiguous public caching
    cc = norm_headers.get("cache-control", "").lower()
    if "public" in cc and "max-age" in cc:
        reasons.append(f"Public Cache-Control header present: {cc}")
        return CacheInterference.AMBIGUOUS_CACHE_CONTROL, reasons

    return CacheInterference.NONE, []


def is_soft_404_or_error(
    status_code: int,
    body: str,
    content_type: str = "",
) -> Tuple[bool, str]:
    """
    Evaluates whether an HTTP response is an empty payload, soft-404, or generic error message,
    even if returned with HTTP 200 OK.

    Decision Table:
    ---------------------------------------------------------------------------------------------------------
    HTTP Status Code  | Response Payload Condition                     | Classification & Output Message
    ---------------------------------------------------------------------------------------------------------
    >= 500            | Any                                            | HTTP server error status code {status_code}
    401, 403          | Any                                            | HTTP authorization denial status code {status_code}
    404, 410          | Any                                            | HTTP client error status code {status_code}
    >= 400            | Any                                            | HTTP error status code {status_code}
    200 / 2xx         | Empty or whitespace ("   ")                    | Empty response body
    200 / 2xx         | "null", '""', "{}", "[]", "false"              | Trivial empty JSON response: {clean_body}
    200 / 2xx         | JSON empty data wrapper ({"data": []}, etc.)   | JSON payload has empty '{wrapper}' container
    200 / 2xx         | JSON error envelope (error, errors, detail)    | JSON error envelope: {val}
    200 / 2xx         | JSON status=fail/error or success=false        | JSON status/indicator failure
    200 / 2xx         | Text/HTML soft-404 keywords (< 2048 chars)     | Soft-404 keyword detected in response body
    200 / 2xx         | Structured, legitimate business data           | (False, "Meaningful response payload")
    ---------------------------------------------------------------------------------------------------------
    """
    if status_code >= 500:
        return True, f"HTTP server error status code {status_code}"
    if status_code in (401, 403):
        return True, f"HTTP authorization denial status code {status_code}"
    if status_code in (404, 410):
        return True, f"HTTP client error status code {status_code}"
    if status_code >= 400:
        return True, f"HTTP error status code {status_code}"

    clean_body = body.strip() if body else ""
    if not clean_body:
        return True, "Empty response body"

    # Minimal payload threshold
    if len(clean_body) < 15:
        if clean_body in ("{}", "[]", "null", '""', "false"):
            return True, f"Trivial empty JSON response: {clean_body}"

    # Try parsing as JSON to check for common error envelopes
    try:
        data = json.loads(clean_body)
        if data is None or data == "" or data == {} or data == []:
            return True, f"Empty JSON container: {clean_body}"

        if isinstance(data, dict):
            # Check empty dictionary
            if not data:
                return True, "Empty JSON object payload"

            # Check for error keys
            error_keys = ("error", "errors", "detail", "errorMessage", "fault")
            for ek in error_keys:
                if ek in data and data[ek] is not None:
                    val = data[ek]
                    if isinstance(val, str) and val.strip():
                        return True, f"JSON error envelope: {val.strip()}"
                    elif isinstance(val, (dict, list)) and len(val) > 0:
                        return True, f"JSON error envelope in key '{ek}': {json.dumps(val)}"

            # Check message key when it indicates an error or failure
            if "message" in data and data["message"] is not None:
                msg_str = str(data["message"]).strip()
                if SOFT_404_KEYWORDS_RE.search(msg_str) or any(w in msg_str.lower() for w in ("invalid", "error", "fail", "denied", "not found")):
                    return True, f"JSON error message: {msg_str}"

            # Check status flags (e.g. {"status": "fail"} or {"success": false})
            status_val = str(data.get("status", "")).strip().lower()
            if status_val in ("fail", "failed", "error", "not_found", "unauthorized"):
                return True, f"JSON status flag indicates failure: status={data.get('status')}"

            if data.get("success") is False:
                return True, "JSON payload has success=false"

            # Check empty nested data wrappers (e.g. {"data": []}, {"data": {}}, {"items": []}, {"order_id": "105", "items": [], "data": []})
            empty_wrappers = [w for w in ("data", "items", "results", "records") if w in data and data[w] in (None, [], {})]
            if empty_wrappers:
                non_empty_substantive = [
                    k for k, v in data.items()
                    if k not in ("data", "items", "results", "records")
                    and v not in (None, [], {}, "")
                    and not k.lower().endswith("_id")
                    and k.lower() not in ("id", "status", "success", "total", "count", "code", "page", "per_page", "limit", "offset")
                ]
                if not non_empty_substantive:
                    return True, f"JSON payload has empty '{empty_wrappers[0]}' container"

        elif isinstance(data, list):
            if len(data) == 0:
                return True, "Empty JSON array payload"
    except Exception:
        # Non-JSON content (HTML/plain text)
        pass

    # Keyword check in HTML or plain text
    if len(clean_body) < 2048 and SOFT_404_KEYWORDS_RE.search(clean_body):
        match = SOFT_404_KEYWORDS_RE.search(clean_body)
        return True, f"Soft-404 keyword detected in response body: '{match.group(0)}'"

    return False, "Meaningful response payload"


def _strip_volatile_nodes(data: Any) -> Any:
    """Helper to remove volatile markers to test pure business data equality."""
    if isinstance(data, dict):
        return {k: _strip_volatile_nodes(v) for k, v in data.items() if v != "[VOLATILE]"}
    elif isinstance(data, list):
        return [_strip_volatile_nodes(x) for x in data if x != "[VOLATILE]"]
    return data


def compute_semantic_similarity(
    body_a: str,
    body_b: str,
    volatile_fields: Optional[Set[str]] = None,
    protected_fields: Optional[Set[str]] = None,
) -> Tuple[float, bool]:
    """
    Computes semantic similarity ratio [0.0, 1.0] between two response bodies
    after masking volatile fields. Returns (similarity_ratio, exact_json_match).
    """
    if body_a == body_b:
        return 1.0, True

    if not body_a or not body_b:
        return 0.0, False

    # Try parsing both as JSON
    try:
        json_a = json.loads(body_a)
        json_b = json.loads(body_b)

        # Mask volatile fields on both
        masked_a = mask_volatile_fields(json_a, volatile_fields, protected_fields)
        masked_b = mask_volatile_fields(json_b, volatile_fields, protected_fields)

        if masked_a == masked_b:
            return 1.0, True

        # If pure non-volatile business data fields are identical, treat as exact match
        clean_a = _strip_volatile_nodes(masked_a)
        clean_b = _strip_volatile_nodes(masked_b)
        if clean_a == clean_b and clean_a:
            return 1.0, True

        # Normalized string representation of masked JSON
        norm_a = json.dumps(masked_a, sort_keys=True)
        norm_b = json.dumps(masked_b, sort_keys=True)

        ratio = difflib.SequenceMatcher(None, norm_a, norm_b).ratio()
        return round(ratio, 4), False
    except Exception:
        # Fall back to textual similarity
        ratio = difflib.SequenceMatcher(None, body_a.strip(), body_b.strip()).ratio()
        return round(ratio, 4), False


DEFAULT_RESOURCE_ID_FIELDS: Set[str] = {
    "id",
    "resource_id",
    "resourceid",
    "item_id",
    "itemid",
    "order_id",
    "orderid",
    "document_id",
    "doc_id",
    "record_id",
    "object_id",
    "entity_id",
    "uuid",
    "guid",
}

DISALLOWED_RESOURCE_FIELDS: Set[str] = {
    "description",
    "desc",
    "message",
    "msg",
    "comment",
    "comments",
    "note",
    "notes",
    "summary",
    "text",
    "title",
    "body",
    "details",
    "info",
    "log",
    "reason",
    "error",
    "errors",
    "timestamp",
    "time",
    "date",
    "created_at",
    "updated_at",
    "deleted_at",
    "request_id",
    "trace_id",
    "span_id",
    "correlation_id",
}


DISALLOWED_NESTED_RESOURCE_FIELDS: Set[str] = {
    "comment_id",
    "comments_id",
    "tag_id",
    "tags_id",
    "event_id",
    "events_id",
    "log_id",
    "logs_id",
    "audit_id",
    "tracking_id",
    "shipping_id",
    "tax_id",
    "coupon_id",
    "discount_id",
    "category_id",
    "action_id",
    "step_id",
    "transaction_id",
    "sub_id",
    "child_id",
    "notification_id",
}


OWNERSHIP_IDENTITY_FIELDS: Set[str] = {
    "user_id",
    "userid",
    "owner_id",
    "creator_id",
    "author_id",
    "created_by",
    "tenant_id",
    "tenantid",
    "account_id",
    "accountid",
    "profile_id",
    "profileid",
    "customer_id",
    "member_id",
    "client_id",
    "sub",
    "subject",
}


def extract_resource_identifiers(
    body: str,
    target_field: Optional[str] = None,
    trusted_fields: Optional[Set[str]] = None,
) -> Tuple[Dict[str, Any], Optional[str]]:
    """
    Extracts recognized resource identity claims from a structured JSON response body.
    Requirements:
    1. Parse JSON payload; non-JSON, non-dict/list, or empty bodies return empty dict (fail closed).
    2. Inspect root keys and standard nested wrappers ('data', 'item', 'resource', 'order', etc.).
    3. Exclude disallowed fields ('description', 'timestamp', 'message', 'request_id', etc.).
    4. Match only recognized resource identity fields or explicitly configured target/trusted fields.
    5. Exclude ownership identity fields (user_id, owner_id, etc.) from resource identity extraction
       unless explicitly targeted or configured in trusted_fields. Never fall back to ownership fields.
    6. Exclude nested sub-entity fields (comment_id, product_id, tracking_id) that do not represent
       the primary resource identity.
    7. Detect conflicting resource IDs within the primary resource container.
    Returns (extracted_dict[field_path -> raw_val], conflict_error_msg_or_none).
    """
    if not body or not body.strip():
        return {}, None

    try:
        data = json.loads(body.strip())
    except Exception:
        return {}, None

    if not isinstance(data, (dict, list)):
        return {}, None

    recognized = DEFAULT_RESOURCE_ID_FIELDS | {f.lower().strip() for f in (trusted_fields or set())}
    if target_field:
        recognized.add(target_field.lower().strip())

    dicts_to_inspect: List[Tuple[str, Dict[str, Any]]] = []

    def _collect_resource_dicts(prefix: str, obj: Any, depth: int = 0) -> None:
        if depth > 3:
            return
        if isinstance(obj, dict):
            dicts_to_inspect.append((prefix, obj))
            for k, v in obj.items():
                norm_k = str(k).strip().lower()
                if norm_k in NESTED_WRAPPER_KEYS or (target_field and norm_k == target_field.lower().strip()):
                    new_prefix = f"{prefix}.{norm_k}" if prefix else norm_k
                    if isinstance(v, (dict, list)):
                        _collect_resource_dicts(new_prefix, v, depth + 1)
        elif isinstance(obj, list) and not prefix:
            # Only inspect top-level list items as primary resource representations
            for i, item in enumerate(obj[:3]):
                new_prefix = f"[{i}]"
                if isinstance(item, (dict, list)):
                    _collect_resource_dicts(new_prefix, item, depth + 1)

    _collect_resource_dicts("", data)

    extracted: Dict[str, Any] = {}

    for prefix, d in dicts_to_inspect:
        for k, v in d.items():
            norm_k = str(k).strip().lower()
            if norm_k in DISALLOWED_RESOURCE_FIELDS or norm_k in DISALLOWED_OWNERSHIP_FIELDS:
                continue

            # Check if this key matches recognized resource fields
            is_recognized = False
            if target_field:
                if norm_k == target_field.lower().strip():
                    is_recognized = True
            else:
                if norm_k in recognized:
                    is_recognized = True
                elif (
                    norm_k.endswith("_id")
                    and norm_k not in OWNERSHIP_IDENTITY_FIELDS
                    and norm_k not in DISALLOWED_RESOURCE_FIELDS
                    and norm_k not in DISALLOWED_NESTED_RESOURCE_FIELDS
                ):
                    # Only accept generic _id on root or known primary wrapper, not nested sub-objects
                    if not prefix or prefix in NESTED_WRAPPER_KEYS:
                        is_recognized = True

            if is_recognized and isinstance(v, (str, int, float)) and not isinstance(v, bool):
                val_str = str(v).strip()
                if val_str:
                    field_path = f"{prefix}.{norm_k}" if prefix and not prefix.endswith(norm_k) else norm_k
                    extracted[field_path] = v

    # Check for conflicting resource IDs across primary resource container fields
    if len(extracted) > 1:
        unique_vals = set()
        for v in extracted.values():
            unique_vals.add(str(v).strip().lower())
        if len(unique_vals) > 1:
            conflict_details = ", ".join(f"{fp}={v}" for fp, v in extracted.items())
            return extracted, f"Contradictory resource identifiers in same payload: {conflict_details}"

    return extracted, None


def validate_resource_identifier(
    body: str,
    expected_identifier: str | int,
    target_field: Optional[str] = None,
    trusted_fields: Optional[Set[str]] = None,
) -> Tuple[bool, str]:
    """
    Validates that the response body contains an exact match for the expected resource identifier
    in recognized resource identity fields using structured JSON parsing.
    Rejects:
    - Non-structured or invalid JSON.
    - Substring matches (e.g. 105 in 2105 or 105 in 1050).
    - Incidental matches in disallowed fields (descriptions, messages, timestamps).
    - Responses containing conflicting resource IDs.
    """
    if expected_identifier is None or not str(expected_identifier).strip():
        return False, "Expected resource identifier is empty or not provided"
    if not body or not body.strip():
        return False, "Response body is empty"

    extracted, conflict_error = extract_resource_identifiers(
        body=body,
        target_field=target_field,
        trusted_fields=trusted_fields,
    )

    if conflict_error:
        return False, f"Conflicting resource identity evidence: {conflict_error}"

    if not extracted:
        return False, "Missing resource identity evidence: no recognized resource ID fields found"

    exp_str = str(expected_identifier).strip()
    exp_is_int = exp_str.isdigit()

    for fp, val in extracted.items():
        act_str = str(val).strip()
        matched = False
        if exp_is_int and act_str.isdigit():
            matched = (int(act_str) == int(exp_str))
        else:
            matched = (act_str.lower() == exp_str.lower())

        if matched:
            return True, f"Resource identifier '{expected_identifier}' confirmed in field '{fp}'"

    return False, f"Resource identifier mismatch: expected '{expected_identifier}', but found {extracted}"


def contains_resource_identifier(
    body: str,
    identifier: str | int,
    target_field: Optional[str] = None,
    trusted_fields: Optional[Set[str]] = None,
) -> bool:
    """Checks if a specific stable resource identifier appears in recognized fields in the response body."""
    ok, _ = validate_resource_identifier(
        body=body,
        expected_identifier=identifier,
        target_field=target_field,
        trusted_fields=trusted_fields,
    )
    return ok


def detect_silent_tenant_scoping(
    body_accessor: str,
    user_a_identifier: str,
    user_b_identifier: Optional[str] = None,
) -> bool:
    """
    Detects if the target server ignored the requested resource ID (belonging to User A)
    and silently returned User B's own data based on User B's active session cookie/token.

    Returns True if:
    - User B's ownership evidence is present in trusted ownership fields AND
    - User A's identity/ownership is absent from the response.
    Fails closed if the payload is non-structured or ambiguous.
    """
    if not body_accessor or not user_a_identifier:
        return False

    has_b = bool(user_b_identifier and check_ownership_evidence(body_accessor, user_b_identifier))
    has_a_owner = check_ownership_evidence(body_accessor, user_a_identifier)
    has_a_res = contains_resource_identifier(body_accessor, user_a_identifier)
    has_a = has_a_owner or has_a_res

    # If the response explicitly contains User B's ownership and NOT User A's,
    # the server silently scoped to User B (safe behavior, NOT BOLA).
    if has_b and not has_a:
        return True

    return False


GENERIC_WRAPPER_OR_STATUS_FIELDS: Set[str] = {
    "status", "success", "message", "msg", "code", "ok", "error", "errors", "type"
}


# Canonical category mappings for ownership claims:
# Note: user_id, account_id, tenant_id, and profile_id are distinct, non-interchangeable categories.
OWNERSHIP_CLAIM_CATEGORIES: Dict[str, str] = {
    # User ID category (identifies the user principal)
    "id": "user_id",
    "user_id": "user_id",
    "userid": "user_id",
    "sub": "user_id",
    "subject": "user_id",
    "uuid": "user_id",
    "guid": "user_id",
    "owner_id": "user_id",
    "creator_id": "user_id",
    "author_id": "user_id",
    # Username category
    "username": "username",
    "user_name": "username",
    "login": "username",
    # Email category
    "email": "email",
    "user_email": "email",
    # Account ID category (distinct from user_id)
    "account_id": "account_id",
    "accountid": "account_id",
    # Tenant ID category (distinct from user_id)
    "tenant_id": "tenant_id",
    "tenantid": "tenant_id",
    # Profile ID category (distinct from user_id)
    "profile_id": "profile_id",
    "profileid": "profile_id",
    # Additional distinct categories
    "customer_id": "customer_id",
    "member_id": "member_id",
    "client_id": "client_id",
}

# Trusted resource ownership field names tying a resource to a specific tenant/owner identity
DEFAULT_TRUSTED_OWNERSHIP_FIELDS: Set[str] = {
    "owner_id",
    "user_id",
    "account_id",
    "creator_id",
    "author_id",
    "owner",
    "user",
    "creator",
    "author",
    "created_by",
    "sub",
    "customer_id",
    "member_id",
    "tenant_id",
    "client_id",
    "profile_id",
}

# Explicitly disallowed non-ownership fields that must never establish ownership proof
DISALLOWED_OWNERSHIP_FIELDS: Set[str] = {
    "description",
    "desc",
    "message",
    "msg",
    "comment",
    "comments",
    "note",
    "notes",
    "summary",
    "text",
    "title",
    "body",
    "details",
    "info",
    "log",
    "reason",
    "error",
    "errors",
}

# Standard wrapper keys for inspecting nested JSON payloads
NESTED_WRAPPER_KEYS: Set[str] = {
    "data",
    "item",
    "resource",
    "result",
    "payload",
    "user",
    "owner",
    "account",
    "profile",
}


def extract_ownership_evidence(
    body: str,
    trusted_fields: Optional[Set[str]] = None,
    field_mappings: Optional[Dict[str, str]] = None,
) -> Tuple[Dict[str, Tuple[str, str]], Optional[str]]:
    """
    Extracts all trusted ownership claims from a response body following explicit rules:
    1. Parse JSON payload; non-JSON or empty bodies return empty evidence.
    2. Inspect root keys and standard nested wrappers ('data', 'item', 'resource', 'owner', 'user').
    3. Exclude disallowed fields ('description', 'message', 'comment', etc.).
    4. For dict-valued ownership/wrapper fields (e.g. 'owner': {'id': '...', 'username': '...'}),
       extract ALL inner identity attributes without stopping at the first key.
    5. Map each attribute to its distinct identity category (user_id, account_id, tenant_id, username, email).
    6. Detect and reject conflicting ownership claims within the same identity category.
    Returns (extracted_claims_dict[field_path -> (category, value)], conflict_error_msg_or_none).
    """
    if not body or not body.strip():
        return {}, None

    try:
        data = json.loads(body.strip())
    except Exception:
        return {}, None

    trusted = DEFAULT_TRUSTED_OWNERSHIP_FIELDS | (trusted_fields or set())
    mappings = field_mappings or {}

    dicts_to_inspect: List[Tuple[str, Dict[str, Any]]] = []

    def _collect_dicts(prefix: str, obj: Any, depth: int = 0) -> None:
        if depth > 4:
            return
        if isinstance(obj, dict):
            dicts_to_inspect.append((prefix, obj))
            for k, v in obj.items():
                norm_k = str(k).strip().lower()
                if norm_k in NESTED_WRAPPER_KEYS or norm_k in trusted:
                    new_prefix = f"{prefix}.{norm_k}" if prefix else norm_k
                    if isinstance(v, (dict, list)):
                        _collect_dicts(new_prefix, v, depth + 1)
        elif isinstance(obj, list):
            for i, item in enumerate(obj[:5]):
                new_prefix = f"{prefix}[{i}]" if prefix else f"[{i}]"
                if isinstance(item, (dict, list)):
                    _collect_dicts(new_prefix, item, depth + 1)

    _collect_dicts("", data)

    # extracted: field_path -> (category, val_str)
    extracted: Dict[str, Tuple[str, str]] = {}

    for prefix, d in dicts_to_inspect:
        for k, v in d.items():
            norm_k = str(k).strip().lower()

            # Disallowed descriptions, messages, comments
            if norm_k in DISALLOWED_OWNERSHIP_FIELDS:
                continue

            target_field = mappings.get(norm_k, norm_k)

            # If scalar value and field is trusted or mapped
            if isinstance(v, (str, int, float)) and str(v).strip():
                val_str = str(v).strip()
                cat = mappings.get(norm_k) or OWNERSHIP_CLAIM_CATEGORIES.get(target_field, target_field)
                if target_field in trusted or norm_k in OWNERSHIP_CLAIM_CATEGORIES:
                    field_path = f"{prefix}.{norm_k}" if prefix and not prefix.endswith(norm_k) else norm_k
                    extracted[field_path] = (cat, val_str)

            # If dictionary value (e.g. owner: {"id": "user-A", "username": "alice"})
            elif isinstance(v, dict):
                dict_prefix = f"{prefix}.{norm_k}" if prefix else norm_k
                for inner_k, inner_v in v.items():
                    norm_inner = str(inner_k).strip().lower()
                    if norm_inner in DISALLOWED_OWNERSHIP_FIELDS:
                        continue
                    if isinstance(inner_v, (str, int, float)) and str(inner_v).strip():
                        inner_val_str = str(inner_v).strip()
                        inner_target = mappings.get(norm_inner, norm_inner)
                        inner_cat = mappings.get(norm_inner) or OWNERSHIP_CLAIM_CATEGORIES.get(inner_target, inner_target)
                        field_path = f"{dict_prefix}.{norm_inner}"
                        extracted[field_path] = (inner_cat, inner_val_str)

    # Check for intra-category contradictions within extracted response claims
    claims_by_cat: Dict[str, Dict[str, str]] = {}
    for fp, (cat, val) in extracted.items():
        claims_by_cat.setdefault(cat, {})[fp] = val

    for cat, field_map in claims_by_cat.items():
        items = list(field_map.items())
        for i in range(len(items)):
            for j in range(i + 1, len(items)):
                f1, v1 = items[i]
                f2, v2 = items[j]
                if v1.strip().lower() != v2.strip().lower():
                    conflict_error = f"Contradictory ownership claims within category '{cat}': {f1}='{v1}' vs {f2}='{v2}'"
                    return extracted, conflict_error

    return extracted, None


def validate_ownership_evidence(
    body: str,
    owner_identifier: str | Dict[str, str],
    expected_claim_type: str = "user_id",
    trusted_fields: Optional[Set[str]] = None,
    field_mappings: Optional[Dict[str, str]] = None,
) -> Tuple[bool, str]:
    """
    Strictly validates that response body contains unambiguous ownership evidence
    in trusted ownership fields matching the expected owner identity claims.
    Validates each claim against its explicitly configured identity category.
    Rejects contradictory claims within the same identity category.
    Fails closed if evidence is missing, ambiguous, in disallowed fields, or contradictory.
    """
    if not owner_identifier:
        return False, "Owner identifier not provided"
    if not body or not body.strip():
        return False, "Response body is empty"

    mappings = field_mappings or {}
    expected_categories: Dict[str, Tuple[str, str]] = {}

    if isinstance(owner_identifier, str):
        norm_id = owner_identifier.strip()
        if not norm_id:
            return False, "Owner identifier not provided"
        target_cat = mappings.get(expected_claim_type) or OWNERSHIP_CLAIM_CATEGORIES.get(expected_claim_type, expected_claim_type)
        expected_categories[target_cat] = (expected_claim_type, norm_id)

    elif isinstance(owner_identifier, dict):
        if not owner_identifier:
            return False, "No expected owner claims configured"
        for k, v in owner_identifier.items():
            if v is not None and str(v).strip():
                val_str = str(v).strip()
                norm_k = str(k).strip().lower()
                target_cat = mappings.get(norm_k) or OWNERSHIP_CLAIM_CATEGORIES.get(norm_k, norm_k)
                if target_cat in expected_categories:
                    prev_k, prev_v = expected_categories[target_cat]
                    if prev_v.strip().lower() != val_str.lower():
                        return False, f"Configured expected claims contain internal contradiction for category '{target_cat}': {prev_k}='{prev_v}' vs {norm_k}='{val_str}'"
                expected_categories[target_cat] = (norm_k, val_str)
    else:
        return False, "Invalid owner_identifier specification"

    if not expected_categories:
        return False, "No non-empty expected owner claims configured"

    extracted, conflict_error = extract_ownership_evidence(body, trusted_fields, field_mappings)

    if conflict_error:
        return False, f"Conflicting ownership evidence: {conflict_error}"

    if not extracted:
        return False, "Missing ownership evidence: no trusted ownership fields found in payload"

    verified_matches: List[str] = []

    for exp_cat, (exp_k, exp_val) in expected_categories.items():
        matching_claims = {fp: val for fp, (c, val) in extracted.items() if c == exp_cat}
        if not matching_claims:
            return (
                False,
                f"Missing ownership evidence: expected category '{exp_cat}' ({exp_k}='{exp_val}') was not found in response"
            )

        for fp, val in matching_claims.items():
            if val.strip().lower() != exp_val.strip().lower():
                return (
                    False,
                    f"Ownership mismatch in field '{fp}' (category '{exp_cat}'): expected '{exp_val}', found '{val}'"
                )
            verified_matches.append(f"{fp}='{val}'")

    if verified_matches:
        return True, f"Ownership verified via: {', '.join(verified_matches)}"

    return False, "Ownership verification failed: no matching ownership evidence"


def check_ownership_evidence(
    body: str,
    owner_identifier: str | Dict[str, str],
    expected_claim_type: str = "user_id",
    trusted_fields: Optional[Set[str]] = None,
    field_mappings: Optional[Dict[str, str]] = None,
) -> bool:
    """
    Determines whether a payload contains strict, field-specific ownership evidence
    tying the resource to the specified user identity.
    Fails closed if ownership evidence is missing, in disallowed fields, or contradictory.
    """
    ok, _ = validate_ownership_evidence(
        body,
        owner_identifier=owner_identifier,
        expected_claim_type=expected_claim_type,
        trusted_fields=trusted_fields,
        field_mappings=field_mappings,
    )
    return ok


def has_substantive_business_data(
    body: str,
    min_non_id_fields: int = 1,
) -> Tuple[bool, str]:
    """
    Evaluates whether an HTTP response payload contains substantive, protected business data
    rather than a reflected identifier, empty response, or minimal stub.
    """
    if not body or not body.strip():
        return False, "Empty response payload"

    clean_body = body.strip()
    try:
        data = json.loads(clean_body)
        if isinstance(data, dict):
            if not data:
                return False, "Empty JSON object"

            # Check if dict only contains generic error or status
            # Find non-id and non-status fields
            substantive_fields = [
                k for k in data.keys()
                if not is_protected_field(k)
                and k.lower() not in GENERIC_WRAPPER_OR_STATUS_FIELDS
                and not k.lower().endswith("_id")
            ]
            if len(substantive_fields) < min_non_id_fields:
                return False, f"Payload lacks substantive business fields (only has {list(data.keys())})"
            return True, f"Substantive business data found ({len(substantive_fields)} fields)"

        elif isinstance(data, list):
            if not data:
                return False, "Empty JSON list"
            for item in data:
                if isinstance(item, dict):
                    sub_fields = [
                        k for k in item.keys()
                        if not is_protected_field(k)
                        and k.lower() not in GENERIC_WRAPPER_OR_STATUS_FIELDS
                        and not k.lower().endswith("_id")
                    ]
                    if len(sub_fields) >= min_non_id_fields:
                        return True, f"Substantive business data found in list item ({len(sub_fields)} fields)"
                elif item is not None and str(item).strip():
                    return True, "Substantive list content"
            return False, "List contains only empty or stub elements"
    except Exception:
        # Non-JSON content (plain text or HTML)
        if len(clean_body) < 20:
            return False, "Response is too short to contain substantive business data"
        return True, "Non-JSON substantive payload"

    return True, "Substantive data"

