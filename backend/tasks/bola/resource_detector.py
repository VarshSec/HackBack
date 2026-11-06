"""
Resource Identifier Detection and Semantic Parameter Role Classification.

Analyzes parameter names, values, schemas, and structural context across
path, query, body, and forms to detect resource identifiers, user identities,
foreign keys, and session tokens.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from tasks.bola.models import (
    CandidateParameter,
    IdentifierType,
    ParameterLocation,
    SemanticRole,
)
from tasks.bola.sanitizer import is_sensitive_key

# Standard UUID: 8-4-4-4-12 hexadecimal
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
# MongoDB ObjectId: 24-char hexadecimal
_OBJECT_ID_RE = re.compile(r"^[0-9a-fA-F]{24}$")
# Integer string
_INT_RE = re.compile(r"^\d+$")
# Alphanumeric slug with hyphen/underscore e.g. 'john-doe-123', 'inv_2026_01'
_SLUG_RE = re.compile(r"^[a-zA-Z0-9]+([-_][a-zA-Z0-9]+)+$")

# Semantic role dictionaries
_USER_IDENTITY_NAMES = {
    "user_id", "userid", "user", "uid", "account_id", "accountid", "account",
    "customer_id", "customerid", "member_id", "memberid", "owner_id", "ownerid",
    "profile_id", "profileid", "author_id", "authorid", "creator_id", "creatorid",
    "sub", "subject_id", "actor_id", "principal_id",
}

_RESOURCE_ID_NAMES = {
    "id", "resource_id", "item_id", "record_id", "doc_id", "document_id",
    "file_id", "invoice_id", "order_id", "ticket_id", "message_id", "comment_id",
    "post_id", "cart_id", "payment_id", "transaction_id", "report_id", "booking_id",
    "device_id", "vehicle_id", "asset_id", "contract_id", "project_id",
}

_PARENT_RESOURCE_NAMES = {
    "org_id", "organization_id", "tenant_id", "workspace_id", "company_id",
    "group_id", "department_id", "team_id", "parent_id", "category_id",
}

_SESSION_TOKEN_NAMES = {
    "token", "access_token", "auth_token", "bearer", "session_id", "sessionid",
    "session", "jwt", "apikey", "api_key", "secret", "csrf", "_csrf", "xsrf",
    "password", "passwd",
}

_ACTION_FLAG_NAMES = {
    "submit", "action", "cmd", "command", "op", "operation", "do", "method",
    "view", "mode", "format", "sort", "order", "dir", "page", "limit", "offset",
}


def detect_identifier_type(value: Optional[Any], schema_type: Optional[str] = None) -> IdentifierType:
    """
    Detects the identifier format from a sample value and/or schema type.
    """
    if value is None:
        if schema_type in ("integer", "int"):
            return IdentifierType.NUMERIC
        return IdentifierType.STATIC

    str_val = str(value).strip()
    if not str_val:
        return IdentifierType.STATIC

    if _UUID_RE.match(str_val):
        return IdentifierType.UUID

    if _OBJECT_ID_RE.match(str_val):
        return IdentifierType.OBJECT_ID

    if _INT_RE.match(str_val):
        return IdentifierType.NUMERIC

    if _SLUG_RE.match(str_val) and re.search(r"\d", str_val):
        return IdentifierType.SLUG

    if len(str_val) >= 4 and re.search(r"\d", str_val) and re.match(r"^[a-zA-Z0-9_\-]+$", str_val):
        return IdentifierType.OPAQUE

    return IdentifierType.STATIC


def classify_semantic_role(
    param_name: str,
    location: ParameterLocation,
    ident_type: IdentifierType,
    resource_context: Optional[str] = None,
) -> SemanticRole:
    """
    Classifies the parameter's semantic role based on name, location, and structural context.
    """
    p_name = param_name.strip().lower()

    if is_sensitive_key(p_name) or p_name in _SESSION_TOKEN_NAMES:
        return SemanticRole.SESSION_TOKEN

    if p_name in _ACTION_FLAG_NAMES:
        return SemanticRole.ACTION_FLAG

    if p_name in _USER_IDENTITY_NAMES:
        return SemanticRole.USER_IDENTITY

    if p_name in _PARENT_RESOURCE_NAMES:
        return SemanticRole.PARENT_RESOURCE_IDENTIFIER

    if p_name in _RESOURCE_ID_NAMES or p_name.endswith("_id") or p_name.endswith("id"):
        return SemanticRole.RESOURCE_IDENTIFIER

    # Path segment identifier with non-static type defaults to resource identifier
    if location == ParameterLocation.PATH and ident_type != IdentifierType.STATIC:
        if resource_context and ("user" in resource_context or "account" in resource_context):
            return SemanticRole.USER_IDENTITY
        return SemanticRole.RESOURCE_IDENTIFIER

    return SemanticRole.UNCLASSIFIED


def extract_query_parameters(query_string: str) -> List[CandidateParameter]:
    """
    Extracts CandidateParameters from a URL query string.
    """
    import urllib.parse

    params: List[CandidateParameter] = []
    if not query_string:
        return params

    parsed_pairs = urllib.parse.parse_qsl(query_string, keep_blank_values=True)
    seen_names = set()

    for name, val in parsed_pairs:
        if not name or name in seen_names:
            continue
        seen_names.add(name)

        ident_type = detect_identifier_type(val)
        dtype = "integer" if ident_type == IdentifierType.NUMERIC else "string"
        role = classify_semantic_role(name, ParameterLocation.QUERY, ident_type)

        params.append(
            CandidateParameter(
                name=name,
                location=ParameterLocation.QUERY,
                data_type=dtype,
                identifier_type=ident_type,
                semantic_role=role,
                sample_value=val if val else None,
            )
        )
    return params


def extract_json_parameters(body: Any, prefix: str = "") -> List[CandidateParameter]:
    """
    Recursively extracts CandidateParameters from a parsed JSON dictionary or list.
    """
    params: List[CandidateParameter] = []

    if isinstance(body, dict):
        for k, v in body.items():
            field_name = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, (dict, list)):
                params.extend(extract_json_parameters(v, prefix=field_name))
            else:
                ident_type = detect_identifier_type(v)
                dtype = "integer" if isinstance(v, int) else ("boolean" if isinstance(v, bool) else "string")
                role = classify_semantic_role(k, ParameterLocation.BODY_JSON, ident_type)

                params.append(
                    CandidateParameter(
                        name=field_name,
                        location=ParameterLocation.BODY_JSON,
                        data_type=dtype,
                        identifier_type=ident_type,
                        semantic_role=role,
                        sample_value=str(v) if v is not None else None,
                    )
                )
    elif isinstance(body, list):
        for idx, item in enumerate(body[:3]):  # Sample up to first 3 elements
            item_prefix = f"{prefix}[{idx}]"
            params.extend(extract_json_parameters(item, prefix=item_prefix))

    return params
