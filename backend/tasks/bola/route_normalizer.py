"""
Deterministic route template normalization and path parameter extraction.

Transforms raw URLs (e.g. /api/users/123/orders/98) into normalized route templates
(e.g. /api/users/{user_id}/orders/{order_id}) while preserving static keywords and
identifying path parameters with their identifier types.
"""
from __future__ import annotations

import re
import urllib.parse
from typing import List, Optional, Tuple

from tasks.bola.models import (
    CandidateParameter,
    IdentifierType,
    ParameterLocation,
    SemanticRole,
)

# Standard UUID: 8-4-4-4-12 hexadecimal
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

# MongoDB ObjectId: 24-char hexadecimal
_OBJECT_ID_RE = re.compile(r"^[0-9a-fA-F]{24}$")

# Pure numeric identifier (non-empty digits)
_NUMERIC_RE = re.compile(r"^\d+$")

# Common API versions that must remain STATIC
_API_VERSION_RE = re.compile(r"^v\d+(\.\d+)?$", re.IGNORECASE)

# Static action or collection keywords that should NOT be treated as identifiers
_STATIC_KEYWORDS = {
    "api",
    "v1", "v2", "v3", "v4", "v5",
    "admin", "administrator", "dashboard", "console",
    "auth", "login", "logout", "signin", "signout", "register", "signup",
    "me", "self", "current", "all", "list", "search", "filter", "query",
    "new", "create", "edit", "update", "delete", "destroy",
    "download", "upload", "export", "import", "bulk", "batch",
    "settings", "preferences", "config", "status", "health", "ping", "metrics",
    "webhook", "webhooks", "callback", "callbacks", "events",
    "static", "assets", "public", "css", "js", "images", "img", "fonts",
}

# Date-like numeric segments (e.g. 2023, 2024, 2025, 2026) that are usually static partitions
_YEAR_RE = re.compile(r"^(19|20)\d{2}$")


def is_static_segment(segment: str) -> bool:
    """True if segment is a known static endpoint or version keyword."""
    s = segment.strip().lower()
    if not s:
        return True
    if s in _STATIC_KEYWORDS:
        return True
    if _API_VERSION_RE.match(s):
        return True
    return False


def classify_segment(segment: str) -> Tuple[bool, IdentifierType]:
    """
    Examines a path segment to determine if it is a dynamic identifier.
    Returns (is_identifier, identifier_type).
    """
    s = segment.strip()
    if is_static_segment(s):
        return False, IdentifierType.STATIC

    if _UUID_RE.match(s):
        return True, IdentifierType.UUID

    if _OBJECT_ID_RE.match(s):
        return True, IdentifierType.OBJECT_ID

    if _NUMERIC_RE.match(s):
        # Defend against treating year partitions as resource IDs unless context dictates
        # A plain 4-digit year like /reports/2026/ might be a partition, but /orders/2026 could be an ID.
        # Still classify as numeric ID, but ensure length > 0
        return True, IdentifierType.NUMERIC

    # Alphanumeric slug / opaque ID: contains digits + letters or dashes/underscores with digits
    # Example: 'user-123', 'order_987abc', 'cus_N6bJ78x9z'
    if re.search(r"\d", s) and re.match(r"^[a-zA-Z0-9_\-]+$", s) and len(s) >= 4:
        return True, IdentifierType.OPAQUE

    return False, IdentifierType.STATIC


def derive_param_name(prev_segment: Optional[str], ident_type: IdentifierType, is_nested: bool) -> str:
    """
    Derives a semantic parameter name based on preceding collection segment.
    E.g. for /users/123 -> 'user_id' or 'id'.
    For /users/123/orders/456 -> 'user_id' and 'order_id'.
    """
    if prev_segment and not is_static_segment(prev_segment):
        # Singularize simple English plural: 'users' -> 'user', 'orders' -> 'order'
        clean_prev = prev_segment.lower()
        if clean_prev.endswith("ies") and len(clean_prev) > 3:
            singular = clean_prev[:-3] + "y"
        elif clean_prev.endswith("es") and len(clean_prev) > 2 and clean_prev[-3] in "sxo":
            singular = clean_prev[:-2]
        elif clean_prev.endswith("s") and not clean_prev.endswith("ss") and len(clean_prev) > 1:
            singular = clean_prev[:-1]
        else:
            singular = clean_prev

        if is_nested:
            return f"{singular}_id"
        return f"{singular}_id" if ident_type != IdentifierType.UUID else f"{singular}_uuid"

    if ident_type == IdentifierType.UUID:
        return "uuid"
    if ident_type == IdentifierType.OBJECT_ID:
        return "object_id"
    return "id"


def normalize_url_path(url_or_path: str) -> Tuple[str, str, List[CandidateParameter]]:
    """
    Parses a URL or relative path and returns:
    (normalized_route_template, inferred_resource_type, path_parameters)

    Examples:
      '/api/v1/users/123' -> ('/api/v1/users/{user_id}', 'users', [CandidateParameter(name='user_id', ...)])
      '/api/users/12/orders/98' -> ('/api/users/{user_id}/orders/{order_id}', 'orders', [...])
    """
    parsed = urllib.parse.urlsplit(url_or_path)
    path = parsed.path.strip()
    if not path:
        path = "/"

    # Normalize multiple consecutive slashes
    clean_path = re.sub(r"/{2,}", "/", path)
    # Strip trailing slash unless path is just '/'
    if len(clean_path) > 1 and clean_path.endswith("/"):
        clean_path = clean_path[:-1]

    raw_segments = clean_path.split("/")
    norm_segments: List[str] = []
    path_params: List[CandidateParameter] = []

    # Count how many identifier segments exist to know if it's nested
    id_count = sum(1 for seg in raw_segments if seg and classify_segment(seg)[0])
    is_nested = id_count > 1

    resource_type = "root"
    prev_segment: Optional[str] = None
    assigned_param_names: set = set()

    for idx, seg in enumerate(raw_segments):
        if not seg:
            continue

        # If already formatted as an OpenAPI template e.g. {id} or :id
        if (seg.startswith("{") and seg.endswith("}")) or seg.startswith(":"):
            raw_param_name = seg[1:-1] if seg.startswith("{") else seg[1:]
            param_name = raw_param_name or "id"
            norm_segments.append(f"{{{param_name}}}")
            path_params.append(
                CandidateParameter(
                    name=param_name,
                    location=ParameterLocation.PATH,
                    data_type="string",
                    identifier_type=IdentifierType.OPAQUE,
                    semantic_role=SemanticRole.RESOURCE_IDENTIFIER,
                    required=True,
                )
            )
            prev_segment = None
            continue

        is_id, ident_type = classify_segment(seg)
        if is_id:
            param_name = derive_param_name(prev_segment, ident_type, is_nested)
            # Ensure unique param names if collision happens
            orig_name = param_name
            counter = 1
            while param_name in assigned_param_names:
                param_name = f"{orig_name}_{counter}"
                counter += 1
            assigned_param_names.add(param_name)

            norm_segments.append(f"{{{param_name}}}")

            # Assign semantic role: if followed by another resource collection, it's a parent
            has_subsequent_id = any(classify_segment(s)[0] for s in raw_segments[idx + 1:])
            role = SemanticRole.PARENT_RESOURCE_IDENTIFIER if has_subsequent_id else SemanticRole.RESOURCE_IDENTIFIER

            dtype = "integer" if ident_type == IdentifierType.NUMERIC else "string"

            path_params.append(
                CandidateParameter(
                    name=param_name,
                    location=ParameterLocation.PATH,
                    data_type=dtype,
                    identifier_type=ident_type,
                    semantic_role=role,
                    sample_value=seg,
                    required=True,
                )
            )
            prev_segment = None
        else:
            norm_segments.append(seg)
            if not is_static_segment(seg):
                resource_type = seg.lower()
            prev_segment = seg

    normalized_template = "/" + "/".join(norm_segments) if norm_segments else "/"
    return normalized_template, resource_type, path_params
