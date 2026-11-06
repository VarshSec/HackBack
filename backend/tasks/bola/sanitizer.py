"""
Secret Redaction and Sanitization Engine for BOLA Candidate Inventory.

Ensures no raw passwords, tokens, API keys, session cookies, or URL user-info
leak into candidate inventory records, evidence snippets, parameter samples,
logs, or serialized database storage.
"""
from __future__ import annotations

import re
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

_SENSITIVE_KEY_RE = re.compile(
    r"(password|passwd|pwd|secret|token|access_token|refresh_token|"
    r"api[_-]?key|apikey|auth|authorization|bearer|cookie|session|session[_-]?id|"
    r"ssn|credit[_-]?card|cvv|csrf|xsrf)",
    re.IGNORECASE,
)

# Pattern for redacting values in key-value text snippets (e.g. password: xyz, "token": "abc")
_KV_SNIPPET_RE = re.compile(
    r"""(?i)(['"]?(?:password|passwd|pwd|secret|token|access_token|refresh_token|api[_-]?key|apikey|auth|authorization|bearer|cookie|session|session[_-]?id|ssn|credit[_-]?card|cvv|csrf|xsrf)['"]?\s*[:=]\s*['"]?)([^"',;\s\r\n&]+)(['"]?)"""
)

# Pattern for redacting sensitive query parameter values in snippets (e.g. ?token=abc&pwd=123)
_QUERY_SNIPPET_RE = re.compile(
    r"""(?i)([?&](?:password|passwd|pwd|secret|token|access_token|refresh_token|api[_-]?key|apikey|auth|authorization|bearer|cookie|session|session[_-]?id|ssn|credit[_-]?card|cvv|csrf|xsrf)=)([^&'"\s;]+)"""
)

# Pattern for redacting Bearer tokens in headers or text
_BEARER_RE = re.compile(r"""(?i)\b(bearer\s+)[a-zA-Z0-9_\-\.~+/]+=*""")

# Pattern for redacting Authorization header values
_AUTH_HEADER_RE = re.compile(r"""(?i)(authorization\s*:\s*)[^\r\n,;]+""")

# Pattern for redacting Cookie header values
_COOKIE_HEADER_RE = re.compile(r"""(?i)(cookie\s*:\s*)[^\r\n;]+""")


def is_sensitive_key(key: str) -> bool:
    """True if key name indicates sensitive credential or token data."""
    if not key:
        return False
    unquoted = urllib.parse.unquote(key)
    return bool(_SENSITIVE_KEY_RE.search(key) or _SENSITIVE_KEY_RE.search(unquoted))


def sanitize_url(raw_url: str) -> str:
    """
    Sanitizes a URL by stripping user-info credentials and redacting sensitive query parameter values.
    Example:
      'https://admin:pass123@api.test/v1/items?token=secret99&id=10'
      -> 'https://api.test/v1/items?token=[REDACTED]&id=10'
    """
    if not raw_url or not isinstance(raw_url, str):
        return ""

    try:
        parsed = urllib.parse.urlsplit(raw_url)
    except Exception:
        return "[INVALID_URL]"

    # 1. Strip user-info from netloc
    netloc = parsed.netloc
    if "@" in netloc:
        netloc = netloc.split("@", 1)[1]

    # 2. Redact sensitive query parameter values
    query = parsed.query
    if query:
        pairs = urllib.parse.parse_qsl(query, keep_blank_values=True)
        sanitized_pairs: List[Tuple[str, str]] = []
        for k, v in pairs:
            if is_sensitive_key(k):
                sanitized_pairs.append((k, "[REDACTED]"))
            else:
                sanitized_pairs.append((k, v))
        query = urllib.parse.urlencode(sanitized_pairs)

    return urllib.parse.urlunsplit((parsed.scheme, netloc, parsed.path, query, parsed.fragment))


def sanitize_snippet(snippet: Optional[str], max_len: int = 500) -> Optional[str]:
    """
    Redacts credential and secret values from evidence snippets while preserving
    non-sensitive diagnostic context and parameter names.
    """
    if snippet is None:
        return None

    s = snippet

    # 1. Redact Authorization headers
    s = _AUTH_HEADER_RE.sub(r"\1[REDACTED]", s)
    # 2. Redact Cookie headers
    s = _COOKIE_HEADER_RE.sub(r"\1[REDACTED]", s)
    # 3. Redact Bearer tokens
    s = _BEARER_RE.sub(r"\1[REDACTED]", s)
    # 4. Redact key-value pairs (password: xyz -> password: [REDACTED])
    s = _KV_SNIPPET_RE.sub(r"\1[REDACTED]\3", s)
    # 5. Redact query parameters in snippet text
    s = _QUERY_SNIPPET_RE.sub(r"\1[REDACTED]", s)

    return s[:max_len]


def sanitize_sample_value(name: str, value: Optional[str]) -> Tuple[Optional[str], bool]:
    """
    Evaluates parameter name and sample value for sensitive data.
    Returns (sanitized_value, is_redacted).
    """
    if not value:
        if is_sensitive_key(name):
            return (None, True)
        return (value, False)

    if is_sensitive_key(name):
        return ("[REDACTED]", True)

    val_str = str(value).strip()
    # Check for JWT pattern (three dot-separated base64-like segments)
    if re.match(r"^eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+$", val_str):
        return ("[REDACTED]", True)

    # Check for Bearer prefix in value
    if val_str.lower().startswith("bearer "):
        return ("[REDACTED]", True)

    return (val_str, False)


def sanitize_schema_dict(schema: Any, parent_is_sensitive: bool = False) -> Any:
    """
    Recursively scrubs sample/example values in OpenAPI or response schemas under sensitive keys.
    """
    if isinstance(schema, dict):
        cleaned = {}
        for k, v in schema.items():
            k_sensitive = is_sensitive_key(str(k))
            if parent_is_sensitive and k in ("example", "default", "examples"):
                if isinstance(v, list):
                    cleaned[k] = ["[REDACTED]" for _ in v]
                else:
                    cleaned[k] = "[REDACTED]"
            elif k_sensitive:
                if isinstance(v, dict):
                    cleaned[k] = sanitize_schema_dict(v, parent_is_sensitive=True)
                elif isinstance(v, list):
                    cleaned[k] = [
                        sanitize_schema_dict(item, parent_is_sensitive=True) if isinstance(item, (dict, list))
                        else "[REDACTED]"
                        for item in v
                    ]
                else:
                    cleaned[k] = "[REDACTED]"
            elif k in ("example", "default") and isinstance(v, str):
                cleaned[k] = sanitize_snippet(v)
            else:
                cleaned[k] = sanitize_schema_dict(v, parent_is_sensitive=parent_is_sensitive)
        return cleaned
    elif isinstance(schema, list):
        return [sanitize_schema_dict(item, parent_is_sensitive=parent_is_sensitive) for item in schema]
    return schema
