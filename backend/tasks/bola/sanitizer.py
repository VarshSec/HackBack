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

# Pattern for redacting userinfo in URLs embedded in snippets (e.g. https://admin:pass@host)
_URL_USERINFO_RE = re.compile(r"""(https?://)[^/\s@]+@""")

# Pattern for detecting and redacting standalone JWT-like values (header.payload.signature)
_JWT_RE = re.compile(r"""\beyJ[a-zA-Z0-9_\-]{8,}\.eyJ[a-zA-Z0-9_\-]{8,}\.[a-zA-Z0-9_\-]{8,}\b""")

# Pattern for redacting Bearer tokens in headers or text
_BEARER_RE = re.compile(r"""(?i)\b(bearer\s+)[a-zA-Z0-9_\-\.~+/]+=*""")

# Pattern for redacting Authorization header values
_AUTH_HEADER_RE = re.compile(r"""(?i)(authorization\s*:\s*)[^\r\n,;]+""")

# Pattern for redacting sensitive cookie values in Cookie header or key-values
_COOKIE_VAL_RE = re.compile(
    r"""(?i)\b((?:session|session_id|sessionid|token|access_token|auth|jwt|csrf|xsrf|apikey|api_key|secret)=)[^;\s\r\n&#]+"""
)

# Pattern for redacting sensitive query and fragment parameter values in snippets (e.g. ?token=abc, #access_token=xyz)
_QUERY_FRAG_SNIPPET_RE = re.compile(
    r"""(?i)([?&#][a-zA-Z0-9_\-]*(?:password|passwd|pwd|secret|token|access_token|refresh_token|api[_-]?key|apikey|auth|authorization|bearer|cookie|session|session[_-]?id|ssn|credit[_-]?card|cvv|csrf|xsrf)[a-zA-Z0-9_\-]*=)[^&#\s'";,\)]+"""
)

# Pattern for redacting JSON quoted key-value pairs (handles values with spaces and compound names)
_JSON_KV_RE = re.compile(
    r"""(?i)(['"][a-zA-Z0-9_\-]*(?:password|passwd|pwd|secret|token|access_token|refresh_token|api[_-]?key|apikey|auth|authorization|bearer|cookie|session|session[_-]?id|ssn|credit[_-]?card|cvv|csrf|xsrf)[a-zA-Z0-9_\-]*['"]\s*:\s*['"])[^'"]*(['"])"""
)

# Pattern for redacting standard key-value pairs (unquoted or colon/equals)
_KV_SNIPPET_RE = re.compile(
    r"""(?i)\b([a-zA-Z0-9_\-]*(?:password|passwd|pwd|secret|token|access_token|refresh_token|api[_-]?key|apikey|auth|authorization|bearer|cookie|session|session[_-]?id|ssn|credit[_-]?card|cvv|csrf|xsrf)[a-zA-Z0-9_\-]*\s*[:=]\s*['"]?)[^"',;\s\r\n&#]+(['"]?)"""
)


def is_sensitive_key(key: str) -> bool:
    """True if key name indicates sensitive credential or token data."""
    if not key:
        return False
    unquoted = urllib.parse.unquote(key)
    return bool(_SENSITIVE_KEY_RE.search(key) or _SENSITIVE_KEY_RE.search(unquoted))


def _sanitize_param_string(param_str: str) -> str:
    """
    Redacts sensitive parameter values from a key=value[&key2=value2] string.
    Preserves harmless parameters, harmless anchors, and non-sensitive values.
    Handles URL-encoded sensitive parameter names (e.g. %61ccess_token).
    """
    if not param_str:
        return ""
    if "=" not in param_str:
        return param_str

    prefix = ""
    target_str = param_str
    if "?" in param_str:
        prefix, target_str = param_str.split("?", 1)
        prefix += "?"

    pairs = urllib.parse.parse_qsl(target_str, keep_blank_values=True)
    if not pairs:
        return param_str

    sanitized_parts: List[str] = []
    for k, v in pairs:
        if is_sensitive_key(k):
            sanitized_parts.append(f"{k}=[REDACTED]")
        else:
            sanitized_parts.append(f"{k}={v}")
    return prefix + "&".join(sanitized_parts)


def sanitize_url(raw_url: str) -> str:
    """
    Sanitizes a URL by stripping user-info credentials and redacting sensitive
    query and fragment parameter values.
    Example:
      'https://admin:pass123@api.test/v1/items?token=secret99#access_token=secret100'
      -> 'https://api.test/v1/items?token=[REDACTED]#access_token=[REDACTED]'
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
    query = _sanitize_param_string(parsed.query)

    # 3. Redact sensitive fragment parameter values
    fragment = _sanitize_param_string(parsed.fragment)

    return urllib.parse.urlunsplit((parsed.scheme, netloc, parsed.path, query, fragment))


def sanitize_snippet(snippet: Optional[str], max_len: int = 500) -> Optional[str]:
    """
    Redacts credential and secret values from evidence snippets while preserving
    non-sensitive diagnostic context and parameter names.
    Protects against:
    - URL user-info credentials embedded in snippets.
    - Sensitive query and fragment values in embedded URLs.
    - Bearer tokens.
    - Standalone JWT-like values.
    - Authorization headers.
    - Sensitive cookie values.
    - JSON and key-value secret patterns.
    """
    if snippet is None:
        return None

    s = snippet

    # 1. Strip embedded URL user-info (e.g. https://user:pass@host)
    s = _URL_USERINFO_RE.sub(r"\1", s)
    # 2. Redact standalone JWT tokens
    s = _JWT_RE.sub("[REDACTED]", s)
    # 3. Redact Authorization headers
    s = _AUTH_HEADER_RE.sub(r"\1[REDACTED]", s)
    # 4. Redact Bearer tokens
    s = _BEARER_RE.sub(r"\1[REDACTED]", s)
    # 5. Redact query and fragment parameters in snippet text
    s = _QUERY_FRAG_SNIPPET_RE.sub(r"\1[REDACTED]", s)
    # 6. Redact sensitive cookie values in Cookie headers or text
    s = _COOKIE_VAL_RE.sub(r"\1[REDACTED]", s)
    # 7. Redact JSON quoted key-value pairs (with spaces/quotes)
    s = _JSON_KV_RE.sub(r"\1[REDACTED]\2", s)
    # 8. Redact standard key-value pairs
    s = _KV_SNIPPET_RE.sub(r"\1[REDACTED]\2", s)

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
