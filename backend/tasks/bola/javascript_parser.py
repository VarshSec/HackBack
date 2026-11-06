"""
Static JavaScript Endpoint Intelligence Parser for BOLA extraction.

Extracts API routes, methods, and parameters from JavaScript code (bundles,
scripts, and HTML script tags) without executing untrusted code.
Recognizes fetch(), axios, XMLHttpRequest, jQuery AJAX, and template literals.
"""
from __future__ import annotations

import re
import urllib.parse
from typing import Dict, List, Optional, Set, Tuple

from tasks.bola.models import (
    CandidateEndpoint,
    CandidateParameter,
    EvidenceRecord,
    IdentifierType,
    ParameterLocation,
    SemanticRole,
)
from tasks.bola.route_normalizer import normalize_url_path
from tasks.bola.resource_detector import (
    classify_semantic_role,
    detect_identifier_type,
    extract_query_parameters,
)
from tasks.bola.scope import is_url_in_scope

# Common static asset extensions to ignore
_IGNORED_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".css", ".scss", ".sass", ".less",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".js", ".jsx", ".ts", ".tsx", ".map",
    ".mp4", ".mp3", ".webm", ".avi",
    ".pdf", ".zip", ".tar", ".gz",
)

# Explicit HTTP client invocation patterns
_FETCH_RE = re.compile(
    r"""\bfetch\s*\(\s*(['"`])([^'"`]+)\1(?:\s*\+\s*([a-zA-Z0-9_\.]+))?(?:\s*,\s*\{[^}]*?method\s*:\s*['"]([a-zA-Z]+)['"])?""",
    re.IGNORECASE,
)

_AXIOS_METHOD_RE = re.compile(
    r"""\baxios\s*\.\s*(get|post|put|delete|patch|head|options)\s*\(\s*(['"`])([^'"`]+)\2(?:\s*\+\s*([a-zA-Z0-9_\.]+))?""",
    re.IGNORECASE,
)

_AXIOS_CONFIG_RE = re.compile(
    r"""\baxios\s*\(\s*\{[^}]*?url\s*:\s*(['"`])([^'"`]+)\1(?:[^}]*?method\s*:\s*['"]([a-zA-Z]+)['"])?""",
    re.IGNORECASE,
)

_XHR_RE = re.compile(
    r"""\bopen\s*\(\s*(['"])(GET|POST|PUT|DELETE|PATCH|HEAD)\1\s*,\s*(['"`])([^'"`]+)\3(?:\s*\+\s*([a-zA-Z0-9_\.]+))?""",
    re.IGNORECASE,
)

_JQUERY_AJAX_RE = re.compile(
    r"""\$\s*\.\s*(?:ajax\s*\(\s*\{[^}]*?url\s*:\s*|get\s*\(\s*|post\s*\(\s*)(['"`])([^'"`]+)\1""",
    re.IGNORECASE,
)

# High-likelihood API route string literal
_API_STRING_RE = re.compile(
    r"""(?:['"`])(/(?:api|rest|v\d+|graphql|auth|oauth|users|accounts|orders|items|files|admin)/[a-zA-Z0-9_\-/{}\$:=&?%.]+)(?:['"`])""",
    re.IGNORECASE,
)

# Template literal expression: `${var}` or `${...}`
_TEMPLATE_EXPR_RE = re.compile(r"\$\{[a-zA-Z0-9_\.]+\}")


def _clean_route_string(raw_route: str) -> str:
    """Cleans up a discovered route string and converts JS template expressions."""
    # Convert `${userId}` or `${id}` to `{userId}`
    route = _TEMPLATE_EXPR_RE.sub(lambda m: "{" + m.group(0)[2:-1] + "}", raw_route)
    # Strip string concatenation artifacts e.g. /api/users/' + id
    route = re.sub(r"['\"`]\s*\+\s*[a-zA-Z0-9_\.]+", "/{id}", route)
    return route.strip()


def _is_valid_api_candidate(route: str) -> bool:
    """Filters out asset paths, malformed URLs, and non-API strings."""
    if not route or len(route) < 3:
        return False
    lower = route.lower()
    for ext in _IGNORED_EXTENSIONS:
        if lower.endswith(ext) or f"{ext}?" in lower:
            return False
    # Must start with / or http
    if not (route.startswith("/") or route.startswith("http://") or route.startswith("https://")):
        return False
    # Avoid javascript: or data: URIs
    if lower.startswith("javascript:") or lower.startswith("data:"):
        return False
    return True


class JavaScriptParser:
    """
    Statically analyzes JavaScript code to extract candidate API endpoints.
    """

    def __init__(self, js_code: str, asset_name: str = "app.js"):
        self.js_code = js_code
        self.asset_name = asset_name

    def extract_candidates(
        self,
        scan_id: str = "",
        target_domain: str = "",
        allowed_subdomains: Optional[Any] = None,
    ) -> List[CandidateEndpoint]:
        candidates: List[CandidateEndpoint] = []
        seen_keys: Set[Tuple[str, str]] = set()

        if not self.js_code:
            return candidates

        # 1. Inspect fetch calls
        for match in _FETCH_RE.finditer(self.js_code):
            raw_url = match.group(2)
            concat_var = match.group(3)
            if concat_var:
                raw_url = f"{raw_url.rstrip('/')}/{{{concat_var}}}"
            method = (match.group(4) or "GET").upper()
            self._process_match(
                raw_url, method, "fetch_call", match.group(0)[:80],
                candidates, seen_keys, scan_id, target_domain, confidence=0.75,
                allowed_subdomains=allowed_subdomains,
            )

        # 2. Inspect axios.<method>() calls
        for match in _AXIOS_METHOD_RE.finditer(self.js_code):
            method = match.group(1).upper()
            raw_url = match.group(3)
            concat_var = match.group(4)
            if concat_var:
                raw_url = f"{raw_url.rstrip('/')}/{{{concat_var}}}"
            self._process_match(
                raw_url, method, "axios_method_call", match.group(0)[:80],
                candidates, seen_keys, scan_id, target_domain, confidence=0.75,
                allowed_subdomains=allowed_subdomains,
            )

        # 3. Inspect axios({url: ..., method: ...})
        for match in _AXIOS_CONFIG_RE.finditer(self.js_code):
            raw_url = match.group(2)
            method = (match.group(3) or "GET").upper()
            self._process_match(
                raw_url, method, "axios_config_call", match.group(0)[:80],
                candidates, seen_keys, scan_id, target_domain, confidence=0.75,
                allowed_subdomains=allowed_subdomains,
            )

        # 4. Inspect XMLHttpRequest.open()
        for match in _XHR_RE.finditer(self.js_code):
            method = match.group(2).upper()
            raw_url = match.group(4)
            concat_var = match.group(5)
            if concat_var:
                raw_url = f"{raw_url.rstrip('/')}/{{{concat_var}}}"
            self._process_match(
                raw_url, method, "xhr_open_call", match.group(0)[:80],
                candidates, seen_keys, scan_id, target_domain, confidence=0.70,
                allowed_subdomains=allowed_subdomains,
            )

        # 5. Inspect jQuery AJAX calls
        for match in _JQUERY_AJAX_RE.finditer(self.js_code):
            raw_url = match.group(2)
            method = "POST" if ".post" in match.group(0) else "GET"
            self._process_match(
                raw_url, method, "jquery_ajax_call", match.group(0)[:80],
                candidates, seen_keys, scan_id, target_domain, confidence=0.70,
                allowed_subdomains=allowed_subdomains,
            )

        # 6. Static API string pattern scanner (fallback heuristic)
        for match in _API_STRING_RE.finditer(self.js_code):
            end_pos = match.end()
            # If immediately followed by '+' string concatenation, it's an incomplete prefix
            remaining = self.js_code[end_pos:end_pos + 10].lstrip()
            if remaining.startswith("+"):
                continue
            raw_url = match.group(1)
            # Default to GET for raw string literals unless already discovered
            self._process_match(
                raw_url, "GET", "api_string_literal", match.group(0)[:80],
                candidates, seen_keys, scan_id, target_domain, confidence=0.50,
                allowed_subdomains=allowed_subdomains,
            )

        return candidates

    def _process_match(
        self,
        raw_url: str,
        method: str,
        call_type: str,
        snippet: str,
        candidates: List[CandidateEndpoint],
        seen_keys: Set[Tuple[str, str]],
        scan_id: str,
        target_domain: str,
        confidence: float,
        allowed_subdomains: Optional[Any] = None,
    ) -> None:
        cleaned_url = _clean_route_string(raw_url)
        if not _is_valid_api_candidate(cleaned_url):
            return

        if target_domain:
            in_scope, resolved = is_url_in_scope(
                cleaned_url, target_domain, allowed_subdomains=allowed_subdomains
            )
            if not in_scope or not resolved:
                return
            parsed = urllib.parse.urlsplit(resolved)
        else:
            parsed = urllib.parse.urlsplit(cleaned_url)

        path = parsed.path
        if not path.startswith("/"):
            path = "/" + path

        norm_template, resource_type, path_params = normalize_url_path(path)
        # Avoid creating duplicate or spurious GET candidates for routes already extracted by explicit HTTP clients
        if call_type == "api_string_literal" and any(tpl == norm_template for (m, tpl) in seen_keys):
            return

        key = (method, norm_template)
        if key in seen_keys:
            return
        seen_keys.add(key)

        # Extract query parameters if present
        all_params = list(path_params)
        if parsed.query:
            query_params = extract_query_parameters(parsed.query)
            all_params.extend(query_params)

        ev = EvidenceRecord(
            source="javascript",
            parser="JavaScriptParser",
            location=f"{self.asset_name}:{call_type}",
            snippet=snippet,
            confidence_signals=[f"js_{call_type}"],
        )

        candidate_id = CandidateEndpoint.generate_candidate_id(method, norm_template, target_domain)
        endpoint = CandidateEndpoint(
            candidate_id=candidate_id,
            scan_id=scan_id,
            target_domain=target_domain,
            method=method,
            original_url=raw_url,
            route_template=norm_template,
            resource_type=resource_type,
            parameters=all_params,
            discovery_sources=["javascript"],
            content_type="application/json",
            confidence=confidence,
            evidence=[ev],
        )
        candidates.append(endpoint)
