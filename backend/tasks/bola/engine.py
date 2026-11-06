"""
Core 4-Way Differential BOLA / IDOR Verification Engine.

Executes controlled, read-only multi-context differential authorization checks:
- Scenario A: Same-User Control (Identity A -> Resource A) [Baseline]
- Scenario B: Cross-User Access Test (Identity B -> Resource A)
- Scenario C: Reverse Same-User Control (Identity B -> Resource B, when available)
- Scenario D: Unauthenticated Control (Anonymous -> Resource A)

Enforces strict safety guardrails:
- Read-only safety switch (state-modifying operations blocked by default)
- Side-effecting keyword inspection on GET/HEAD
- Connection-level SSRF defense via net_guard.guarded_request
- Cache-busting headers and cache interference detection (SUSPECTED_CACHE_HIT -> INCONCLUSIVE)
- allow_redirects=False with authentication challenge inspection
- Stable resource identifier verification and silent tenant scoping detection
- Evidence-based confidence scoring separate from verdicts
- Zero credential exposure in evidence or reproduction cURL commands
- Principal-validated secondary authentication for 3-way fallback
- Explicit 404 verdict refinement (RESOURCE_EXISTENCE_CONCEALED vs ACCESS_NOT_DEMONSTRATED)
- Strict access policy classification (PUBLIC_RESOURCE vs UNEXPECTED_ANONYMOUS_ACCESS vs INCONCLUSIVE)
"""
from __future__ import annotations

import enum
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlsplit

import requests
from pydantic import BaseModel, Field, field_validator, model_validator

from config import settings
import net_guard
from tasks.bola.auth_manager import (
    SessionIdentityManager,
    IDENTITY_PRIMARY,
    IDENTITY_SECONDARY,
    IDENTITY_ANONYMOUS,
    AuthOutcome,
)
from tasks.bola.comparator import (
    CacheInterference,
    inspect_cache_interference,
    is_soft_404_or_error,
    compute_semantic_similarity,
    detect_silent_tenant_scoping,
    contains_resource_identifier,
    check_ownership_evidence,
    validate_ownership_evidence,
    has_substantive_business_data,
    is_protected_field,
)
from tasks.bola.models import CandidateEndpoint, CandidateParameter, SemanticRole
from tasks.bola.sanitizer import sanitize_url, sanitize_snippet, is_sensitive_key

logger = logging.getLogger(__name__)

# Dangerous keywords indicating side-effecting operations even over GET/HEAD
SIDE_EFFECT_KEYWORDS: Set[str] = {
    "delete",
    "remove",
    "cancel",
    "drop",
    "terminate",
    "reset",
    "purge",
    "destroy",
    "execute",
    "update",
    "modify",
    "logout",
    "revoke",
    "kill",
    "wipe",
}

# Recognized authentication challenge paths for redirect inspection
AUTH_CHALLENGE_KEYWORDS: Set[str] = {
    "login",
    "signin",
    "sign-in",
    "auth",
    "oauth",
    "sso",
    "unauthorized",
    "session/new",
}

# Generic routing or web-server error patterns indicating routing failure rather than authorization
ROUTING_ERROR_PATTERNS = re.compile(
    r"\b(cannot (get|post|put|delete)|no route matches|route not found|unmatched route|not found on this server|nginx|apache|cloudflare)\b",
    re.IGNORECASE,
)

# Canonical attribute names mapped to normalized claim categories
# User ID, Account ID, Tenant ID, Profile ID, Username, and Email are separated into distinct categories
CLAIM_CATEGORY_MAP: Dict[str, str] = {
    # Canonical User ID
    "id": "user_id",
    "user_id": "user_id",
    "userid": "user_id",
    "sub": "user_id",
    "subject": "user_id",
    "uuid": "user_id",
    "guid": "user_id",
    # Account ID category (distinct from user_id)
    "account_id": "account_id",
    "accountid": "account_id",
    # Tenant ID category (distinct from user_id)
    "tenant_id": "tenant_id",
    "tenantid": "tenant_id",
    # Profile ID category (distinct from user_id)
    "profile_id": "profile_id",
    "profileid": "profile_id",
    # Username category
    "username": "username",
    "user_name": "username",
    "login": "username",
    # Email category
    "email": "email",
    "user_email": "email",
    # Customer / Member / Client categories
    "customer_id": "customer_id",
    "member_id": "member_id",
    "client_id": "client_id",
}

# Sensitive headers requiring redaction to prevent secret leakage in stored evidence
SENSITIVE_RESPONSE_HEADERS: Set[str] = {
    "set-cookie",
    "set-cookie2",
    "authorization",
    "proxy-authenticate",
    "proxy-authorization",
    "www-authenticate",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-xsrf-token",
    "cookie",
    "x-access-token",
    "x-session-id",
}

# Safe cache and timing headers to preserve for diagnostic and cache-interference inspection
SAFE_CACHE_RESPONSE_HEADERS: Set[str] = {
    "age",
    "x-cache",
    "x-cache-lookup",
    "cf-cache-status",
    "x-varnish",
    "cache-control",
    "etag",
    "last-modified",
    "expires",
    "via",
    "server-timing",
}


def sanitize_response_headers(headers: Optional[Dict[str, str]]) -> Dict[str, str]:
    """
    Sanitizes response headers by redacting sensitive cookie, token, and authentication metadata
    while preserving safe cache, timing, and diagnostic headers required for cache-interference detection.
    """
    if not headers:
        return {}
    sanitized: Dict[str, str] = {}
    for k, v in headers.items():
        k_str = str(k).strip()
        norm_k = k_str.lower()
        if norm_k in SAFE_CACHE_RESPONSE_HEADERS:
            sanitized[k_str] = str(v)
        elif norm_k in SENSITIVE_RESPONSE_HEADERS or is_sensitive_key(norm_k):
            sanitized[k_str] = "[REDACTED]"
        else:
            sanitized[k_str] = sanitize_snippet(str(v), max_len=200) or ""
    return sanitized


class AccessPolicy(str, enum.Enum):
    PUBLIC = "public"
    PRIVATE = "private"
    UNKNOWN = "unknown"


class VerificationScenario(str, enum.Enum):
    SCENARIO_A = "scenario_a"  # Owner control: Identity A -> Resource A
    SCENARIO_B = "scenario_b"  # Cross-user test: Identity B -> Resource A
    SCENARIO_C = "scenario_c"  # Reverse owner control: Identity B -> Resource B
    SCENARIO_D = "scenario_d"  # Unauthenticated control: Anonymous -> Resource A


class BOLAOutcome(str, enum.Enum):
    CONFIRMED_BOLA = "confirmed_bola"
    HIGH_PROBABLE_BOLA = "high_probable_bola"
    AUTHORIZED = "authorized"
    RESOURCE_EXISTENCE_CONCEALED = "resource_existence_concealed"
    ACCESS_NOT_DEMONSTRATED = "access_not_demonstrated"
    PUBLIC_RESOURCE = "public_resource"
    UNEXPECTED_ANONYMOUS_ACCESS = "unexpected_anonymous_access"
    SOFT_404_AUTHORIZED = "soft_404_authorized"
    INCONCLUSIVE = "inconclusive"
    SINGLE_IDENTITY_UNVERIFIED = "single_identity_unverified"
    BASELINE_FAILED = "baseline_failed"


class ConfidenceLevel(str, enum.Enum):
    CERTAIN = "certain"    # >= 0.95 (Full 4-way corroboration with distinct Resource B)
    HIGH = "high"          # 0.80 - 0.94 (3-way with strong evidence or minor volatility)
    MEDIUM = "medium"      # 0.60 - 0.79 (Partial corroboration or structural signals)
    LOW = "low"            # < 0.60 (Weak signals or unverified baseline)


class ConfidenceAssessment(BaseModel):
    score: float = Field(ge=0.0, le=1.0)
    level: ConfidenceLevel
    signals: List[str] = Field(default_factory=list)
    deductions: List[str] = Field(default_factory=list)


class ScenarioExecutionResult(BaseModel):
    scenario: VerificationScenario
    identity: str
    url: str
    method: str
    status_code: int
    content_type: str = ""
    body_sample: Optional[str] = None
    response_headers: Dict[str, str] = Field(default_factory=dict)
    execution_time_ms: float = 0.0
    is_redirect: bool = False
    redirect_location: Optional[str] = None
    error: Optional[str] = None

    @field_validator("url", mode="before")
    @classmethod
    def sanitize_scenario_url(cls, v: Any) -> str:
        if isinstance(v, str):
            return sanitize_url(v)
        return str(v) if v is not None else ""


class BOLAVerificationResult(BaseModel):
    candidate_id: str
    target_url: str
    method: str
    outcome: BOLAOutcome
    confidence: ConfidenceAssessment
    title: str
    explanation: str
    is_vulnerable: bool
    scenario_results: Dict[str, ScenarioExecutionResult] = Field(default_factory=dict)
    cache_interference: CacheInterference = CacheInterference.NONE
    reproduction_curl: Optional[str] = None
    verified_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("target_url", mode="before")
    @classmethod
    def sanitize_target_url(cls, v: Any) -> str:
        if isinstance(v, str):
            return sanitize_url(v)
        return str(v) if v is not None else ""

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")


# Trusted provenance sources allowed to establish target authorization policy
TRUSTED_PROVENANCE_SOURCES: Set[str] = {
    "target_config",
    "verified_target_profile",
    "authenticated_scan_config",
    "scan_manifest",
    "security_policy_registry",
}

# Internal trust secret resolution and storage for policy HMAC tokens
_POLICY_TRUST_SECRET_OVERRIDE: Optional[bytes] = None
_CACHED_POLICY_TRUST_SECRET: Optional[bytes] = None


def set_policy_trust_secret_override(secret: Optional[bytes]) -> None:
    """Sets a policy trust secret override for testing or key rotation."""
    global _POLICY_TRUST_SECRET_OVERRIDE, _CACHED_POLICY_TRUST_SECRET
    _POLICY_TRUST_SECRET_OVERRIDE = secret
    _CACHED_POLICY_TRUST_SECRET = None


def clear_policy_trust_secret_override() -> None:
    """Clears the policy trust secret override."""
    global _POLICY_TRUST_SECRET_OVERRIDE, _CACHED_POLICY_TRUST_SECRET
    _POLICY_TRUST_SECRET_OVERRIDE = None
    _CACHED_POLICY_TRUST_SECRET = None


def _get_policy_trust_secret() -> bytes:
    """
    Resolves the internal root key used to compute and verify cryptographic
    policy trust tokens. The secret is NOT hardcoded in plaintext and is NOT
    exposed via public models, APIs, or serialization.

    Resolution order:
    1. Active test override / key rotation injection (if configured).
    2. Environment variable HACKBACK_POLICY_TRUST_SECRET (explicit operational secret).
    3. Derived from backend application settings SECRET_KEY via HMAC-SHA256
       with a domain-separation label ('hackback:bola:target_policy_trust_token:v1').
    4. Deterministic file-backed local trust root (~/.hackback/policy_trust.key
       or .hackback_policy_trust.key with secure 0600 permissions) ensuring persistence
       across legitimate application restarts if SECRET_KEY is not configured.
    5. Fallback deterministic derived key if filesystem is strictly read-only.
    """
    global _CACHED_POLICY_TRUST_SECRET
    if _POLICY_TRUST_SECRET_OVERRIDE is not None:
        return _POLICY_TRUST_SECRET_OVERRIDE

    if _CACHED_POLICY_TRUST_SECRET is not None:
        return _CACHED_POLICY_TRUST_SECRET

    # 1. Environment variable
    env_secret = os.environ.get("HACKBACK_POLICY_TRUST_SECRET")
    if env_secret:
        _CACHED_POLICY_TRUST_SECRET = env_secret.encode("utf-8")
        return _CACHED_POLICY_TRUST_SECRET

    # 2. Derive from application settings SECRET_KEY
    try:
        from config import settings
        app_secret = getattr(settings, "SECRET_KEY", None)
        if app_secret and app_secret != "change-me-in-production":
            _CACHED_POLICY_TRUST_SECRET = hmac.new(
                app_secret.encode("utf-8"),
                b"hackback:bola:target_policy_trust_token:v1",
                hashlib.sha256,
            ).digest()
            return _CACHED_POLICY_TRUST_SECRET
    except Exception:
        pass

    # 3. Persistent keyfile across application restarts
    try:
        key_dir = os.path.expanduser("~/.hackback")
        os.makedirs(key_dir, exist_ok=True)
        key_file = os.path.join(key_dir, "policy_trust.key")
        if os.path.exists(key_file):
            with open(key_file, "rb") as f:
                key_data = f.read().strip()
            if len(key_data) >= 32:
                _CACHED_POLICY_TRUST_SECRET = key_data
                return _CACHED_POLICY_TRUST_SECRET
        new_key = secrets.token_bytes(32)
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
            fd = os.open(key_file, flags, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(new_key)
            _CACHED_POLICY_TRUST_SECRET = new_key
            return _CACHED_POLICY_TRUST_SECRET
        except Exception:
            pass
    except Exception:
        pass

    # 4. Fallback deterministic derived key if filesystem is read-only
    _CACHED_POLICY_TRUST_SECRET = hashlib.sha256(b"hackback_target_authorization_policy_default_trust_root_v1").digest()
    return _CACHED_POLICY_TRUST_SECRET


def compute_policy_trust_token(
    target_domain: str,
    route_template: Optional[str],
    config_version: str,
    masks_404: bool,
    provenance: str,
) -> str:
    """
    Computes an HMAC-SHA256 signature binding the authorization policy to target domain,
    route template, configuration version, masking behavior, and trusted provenance.
    """
    norm_domain = (target_domain or "").strip().lower()
    norm_route = (route_template or "").strip()
    norm_ver = (config_version or "").strip()
    norm_prov = (provenance or "").strip().lower()
    payload = f"{norm_domain}|{norm_route}|{norm_ver}|{masks_404}|{norm_prov}"
    secret = _get_policy_trust_secret()
    return hmac.new(secret, payload.encode("utf-8"), hashlib.sha256).hexdigest()


class TargetAuthorizationPolicy(BaseModel):
    """
    Trusted, scope-bound target authorization policy configuration.
    Must originate from an authenticated scan configuration or verified target profile,
    bound to the specific target domain, route template or endpoint, and configuration version.

    Trust cannot be established by caller-supplied is_trusted=True or raw provenance strings.
    Policies must be constructed through TargetAuthorizationPolicy.create_trusted_policy(),
    which attaches a cryptographic HMAC trust token verified at execution time.
    """
    target_domain: str
    route_template: Optional[str] = None
    endpoint_pattern: Optional[str] = None
    config_version: str = "1.0"
    masks_404: bool = False
    provenance: str = "untrusted_input"
    is_trusted: bool = False
    trust_token: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _enforce_trust_integrity(self) -> "TargetAuthorizationPolicy":
        """
        Prevents untrusted deserialization or forged caller input from claiming is_trusted=True.
        If is_trusted is True, a valid cryptographic trust_token must be present and verified;
        otherwise, is_trusted is automatically demoted to False to fail closed.
        """
        if self.is_trusted:
            if not self.trust_token:
                self.is_trusted = False
            else:
                expected = compute_policy_trust_token(
                    target_domain=self.target_domain,
                    route_template=self.route_template,
                    config_version=self.config_version,
                    masks_404=self.masks_404,
                    provenance=self.provenance,
                )
                if not hmac.compare_digest(self.trust_token, expected):
                    self.is_trusted = False
        return self

    @classmethod
    def create_trusted_policy(
        cls,
        target_domain: str,
        route_template: Optional[str] = None,
        config_version: str = "1.0",
        masks_404: bool = True,
        provenance: str = "verified_target_profile",
        endpoint_pattern: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> "TargetAuthorizationPolicy":
        """
        Authorized factory constructor for trusted TargetAuthorizationPolicy instances.
        Validates input sanitization (blocking delimiter injection) and computes
        the cryptographic trust token binding target_domain, route_template,
        config_version, masks_404, and provenance.
        """
        if provenance not in TRUSTED_PROVENANCE_SOURCES:
            raise ValueError(
                f"Cannot create trusted policy with untrusted provenance '{provenance}'. "
                f"Must be one of {sorted(list(TRUSTED_PROVENANCE_SOURCES))}"
            )

        # Signing oracle defense: prevent delimiter or control character injection
        for field_val, field_name in [
            (target_domain, "target_domain"),
            (route_template or "", "route_template"),
            (config_version, "config_version"),
            (provenance, "provenance"),
        ]:
            if any(char in field_val for char in ("\n", "\r", "\x00", "|")):
                raise ValueError(
                    f"Invalid characters in {field_name}: delimiters ('|', newline, null byte) are forbidden"
                )

        norm_domain = (target_domain or "").strip()
        if not norm_domain or norm_domain.startswith(("-", ".")):
            raise ValueError(f"Invalid target_domain '{target_domain}' for trusted policy")

        token = compute_policy_trust_token(
            target_domain=target_domain,
            route_template=route_template,
            config_version=config_version,
            masks_404=masks_404,
            provenance=provenance,
        )
        return cls(
            target_domain=target_domain,
            route_template=route_template,
            endpoint_pattern=endpoint_pattern,
            config_version=config_version,
            masks_404=masks_404,
            provenance=provenance,
            is_trusted=True,
            trust_token=token,
            metadata=metadata or {},
        )

    def validate_for_candidate(
        self,
        candidate: CandidateEndpoint,
        target_url: str,
        expected_config_version: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """
        Validates that this policy is cryptographically verified, scope-bound,
        and applies to the given candidate endpoint, target URL, and configuration version.
        """
        # 1. Caller-supplied is_trusted=True is NOT trusted without valid trust_token
        if not self.is_trusted or not self.trust_token:
            return False, f"Policy is untrusted or missing cryptographic trust token (is_trusted={self.is_trusted}, has_token={bool(self.trust_token)})"

        # 2. Check provenance authority
        if self.provenance not in TRUSTED_PROVENANCE_SOURCES:
            return False, f"Policy provenance '{self.provenance}' is not an authorized trusted source"

        # 3. Cryptographic integrity check: verify HMAC token against policy fields
        expected_token = compute_policy_trust_token(
            target_domain=self.target_domain,
            route_template=self.route_template,
            config_version=self.config_version,
            masks_404=self.masks_404,
            provenance=self.provenance,
        )
        if not hmac.compare_digest(self.trust_token, expected_token):
            return False, "Forged policy detected: cryptographic trust token mismatch"

        # 4. Check configuration version binding
        if expected_config_version and self.config_version != expected_config_version:
            return False, f"Policy config_version '{self.config_version}' does not match expected version '{expected_config_version}'"

        # 5. Check target_domain scope binding
        norm_policy_domain = self.target_domain.strip().lower()
        norm_cand_domain = candidate.target_domain.strip().lower()
        if norm_policy_domain != norm_cand_domain:
            return False, f"Policy target_domain '{self.target_domain}' does not match candidate target_domain '{candidate.target_domain}'"

        # 6. Check route_template scope binding
        if self.route_template:
            norm_policy_route = self.route_template.strip()
            norm_cand_route = candidate.route_template.strip()
            if norm_policy_route != norm_cand_route and norm_policy_route not in target_url:
                return False, f"Policy route_template '{self.route_template}' does not match candidate route '{candidate.route_template}'"

        # 7. Check that policy explicitly enables 404 masking
        if not self.masks_404:
            return False, "Policy does not enable 404 authorization masking (masks_404=False)"

        return True, f"Policy verified and trusted from '{self.provenance}' (v{self.config_version})"


def is_potentially_side_effecting(method: str, url: str) -> Tuple[bool, str]:
    """
    Checks whether a request is potentially state-modifying or side-effecting.
    Always flags non-GET/HEAD methods. Also inspects path segments for action verbs.
    """
    norm_method = method.strip().upper()
    if norm_method not in ("GET", "HEAD"):
        return True, f"Non-idempotent HTTP method: {norm_method}"

    parsed = urlsplit(url)
    path_segments = [s.lower() for s in parsed.path.split("/") if s]
    for seg in path_segments:
        for kw in SIDE_EFFECT_KEYWORDS:
            if kw in seg:
                return True, f"Potentially side-effecting action verb in path segment: '{seg}'"

    return False, "Safe read-only operation"


def is_auth_challenge_redirect(status_code: int, location: str) -> bool:
    """
    Evaluates whether a redirect status (301, 302, 303, 307, 308) is an authentication
    challenge redirecting to a login or authentication gateway.
    """
    if status_code not in (301, 302, 303, 307, 308) or not location:
        return False

    norm_loc = location.lower()
    parsed = urlsplit(norm_loc)
    path = parsed.path.lower()

    for kw in AUTH_CHALLENGE_KEYWORDS:
        if kw in path:
            return True

    return False


def is_routing_error(body: str) -> bool:
    """
    Detects whether a 404 response is an ambiguous framework or proxy routing error
    (e.g., Express "Cannot GET", Nginx 404, Django "No route matches").
    """
    if not body:
        return False
    return bool(ROUTING_ERROR_PATTERNS.search(body))


# Action, filter, diagnostic, and sub-route segments that cannot represent a resource identifier.
# Resource collection names (e.g. 'orders', 'users', 'accounts', 'items', 'products', 'invoices')
# are valid collection targets that precede resource identifiers in URL paths and are permitted.
ACTION_FILTER_PATH_SEGMENTS: Set[str] = {
    "summary",
    "export",
    "filter",
    "filters",
    "search",
    "download",
    "upload",
    "delete",
    "remove",
    "view",
    "stats",
    "status",
    "metrics",
    "count",
    "aggregate",
    "list",
    "all",
    "batch",
    "bulk",
    "me",
    "self",
    "health",
    "ping",
    "info",
    "help",
    "swagger",
    "openapi",
    "docs",
    "preview",
    "print",
    "audit",
    "logs",
    "history",
    "active",
    "pending",
}

# Backward compatibility alias
DISALLOWED_RESOURCE_PATH_SEGMENTS: Set[str] = ACTION_FILTER_PATH_SEGMENTS


def resolve_url_resource_identifier(
    url: str,
    endpoint_mapping: Optional[Union[str, Dict[str, Any]]] = None,
    explicit_identifier: Optional[str] = None,
) -> Tuple[Optional[str], Optional[str]]:
    """
    Resolves the targeted resource identifier for a URL following strict rules:
    1. Validates mapping types, structure, and path segments.
    2. Rejects mappings that identify action, filter, or non-resource sub-route segments.
    3. Scans URL path segments for candidate identifiers (numeric, UUID, length 24/32/36, or containing '_').
    4. Matches candidate segment via exact endpoint_mapping or single candidate.
    5. Rejects conflicts between explicit identifiers and URL-mapped identifiers.
    6. Never assumes an arbitrary final path segment is an identifier (e.g. /summary, /export).
    7. Never substitutes user, tenant, account, or owner identifiers for resource identifiers.
    Returns (resolved_identifier_or_none, error_reason_or_none).
    """
    norm_explicit = None
    if explicit_identifier is not None:
        norm_explicit = str(explicit_identifier).strip()
        if not norm_explicit:
            return None, "Explicit resource identifier is empty"

    if not url:
        return None, "URL is empty"

    parsed = urlsplit(url)
    segments = [s for s in parsed.path.split('/') if s]
    if not segments:
        return None, "URL path has no segments"

    # Validate endpoint_mapping type if provided
    if endpoint_mapping is not None:
        if not isinstance(endpoint_mapping, (str, dict)):
            return None, f"Invalid endpoint_mapping type: expected str or dict, got {type(endpoint_mapping).__name__}"
        if isinstance(endpoint_mapping, dict):
            if not endpoint_mapping:
                return None, "Invalid endpoint_mapping dictionary: empty dictionary"
            valid_keys = {"resource", "resource_segment", "resource_name", "param_name", "resource_id", "path_index"}
            if not any(k in valid_keys for k in endpoint_mapping.keys()):
                return None, f"Invalid endpoint_mapping dictionary: must specify one of {sorted(list(valid_keys))}"

    # Extract mapping target name and path index
    mapping_target = None
    path_index = None
    if endpoint_mapping:
        if isinstance(endpoint_mapping, dict):
            path_index = endpoint_mapping.get("path_index")
            for k in ("resource", "resource_segment", "resource_name", "param_name", "resource_id"):
                v = endpoint_mapping.get(k)
                if v:
                    mapping_target = str(v).lower().replace("_id", "").replace("id", "").strip()
                    break
            if not mapping_target and path_index is None:
                for v in endpoint_mapping.values():
                    if isinstance(v, str) and v.strip():
                        mapping_target = str(v).lower().replace("_id", "").replace("id", "").strip()
                        break
        elif isinstance(endpoint_mapping, str):
            mapping_target = endpoint_mapping.lower().replace("_id", "").replace("id", "").strip()

    # Reject mappings that identify action, filter, or non-resource sub-routes
    if mapping_target and mapping_target in DISALLOWED_RESOURCE_PATH_SEGMENTS:
        return None, f"Endpoint mapping target '{mapping_target}' is an action, filter, or non-resource sub-route segment and cannot represent a resource identifier."

    # Validate path_index if specified
    if path_index is not None:
        if not isinstance(path_index, int) or isinstance(path_index, bool):
            return None, f"Invalid path_index in endpoint_mapping: expected integer, got {type(path_index).__name__}"
        if path_index < 0 or path_index >= len(segments):
            return None, f"Path index {path_index} out of range for URL path with {len(segments)} segments"
        cand_at_index = segments[path_index]
        is_cand = cand_at_index.isdigit() or len(cand_at_index) in (24, 32, 36) or ('_' in cand_at_index and any(c.isdigit() for c in cand_at_index))
        if not is_cand:
            return None, f"URL segment at path_index {path_index} ('{cand_at_index}') is not a recognized resource identifier format"
        mapped_cand = cand_at_index
    else:
        # Collect candidate identifier segments with preceding resource names
        candidates: List[Tuple[str, str, int]] = []
        for i, s in enumerate(segments):
            if s.isdigit() or len(s) in (24, 32, 36) or ('_' in s and any(c.isdigit() for c in s)):
                preceding = segments[i - 1].lower() if i > 0 else ""
                candidates.append((preceding, s, i))

        if not candidates:
            if norm_explicit is not None:
                return norm_explicit, None
            return None, "No candidate resource identifiers found in URL path"

        mapped_cand = None
        if mapping_target:
            cand_ids = [c[1] for c in candidates]
            matched = []
            for prec, cand, idx in candidates:
                norm_prec = prec.replace("_id", "").replace("id", "").strip()
                if norm_prec == mapping_target or prec == mapping_target:
                    matched.append(cand)
            if len(matched) == 1:
                mapped_cand = matched[0]
            elif len(matched) > 1:
                return None, f"Ambiguous endpoint mapping: matches multiple duplicate candidate segments in URL path ({matched})"
            else:
                return None, f"Endpoint mapping '{endpoint_mapping}' did not match any candidate resource identifier in URL path ({cand_ids})"
        else:
            # If no mapping provided and multiple candidates exist: fail closed
            if len(candidates) > 1:
                cand_ids = [c[1] for c in candidates]
                return None, f"Multiple candidate resource identifiers found in URL path ({cand_ids}) without an explicit endpoint mapping. Ambiguous resource identity."

            # If single candidate exists, check if final segment is a non-identifier action/sub-route
            prec, cand, idx = candidates[0]
            if segments[-1] != cand:
                return None, f"Final URL path segment '{segments[-1]}' is not a resource identifier and no explicit endpoint mapping was provided."
            mapped_cand = cand

    # Check for conflict between explicit_identifier and mapped_cand
    if norm_explicit is not None and mapped_cand is not None:
        if norm_explicit != mapped_cand:
            return None, f"Conflict between explicit resource identifier ('{norm_explicit}') and URL-mapped identifier ('{mapped_cand}'). Ambiguous resource identity."
        return norm_explicit, None

    if norm_explicit is not None:
        return norm_explicit, None

    return mapped_cand, None


def check_session_isolation(
    session_a: Optional[requests.Session],
    session_b: Optional[requests.Session],
) -> Tuple[bool, str]:
    """
    Performs a deep session isolation audit between User A and User B sessions.
    Fails closed if either session is missing, or if mutable session state,
    transport state, or credentials are shared.
    Checks:
    - Session existence: both sessions must be explicitly initialized.
    - Session instance identity: session_b is not session_a.
    - Mutable headers identity: session_b.headers is not session_a.headers.
    - CookieJar instance identity: session_b.cookies is not session_a.cookies.
    - Mutable auth object identity: session_b.auth is not session_a.auth.
    - Mutable adapter transport dictionary: session_b.adapters is not session_a.adapters.
    - Mutable params dictionary: session_b.params is not session_a.params.
    - Mutable hooks dictionary: session_b.hooks is not session_a.hooks.
    - Identical non-empty Authorization headers.
    - Identical sensitive auth cookies (sessionid, token, jwt, auth, etc.).
    Note: Safe shared immutable configuration (e.g. Boolean flags like verify_ssl,
    CA bundle strings, adapter class types) is permitted.
    """
    if session_a is None and session_b is None:
        return False, "Session isolation unverified: both primary and secondary sessions are None"
    if session_a is None:
        return False, "Session isolation unverified: primary session is None"
    if session_b is None:
        return False, "Session isolation unverified: secondary session is None"

    if session_b is session_a:
        return False, "Session isolation violation: User B session is identical instance to User A session."

    if getattr(session_b, "headers", None) is getattr(session_a, "headers", None):
        return False, "Session isolation violation: User B session shares mutable headers dict with User A session."

    if getattr(session_b, "cookies", None) is getattr(session_a, "cookies", None):
        return False, "Session isolation violation: User B session shares CookieJar instance with User A session."

    if getattr(session_b, "auth", None) is not None and getattr(session_b, "auth", None) is getattr(session_a, "auth", None):
        return False, "Session isolation violation: User B session shares mutable auth object with User A session."

    if getattr(session_b, "adapters", None) is getattr(session_a, "adapters", None) and getattr(session_a, "adapters", None) is not None:
        return False, "Session isolation violation: User B session shares mutable adapters dict with User A session."

    if getattr(session_b, "params", None) is getattr(session_a, "params", None) and getattr(session_a, "params", None) is not None:
        return False, "Session isolation violation: User B session shares mutable params dict with User A session."

    if getattr(session_b, "hooks", None) is getattr(session_a, "hooks", None) and getattr(session_a, "hooks", None) is not None:
        return False, "Session isolation violation: User B session shares mutable hooks dict with User A session."

    # Check for shared/identical Authorization header
    auth_a = session_a.headers.get("Authorization") if hasattr(session_a, "headers") else None
    auth_b = session_b.headers.get("Authorization") if hasattr(session_b, "headers") else None
    if auth_a and auth_b and str(auth_a).strip() == str(auth_b).strip():
        return False, "Session isolation violation: User B session shares identical Authorization header with User A session."

    # Check for shared sensitive authentication cookies
    if hasattr(session_a, "cookies") and hasattr(session_b, "cookies"):
        sensitive_cookie_keys = {"session", "sessionid", "token", "jwt", "auth", "access_token"}
        cookies_a = {str(k).lower(): str(v) for k, v in session_a.cookies.items()}
        cookies_b = {str(k).lower(): str(v) for k, v in session_b.cookies.items()}
        for key in sensitive_cookie_keys:
            if key in cookies_a and key in cookies_b:
                if cookies_a[key] and cookies_a[key] == cookies_b[key]:
                    return False, f"Session isolation violation: User B session shares identical sensitive cookie '{key}' with User A session."

    return True, "Sessions strictly isolated"


def extract_authenticated_principal(body: str) -> Optional[Dict[str, str]]:
    """
    Extracts authenticated principal identity attributes from a validation endpoint response.
    Returns a dict of normalized principal attributes if found, or None if response
    is non-JSON, empty, or lacks explicit principal identifiers.
    """
    if not body or not body.strip():
        return None
    try:
        data = json.loads(body.strip())
    except Exception:
        return None

    if not isinstance(data, dict):
        return None

    # Search top-level and common user/profile wrapper objects
    candidates: List[Dict[str, Any]] = [data]
    for key in ("user", "data", "profile", "principal", "account", "identity"):
        val = data.get(key)
        if isinstance(val, dict):
            candidates.append(val)

    found_attributes: Dict[str, str] = {}
    for c in candidates:
        for k in CLAIM_CATEGORY_MAP.keys():
            if k in c and c[k] is not None:
                val_str = str(c[k]).strip()
                if val_str:
                    found_attributes[k] = val_str

    if not found_attributes:
        return None

    return found_attributes


def compare_authenticated_principal(
    extracted_claims: Dict[str, str],
    expected_claims: Dict[str, str] | str,
    expected_claim_type: str = "user_id",
    claim_mappings: Optional[Dict[str, str]] = None,
) -> Tuple[bool, str]:
    """
    Compares extracted principal attributes against expected identity claims.
    Enforces attribute-specific matching across distinct identity categories:
    - User ID, Account ID, Tenant ID, Profile ID, Username, and Email are separated.
    - Any cross-category mapping (e.g. account_id to user_id) requires explicit claim_mappings configuration.
    - If multiple configured claims contradict each other within a category, fails closed.
    - If response contains conflicting claims within a category, fails closed.
    """
    if not extracted_claims:
        return False, "Validation response lacks extracted principal attributes"

    # Build effective category mapping, applying explicit cross-category mappings if configured
    category_map = dict(CLAIM_CATEGORY_MAP)
    if claim_mappings:
        for src, dst in claim_mappings.items():
            category_map[src.strip().lower()] = dst.strip().lower()

    # Normalize expected_claims into Dict[str, str]
    claims_to_check: Dict[str, str] = {}
    if isinstance(expected_claims, str):
        if not expected_claims.strip():
            return False, "Expected identity identifier is empty"
        claims_to_check[expected_claim_type.lower()] = expected_claims.strip()
    elif isinstance(expected_claims, dict):
        if not expected_claims:
            return False, "No expected identity claims configured"
        for k, v in expected_claims.items():
            if v and str(v).strip():
                claims_to_check[k.lower()] = str(v).strip()
    else:
        return False, "Invalid expected_claims specification"

    if not claims_to_check:
        return False, "No non-empty expected identity claims configured"

    # Check for internal contradictions within configured expected_claims
    cat_to_expected: Dict[str, Tuple[str, str]] = {}
    for claim_name, claim_val in claims_to_check.items():
        cat = category_map.get(claim_name, claim_name)
        if cat in cat_to_expected:
            prev_name, prev_val = cat_to_expected[cat]
            if prev_val.lower() != claim_val.lower():
                return False, f"Configured expected claims contain internal contradiction for category '{cat}': {prev_name}='{prev_val}' vs {claim_name}='{claim_val}'"
        else:
            cat_to_expected[cat] = (claim_name, claim_val)

    # Check for internal contradictions within extracted claims from response
    cat_to_extracted: Dict[str, Tuple[str, str]] = {}
    for claim_name, claim_val in extracted_claims.items():
        cat = category_map.get(claim_name, claim_name)
        if cat in cat_to_extracted:
            prev_name, prev_val = cat_to_extracted[cat]
            if prev_val.lower() != claim_val.lower():
                return False, f"Validation response contains conflicting '{cat}' claims: {prev_name}='{prev_val}' vs {claim_name}='{claim_val}'"
        else:
            cat_to_extracted[cat] = (claim_name, claim_val)

    # Perform category-specific comparison
    verified_signals: List[str] = []
    for exp_claim_name, exp_claim_val in claims_to_check.items():
        target_cat = category_map.get(exp_claim_name, exp_claim_name)
        exp_norm = exp_claim_val.strip().lower()

        # Find all extracted claims matching target_cat
        matching_extracted = {
            k: v for k, v in extracted_claims.items()
            if category_map.get(k, k) == target_cat
        }

        if not matching_extracted:
            return (
                False,
                f"Required identity claim '{exp_claim_name}' (category '{target_cat}') was not found in validation response. Extracted attributes: {list(extracted_claims.keys())}"
            )

        # Ensure every extracted claim in this category matches the expected value
        for ext_k, ext_v in matching_extracted.items():
            ext_norm = ext_v.strip().lower()
            if ext_norm != exp_norm:
                return (
                    False,
                    f"Principal mismatch for claim '{exp_claim_name}' (category '{target_cat}'): expected '{exp_claim_val}', but response has '{ext_k}={ext_v}'"
                )

        verified_signals.append(f"{exp_claim_name}={exp_claim_val}")

    return True, f"Principal identity verified: {', '.join(verified_signals)}"


def build_sanitized_curl(method: str, url: str) -> str:
    """
    Constructs a sanitized reproduction cURL command with zero credentials or tokens.
    """
    safe_url = sanitize_url(url)
    return f'curl -s -X {method.upper()} "{safe_url}" -H "Authorization: [REDACTED]" -H "Cache-Control: no-cache"'


def calculate_confidence(
    outcome: BOLAOutcome,
    scenario_a: ScenarioExecutionResult,
    scenario_b: Optional[ScenarioExecutionResult],
    scenario_c: Optional[ScenarioExecutionResult],
    scenario_d: Optional[ScenarioExecutionResult],
    has_id_a_in_b: bool,
    similarity_a_b: float,
    cache_interference: CacheInterference,
    has_owner_a_in_b: bool = True,
    is_anon_denied: bool = False,
) -> ConfidenceAssessment:
    """
    Calculates an explainable, evidence-based confidence score and level.
    Never assigns arbitrary magic numbers; computes from corroborating signals.

    NOTE: The scoring weights applied here are heuristic indicators pending calibration
    against real-world and controlled benchmark datasets. Confidence assessment is strictly
    decoupled from verdict assignment: mandatory evidence failures force non-vulnerable or
    inconclusive verdicts regardless of score, and a high confidence score can NEVER promote
    an otherwise invalid or unproven outcome.
    """
    score = 0.0
    signals: List[str] = []
    deductions: List[str] = []

    # 1. Baseline Success
    if scenario_a.status_code == 200 and not scenario_a.error:
        score += 0.25
        signals.append("Scenario A verified owner access (+0.25)")
    else:
        deductions.append("Scenario A baseline failed or errored")
        return ConfidenceAssessment(
            score=0.0,
            level=ConfidenceLevel.LOW,
            signals=signals,
            deductions=deductions,
        )

    # 2. Cross-user access signals with Resource Identity & Ownership Evidence
    if scenario_b and scenario_b.status_code == 200 and not scenario_b.error:
        if has_id_a_in_b:
            score += 0.25
            signals.append("Scenario B confirmed presence of Resource A identifier (+0.25)")
        else:
            deductions.append("Scenario B response lacks Resource A identifier")

        if has_owner_a_in_b:
            signals.append("Scenario B confirmed presence of User A ownership evidence")
        else:
            score -= 0.25
            deductions.append("Scenario B lacks User A ownership evidence (-0.25)")

        if similarity_a_b >= 0.85:
            score += 0.15
            signals.append(f"Scenario B semantic similarity to Resource A is high ({similarity_a_b:.2f}) (+0.15)")
        else:
            score -= 0.15
            deductions.append(f"Low semantic similarity to Resource A ({similarity_a_b:.2f}) (-0.15)")
    else:
        deductions.append("Scenario B was denied or failed")

    # 3. Unauthenticated rejection signals
    if scenario_d and (scenario_d.status_code in (401, 403) or scenario_d.is_redirect or is_anon_denied):
        score += 0.20
        signals.append("Scenario D confirmed unauthenticated access is denied (+0.20)")
    elif scenario_d and scenario_d.status_code == 200:
        deductions.append("Scenario D unauthenticated access succeeded (indicates public resource)")

    # 4. Reverse owner control validation (Scenario C)
    if scenario_c and scenario_c.status_code == 200 and not scenario_c.error:
        score += 0.15
        signals.append("Scenario C validated User B independent control on distinct Resource B (+0.15)")
    else:
        if outcome == BOLAOutcome.HIGH_PROBABLE_BOLA:
            deductions.append("Scenario C unavailable (Resource B missing, verified via 3-way path)")

    # 5. Cache penalty
    if cache_interference != CacheInterference.NONE:
        score -= 0.35
        deductions.append(f"Cache interference detected: {cache_interference.value} (-0.35)")

    bounded_score = max(0.0, min(1.0, round(score, 2)))

    # Map to level
    if bounded_score >= 0.95 and outcome == BOLAOutcome.CONFIRMED_BOLA:
        level = ConfidenceLevel.CERTAIN
    elif bounded_score >= 0.80:
        level = ConfidenceLevel.HIGH
    elif bounded_score >= 0.60:
        level = ConfidenceLevel.MEDIUM
    else:
        level = ConfidenceLevel.LOW

    return ConfidenceAssessment(
        score=bounded_score,
        level=level,
        signals=signals,
        deductions=deductions,
    )


class BOLAVerificationEngine:
    """
    BOLA / IDOR Verification Engine executing 4-way differential verification.
    """

    def __init__(
        self,
        auth_manager: SessionIdentityManager,
        allow_state_modification: bool = False,
        request_timeout: int = 15,
        max_candidates: int = 10,
        default_validation_url: Optional[str] = None,
    ):
        self.auth_manager = auth_manager
        self.allow_state_modification = allow_state_modification
        self.request_timeout = request_timeout
        self.max_candidates = max_candidates
        self.default_validation_url = default_validation_url

    def _execute_request(
        self,
        identity: str,
        method: str,
        url: str,
    ) -> ScenarioExecutionResult:
        """
        Executes a single HTTP request in the given identity context.
        Applies:
        - net_guard IP pinning and SSRF defense
        - Cache-busting headers
        - allow_redirects=False with redirect inspection
        - Session refresh handling on 401
        """
        session = self.auth_manager.get_session(identity, auto_authenticate=True)
        headers = {
            "Cache-Control": "no-cache, no-store, max-age=0",
            "Pragma": "no-cache",
            "Accept": "application/json, text/plain, */*",
        }

        start_time = time.monotonic()
        try:
            resp = net_guard.guarded_request(
                method=method.lower(),
                url=url,
                session=session,
                headers=headers,
                timeout=self.request_timeout,
                allow_redirects=False,
            )
            elapsed_ms = (time.monotonic() - start_time) * 1000

            # Check if 401 triggers a controlled session refresh
            if resp.status_code == 401 and identity in (IDENTITY_PRIMARY, IDENTITY_SECONDARY):
                refreshed = self.auth_manager.handle_response_auth_status(identity, resp)
                if refreshed:
                    # Retry request once with the refreshed session
                    session = self.auth_manager.get_session(identity, auto_authenticate=False)
                    start_time = time.monotonic()
                    resp = net_guard.guarded_request(
                        method=method.lower(),
                        url=url,
                        session=session,
                        headers=headers,
                        timeout=self.request_timeout,
                        allow_redirects=False,
                    )
                    elapsed_ms = (time.monotonic() - start_time) * 1000

            is_redirect = resp.status_code in (301, 302, 303, 307, 308)
            redirect_loc = resp.headers.get("Location") if is_redirect else None
            safe_redirect_loc = sanitize_url(redirect_loc) if redirect_loc else None

            # Sanitize snippet, URL, and response headers
            safe_body_snippet = sanitize_snippet(resp.text[:2000]) if resp.text else ""
            safe_url = sanitize_url(url)
            safe_response_headers = sanitize_response_headers(dict(resp.headers))

            return ScenarioExecutionResult(
                scenario=VerificationScenario.SCENARIO_A,  # overridden by caller
                identity=identity,
                url=safe_url,
                method=method.upper(),
                status_code=resp.status_code,
                content_type=resp.headers.get("Content-Type", ""),
                body_sample=safe_body_snippet,
                response_headers=safe_response_headers,
                execution_time_ms=round(elapsed_ms, 2),
                is_redirect=is_redirect,
                redirect_location=safe_redirect_loc,
            )
        except requests.exceptions.RequestException as e:
            elapsed_ms = (time.monotonic() - start_time) * 1000
            safe_url = sanitize_url(url)
            safe_err = sanitize_snippet(f"{type(e).__name__}: {str(e)[:150]}")
            return ScenarioExecutionResult(
                scenario=VerificationScenario.SCENARIO_A,
                identity=identity,
                url=safe_url,
                method=method.upper(),
                status_code=0,
                execution_time_ms=round(elapsed_ms, 2),
                error=safe_err,
            )
        except Exception as e:
            elapsed_ms = (time.monotonic() - start_time) * 1000
            safe_url = sanitize_url(url)
            safe_err = sanitize_snippet(f"Unexpected error: {type(e).__name__}: {str(e)[:150]}")
            return ScenarioExecutionResult(
                scenario=VerificationScenario.SCENARIO_A,
                identity=identity,
                url=safe_url,
                method=method.upper(),
                status_code=0,
                execution_time_ms=round(elapsed_ms, 2),
                error=safe_err,
            )

    def _validate_secondary_authentication(
        self,
        expected_user_b_identifier: Optional[str] = None,
        expected_user_b_claims: Optional[Dict[str, str]] = None,
        expected_claim_type: str = "id",
        user_b_validation_url: Optional[str] = None,
        session_to_use: Optional[requests.Session] = None,
    ) -> Tuple[bool, str]:
        """
        Independently validates User B's authentication session and verifies the authenticated principal.

        TRUSTED PRINCIPAL SPECIFICATION:
        1. An expected User B identity or explicit claims mapping must be independently configured.
        2. An explicit, safe, non-mutating validation endpoint (e.g. /api/user/me, /api/auth/status)
           must be configured. Arbitrary endpoints are never assumed.
        3. The request must use User B's isolated session and credentials.
           If User B's session is identical to User A's session, shares mutable headers/cookies,
           or shares credentials, a session isolation violation is flagged.
        4. The validation request executes a non-mutating GET with allow_redirects=False.
        5. The response must return HTTP 200 OK without redirect or auth challenge.
        6. The validation response must identify the authenticated principal.
        7. The extracted principal is compared against expected User B identity claims strictly by attribute category.
        8. A public profile endpoint returning HTTP 200 without identifying the authenticated
           principal (or returning guest/anonymous/other user) fails closed with INCONCLUSIVE.
        """
        auth_b = getattr(self.auth_manager, "_auth_configs", {}).get(IDENTITY_SECONDARY) or {}
        configured_claims = expected_user_b_claims or auth_b.get("expected_claims")

        if not configured_claims:
            exp_id = expected_user_b_identifier or auth_b.get("username")
            if not exp_id or not str(exp_id).strip():
                return (
                    False,
                    "Expected User B identity must be independently configured to validate authenticated principal."
                )
            configured_claims = {expected_claim_type: str(exp_id).strip()}

        validation_url = (
            user_b_validation_url
            or self.default_validation_url
            or auth_b.get("validation_url")
            or auth_b.get("profile_url")
            or auth_b.get("auth_test_url")
        )

        if not validation_url:
            return (
                False,
                "No safe, non-mutating authentication validation endpoint (e.g. validation_url or profile_url) "
                "was configured to independently verify User B's session. Credential presence alone cannot establish trust."
            )

        session_b = session_to_use or self.auth_manager.get_session(IDENTITY_SECONDARY, auto_authenticate=False)
        if session_b is None:
            return False, "User B session could not be retrieved from auth manager."

        session_a = self.auth_manager.get_session(IDENTITY_PRIMARY, auto_authenticate=False)
        is_isolated, isolation_reason = check_session_isolation(session_a, session_b)
        if not is_isolated:
            return False, isolation_reason

        # Execute safe, read-only GET request under User B's session
        try:
            resp = net_guard.guarded_request(
                method="get",
                url=validation_url,
                session=session_b,
                headers={"Cache-Control": "no-cache, no-store", "Accept": "application/json, text/plain, */*"},
                timeout=self.request_timeout,
                allow_redirects=False,
            )
        except Exception as e:
            return False, f"Authentication validation request failed: {type(e).__name__}: {str(e)[:100]}"

        # Check for authentication challenge, redirect, or error
        if resp.status_code in (401, 403):
            return False, f"Validation endpoint returned {resp.status_code} Unauthorized/Forbidden. Credentials in session are expired or invalid."

        if resp.status_code in (301, 302, 303, 307, 308):
            loc = resp.headers.get("Location", "")
            return False, f"Validation endpoint redirected (status {resp.status_code}, Location: {loc}). Session is unauthenticated."

        if resp.status_code != 200:
            return False, f"Validation endpoint returned non-200 status {resp.status_code}. Authentication validation is ambiguous."

        # Extract and compare authenticated principal
        principal = extract_authenticated_principal(resp.text)
        if not principal:
            return False, "Validation endpoint returned 200 OK but response lacks authenticated principal identity attributes (public endpoint or incomplete identity attributes)."

        is_match, match_msg = compare_authenticated_principal(
            extracted_claims=principal,
            expected_claims=configured_claims,
            expected_claim_type=expected_claim_type,
        )
        if not is_match:
            return False, match_msg

        return True, f"User B authenticated session independently confirmed: {match_msg}."

    def _execute_secure_nonexistent_probe(
        self,
        candidate: CandidateEndpoint,
        target_url_a: str,
        method: str,
        nonexistent_resource_url: str,
        res_d: ScenarioExecutionResult,
        scenario_results: Dict[str, ScenarioExecutionResult],
        verified_masking_policy: Optional[TargetAuthorizationPolicy] = None,
    ) -> Tuple[bool, Optional[BOLAVerificationResult]]:
        """
        Executes a secure nonexistent-resource control probe enforcing:
        1. Target scope boundary (same host, scheme, port as target_url_a and candidate).
        2. SSRF guard (rejects localhost, private, link-local, metadata IP ranges).
        3. Strict redirect prohibition (disables redirects; any redirect fails closed).
        4. Correct anonymous context (IDENTITY_ANONYMOUS without credentials).
        5. Meaningful response evidence comparison (not HTTP status alone).
        Returns (is_anon_denied, inconclusive_result_or_none).
        """
        parsed_target = urlsplit(target_url_a)
        parsed_probe = urlsplit(nonexistent_resource_url)

        if not parsed_probe.scheme or parsed_probe.scheme not in ("http", "https"):
            return False, BOLAVerificationResult(
                candidate_id=candidate.candidate_id,
                target_url=sanitize_url(target_url_a),
                method=method,
                outcome=BOLAOutcome.INCONCLUSIVE,
                confidence=ConfidenceAssessment(
                    score=0.30,
                    level=ConfidenceLevel.LOW,
                    signals=["Scenario A succeeded", "Scenario B returned 200 OK"],
                    deductions=[f"Nonexistent probe URL '{sanitize_url(nonexistent_resource_url)}' has invalid scheme"],
                ),
                title="BOLA Inconclusive (Nonexistent Control Probe Invalid Scheme)",
                explanation=f"Nonexistent resource control probe URL scheme '{parsed_probe.scheme}' is invalid. Must be http or https matching target.",
                is_vulnerable=False,
                scenario_results=scenario_results,
            )

        if parsed_probe.scheme != parsed_target.scheme:
            return False, BOLAVerificationResult(
                candidate_id=candidate.candidate_id,
                target_url=sanitize_url(target_url_a),
                method=method,
                outcome=BOLAOutcome.INCONCLUSIVE,
                confidence=ConfidenceAssessment(
                    score=0.30,
                    level=ConfidenceLevel.LOW,
                    signals=["Scenario A succeeded", "Scenario B returned 200 OK"],
                    deductions=[f"Nonexistent probe scheme '{parsed_probe.scheme}' does not match target scheme '{parsed_target.scheme}'"],
                ),
                title="BOLA Inconclusive (Nonexistent Control Probe Scheme Mismatch)",
                explanation=f"Nonexistent probe scheme '{parsed_probe.scheme}' differs from target scheme '{parsed_target.scheme}'. Control probe must use the same scheme.",
                is_vulnerable=False,
                scenario_results=scenario_results,
            )

        probe_host = (parsed_probe.hostname or "").lower()
        target_host = (parsed_target.hostname or "").lower()
        cand_domain = (candidate.target_domain or "").lower()
        if probe_host != target_host and probe_host != cand_domain:
            return False, BOLAVerificationResult(
                candidate_id=candidate.candidate_id,
                target_url=sanitize_url(target_url_a),
                method=method,
                outcome=BOLAOutcome.INCONCLUSIVE,
                confidence=ConfidenceAssessment(
                    score=0.30,
                    level=ConfidenceLevel.LOW,
                    signals=["Scenario A succeeded", "Scenario B returned 200 OK"],
                    deductions=[f"Cross-origin nonexistent probe host '{probe_host}' rejected; does not match target '{target_host}'"],
                ),
                title="BOLA Inconclusive (Nonexistent Control Probe Out of Scope)",
                explanation=f"Nonexistent resource control probe host '{probe_host}' violates target scope boundary. Probe must target the same approved host as the candidate endpoint.",
                is_vulnerable=False,
                scenario_results=scenario_results,
            )

        probe_port = parsed_probe.port or (443 if parsed_probe.scheme == "https" else 80)
        target_port = parsed_target.port or (443 if parsed_target.scheme == "https" else 80)
        if probe_port != target_port:
            return False, BOLAVerificationResult(
                candidate_id=candidate.candidate_id,
                target_url=sanitize_url(target_url_a),
                method=method,
                outcome=BOLAOutcome.INCONCLUSIVE,
                confidence=ConfidenceAssessment(
                    score=0.30,
                    level=ConfidenceLevel.LOW,
                    signals=["Scenario A succeeded", "Scenario B returned 200 OK"],
                    deductions=[f"Nonexistent probe port '{probe_port}' does not match target port '{target_port}'"],
                ),
                title="BOLA Inconclusive (Nonexistent Control Probe Port Mismatch)",
                explanation=f"Nonexistent resource control probe port '{probe_port}' does not match target port '{target_port}'.",
                is_vulnerable=False,
                scenario_results=scenario_results,
            )

        # Check SSRF via net_guard
        try:
            net_guard.assert_public_host(probe_host)
        except (net_guard.SsrfBlocked, ValueError) as ssrf_err:
            return False, BOLAVerificationResult(
                candidate_id=candidate.candidate_id,
                target_url=sanitize_url(target_url_a),
                method=method,
                outcome=BOLAOutcome.INCONCLUSIVE,
                confidence=ConfidenceAssessment(
                    score=0.0,
                    level=ConfidenceLevel.LOW,
                    signals=[],
                    deductions=[f"SSRF guard blocked nonexistent probe host '{probe_host}': {ssrf_err}"],
                ),
                title="BOLA Inconclusive (Nonexistent Control Probe SSRF Blocked)",
                explanation=f"Nonexistent resource control probe host '{probe_host}' resolves to non-public or disallowed IP range ({ssrf_err}). Outbound request blocked by SSRF defense.",
                is_vulnerable=False,
                scenario_results=scenario_results,
            )

        # Execute request using IDENTITY_ANONYMOUS
        res_nonexistent = self._execute_request(IDENTITY_ANONYMOUS, method, nonexistent_resource_url)

        if res_nonexistent.error:
            return False, BOLAVerificationResult(
                candidate_id=candidate.candidate_id,
                target_url=sanitize_url(target_url_a),
                method=method,
                outcome=BOLAOutcome.INCONCLUSIVE,
                confidence=ConfidenceAssessment(
                    score=0.30,
                    level=ConfidenceLevel.LOW,
                    signals=["Scenario A succeeded", "Scenario B returned 200 OK"],
                    deductions=[f"Nonexistent probe failed with error: {res_nonexistent.error}"],
                ),
                title="BOLA Inconclusive (Nonexistent Control Probe Error)",
                explanation=f"Nonexistent resource control probe request failed ({res_nonexistent.error}). Cannot establish 404 masking behavior.",
                is_vulnerable=False,
                scenario_results=scenario_results,
            )

        if res_nonexistent.is_redirect or res_nonexistent.status_code in (301, 302, 303, 307, 308):
            return False, BOLAVerificationResult(
                candidate_id=candidate.candidate_id,
                target_url=sanitize_url(target_url_a),
                method=method,
                outcome=BOLAOutcome.INCONCLUSIVE,
                confidence=ConfidenceAssessment(
                    score=0.30,
                    level=ConfidenceLevel.LOW,
                    signals=["Scenario A succeeded", "Scenario B returned 200 OK"],
                    deductions=[f"Nonexistent probe returned unexpected redirect HTTP {res_nonexistent.status_code} to '{res_nonexistent.redirect_location}'"],
                ),
                title="BOLA Inconclusive (Nonexistent Control Probe Redirect Rejected)",
                explanation=f"Nonexistent resource control probe returned redirect (status {res_nonexistent.status_code}). Control probe must directly return the application 404 response without redirects.",
                is_vulnerable=False,
                scenario_results=scenario_results,
            )

        if res_nonexistent.status_code != 404:
            return False, BOLAVerificationResult(
                candidate_id=candidate.candidate_id,
                target_url=sanitize_url(target_url_a),
                method=method,
                outcome=BOLAOutcome.INCONCLUSIVE,
                confidence=ConfidenceAssessment(
                    score=0.35,
                    level=ConfidenceLevel.LOW,
                    signals=["Scenario A succeeded", "Scenario B returned 200 OK"],
                    deductions=[f"Nonexistent resource control probe returned status {res_nonexistent.status_code}, failing to verify 404 masking semantics"],
                ),
                title="BOLA Inconclusive (Nonexistent Resource Control Mismatch)",
                explanation=f"Nonexistent resource control probe returned status {res_nonexistent.status_code} instead of HTTP 404. Application does not consistently mask resources with 404.",
                is_vulnerable=False,
                scenario_results=scenario_results,
            )

        if is_routing_error(res_nonexistent.body_sample or ""):
            return False, BOLAVerificationResult(
                candidate_id=candidate.candidate_id,
                target_url=sanitize_url(target_url_a),
                method=method,
                outcome=BOLAOutcome.INCONCLUSIVE,
                confidence=ConfidenceAssessment(
                    score=0.30,
                    level=ConfidenceLevel.LOW,
                    signals=["Scenario A succeeded", "Scenario B returned 200 OK"],
                    deductions=["Nonexistent probe returned generic framework or gateway routing error text"],
                ),
                title="BOLA Inconclusive (Nonexistent Control Probe Ambiguous Routing Error)",
                explanation="Nonexistent resource control probe returned a generic proxy or framework routing error, failing to establish application-level 404 masking.",
                is_vulnerable=False,
                scenario_results=scenario_results,
            )

        # Meaningful response evidence comparison
        ct_d = (res_d.content_type or "").split(";")[0].strip().lower()
        ct_probe = (res_nonexistent.content_type or "").split(";")[0].strip().lower()
        if ct_d and ct_probe and ct_d != ct_probe:
            return False, BOLAVerificationResult(
                candidate_id=candidate.candidate_id,
                target_url=sanitize_url(target_url_a),
                method=method,
                outcome=BOLAOutcome.INCONCLUSIVE,
                confidence=ConfidenceAssessment(
                    score=0.35,
                    level=ConfidenceLevel.LOW,
                    signals=["Scenario A succeeded", "Scenario B returned 200 OK"],
                    deductions=[f"Content-Type mismatch between Scenario D ('{ct_d}') and control probe ('{ct_probe}')"],
                ),
                title="BOLA Inconclusive (Nonexistent Resource Control Response Mismatch)",
                explanation=f"Scenario D 404 response Content-Type ('{ct_d}') does not match control probe Content-Type ('{ct_probe}'). Responses are not comparable.",
                is_vulnerable=False,
                scenario_results=scenario_results,
            )

        body_d = (res_d.body_sample or "").strip()
        body_probe = (res_nonexistent.body_sample or "").strip()
        if not body_probe or not body_d:
            return False, BOLAVerificationResult(
                candidate_id=candidate.candidate_id,
                target_url=sanitize_url(target_url_a),
                method=method,
                outcome=BOLAOutcome.INCONCLUSIVE,
                confidence=ConfidenceAssessment(
                    score=0.35,
                    level=ConfidenceLevel.LOW,
                    signals=["Scenario A succeeded", "Scenario B returned 200 OK"],
                    deductions=["Nonexistent control probe or Scenario D returned empty response body"],
                ),
                title="BOLA Inconclusive (Nonexistent Resource Control Response Mismatch)",
                explanation="Nonexistent resource control probe or Scenario D returned an empty body, failing to provide comparable 404 masking evidence.",
                is_vulnerable=False,
                scenario_results=scenario_results,
            )

        # Deep semantic error comparison:
        # Neither Content-Type, superficial JSON key matching, nor moderate text similarity
        # can independently establish authorization semantics. Ambiguous control evidence must return INCONCLUSIVE.
        is_json_d = False
        is_json_probe = False
        data_d = None
        data_probe = None
        try:
            data_d = json.loads(body_d)
            is_json_d = isinstance(data_d, dict)
        except Exception:
            pass

        try:
            data_probe = json.loads(body_probe)
            is_json_probe = isinstance(data_probe, dict)
        except Exception:
            pass

        if is_json_d != is_json_probe:
            return False, BOLAVerificationResult(
                candidate_id=candidate.candidate_id,
                target_url=sanitize_url(target_url_a),
                method=method,
                outcome=BOLAOutcome.INCONCLUSIVE,
                confidence=ConfidenceAssessment(
                    score=0.35,
                    level=ConfidenceLevel.LOW,
                    signals=["Scenario A succeeded", "Scenario B returned 200 OK"],
                    deductions=["Payload format mismatch: one response is JSON and the other is not"],
                ),
                title="BOLA Inconclusive (Nonexistent Resource Control Response Mismatch)",
                explanation="Scenario D response format does not match control probe format (JSON vs non-JSON). Cannot confirm masking semantics.",
                is_vulnerable=False,
                scenario_results=scenario_results,
            )

        if is_json_d and is_json_probe:
            # Both are JSON dicts.
            if not data_d or not data_probe:
                return False, BOLAVerificationResult(
                    candidate_id=candidate.candidate_id,
                    target_url=sanitize_url(target_url_a),
                    method=method,
                    outcome=BOLAOutcome.INCONCLUSIVE,
                    confidence=ConfidenceAssessment(
                        score=0.35,
                        level=ConfidenceLevel.LOW,
                        signals=["Scenario A succeeded", "Scenario B returned 200 OK"],
                        deductions=["Trivial empty JSON container in 404 response"],
                    ),
                    title="BOLA Inconclusive (Nonexistent Resource Control Response Mismatch)",
                    explanation="One or both 404 responses returned empty JSON containers. Empty responses do not establish masking semantics.",
                    is_vulnerable=False,
                    scenario_results=scenario_results,
                )

            # Check for recognized error envelope keys
            recognized_err_keys = {"error", "errors", "detail", "message", "errorMessage", "code", "errorCode", "status", "fault"}
            keys_d = set(data_d.keys())
            keys_probe = set(data_probe.keys())
            common_err_keys = keys_d.intersection(keys_probe).intersection(recognized_err_keys)

            if not common_err_keys:
                return False, BOLAVerificationResult(
                    candidate_id=candidate.candidate_id,
                    target_url=sanitize_url(target_url_a),
                    method=method,
                    outcome=BOLAOutcome.INCONCLUSIVE,
                    confidence=ConfidenceAssessment(
                        score=0.35,
                        level=ConfidenceLevel.LOW,
                        signals=["Scenario A succeeded", "Scenario B returned 200 OK"],
                        deductions=[f"JSON error envelopes do not share recognized error keys: Scenario D {sorted(list(keys_d))} vs Probe {sorted(list(keys_probe))}"],
                    ),
                    title="BOLA Inconclusive (Nonexistent Resource Control Response Mismatch)",
                    explanation="Scenario D 404 JSON envelope does not share any recognized error keys with control probe 404 response.",
                    is_vulnerable=False,
                    scenario_results=scenario_results,
                )

            # Semantic error consistency check on shared keys:
            # Matching JSON keys alone must NOT independently establish authorization semantics.
            # Values of shared error keys must not contradict each other.
            for ek in common_err_keys:
                val_d = str(data_d[ek]).strip().lower()
                val_probe = str(data_probe[ek]).strip().lower()

                # If key is status/code: check for contradictory error types
                if ek in ("code", "errorCode", "status"):
                    if val_d != val_probe:
                        return False, BOLAVerificationResult(
                            candidate_id=candidate.candidate_id,
                            target_url=sanitize_url(target_url_a),
                            method=method,
                            outcome=BOLAOutcome.INCONCLUSIVE,
                            confidence=ConfidenceAssessment(
                                score=0.35,
                                level=ConfidenceLevel.LOW,
                                signals=["Scenario A succeeded", "Scenario B returned 200 OK"],
                                deductions=[f"Conflicting error {ek}: Scenario D has '{data_d[ek]}' vs Probe has '{data_probe[ek]}'"],
                            ),
                            title="BOLA Inconclusive (Nonexistent Resource Control Response Mismatch)",
                            explanation=f"Scenario D 404 error {ek} contradicts control probe error {ek}. Contradictory error semantics cannot establish authorization masking.",
                            is_vulnerable=False,
                            scenario_results=scenario_results,
                        )

                # If key is error/message/detail: check for contradictory semantic meanings
                if ek in ("error", "message", "detail", "errorMessage"):
                    d_is_validation = any(w in val_d for w in ("validation", "syntax", "bad request", "invalid param", "malformed", "missing parameter"))
                    probe_is_validation = any(w in val_probe for w in ("validation", "syntax", "bad request", "invalid param", "malformed", "missing parameter"))
                    if d_is_validation != probe_is_validation:
                        return False, BOLAVerificationResult(
                            candidate_id=candidate.candidate_id,
                            target_url=sanitize_url(target_url_a),
                            method=method,
                            outcome=BOLAOutcome.INCONCLUSIVE,
                            confidence=ConfidenceAssessment(
                                score=0.35,
                                level=ConfidenceLevel.LOW,
                                signals=["Scenario A succeeded", "Scenario B returned 200 OK"],
                                deductions=["Semantic error conflict: one response indicates parameter/validation error while the other indicates resource not-found"],
                            ),
                            title="BOLA Inconclusive (Nonexistent Resource Control Response Mismatch)",
                            explanation="Scenario D error message indicates a validation or input error rather than consistent resource not-found masking.",
                            is_vulnerable=False,
                            scenario_results=scenario_results,
                        )

            # Additional structural sanity: JSON similarity check across full payload representations
            json_sim, _ = compute_semantic_similarity(body_d, body_probe)
            if json_sim < 0.50:
                return False, BOLAVerificationResult(
                    candidate_id=candidate.candidate_id,
                    target_url=sanitize_url(target_url_a),
                    method=method,
                    outcome=BOLAOutcome.INCONCLUSIVE,
                    confidence=ConfidenceAssessment(
                        score=0.35,
                        level=ConfidenceLevel.LOW,
                        signals=["Scenario A succeeded", "Scenario B returned 200 OK"],
                        deductions=[f"JSON 404 payload similarity too low ({json_sim:.2f} < 0.50): schema or structure differs significantly"],
                    ),
                    title="BOLA Inconclusive (Nonexistent Resource Control Response Mismatch)",
                    explanation="Scenario D 404 JSON body structure differs significantly from control probe response body despite superficial key overlap.",
                    is_vulnerable=False,
                    scenario_results=scenario_results,
                )

        else:
            # Non-JSON responses (HTML/text):
            # 1. Routing error check
            if is_routing_error(body_d) or is_routing_error(body_probe):
                return False, BOLAVerificationResult(
                    candidate_id=candidate.candidate_id,
                    target_url=sanitize_url(target_url_a),
                    method=method,
                    outcome=BOLAOutcome.INCONCLUSIVE,
                    confidence=ConfidenceAssessment(
                        score=0.30,
                        level=ConfidenceLevel.LOW,
                        signals=["Scenario A succeeded", "Scenario B returned 200 OK"],
                        deductions=["Non-JSON 404 body contains generic web-server or gateway error text"],
                    ),
                    title="BOLA Inconclusive (Nonexistent Control Probe Ambiguous Routing Error)",
                    explanation="Scenario D or control probe 404 response contains generic web server or proxy routing error text, failing to establish application-level masking.",
                    is_vulnerable=False,
                    scenario_results=scenario_results,
                )

            # 2. Strict similarity threshold for non-JSON: >= 0.85 (0.60 is too weak for HTML boilerplate)
            sim, _ = compute_semantic_similarity(body_d, body_probe)
            if sim < 0.85:
                return False, BOLAVerificationResult(
                    candidate_id=candidate.candidate_id,
                    target_url=sanitize_url(target_url_a),
                    method=method,
                    outcome=BOLAOutcome.INCONCLUSIVE,
                    confidence=ConfidenceAssessment(
                        score=0.35,
                        level=ConfidenceLevel.LOW,
                        signals=["Scenario A succeeded", "Scenario B returned 200 OK"],
                        deductions=[f"Non-JSON 404 bodies are insufficiently similar (similarity {sim:.2f} < 0.85)"],
                    ),
                    title="BOLA Inconclusive (Nonexistent Resource Control Response Mismatch)",
                    explanation="Scenario D 404 body does not closely match nonexistent control probe response body (similarity < 0.85). Cannot confirm consistent authorization masking.",
                    is_vulnerable=False,
                    scenario_results=scenario_results,
                )

        # FINAL DECISION BRANCH:
        # Matching status codes, JSON keys, structural similarity, and text similarity
        # must NEVER independently prove authorization semantics.
        # Corroboration strictly requires:
        # EITHER:
        #   (a) Trusted application-specific error semantics:
        #       - A recognized application-level error code or domain message specifically
        #         indicating resource-not-found / absence masking.
        #       - Superficial/generic error payloads (e.g. {"status": "404"} or {"error": "error"})
        #         do NOT independently prove authorization denial.
        # OR:
        #   (b) Corroboration via a cryptographically verified TargetAuthorizationPolicy.
        #
        # Otherwise, fail closed and return INCONCLUSIVE.
        has_app_error_semantics = False

        if is_json_d and is_json_probe:
            resource_absence_markers = (
                "resource_not_found", "resourcenotfound", "not_found", "notfound",
                "object_not_found", "item_not_found", "record_not_found",
                "err_not_found", "entity_not_found", "no_such_resource",
                "resource_unavailable", "access_denied_or_not_found", "does not exist",
            )
            # 1. Check specific error codes in code / errorCode / status
            for ck in ("code", "errorCode", "status"):
                if ck in data_d and ck in data_probe:
                    code_d = str(data_d[ck]).strip().lower()
                    code_probe = str(data_probe[ck]).strip().lower()
                    if code_d == code_probe and any(m in code_d for m in resource_absence_markers):
                        has_app_error_semantics = True
                        break

            # 2. Check application-level domain messages
            if not has_app_error_semantics:
                for mk in ("message", "detail", "error", "errorMessage"):
                    if mk in data_d and mk in data_probe:
                        msg_d = str(data_d[mk]).strip().lower()
                        msg_probe = str(data_probe[mk]).strip().lower()
                        if any(phrase in msg_d for phrase in ("resource not found", "item not found", "does not exist", "could not find", "no such", "not found")) and \
                           any(phrase in msg_probe for phrase in ("resource not found", "item not found", "does not exist", "could not find", "no such", "not found")):
                            has_app_error_semantics = True
                            break
        else:
            # Non-JSON responses: must contain explicit application resource-not-found text
            bd_lower = body_d.lower()
            bp_lower = body_probe.lower()
            if any(phrase in bd_lower for phrase in ("resource not found", "item not found", "does not exist", "record not found", "not found")) and \
               any(phrase in bp_lower for phrase in ("resource not found", "item not found", "does not exist", "record not found", "not found")):
                has_app_error_semantics = True

        if not has_app_error_semantics and not verified_masking_policy:
            return False, BOLAVerificationResult(
                candidate_id=candidate.candidate_id,
                target_url=sanitize_url(target_url_a),
                method=method,
                outcome=BOLAOutcome.INCONCLUSIVE,
                confidence=ConfidenceAssessment(
                    score=0.35,
                    level=ConfidenceLevel.LOW,
                    signals=["Scenario A succeeded", "Scenario B returned 200 OK"],
                    deductions=[
                        "Matching status codes, JSON keys, and structural similarity alone cannot independently prove authorization semantics without application-specific error semantics or trusted masking policy"
                    ],
                ),
                title="BOLA Inconclusive (Uncorroborated Authorization Masking Semantics)",
                explanation=(
                    "Control probe returned HTTP 404 matching Scenario D, but responses lack trusted application-specific "
                    "error semantics (e.g. domain resource-not-found error codes) and no trusted target authorization-masking "
                    "policy was configured. Superficial status code and JSON key matches cannot independently establish authorization denial."
                ),
                is_vulnerable=False,
                scenario_results=scenario_results,
            )

        return True, None

    def verify_candidate(
        self,
        candidate: CandidateEndpoint,
        target_url_a: str,
        user_a_identifier: str,
        target_url_b: Optional[str] = None,
        user_b_identifier: Optional[str] = None,
        resource_a_identifier: Optional[str] = None,
        resource_b_identifier: Optional[str] = None,
        user_b_validation_url: Optional[str] = None,
        expected_user_b_identifier: Optional[str] = None,
        expected_user_b_claims: Optional[Dict[str, str]] = None,
        expected_claim_type: str = "id",
        expected_access_policy: AccessPolicy = AccessPolicy.UNKNOWN,
        endpoint_resource_mapping: Optional[Union[str, Dict[str, Any]]] = None,
        authorization_masking_policy: Optional[Union[TargetAuthorizationPolicy, Dict[str, Any], bool]] = None,
        nonexistent_resource_url: Optional[str] = None,
    ) -> BOLAVerificationResult:
        """
        Executes the 4-way differential verification protocol for a candidate endpoint.

        Parameters:
            candidate: CandidateEndpoint being evaluated.
            target_url_a: Primary resource URL accessed with User A's session.
            user_a_identifier: Primary resource owner identifier (User A).
            target_url_b: Secondary resource URL accessed with User B's session for 4-way reverse control.
            user_b_identifier: Secondary tenant identifier (User B).
            resource_a_identifier: Explicit Resource A identifier. Required for 4-way corroboration.
            resource_b_identifier: Explicit Resource B identifier. Required for 4-way corroboration.
            user_b_validation_url: Safe validation endpoint to independently establish User B's session.
            expected_user_b_identifier: Expected User B identifier used for session and ownership validation when claims are not supplied.
            expected_user_b_claims: Explicit category-to-claim mapping for User B.
            expected_claim_type: Category of claim expected (e.g. 'id', 'user_id', 'username'). Defaults to 'id'.
            expected_access_policy: Access policy classification (PUBLIC, PRIVATE, UNKNOWN).
            endpoint_resource_mapping: Documented mapping indicating target resource segment in URL path.
            authorization_masking_policy: Set to True if application intentionally masks private resources with HTTP 404.
            nonexistent_resource_url: URL of a known nonexistent resource used as a control probe to verify 404 masking behavior.
        """
        method = candidate.method.upper()

        # Resolve Resource A identifier using strict URL resource mapping rules
        res_a_id, err_a = resolve_url_resource_identifier(
            target_url_a,
            endpoint_mapping=endpoint_resource_mapping,
            explicit_identifier=resource_a_identifier,
        )
        if err_a:
            if target_url_b:
                return BOLAVerificationResult(
                    candidate_id=candidate.candidate_id,
                    target_url=sanitize_url(target_url_a),
                    method=method,
                    outcome=BOLAOutcome.INCONCLUSIVE,
                    confidence=ConfidenceAssessment(
                        score=0.25,
                        level=ConfidenceLevel.LOW,
                        signals=[],
                        deductions=[f"Resource A identifier resolution failed: {err_a}"],
                    ),
                    title="BOLA Inconclusive (Resource A Identifier Missing)",
                    explanation=f"Scenario C reverse control aborted: cannot determine Resource A identifier for URL '{target_url_a}': {err_a}. Full four-way confirmation requires independently established and distinct resource identifiers.",
                    is_vulnerable=False,
                )
            return BOLAVerificationResult(
                candidate_id=candidate.candidate_id,
                target_url=sanitize_url(target_url_a),
                method=method,
                outcome=BOLAOutcome.INCONCLUSIVE,
                confidence=ConfidenceAssessment(
                    score=0.25,
                    level=ConfidenceLevel.LOW,
                    signals=[],
                    deductions=[f"Resource A identifier resolution failed: {err_a}"],
                ),
                title="BOLA Inconclusive (Ambiguous URL Resource Mapping)",
                explanation=f"Cannot determine target resource identifier for URL '{target_url_a}': {err_a}. Trusted endpoint mapping or explicit resource identifier is required.",
                is_vulnerable=False,
            )
        resource_a_identifier = res_a_id

        # Resolve Resource B identifier if target_url_b is provided
        if target_url_b:
            res_b_id, err_b = resolve_url_resource_identifier(
                target_url_b,
                endpoint_mapping=endpoint_resource_mapping,
                explicit_identifier=resource_b_identifier,
            )
            if err_b:
                return BOLAVerificationResult(
                    candidate_id=candidate.candidate_id,
                    target_url=sanitize_url(target_url_a),
                    method=method,
                    outcome=BOLAOutcome.INCONCLUSIVE,
                    confidence=ConfidenceAssessment(
                        score=0.25,
                        level=ConfidenceLevel.LOW,
                        signals=[],
                        deductions=[f"Resource B identifier resolution failed: {err_b}"],
                    ),
                    title="BOLA Inconclusive (Resource B Identifier Missing)",
                    explanation=f"Scenario C reverse control aborted: cannot determine Resource B identifier for URL '{target_url_b}': {err_b}. Full four-way confirmation requires independently established and distinct resource identifiers.",
                    is_vulnerable=False,
                )
            resource_b_identifier = res_b_id

        # Validate required resource identifiers up-front when 4-way reverse control is configured
        if target_url_b:
            if not resource_a_identifier or not str(resource_a_identifier).strip():
                return BOLAVerificationResult(
                    candidate_id=candidate.candidate_id,
                    target_url=sanitize_url(target_url_a),
                    method=method,
                    outcome=BOLAOutcome.INCONCLUSIVE,
                    confidence=ConfidenceAssessment(
                        score=0.35,
                        level=ConfidenceLevel.LOW,
                        signals=[],
                        deductions=["Resource A identifier missing; full four-way confirmation requires independently established resource identifiers"],
                    ),
                    title="BOLA Inconclusive (Resource A Identifier Missing)",
                    explanation="Scenario C reverse control aborted because Resource A identifier is missing or empty. Full four-way confirmation requires independently established and distinct resource identifiers.",
                    is_vulnerable=False,
                )

            if not resource_b_identifier or not str(resource_b_identifier).strip():
                return BOLAVerificationResult(
                    candidate_id=candidate.candidate_id,
                    target_url=sanitize_url(target_url_a),
                    method=method,
                    outcome=BOLAOutcome.INCONCLUSIVE,
                    confidence=ConfidenceAssessment(
                        score=0.35,
                        level=ConfidenceLevel.LOW,
                        signals=[],
                        deductions=["Resource B identifier missing; full four-way confirmation requires independently established resource identifiers"],
                    ),
                    title="BOLA Inconclusive (Resource B Identifier Missing)",
                    explanation="Scenario C reverse control aborted because Resource B identifier is missing or empty. Full four-way confirmation requires independently established and distinct resource identifiers.",
                    is_vulnerable=False,
                )

        # 1. State-modifying Safety Check (Requirement 7)
        is_side_effecting, reason = is_potentially_side_effecting(method, target_url_a)
        if is_side_effecting and not self.allow_state_modification:
            return BOLAVerificationResult(
                candidate_id=candidate.candidate_id,
                target_url=target_url_a,
                method=method,
                outcome=BOLAOutcome.INCONCLUSIVE,
                confidence=ConfidenceAssessment(
                    score=0.0,
                    level=ConfidenceLevel.LOW,
                    signals=[],
                    deductions=[f"Safety guardrail blocked execution: {reason}"],
                ),
                title="BOLA Verification Skipped (Side-Effecting Guardrail)",
                explanation=f"Operation was not executed because it is potentially state-modifying ({reason}) and safety guardrail allow_state_modification is disabled.",
                is_vulnerable=False,
            )

        # 2. Check if secondary identity is configured
        has_secondary = self.auth_manager.is_identity_configured(IDENTITY_SECONDARY)
        if not has_secondary:
            # Single-identity baseline check
            res_a = self._execute_request(IDENTITY_PRIMARY, method, target_url_a)
            res_a.scenario = VerificationScenario.SCENARIO_A

            return BOLAVerificationResult(
                candidate_id=candidate.candidate_id,
                target_url=target_url_a,
                method=method,
                outcome=BOLAOutcome.SINGLE_IDENTITY_UNVERIFIED,
                confidence=ConfidenceAssessment(
                    score=0.30,
                    level=ConfidenceLevel.LOW,
                    signals=["Scenario A established single-identity baseline (+0.30)"],
                    deductions=["Secondary credentials not configured; cross-user verification cannot be performed"],
                ),
                title="BOLA Unverified (Single Identity Only)",
                explanation="Two-identity verification was not performed because secondary credentials were not configured.",
                is_vulnerable=False,
                scenario_results={"scenario_a": res_a},
                reproduction_curl=build_sanitized_curl(method, target_url_a),
            )

        # Pre-execution Session Isolation Check between primary and secondary
        session_a = self.auth_manager.get_session(IDENTITY_PRIMARY, auto_authenticate=True)
        session_b = self.auth_manager.get_session(IDENTITY_SECONDARY, auto_authenticate=True)
        is_isolated, isolation_reason = check_session_isolation(session_a, session_b)
        if not is_isolated:
            return BOLAVerificationResult(
                candidate_id=candidate.candidate_id,
                target_url=target_url_a,
                method=method,
                outcome=BOLAOutcome.INCONCLUSIVE,
                confidence=ConfidenceAssessment(
                    score=0.20,
                    level=ConfidenceLevel.LOW,
                    signals=[],
                    deductions=[isolation_reason],
                ),
                title="BOLA Inconclusive (Session Isolation Violation)",
                explanation=f"Verification aborted because User A and User B sessions share mutable state or credentials ({isolation_reason}).",
                is_vulnerable=False,
                scenario_results={},
            )

        # 3. Step 1: Scenario A (Owner Control)
        res_a = self._execute_request(IDENTITY_PRIMARY, method, target_url_a)
        res_a.scenario = VerificationScenario.SCENARIO_A

        # Evaluate Scenario A baseline
        if res_a.error or res_a.status_code == 0:
            return BOLAVerificationResult(
                candidate_id=candidate.candidate_id,
                target_url=sanitize_url(target_url_a),
                method=method,
                outcome=BOLAOutcome.INCONCLUSIVE,
                confidence=ConfidenceAssessment(
                    score=0.0,
                    level=ConfidenceLevel.LOW,
                    signals=[],
                    deductions=[f"Scenario A network or connection failure: {res_a.error or 'Status 0'}"],
                ),
                title="BOLA Inconclusive (Network Error on Baseline)",
                explanation=f"Scenario A baseline request encountered a network or connection error ({res_a.error or 'no response'}). Cannot establish baseline.",
                is_vulnerable=False,
                scenario_results={"scenario_a": res_a},
            )

        if res_a.status_code >= 500:
            return BOLAVerificationResult(
                candidate_id=candidate.candidate_id,
                target_url=sanitize_url(target_url_a),
                method=method,
                outcome=BOLAOutcome.INCONCLUSIVE,
                confidence=ConfidenceAssessment(
                    score=0.0,
                    level=ConfidenceLevel.LOW,
                    signals=[],
                    deductions=[f"Scenario A target server returned HTTP {res_a.status_code} server error"],
                ),
                title="BOLA Inconclusive (Server Error on Baseline)",
                explanation=f"Resource owner (User A) encountered server error HTTP {res_a.status_code}. Server errors indicate upstream instability and cannot be interpreted as authorization decisions.",
                is_vulnerable=False,
                scenario_results={"scenario_a": res_a},
            )

        if res_a.is_redirect or res_a.status_code in (301, 302, 303, 307, 308):
            return BOLAVerificationResult(
                candidate_id=candidate.candidate_id,
                target_url=sanitize_url(target_url_a),
                method=method,
                outcome=BOLAOutcome.INCONCLUSIVE,
                confidence=ConfidenceAssessment(
                    score=0.0,
                    level=ConfidenceLevel.LOW,
                    signals=[],
                    deductions=[f"Scenario A baseline request returned unexpected redirect HTTP {res_a.status_code}"],
                ),
                title="BOLA Inconclusive (Unexpected Redirect on Baseline)",
                explanation=f"Resource owner (User A) encountered an unexpected or ambiguous redirect (status {res_a.status_code} to '{res_a.redirect_location or 'unknown'}'). Cannot establish baseline on ambiguous redirect.",
                is_vulnerable=False,
                scenario_results={"scenario_a": res_a},
            )

        if res_a.status_code in (401, 403):
            return BOLAVerificationResult(
                candidate_id=candidate.candidate_id,
                target_url=sanitize_url(target_url_a),
                method=method,
                outcome=BOLAOutcome.BASELINE_FAILED,
                confidence=ConfidenceAssessment(
                    score=0.0,
                    level=ConfidenceLevel.LOW,
                    signals=[],
                    deductions=[f"Scenario A returned HTTP {res_a.status_code} authorization denial for owner"],
                ),
                title="BOLA Baseline Verification Failed (Authorization Denial)",
                explanation=f"Resource owner (User A) was denied access to their own resource (status {res_a.status_code}). Baseline access failure, not BOLA.",
                is_vulnerable=False,
                scenario_results={"scenario_a": res_a},
            )

        if res_a.status_code in (404, 410):
            return BOLAVerificationResult(
                candidate_id=candidate.candidate_id,
                target_url=sanitize_url(target_url_a),
                method=method,
                outcome=BOLAOutcome.BASELINE_FAILED,
                confidence=ConfidenceAssessment(
                    score=0.0,
                    level=ConfidenceLevel.LOW,
                    signals=[],
                    deductions=[f"Scenario A returned HTTP {res_a.status_code} (resource does not exist or has been removed)"],
                ),
                title="BOLA Baseline Verification Failed (Resource Not Found)",
                explanation=f"Target resource does not exist or was removed for User A (status {res_a.status_code}). Cannot establish baseline.",
                is_vulnerable=False,
                scenario_results={"scenario_a": res_a},
            )

        if res_a.status_code != 200:
            return BOLAVerificationResult(
                candidate_id=candidate.candidate_id,
                target_url=sanitize_url(target_url_a),
                method=method,
                outcome=BOLAOutcome.INCONCLUSIVE,
                confidence=ConfidenceAssessment(
                    score=0.0,
                    level=ConfidenceLevel.LOW,
                    signals=[],
                    deductions=[f"Scenario A baseline request returned unexpected status HTTP {res_a.status_code}"],
                ),
                title="BOLA Inconclusive (Unexpected Status on Baseline)",
                explanation=f"Resource owner (User A) received unexpected non-200 status {res_a.status_code}. Do not classify infrastructure or upstream failures as definitive baseline failures.",
                is_vulnerable=False,
                scenario_results={"scenario_a": res_a},
            )

        is_soft_err_a, msg_a = is_soft_404_or_error(res_a.status_code, res_a.body_sample or "")
        if is_soft_err_a:
            return BOLAVerificationResult(
                candidate_id=candidate.candidate_id,
                target_url=target_url_a,
                method=method,
                outcome=BOLAOutcome.BASELINE_FAILED,
                confidence=ConfidenceAssessment(
                    score=0.0,
                    level=ConfidenceLevel.LOW,
                    signals=[],
                    deductions=[f"Scenario A returned non-meaningful or error data: {msg_a}"],
                ),
                title="BOLA Baseline Empty or Error Payload",
                explanation=f"Resource owner received a soft-404 or empty response ({msg_a}). Cannot establish baseline.",
                is_vulnerable=False,
                scenario_results={"scenario_a": res_a},
            )

        # Check ownership evidence in Scenario A: User A must own Resource A (unless explicitly configured as PUBLIC)
        has_owner_a_in_a = check_ownership_evidence(res_a.body_sample or "", user_a_identifier)
        if not has_owner_a_in_a and expected_access_policy != AccessPolicy.PUBLIC:
            return BOLAVerificationResult(
                candidate_id=candidate.candidate_id,
                target_url=target_url_a,
                method=method,
                outcome=BOLAOutcome.INCONCLUSIVE,
                confidence=ConfidenceAssessment(
                    score=0.25,
                    level=ConfidenceLevel.LOW,
                    signals=["Scenario A returned 200 OK"],
                    deductions=[f"Scenario A response lacks ownership evidence proving User A owns Resource A ('{user_a_identifier}' not found in payload)"],
                ),
                title="BOLA Inconclusive (Owner Ownership Evidence Missing)",
                explanation=f"Scenario A returned HTTP 200, but response payload lacks ownership evidence proving User A ('{user_a_identifier}') owns the resource. If ownership cannot be established, cross-user verification cannot proceed.",
                is_vulnerable=False,
                scenario_results={"scenario_a": res_a},
            )

        # Check resource identity in Scenario A: payload must contain Resource A identifier
        if resource_a_identifier:
            has_id_a_in_a = contains_resource_identifier(res_a.body_sample or "", resource_a_identifier)
            if not has_id_a_in_a:
                return BOLAVerificationResult(
                    candidate_id=candidate.candidate_id,
                    target_url=sanitize_url(target_url_a),
                    method=method,
                    outcome=BOLAOutcome.INCONCLUSIVE,
                    confidence=ConfidenceAssessment(
                        score=0.25,
                        level=ConfidenceLevel.LOW,
                        signals=["Scenario A returned 200 OK"],
                        deductions=[f"Scenario A response lacks Resource A identifier ('{resource_a_identifier}' not found in structured payload)"],
                    ),
                    title="BOLA Inconclusive (Resource A Identifier Missing in Scenario A Response)",
                    explanation=f"Scenario A returned HTTP 200, but response payload does not contain the target Resource A identifier '{resource_a_identifier}'. Structured response must match the target resource identifier to establish baseline.",
                    is_vulnerable=False,
                    scenario_results={"scenario_a": res_a},
                )

        # Check that Scenario A returns substantive business data
        is_substantive_a, sub_reason_a = has_substantive_business_data(res_a.body_sample or "")
        if not is_substantive_a:
            return BOLAVerificationResult(
                candidate_id=candidate.candidate_id,
                target_url=target_url_a,
                method=method,
                outcome=BOLAOutcome.BASELINE_FAILED,
                confidence=ConfidenceAssessment(
                    score=0.0,
                    level=ConfidenceLevel.LOW,
                    signals=[],
                    deductions=[f"Scenario A returned non-substantive payload: {sub_reason_a}"],
                ),
                title="BOLA Baseline Insufficient Business Data",
                explanation=f"Scenario A returned HTTP 200, but payload lacks substantive business data ({sub_reason_a}). Cannot establish baseline.",
                is_vulnerable=False,
                scenario_results={"scenario_a": res_a},
            )

        # 4. Step 2: Scenario B (Cross-User Access Test)
        res_b = self._execute_request(IDENTITY_SECONDARY, method, target_url_a)
        res_b.scenario = VerificationScenario.SCENARIO_B

        # Validate secondary identity authentication status
        # Failed or expired secondary authentication cannot be mistaken for cross-user authorization
        st_b = self.auth_manager.get_state(IDENTITY_SECONDARY)
        if st_b.outcome not in (AuthOutcome.CONFIRMED, AuthOutcome.PROBABLE):
            return BOLAVerificationResult(
                candidate_id=candidate.candidate_id,
                target_url=target_url_a,
                method=method,
                outcome=BOLAOutcome.INCONCLUSIVE,
                confidence=ConfidenceAssessment(
                    score=0.20,
                    level=ConfidenceLevel.LOW,
                    signals=["Scenario A verified owner access"],
                    deductions=[f"Secondary identity (User B) authentication failed or invalid: {st_b.outcome.value}"],
                ),
                title="BOLA Inconclusive (Secondary Identity Authentication Invalid)",
                explanation=f"Secondary identity (User B) is not validly authenticated ({st_b.outcome.value}: {st_b.detail}). Failed or expired authentication cannot be mistaken for cross-user authorization.",
                is_vulnerable=False,
                scenario_results={"scenario_a": res_a, "scenario_b": res_b},
            )

        # Check for server or network errors on Scenario B
        is_5xx_or_err = res_b.status_code >= 500 or bool(res_b.error)
        if is_5xx_or_err:
            return BOLAVerificationResult(
                candidate_id=candidate.candidate_id,
                target_url=target_url_a,
                method=method,
                outcome=BOLAOutcome.INCONCLUSIVE,
                confidence=ConfidenceAssessment(
                    score=0.20,
                    level=ConfidenceLevel.LOW,
                    signals=["Scenario A established baseline"],
                    deductions=[f"Scenario B returned server or gateway error: status {res_b.status_code} ({res_b.error or 'server error'})"],
                ),
                title="BOLA Inconclusive (Server Error on Scenario B)",
                explanation=f"Target server returned status {res_b.status_code} on Scenario B. Verification cannot conclude without a definitive application response.",
                is_vulnerable=False,
                scenario_results={"scenario_a": res_a, "scenario_b": res_b},
            )

        # Check Cache Interference on Scenario B (Requirement 3)
        cache_interf_b, cache_reasons_b = inspect_cache_interference(res_b.response_headers)

        # Check if Scenario B was rejected (401, 403, or Auth Challenge Redirect)
        is_denied = res_b.status_code in (401, 403)
        if not is_denied and res_b.is_redirect and res_b.redirect_location:
            is_denied = is_auth_challenge_redirect(res_b.status_code, res_b.redirect_location)

        is_404 = res_b.status_code == 404

        if is_denied:
            confidence = calculate_confidence(
                outcome=BOLAOutcome.AUTHORIZED,
                scenario_a=res_a,
                scenario_b=res_b,
                scenario_c=None,
                scenario_d=None,
                has_id_a_in_b=False,
                similarity_a_b=0.0,
                cache_interference=CacheInterference.NONE,
                has_owner_a_in_b=False,
            )
            scenario_results: Dict[str, ScenarioExecutionResult] = {"scenario_a": res_a, "scenario_b": res_b}
            # If Resource B is configured, optionally verify Scenario C as proof of active session
            if target_url_b and user_b_identifier:
                res_c_denied = self._execute_request(IDENTITY_SECONDARY, method, target_url_b)
                res_c_denied.scenario = VerificationScenario.SCENARIO_C
                scenario_results["scenario_c"] = res_c_denied

            title = (
                "Object-Level Access Control Properly Enforced (403 Forbidden)"
                if res_b.status_code == 403
                else "Authentication Challenge Issued (Authorized)"
            )
            explanation = (
                f"Target server correctly rejected unauthorized cross-user access from User B with explicit 403 Forbidden."
                if res_b.status_code == 403
                else f"Target server challenged unauthorized cross-user access with authentication challenge (status {res_b.status_code})."
            )

            return BOLAVerificationResult(
                candidate_id=candidate.candidate_id,
                target_url=target_url_a,
                method=method,
                outcome=BOLAOutcome.AUTHORIZED,
                confidence=confidence,
                title=title,
                explanation=explanation,
                is_vulnerable=False,
                scenario_results=scenario_results,
            )

        if is_404:
            # Check for ambiguous framework/gateway routing errors in the 404 payload
            if is_routing_error(res_b.body_sample or ""):
                scenario_results = {"scenario_a": res_a, "scenario_b": res_b}
                return BOLAVerificationResult(
                    candidate_id=candidate.candidate_id,
                    target_url=target_url_a,
                    method=method,
                    outcome=BOLAOutcome.INCONCLUSIVE,
                    confidence=ConfidenceAssessment(
                        score=0.20,
                        level=ConfidenceLevel.LOW,
                        signals=["Scenario A confirmed Resource A exists"],
                        deductions=["Scenario B 404 response matches generic gateway or framework routing error"],
                    ),
                    title="BOLA Inconclusive (Ambiguous Routing Error on Scenario B)",
                    explanation="Scenario B returned 404 with generic routing or gateway error text (e.g. proxy or framework routing failure). Cannot distinguish route misconfiguration from access control.",
                    is_vulnerable=False,
                    scenario_results=scenario_results,
                )

            # Check if resource existence was independently established in Scenario A
            resource_existence_established = (
                res_a.status_code == 200
                and not res_a.error
                and has_owner_a_in_a
                and is_substantive_a
            )
            scenario_results = {"scenario_a": res_a, "scenario_b": res_b}
            if target_url_b and user_b_identifier:
                res_c_404 = self._execute_request(IDENTITY_SECONDARY, method, target_url_b)
                res_c_404.scenario = VerificationScenario.SCENARIO_C
                scenario_results["scenario_c"] = res_c_404

            if resource_existence_established:
                # 404 conceals existence of an established resource (safe IDOR enumeration defense)
                return BOLAVerificationResult(
                    candidate_id=candidate.candidate_id,
                    target_url=target_url_a,
                    method=method,
                    outcome=BOLAOutcome.RESOURCE_EXISTENCE_CONCEALED,
                    confidence=ConfidenceAssessment(
                        score=0.85,
                        level=ConfidenceLevel.HIGH,
                        signals=[
                            "Scenario A confirmed Resource A exists and is owned by User A",
                            "Scenario B returned 404 Not Found to unauthorized caller (safe enumeration masking)",
                        ],
                        deductions=[],
                    ),
                    title="Resource Existence Concealed via 404",
                    explanation="Resource A existence was confirmed in Scenario A. Target server returned 404 Not Found to User B, safely concealing resource existence to prevent IDOR enumeration. Authorization enforcement is concealed rather than explicitly demonstrated.",
                    is_vulnerable=False,
                    scenario_results=scenario_results,
                )
            else:
                # 404 on an unverified or ambiguous resource does NOT demonstrate access control
                return BOLAVerificationResult(
                    candidate_id=candidate.candidate_id,
                    target_url=target_url_a,
                    method=method,
                    outcome=BOLAOutcome.ACCESS_NOT_DEMONSTRATED,
                    confidence=ConfidenceAssessment(
                        score=0.20,
                        level=ConfidenceLevel.LOW,
                        signals=[],
                        deductions=["Resource A existence was not independently confirmed; 404 does not prove authorization enforcement"],
                    ),
                    title="BOLA Access Not Demonstrated (404 on Unverified Resource)",
                    explanation="Target server returned 404 Not Found to User B, but Resource A existence could not be independently confirmed. A 404 on a non-existent or ambiguous resource does not demonstrate access control enforcement.",
                    is_vulnerable=False,
                    scenario_results=scenario_results,
                )

        # If Scenario B returned 200 OK, check for Soft-404 or Error (Finding 2)
        # An empty or generic 200 response must NEVER be treated as proof that authorization is enforced.
        # It must fail closed as INCONCLUSIVE unless safe tenant scoping is independently established or definitive denial received.
        is_soft_err_b, msg_b = is_soft_404_or_error(res_b.status_code, res_b.body_sample or "")
        if is_soft_err_b:
            return BOLAVerificationResult(
                candidate_id=candidate.candidate_id,
                target_url=target_url_a,
                method=method,
                outcome=BOLAOutcome.INCONCLUSIVE,
                confidence=ConfidenceAssessment(
                    score=0.20,
                    level=ConfidenceLevel.LOW,
                    signals=[f"Scenario B returned 200 OK with soft-404/error signature: {msg_b}"],
                    deductions=[
                        f"Scenario B returned generic empty or error payload: {msg_b}",
                        "Empty or generic 200 response cannot be treated as proof of authorization enforcement",
                    ],
                ),
                title="BOLA Inconclusive (Soft-404 / Generic Error Payload on Scenario B)",
                explanation=f"User B request returned 200 OK but payload is empty, generic, or an application error ({msg_b}). An empty or error response cannot prove access control enforcement without a definitive authorization decision.",
                is_vulnerable=False,
                scenario_results={"scenario_a": res_a, "scenario_b": res_b},
            )

        # Check for Silent Tenant Scoping (Requirement 5)
        is_silent_scoping = detect_silent_tenant_scoping(
            body_accessor=res_b.body_sample or "",
            user_a_identifier=user_a_identifier,
            user_b_identifier=user_b_identifier,
        )
        if is_silent_scoping:
            confidence = calculate_confidence(
                outcome=BOLAOutcome.AUTHORIZED,
                scenario_a=res_a,
                scenario_b=res_b,
                scenario_c=None,
                scenario_d=None,
                has_id_a_in_b=False,
                similarity_a_b=0.0,
                cache_interference=CacheInterference.NONE,
                has_owner_a_in_b=False,
            )
            scenario_results = {"scenario_a": res_a, "scenario_b": res_b}
            if target_url_b and user_b_identifier:
                res_c_scope = self._execute_request(IDENTITY_SECONDARY, method, target_url_b)
                res_c_scope.scenario = VerificationScenario.SCENARIO_C
                scenario_results["scenario_c"] = res_c_scope

            return BOLAVerificationResult(
                candidate_id=candidate.candidate_id,
                target_url=target_url_a,
                method=method,
                outcome=BOLAOutcome.AUTHORIZED,
                confidence=confidence,
                title="Server-Side Tenant Scoping Enforced (Authorized)",
                explanation="The target server safely enforced session-based tenant scoping, ignoring the requested resource ID and returning User B's active session record.",
                is_vulnerable=False,
                scenario_results=scenario_results,
            )

        # Check that Scenario B returned substantive business data (not a reflected stub)
        is_substantive_b, sub_reason_b = has_substantive_business_data(res_b.body_sample or "")
        if not is_substantive_b:
            return BOLAVerificationResult(
                candidate_id=candidate.candidate_id,
                target_url=target_url_a,
                method=method,
                outcome=BOLAOutcome.INCONCLUSIVE,
                confidence=ConfidenceAssessment(
                    score=0.30,
                    level=ConfidenceLevel.LOW,
                    signals=["Scenario A succeeded", "Scenario B returned 200 OK"],
                    deductions=[f"Scenario B returned insufficient business data: {sub_reason_b}"],
                ),
                title="BOLA Inconclusive (Insufficient Protected Business Data)",
                explanation=f"User B request returned 200 OK, but payload lacks substantive protected business data ({sub_reason_b}). A reflected identifier or minimal stub cannot independently establish BOLA.",
                is_vulnerable=False,
                scenario_results={"scenario_a": res_a, "scenario_b": res_b},
            )

        # Compute semantic similarity between Response A and Response B
        similarity_a_b, exact_match = compute_semantic_similarity(
            res_a.body_sample or "",
            res_b.body_sample or "",
        )

        # Independent Resource Identity and Ownership Evidence evaluation
        has_id_a_in_b = contains_resource_identifier(res_b.body_sample or "", resource_a_identifier)
        has_owner_a_in_b = check_ownership_evidence(res_b.body_sample or "", user_a_identifier)

        # Check Cache Interference: If responses are identical and cache headers indicate HIT (Requirement 3)
        if cache_interf_b == CacheInterference.SUSPECTED_CACHE_HIT and similarity_a_b >= 0.85:
            return BOLAVerificationResult(
                candidate_id=candidate.candidate_id,
                target_url=target_url_a,
                method=method,
                outcome=BOLAOutcome.INCONCLUSIVE,
                confidence=ConfidenceAssessment(
                    score=0.20,
                    level=ConfidenceLevel.LOW,
                    signals=["Scenario A succeeded", "Scenario B matched Scenario A"],
                    deductions=[f"Unresolved cache interference: {'; '.join(cache_reasons_b)}"],
                ),
                title="BOLA Inconclusive (Suspected Cache Interference)",
                explanation=f"Response for User B matched User A but proxy/CDN cache headers indicate a cache hit ({'; '.join(cache_reasons_b)}). Cannot guarantee origin authorization bypass.",
                is_vulnerable=False,
                scenario_results={"scenario_a": res_a, "scenario_b": res_b},
                cache_interference=cache_interf_b,
            )

        # Check Resource Identity Evidence:
        if not has_id_a_in_b:
            return BOLAVerificationResult(
                candidate_id=candidate.candidate_id,
                target_url=target_url_a,
                method=method,
                outcome=BOLAOutcome.INCONCLUSIVE,
                confidence=ConfidenceAssessment(
                    score=0.30,
                    level=ConfidenceLevel.LOW,
                    signals=["Scenario A succeeded"],
                    deductions=[f"Scenario B response lacks Resource A identifier '{resource_a_identifier}'"],
                ),
                title="BOLA Inconclusive (Resource Identity Evidence Missing)",
                explanation=f"User B request returned 200 OK, but response lacks Resource A identifier ('{resource_a_identifier}'). Similar JSON structure or schema alone cannot establish BOLA.",
                is_vulnerable=False,
                scenario_results={"scenario_a": res_a, "scenario_b": res_b},
            )

        # Check Ownership Evidence (for private resources):
        if not has_owner_a_in_b and expected_access_policy != AccessPolicy.PUBLIC:
            return BOLAVerificationResult(
                candidate_id=candidate.candidate_id,
                target_url=target_url_a,
                method=method,
                outcome=BOLAOutcome.INCONCLUSIVE,
                confidence=ConfidenceAssessment(
                    score=0.35,
                    level=ConfidenceLevel.LOW,
                    signals=["Scenario A succeeded", "Scenario B contained Resource A identifier"],
                    deductions=[f"Scenario B response lacks User A ownership evidence ('{user_a_identifier}')"],
                ),
                title="BOLA Inconclusive (Resource Ownership Evidence Missing)",
                explanation=f"User B request returned 200 OK with Resource A identifier, but response lacks verified ownership evidence tying the resource to User A ('{user_a_identifier}'). If ownership cannot be established, cross-user exposure cannot be confirmed.",
                is_vulnerable=False,
                scenario_results={"scenario_a": res_a, "scenario_b": res_b},
            )

        # Check Semantic Similarity:
        if similarity_a_b < 0.85:
            return BOLAVerificationResult(
                candidate_id=candidate.candidate_id,
                target_url=target_url_a,
                method=method,
                outcome=BOLAOutcome.INCONCLUSIVE,
                confidence=ConfidenceAssessment(
                    score=0.35,
                    level=ConfidenceLevel.LOW,
                    signals=["Scenario A succeeded"],
                    deductions=[f"Low semantic similarity between Response A and Response B ({similarity_a_b:.2f})"],
                ),
                title="BOLA Inconclusive (Low Semantic Similarity)",
                explanation=f"User B request returned 200 OK, but response semantic similarity to Resource A is low ({similarity_a_b:.2f}).",
                is_vulnerable=False,
                scenario_results={"scenario_a": res_a, "scenario_b": res_b},
            )

        # 5. Step 3: Scenario D (Unauthenticated Control)
        res_d = self._execute_request(IDENTITY_ANONYMOUS, method, target_url_a)
        res_d.scenario = VerificationScenario.SCENARIO_D

        # Check Cache Interference on Scenario D (Requirement 2)
        cache_interf_d, cache_reasons_d = inspect_cache_interference(res_d.response_headers)

        # Check if unauthenticated access also succeeded with identical data
        if res_d.status_code == 200 and not res_d.error:
            # 1. Cache hit on anonymous request indicates proxy cache, not public origin
            if cache_interf_d == CacheInterference.SUSPECTED_CACHE_HIT:
                return BOLAVerificationResult(
                    candidate_id=candidate.candidate_id,
                    target_url=target_url_a,
                    method=method,
                    outcome=BOLAOutcome.INCONCLUSIVE,
                    confidence=ConfidenceAssessment(
                        score=0.35,
                        level=ConfidenceLevel.LOW,
                        signals=["Scenario A succeeded", "Scenario B returned 200 OK"],
                        deductions=[f"Suspected cache hit on anonymous response: {'; '.join(cache_reasons_d)}"],
                    ),
                    title="BOLA Inconclusive (Suspected Cache Hit on Anonymous Request)",
                    explanation=f"Anonymous request returned 200 OK, but cache headers indicate a cache hit ({'; '.join(cache_reasons_d)}). Cannot confirm origin authorization bypass.",
                    is_vulnerable=False,
                    scenario_results={"scenario_a": res_a, "scenario_b": res_b, "scenario_d": res_d},
                    cache_interference=cache_interf_d,
                )

            # 2. Check substantive business data on Response D
            is_substantive_d, sub_reason_d = has_substantive_business_data(res_d.body_sample or "")
            if not is_substantive_d:
                return BOLAVerificationResult(
                    candidate_id=candidate.candidate_id,
                    target_url=target_url_a,
                    method=method,
                    outcome=BOLAOutcome.INCONCLUSIVE,
                    confidence=ConfidenceAssessment(
                        score=0.35,
                        level=ConfidenceLevel.LOW,
                        signals=["Scenario A succeeded", "Scenario B returned 200 OK"],
                        deductions=[f"Anonymous response lacks substantive resource data: {sub_reason_d}"],
                    ),
                    title="BOLA Inconclusive (Anonymous Response Lacks Substantive Resource Data)",
                    explanation=f"Anonymous request returned 200 OK, but payload lacks substantive resource data ({sub_reason_d}). Generic responses or minimal stubs cannot establish PUBLIC_RESOURCE.",
                    is_vulnerable=False,
                    scenario_results={"scenario_a": res_a, "scenario_b": res_b, "scenario_d": res_d},
                )

            # 3. Check Resource Identity Evidence on Response D
            has_id_a_in_d = contains_resource_identifier(res_d.body_sample or "", resource_a_identifier)
            if not has_id_a_in_d:
                return BOLAVerificationResult(
                    candidate_id=candidate.candidate_id,
                    target_url=target_url_a,
                    method=method,
                    outcome=BOLAOutcome.INCONCLUSIVE,
                    confidence=ConfidenceAssessment(
                        score=0.35,
                        level=ConfidenceLevel.LOW,
                        signals=["Scenario A succeeded", "Scenario B returned 200 OK"],
                        deductions=[f"Anonymous response lacks Resource A identifier ('{resource_a_identifier}')"],
                    ),
                    title="BOLA Inconclusive (Anonymous Response Lacks Resource A Identity)",
                    explanation=f"Anonymous request returned 200 OK, but response lacks Resource A identifier ('{resource_a_identifier}'). Similar JSON structure or schema alone cannot establish PUBLIC_RESOURCE.",
                    is_vulnerable=False,
                    scenario_results={"scenario_a": res_a, "scenario_b": res_b, "scenario_d": res_d},
                )

            # 4. Check Ownership Evidence on Response D (for private resources)
            has_owner_a_in_d = check_ownership_evidence(res_d.body_sample or "", user_a_identifier)
            if not has_owner_a_in_d and expected_access_policy != AccessPolicy.PUBLIC:
                return BOLAVerificationResult(
                    candidate_id=candidate.candidate_id,
                    target_url=target_url_a,
                    method=method,
                    outcome=BOLAOutcome.INCONCLUSIVE,
                    confidence=ConfidenceAssessment(
                        score=0.35,
                        level=ConfidenceLevel.LOW,
                        signals=["Scenario A succeeded", "Scenario B returned 200 OK"],
                        deductions=[f"Anonymous response lacks User A ownership evidence ('{user_a_identifier}')"],
                    ),
                    title="BOLA Inconclusive (Anonymous Response Lacks Ownership Evidence)",
                    explanation=f"Anonymous request returned 200 OK with Resource A identifier, but response lacks ownership evidence tying it to User A ('{user_a_identifier}'). Identity is ambiguous.",
                    is_vulnerable=False,
                    scenario_results={"scenario_a": res_a, "scenario_b": res_b, "scenario_d": res_d},
                )

            # 5. Check Semantic Similarity on Response D
            similarity_a_d, _ = compute_semantic_similarity(
                res_a.body_sample or "",
                res_d.body_sample or "",
            )
            if similarity_a_d < 0.85:
                return BOLAVerificationResult(
                    candidate_id=candidate.candidate_id,
                    target_url=target_url_a,
                    method=method,
                    outcome=BOLAOutcome.INCONCLUSIVE,
                    confidence=ConfidenceAssessment(
                        score=0.35,
                        level=ConfidenceLevel.LOW,
                        signals=["Scenario A succeeded", "Scenario B returned 200 OK"],
                        deductions=[f"Anonymous response semantic similarity to Resource A is low ({similarity_a_d:.2f})"],
                    ),
                    title="BOLA Inconclusive (Anonymous Response Semantic Mismatch)",
                    explanation=f"Anonymous request returned 200 OK, but semantic similarity to Resource A is low ({similarity_a_d:.2f}). Identity of public data is ambiguous.",
                    is_vulnerable=False,
                    scenario_results={"scenario_a": res_a, "scenario_b": res_b, "scenario_d": res_d},
                )

            # Access policy evaluation:
            # Under security-first engineering, discovery authentication context alone
            # must NEVER be treated as authoritative policy evidence.
            # Explicit trusted PUBLIC policy -> PUBLIC_RESOURCE
            # Explicit trusted PRIVATE policy -> UNEXPECTED_ANONYMOUS_ACCESS
            # UNKNOWN policy -> INCONCLUSIVE (unclassified anonymous exposure)
            resolved_policy = expected_access_policy

            if resolved_policy == AccessPolicy.PUBLIC:
                confidence = calculate_confidence(
                    outcome=BOLAOutcome.PUBLIC_RESOURCE,
                    scenario_a=res_a,
                    scenario_b=res_b,
                    scenario_c=None,
                    scenario_d=res_d,
                    has_id_a_in_b=has_id_a_in_b,
                    similarity_a_b=similarity_a_b,
                    cache_interference=CacheInterference.NONE,
                    has_owner_a_in_b=has_owner_a_in_b,
                )
                return BOLAVerificationResult(
                    candidate_id=candidate.candidate_id,
                    target_url=target_url_a,
                    method=method,
                    outcome=BOLAOutcome.PUBLIC_RESOURCE,
                    confidence=confidence,
                    title="Explicitly Public Resource (Expected Anonymous Access)",
                    explanation="Endpoint has an explicitly defined trusted PUBLIC access policy. Target server returned matching resource data to unauthenticated callers as intended.",
                    is_vulnerable=False,
                    scenario_results={"scenario_a": res_a, "scenario_b": res_b, "scenario_d": res_d},
                )
            elif resolved_policy == AccessPolicy.PRIVATE:
                confidence = ConfidenceAssessment(
                    score=0.90,
                    level=ConfidenceLevel.HIGH,
                    signals=[
                        "Scenario A confirmed Resource A is a private resource owned by User A",
                        "Scenario B confirmed User B cross-user access",
                        "Scenario D confirmed unauthenticated/anonymous callers can access protected private data",
                        "Configured access policy provenance: explicitly declared PRIVATE",
                    ],
                    deductions=[],
                )
                return BOLAVerificationResult(
                    candidate_id=candidate.candidate_id,
                    target_url=target_url_a,
                    method=method,
                    outcome=BOLAOutcome.UNEXPECTED_ANONYMOUS_ACCESS,
                    confidence=confidence,
                    title="Critical Exposure: Unexpected Anonymous Access to Private Resource",
                    explanation=f"Endpoint is configured with an explicit PRIVATE access policy, but unauthenticated callers retrieved User A's private resource '{user_a_identifier}' with verified identity and ownership evidence. This constitutes a severe broken authentication / unauthenticated data exposure.",
                    is_vulnerable=True,
                    scenario_results={"scenario_a": res_a, "scenario_b": res_b, "scenario_d": res_d},
                    reproduction_curl=build_sanitized_curl(method, target_url_a),
                )
            else:
                # AccessPolicy.UNKNOWN
                return BOLAVerificationResult(
                    candidate_id=candidate.candidate_id,
                    target_url=target_url_a,
                    method=method,
                    outcome=BOLAOutcome.INCONCLUSIVE,
                    confidence=ConfidenceAssessment(
                        score=0.35,
                        level=ConfidenceLevel.LOW,
                        signals=["Scenario A succeeded", "Scenario B returned 200 OK"],
                        deductions=[
                            "Anonymous request retrieved matching resource data, but endpoint access policy is UNKNOWN",
                            "Discovery authentication context alone cannot be treated as authoritative policy evidence",
                        ],
                    ),
                    title="BOLA Inconclusive (Unclassified Anonymous Exposure — Policy Unknown)",
                    explanation="Anonymous request returned matching protected resource data, but endpoint access policy is UNKNOWN. Under security-first engineering, discovery authentication context alone cannot be treated as authoritative policy evidence. Cannot distinguish between an intentionally public resource and an unexpected anonymous data exposure without explicit policy definition.",
                    is_vulnerable=False,
                    scenario_results={"scenario_a": res_a, "scenario_b": res_b, "scenario_d": res_d},
                )

        # Check if Scenario D returned a generic framework or gateway routing error
        if res_d.status_code == 404 and is_routing_error(res_d.body_sample or ""):
            return BOLAVerificationResult(
                candidate_id=candidate.candidate_id,
                target_url=sanitize_url(target_url_a),
                method=method,
                outcome=BOLAOutcome.INCONCLUSIVE,
                confidence=ConfidenceAssessment(
                    score=0.30,
                    level=ConfidenceLevel.LOW,
                    signals=["Scenario A succeeded", "Scenario B returned 200 OK"],
                    deductions=["Scenario D 404 response matches generic gateway or framework routing error"],
                ),
                title="BOLA Inconclusive (Ambiguous Routing Error on Scenario D)",
                explanation="Unauthenticated control (Scenario D) returned 404 with generic routing or gateway error text (e.g. proxy or framework routing failure). Cannot distinguish route failure from authorization-masking denial.",
                is_vulnerable=False,
                scenario_results={"scenario_a": res_a, "scenario_b": res_b, "scenario_d": res_d},
            )

        # Evaluate unauthenticated access denial:
        # An anonymous 404 must NOT independently establish authorization denial.
        # It requires matched authenticated-versus-anonymous evidence for the same resource,
        # verified against a trusted authorization_masking_policy or nonexistent-resource control.
        is_anon_denied = False
        masking_signal = None
        if res_d.status_code in (401, 403):
            is_anon_denied = True
        elif res_d.is_redirect and res_d.redirect_location:
            is_anon_denied = is_auth_challenge_redirect(res_d.status_code, res_d.redirect_location)
        elif res_d.status_code == 404:
            if authorization_masking_policy is not None:
                # Caller-supplied raw boolean cannot independently establish trusted authorization policy
                if isinstance(authorization_masking_policy, bool):
                    return BOLAVerificationResult(
                        candidate_id=candidate.candidate_id,
                        target_url=sanitize_url(target_url_a),
                        method=method,
                        outcome=BOLAOutcome.INCONCLUSIVE,
                        confidence=ConfidenceAssessment(
                            score=0.35,
                            level=ConfidenceLevel.LOW,
                            signals=["Scenario A succeeded", "Scenario B returned 200 OK"],
                            deductions=[
                                "Caller-supplied boolean authorization_masking_policy rejected; policy must originate from trusted, scope-bound configuration",
                            ],
                        ),
                        title="BOLA Inconclusive (Untrusted Authorization Masking Policy)",
                        explanation="Caller supplied a raw boolean authorization_masking_policy without verified provenance or scope binding. Under trust-boundary verification rules, untrusted boolean flags cannot establish authorization masking.",
                        is_vulnerable=False,
                        scenario_results={"scenario_a": res_a, "scenario_b": res_b, "scenario_d": res_d},
                    )

                policy_obj = authorization_masking_policy
                if isinstance(policy_obj, dict):
                    try:
                        policy_obj = TargetAuthorizationPolicy(**policy_obj)
                    except Exception as pe:
                        return BOLAVerificationResult(
                            candidate_id=candidate.candidate_id,
                            target_url=sanitize_url(target_url_a),
                            method=method,
                            outcome=BOLAOutcome.INCONCLUSIVE,
                            confidence=ConfidenceAssessment(
                                score=0.35,
                                level=ConfidenceLevel.LOW,
                                signals=["Scenario A succeeded", "Scenario B returned 200 OK"],
                                deductions=[f"Invalid authorization_masking_policy structure: {pe}"],
                            ),
                            title="BOLA Inconclusive (Untrusted Authorization Masking Policy)",
                            explanation=f"Target authorization policy schema validation failed ({pe}). Cannot establish trusted masking policy.",
                            is_vulnerable=False,
                            scenario_results={"scenario_a": res_a, "scenario_b": res_b, "scenario_d": res_d},
                        )

                if isinstance(policy_obj, TargetAuthorizationPolicy):
                    is_valid_pol, pol_reason = policy_obj.validate_for_candidate(candidate, target_url_a)
                    if not is_valid_pol:
                        return BOLAVerificationResult(
                            candidate_id=candidate.candidate_id,
                            target_url=sanitize_url(target_url_a),
                            method=method,
                            outcome=BOLAOutcome.INCONCLUSIVE,
                            confidence=ConfidenceAssessment(
                                score=0.35,
                                level=ConfidenceLevel.LOW,
                                signals=["Scenario A succeeded", "Scenario B returned 200 OK"],
                                deductions=[f"Target authorization policy rejected: {pol_reason}"],
                            ),
                            title="BOLA Inconclusive (Untrusted Authorization Masking Policy)",
                            explanation=f"Target authorization masking policy failed trust or scope boundary validation ({pol_reason}).",
                            is_vulnerable=False,
                            scenario_results={"scenario_a": res_a, "scenario_b": res_b, "scenario_d": res_d},
                        )
                    is_anon_denied = True
                    masking_signal = f"Target authorization-masking policy verified from '{policy_obj.provenance}' for '{policy_obj.target_domain}'"
                    # If nonexistent_resource_url was also provided, corroborate with the probe
                    if nonexistent_resource_url:
                        is_probe_denied, probe_inconclusive = self._execute_secure_nonexistent_probe(
                            candidate=candidate,
                            target_url_a=target_url_a,
                            method=method,
                            nonexistent_resource_url=nonexistent_resource_url,
                            res_d=res_d,
                            scenario_results={"scenario_a": res_a, "scenario_b": res_b, "scenario_d": res_d},
                            verified_masking_policy=policy_obj,
                        )
                        if probe_inconclusive:
                            return probe_inconclusive
                        is_anon_denied = is_probe_denied
                        masking_signal += " and corroborated by control probe"
                else:
                    return BOLAVerificationResult(
                        candidate_id=candidate.candidate_id,
                        target_url=sanitize_url(target_url_a),
                        method=method,
                        outcome=BOLAOutcome.INCONCLUSIVE,
                        confidence=ConfidenceAssessment(
                            score=0.35,
                            level=ConfidenceLevel.LOW,
                            signals=["Scenario A succeeded", "Scenario B returned 200 OK"],
                            deductions=["Unknown or unsupported authorization_masking_policy type"],
                        ),
                        title="BOLA Inconclusive (Untrusted Authorization Masking Policy)",
                        explanation="Supplied authorization_masking_policy type is unrecognized.",
                        is_vulnerable=False,
                        scenario_results={"scenario_a": res_a, "scenario_b": res_b, "scenario_d": res_d},
                    )
            elif nonexistent_resource_url:
                is_probe_denied, probe_inconclusive = self._execute_secure_nonexistent_probe(
                    candidate=candidate,
                    target_url_a=target_url_a,
                    method=method,
                    nonexistent_resource_url=nonexistent_resource_url,
                    res_d=res_d,
                    scenario_results={"scenario_a": res_a, "scenario_b": res_b, "scenario_d": res_d},
                    verified_masking_policy=None,
                )
                if probe_inconclusive:
                    return probe_inconclusive
                is_anon_denied = is_probe_denied
                masking_signal = "Nonexistent-resource control probe confirmed 404 masking semantics"
            else:
                # Ambiguous application-level 404 without trusted masking policy or nonexistent control probe: fail closed
                return BOLAVerificationResult(
                    candidate_id=candidate.candidate_id,
                    target_url=sanitize_url(target_url_a),
                    method=method,
                    outcome=BOLAOutcome.INCONCLUSIVE,
                    confidence=ConfidenceAssessment(
                        score=0.35,
                        level=ConfidenceLevel.LOW,
                        signals=["Scenario A succeeded", "Scenario B returned 200 OK"],
                        deductions=["Scenario D returned 404 without trusted authorization-masking policy or nonexistent-resource control"],
                    ),
                    title="BOLA Inconclusive (Ambiguous Anonymous 404 Response)",
                    explanation="Unauthenticated control (Scenario D) returned 404, but no trusted authorization-masking policy or nonexistent-resource control was established. An anonymous 404 without verified masking semantics cannot independently establish authorization denial.",
                    is_vulnerable=False,
                    scenario_results={"scenario_a": res_a, "scenario_b": res_b, "scenario_d": res_d},
                )

        if not is_anon_denied:
            return BOLAVerificationResult(
                candidate_id=candidate.candidate_id,
                target_url=target_url_a,
                method=method,
                outcome=BOLAOutcome.INCONCLUSIVE,
                confidence=ConfidenceAssessment(
                    score=0.40,
                    level=ConfidenceLevel.LOW,
                    signals=["Scenario A succeeded", "Scenario B returned 200 OK"],
                    deductions=[f"Scenario D did not return an explicit authorization denial (status {res_d.status_code})"],
                ),
                title="BOLA Inconclusive (Ambiguous Unauthenticated Response)",
                explanation=f"Unauthenticated request did not return a definitive authorization denial (status {res_d.status_code}). Cannot prove resource is private.",
                is_vulnerable=False,
                scenario_results={"scenario_a": res_a, "scenario_b": res_b, "scenario_d": res_d},
            )

        # 6. Step 4: Scenario C (Reverse Owner Control, if Resource B is available)
        res_c: Optional[ScenarioExecutionResult] = None
        has_resource_b = bool(target_url_b)

        if has_resource_b:
            # Full 4-way corroboration requires non-empty resource_a_identifier and resource_b_identifier
            if not resource_a_identifier or not str(resource_a_identifier).strip():
                return BOLAVerificationResult(
                    candidate_id=candidate.candidate_id,
                    target_url=sanitize_url(target_url_a),
                    method=method,
                    outcome=BOLAOutcome.INCONCLUSIVE,
                    confidence=ConfidenceAssessment(
                        score=0.35,
                        level=ConfidenceLevel.LOW,
                        signals=["Scenario A succeeded", "Scenario B returned 200 OK"],
                        deductions=["Resource A identifier missing; full four-way confirmation requires independently established resource identifiers"],
                    ),
                    title="BOLA Inconclusive (Resource A Identifier Missing)",
                    explanation="Scenario C reverse control aborted because Resource A identifier is missing or empty. Full four-way confirmation requires independently established and distinct resource identifiers.",
                    is_vulnerable=False,
                    scenario_results={
                        "scenario_a": res_a,
                        "scenario_b": res_b,
                        "scenario_d": res_d,
                    },
                )

            if not resource_b_identifier or not str(resource_b_identifier).strip():
                return BOLAVerificationResult(
                    candidate_id=candidate.candidate_id,
                    target_url=sanitize_url(target_url_a),
                    method=method,
                    outcome=BOLAOutcome.INCONCLUSIVE,
                    confidence=ConfidenceAssessment(
                        score=0.35,
                        level=ConfidenceLevel.LOW,
                        signals=["Scenario A succeeded", "Scenario B returned 200 OK"],
                        deductions=["Resource B identifier missing; full four-way confirmation requires independently established resource identifiers"],
                    ),
                    title="BOLA Inconclusive (Resource B Identifier Missing)",
                    explanation="Scenario C reverse control aborted because Resource B identifier is missing or empty. Full four-way confirmation requires independently established and distinct resource identifiers.",
                    is_vulnerable=False,
                    scenario_results={
                        "scenario_a": res_a,
                        "scenario_b": res_b,
                        "scenario_d": res_d,
                    },
                )

            # Require Resource B to be distinct from Resource A.
            # URL inequality is NOT proof of resource inequality.
            # Both resource identifiers must be distinct and URLs must not be identical.
            res_a_id_norm = str(resource_a_identifier).strip().lower()
            res_b_id_norm = str(resource_b_identifier).strip().lower()

            if target_url_b == target_url_a or res_a_id_norm == res_b_id_norm:
                return BOLAVerificationResult(
                    candidate_id=candidate.candidate_id,
                    target_url=sanitize_url(target_url_a),
                    method=method,
                    outcome=BOLAOutcome.INCONCLUSIVE,
                    confidence=ConfidenceAssessment(
                        score=0.35,
                        level=ConfidenceLevel.LOW,
                        signals=["Scenario A succeeded", "Scenario B returned 200 OK"],
                        deductions=["Resource B target URL or identifier is identical to Resource A; reverse control requires a distinct resource"],
                    ),
                    title="BOLA Inconclusive (Resource B Identical to Resource A)",
                    explanation="Scenario C reverse control aborted because Resource B target URL or identifier is identical to Resource A. Verification requires distinct resources.",
                    is_vulnerable=False,
                    scenario_results={
                        "scenario_a": res_a,
                        "scenario_b": res_b,
                        "scenario_d": res_d,
                    },
                )

            res_c = self._execute_request(IDENTITY_SECONDARY, method, target_url_b)  # type: ignore[arg-type]
            res_c.scenario = VerificationScenario.SCENARIO_C

            # Validate Scenario C: User B accessing their own Resource B!
            # If Scenario C fails (e.g. 401, 403, 404, or network error):
            if res_c.status_code != 200 or res_c.error:
                return BOLAVerificationResult(
                    candidate_id=candidate.candidate_id,
                    target_url=sanitize_url(target_url_a),
                    method=method,
                    outcome=BOLAOutcome.INCONCLUSIVE,
                    confidence=ConfidenceAssessment(
                        score=0.40,
                        level=ConfidenceLevel.LOW,
                        signals=["Scenario A succeeded", "Scenario B returned Resource A"],
                        deductions=[f"Secondary identity failed reverse control on own Resource B (status {res_c.status_code}, error={res_c.error})"],
                    ),
                    title="BOLA Inconclusive (Secondary Identity Reverse Control Failed)",
                    explanation=f"Secondary identity reverse control failed: User B could not successfully access their own Resource B (status {res_c.status_code}). Secondary session or account is invalid.",
                    is_vulnerable=False,
                    scenario_results={
                        "scenario_a": res_a,
                        "scenario_b": res_b,
                        "scenario_c": res_c,
                        "scenario_d": res_d,
                    },
                )

            # Check soft-404 on Response C
            is_soft_err_c, msg_c = is_soft_404_or_error(res_c.status_code, res_c.body_sample or "")
            if is_soft_err_c:
                return BOLAVerificationResult(
                    candidate_id=candidate.candidate_id,
                    target_url=sanitize_url(target_url_a),
                    method=method,
                    outcome=BOLAOutcome.INCONCLUSIVE,
                    confidence=ConfidenceAssessment(
                        score=0.35,
                        level=ConfidenceLevel.LOW,
                        signals=["Scenario A succeeded", "Scenario B returned Resource A"],
                        deductions=[f"Scenario C returned soft-404 or empty response: {msg_c}"],
                    ),
                    title="BOLA Inconclusive (Resource B Soft-404 or Error Payload)",
                    explanation=f"Scenario C returned a soft-404 or empty response ({msg_c}). Access to Resource B was not established.",
                    is_vulnerable=False,
                    scenario_results={
                        "scenario_a": res_a,
                        "scenario_b": res_b,
                        "scenario_c": res_c,
                        "scenario_d": res_d,
                    },
                )

            # Check substantive business data on Response C
            is_substantive_c, sub_reason_c = has_substantive_business_data(res_c.body_sample or "")
            if not is_substantive_c:
                return BOLAVerificationResult(
                    candidate_id=candidate.candidate_id,
                    target_url=sanitize_url(target_url_a),
                    method=method,
                    outcome=BOLAOutcome.INCONCLUSIVE,
                    confidence=ConfidenceAssessment(
                        score=0.35,
                        level=ConfidenceLevel.LOW,
                        signals=["Scenario A succeeded", "Scenario B returned Resource A"],
                        deductions=[f"Scenario C lacks substantive business data: {sub_reason_c}"],
                    ),
                    title="BOLA Inconclusive (Resource B Insufficient Business Data)",
                    explanation=f"Scenario C response lacks substantive business data ({sub_reason_c}). Cannot establish access to Resource B.",
                    is_vulnerable=False,
                    scenario_results={
                        "scenario_a": res_a,
                        "scenario_b": res_b,
                        "scenario_c": res_c,
                        "scenario_d": res_d,
                    },
                )

            # Reject if Response C unexpectedly contains Resource A identifier (conflicting resource data or URL alias)
            has_id_a_in_c = contains_resource_identifier(res_c.body_sample or "", resource_a_identifier)
            if has_id_a_in_c:
                return BOLAVerificationResult(
                    candidate_id=candidate.candidate_id,
                    target_url=sanitize_url(target_url_a),
                    method=method,
                    outcome=BOLAOutcome.INCONCLUSIVE,
                    confidence=ConfidenceAssessment(
                        score=0.35,
                        level=ConfidenceLevel.LOW,
                        signals=["Scenario A succeeded", "Scenario B returned 200 OK"],
                        deductions=[f"Scenario C response unexpectedly contains Resource A identifier '{resource_a_identifier}' (conflicting resource data or URL alias)"],
                    ),
                    title="BOLA Inconclusive (Scenario C Contains Resource A Identifier)",
                    explanation=f"Scenario C returned HTTP 200, but response contains Resource A identifier '{resource_a_identifier}'. Reverse control must establish access to a distinct resource, not Resource A.",
                    is_vulnerable=False,
                    scenario_results={
                        "scenario_a": res_a,
                        "scenario_b": res_b,
                        "scenario_c": res_c,
                        "scenario_d": res_d,
                    },
                )

            # Verify resource_b_identifier independently in Response C (Do NOT substitute user identity for resource identity)
            has_id_b_in_c = contains_resource_identifier(res_c.body_sample or "", resource_b_identifier)
            if not has_id_b_in_c:
                return BOLAVerificationResult(
                    candidate_id=candidate.candidate_id,
                    target_url=sanitize_url(target_url_a),
                    method=method,
                    outcome=BOLAOutcome.INCONCLUSIVE,
                    confidence=ConfidenceAssessment(
                        score=0.40,
                        level=ConfidenceLevel.LOW,
                        signals=["Scenario A succeeded", "Scenario B returned 200 OK"],
                        deductions=[f"Scenario C response lacks Resource B identifier '{resource_b_identifier}' in recognized fields"],
                    ),
                    title="BOLA Inconclusive (Resource B Identifier Missing)",
                    explanation=f"Scenario C returned HTTP 200, but response lacks Resource B identifier '{resource_b_identifier}'. Access to Resource B was not established.",
                    is_vulnerable=False,
                    scenario_results={
                        "scenario_a": res_a,
                        "scenario_b": res_b,
                        "scenario_c": res_c,
                        "scenario_d": res_d,
                    },
                )

            # Verify User B ownership independently using trusted ownership fields
            expected_owner_b = expected_user_b_claims or (expected_user_b_identifier or user_b_identifier)
            has_owner_b_in_c, owner_msg_c = validate_ownership_evidence(
                res_c.body_sample or "",
                expected_owner_b,
                expected_claim_type=expected_claim_type,
            )
            if not has_owner_b_in_c and expected_access_policy != AccessPolicy.PUBLIC:
                return BOLAVerificationResult(
                    candidate_id=candidate.candidate_id,
                    target_url=sanitize_url(target_url_a),
                    method=method,
                    outcome=BOLAOutcome.INCONCLUSIVE,
                    confidence=ConfidenceAssessment(
                        score=0.40,
                        level=ConfidenceLevel.LOW,
                        signals=["Scenario A succeeded", "Scenario B returned 200 OK", f"Resource B identifier '{resource_b_identifier}' confirmed"],
                        deductions=[f"Scenario C response lacks valid User B ownership evidence: {owner_msg_c}"],
                    ),
                    title="BOLA Inconclusive (Resource B Ownership Evidence Missing or Invalid)",
                    explanation=f"Scenario C returned HTTP 200, but failed ownership validation for User B: {owner_msg_c}. Access to Resource B must be tied to User B.",
                    is_vulnerable=False,
                    scenario_results={
                        "scenario_a": res_a,
                        "scenario_b": res_b,
                        "scenario_c": res_c,
                        "scenario_d": res_d,
                    },
                )

            # Reject if User A ownership appears in Response C
            if user_a_identifier and check_ownership_evidence(res_c.body_sample or "", user_a_identifier):
                return BOLAVerificationResult(
                    candidate_id=candidate.candidate_id,
                    target_url=sanitize_url(target_url_a),
                    method=method,
                    outcome=BOLAOutcome.INCONCLUSIVE,
                    confidence=ConfidenceAssessment(
                        score=0.35,
                        level=ConfidenceLevel.LOW,
                        signals=["Scenario A succeeded", "Scenario B returned 200 OK"],
                        deductions=[f"Scenario C response contains User A ownership evidence '{user_a_identifier}'"],
                    ),
                    title="BOLA Inconclusive (Scenario C Claims User A Ownership)",
                    explanation="Scenario C response contains ownership claims belonging to User A. Reverse control requires User B ownership of Resource B.",
                    is_vulnerable=False,
                    scenario_results={
                        "scenario_a": res_a,
                        "scenario_b": res_b,
                        "scenario_c": res_c,
                        "scenario_d": res_d,
                    },
                )

            # Record similarity between Response A and Response C as a diagnostic signal.
            # Similarity is not resource identity: exact Resource A and Resource B identifiers
            # and ownership have been independently validated. High semantic similarity
            # (e.g. shared schemas, default fields) alone must NOT invalidate Scenario C.
            similarity_a_c, _ = compute_semantic_similarity(res_a.body_sample or "", res_c.body_sample or "")

            # Full 4-Way Verification Confirmed!
            confidence = calculate_confidence(
                outcome=BOLAOutcome.CONFIRMED_BOLA,
                scenario_a=res_a,
                scenario_b=res_b,
                scenario_c=res_c,
                scenario_d=res_d,
                has_id_a_in_b=has_id_a_in_b,
                similarity_a_b=similarity_a_b,
                cache_interference=cache_interf_b,
                has_owner_a_in_b=has_owner_a_in_b,
                is_anon_denied=is_anon_denied,
            )
            if masking_signal:
                confidence.signals.append(masking_signal)
            if similarity_a_c >= 0.90:
                confidence.signals.append(
                    f"Scenario C schema similarity to Resource A is high ({similarity_a_c:.2f}) with distinct verified resource identity"
                )
            return BOLAVerificationResult(
                candidate_id=candidate.candidate_id,
                target_url=target_url_a,
                method=method,
                outcome=BOLAOutcome.CONFIRMED_BOLA,
                confidence=confidence,
                title="Confirmed Broken Object Level Authorization (BOLA)",
                explanation=f"User B successfully accessed User A's protected resource '{user_a_identifier}' (similarity {similarity_a_b:.2f}). Reverse control on Resource B succeeded and anonymous access was denied.",
                is_vulnerable=True,
                scenario_results={
                    "scenario_a": res_a,
                    "scenario_b": res_b,
                    "scenario_c": res_c,
                    "scenario_d": res_d,
                },
                reproduction_curl=build_sanitized_curl(method, target_url_a),
            )
        else:
            # 3-Way Fallback Path (Requirement 1 & 6)
            # Downgrade to HIGH_PROBABLE_BOLA only if evidence is strong
            # Independently validate User B's authenticated identity and principal
            expected_b_id = expected_user_b_identifier or user_b_identifier
            is_b_authenticated, auth_reason = self._validate_secondary_authentication(
                expected_user_b_identifier=expected_b_id,
                expected_user_b_claims=expected_user_b_claims,
                expected_claim_type=expected_claim_type,
                user_b_validation_url=user_b_validation_url,
            )
            if not is_b_authenticated:
                return BOLAVerificationResult(
                    candidate_id=candidate.candidate_id,
                    target_url=target_url_a,
                    method=method,
                    outcome=BOLAOutcome.INCONCLUSIVE,
                    confidence=ConfidenceAssessment(
                        score=0.40,
                        level=ConfidenceLevel.LOW,
                        signals=["Scenario A succeeded", "Scenario B returned 200 OK"],
                        deductions=[f"Secondary authentication could not be independently established: {auth_reason}"],
                    ),
                    title="BOLA Inconclusive (Secondary Identity Authentication Unverified in 3-Way Fallback)",
                    explanation=f"Secondary resource B was unavailable, and {auth_reason}. Credential presence alone cannot establish trust.",
                    is_vulnerable=False,
                    scenario_results={
                        "scenario_a": res_a,
                        "scenario_b": res_b,
                        "scenario_d": res_d,
                    },
                )

            evidence_is_strong = (
                is_anon_denied
                and similarity_a_b >= 0.85
                and has_id_a_in_b
                and has_owner_a_in_b
                and cache_interf_b == CacheInterference.NONE
            )

            if evidence_is_strong:
                confidence = calculate_confidence(
                    outcome=BOLAOutcome.HIGH_PROBABLE_BOLA,
                    scenario_a=res_a,
                    scenario_b=res_b,
                    scenario_c=None,
                    scenario_d=res_d,
                    has_id_a_in_b=has_id_a_in_b,
                    similarity_a_b=similarity_a_b,
                    cache_interference=cache_interf_b,
                    has_owner_a_in_b=has_owner_a_in_b,
                    is_anon_denied=is_anon_denied,
                )
                if masking_signal:
                    confidence.signals.append(masking_signal)
                return BOLAVerificationResult(
                    candidate_id=candidate.candidate_id,
                    target_url=target_url_a,
                    method=method,
                    outcome=BOLAOutcome.HIGH_PROBABLE_BOLA,
                    confidence=confidence,
                    title="Probable BOLA (3-Way Verification)",
                    explanation=f"User B accessed User A's protected resource '{user_a_identifier}' while anonymous access was denied. Secondary resource B was unavailable for reverse control check.",
                    is_vulnerable=True,
                    scenario_results={
                        "scenario_a": res_a,
                        "scenario_b": res_b,
                        "scenario_d": res_d,
                    },
                    reproduction_curl=build_sanitized_curl(method, target_url_a),
                )
            else:
                return BOLAVerificationResult(
                    candidate_id=candidate.candidate_id,
                    target_url=target_url_a,
                    method=method,
                    outcome=BOLAOutcome.INCONCLUSIVE,
                    confidence=ConfidenceAssessment(
                        score=0.45,
                        level=ConfidenceLevel.LOW,
                        signals=["Scenario A succeeded", "Scenario B returned 200 OK"],
                        deductions=["Resource B unavailable and remaining evidence insufficient for high-probability verdict"],
                    ),
                    title="BOLA Inconclusive (Insufficient Evidence)",
                    explanation="Secondary resource B was unavailable and evidence from 3-way check was insufficient to eliminate false positives.",
                    is_vulnerable=False,
                    scenario_results={
                        "scenario_a": res_a,
                        "scenario_b": res_b,
                        "scenario_d": res_d,
                    },
                )
