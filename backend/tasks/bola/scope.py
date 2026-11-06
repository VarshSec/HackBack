"""
Target Scope Enforcement for BOLA Extraction Pipeline.

Provides centralized URL scope validation to ensure only explicitly authorized
target hosts and approved subdomains are ingested, rejecting lookalike domains,
unrelated external hosts, malformed URLs, unsupported schemes, and URL user-info.
"""
from __future__ import annotations

import urllib.parse
from typing import Iterable, Optional, Set, Tuple


def normalize_target_host(target_domain: str) -> str:
    """
    Extracts, lowercases, and normalizes a target host string.
    Strips schemes, trailing paths, port numbers, and trailing dots.
    """
    if not target_domain or not isinstance(target_domain, str):
        return ""

    domain = target_domain.strip().lower()
    if not domain:
        return ""

    if "://" in domain:
        try:
            parsed = urllib.parse.urlsplit(domain)
            domain = parsed.hostname or domain
        except Exception:
            pass
    else:
        # Strip trailing path if present
        domain = domain.split("/")[0]
        # Strip port if present (and not an IPv6 literal)
        if ":" in domain and not domain.startswith("["):
            domain = domain.split(":")[0]

    # Strip trailing dot (DNS root) and surrounding whitespace
    return domain.strip().rstrip(".").lower()


def is_url_in_scope(
    url: str,
    target_domain: str,
    base_url: Optional[str] = None,
    allowed_subdomains: Optional[Iterable[str]] = None,
) -> Tuple[bool, Optional[str]]:
    """
    Validates whether a URL is within the explicitly authorized scope of target_domain.

    Explicit Authorization Model:
    - Exact target host is allowed.
    - Additional hosts/subdomains are allowed ONLY when explicitly listed in allowed_subdomains.
    - Authorization is NEVER inferred merely from a hostname suffix (e.g. `.{target_host}`).
    - Hostnames are normalized consistently across case and trailing dots.
    - Reject lookalike domains (e.g. target.test.attacker.test, nottarget.test).
    - Reject URL user-info credentials (e.g. user:pass@target.test).
    - Reject unsupported schemes (only http and https allowed).
    - Reject javascript:, file:, data:, mailto: schemes.
    - Resolves relative URLs if base_url is provided and in scope.

    Returns:
        (is_in_scope: bool, resolved_url: Optional[str])
    """
    if not url or not isinstance(url, str):
        return False, None

    clean_url = url.strip()
    if not clean_url:
        return False, None

    target_host = normalize_target_host(target_domain)
    if not target_host:
        return False, None

    # Construct set of normalized explicitly authorized hosts
    approved_hosts: Set[str] = set()
    if allowed_subdomains:
        for s in allowed_subdomains:
            norm_s = normalize_target_host(s)
            if norm_s:
                approved_hosts.add(norm_s)

    # Handle relative URLs using base_url if supplied
    is_relative = clean_url.startswith("/") or not urllib.parse.urlsplit(clean_url).scheme
    if is_relative:
        if base_url:
            # Ensure base_url itself is in scope before using it to resolve
            base_parsed = urllib.parse.urlsplit(base_url)
            base_host = (base_parsed.hostname or "").strip().rstrip(".").lower()
            if not base_host or (base_host != target_host and base_host not in approved_hosts):
                return False, None
            resolved = urllib.parse.urljoin(base_url, clean_url)
        else:
            resolved = clean_url if clean_url.startswith("/") else f"/{clean_url}"
    else:
        resolved = clean_url

    parsed = urllib.parse.urlsplit(resolved)

    # 1. Reject unsupported schemes
    scheme = parsed.scheme.lower()
    if scheme and scheme not in ("http", "https"):
        return False, None

    # 2. Reject URL user-info credentials (e.g. user:pass@host)
    if parsed.username or parsed.password or ("@" in parsed.netloc):
        return False, None

    # 3. Check hostname if absolute URL
    host = (parsed.hostname or "").strip().rstrip(".").lower()
    if host:
        # Explicit authorization: exact target host or explicitly approved subdomain
        if host == target_host or host in approved_hosts:
            is_valid = True
        else:
            # Unapproved subdomain, external host, or lookalike domain
            return False, None
    else:
        # Relative path without base_url: valid only if starts with '/'
        if not clean_url.startswith("/"):
            return False, None

    return True, resolved
