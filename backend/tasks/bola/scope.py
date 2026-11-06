"""
Target Scope Enforcement for BOLA Extraction Pipeline.

Provides centralized URL scope validation to ensure only explicitly authorized
target hosts and approved subdomains are ingested, rejecting lookalike domains,
unrelated external hosts, malformed URLs, unsupported schemes, and URL user-info.
"""
from __future__ import annotations

import urllib.parse
from typing import Optional, Tuple


def normalize_target_host(target_domain: str) -> str:
    """Extracts and lowercases the hostname from a target domain or URL."""
    domain = target_domain.strip().lower()
    if "://" in domain:
        parsed = urllib.parse.urlsplit(domain)
        domain = parsed.hostname or domain
    else:
        # Strip trailing path or port if present
        domain = domain.split("/")[0]
        if ":" in domain and not domain.startswith("["):
            domain = domain.split(":")[0]
    return domain.strip().lower()


def is_url_in_scope(
    url: str,
    target_domain: str,
    base_url: Optional[str] = None,
) -> Tuple[bool, Optional[str]]:
    """
    Validates whether a URL is within the authorized scope of target_domain.

    Rules:
    - Allows exact target host (e.g. target.test).
    - Allows legitimate subdomains (e.g. api.target.test).
    - Rejects lookalike domains (e.g. target.test.attacker.test, nottarget.test).
    - Rejects URL user-info credentials (e.g. user:pass@target.test).
    - Rejects unsupported schemes (only http and https allowed).
    - Rejects javascript:, file:, data:, mailto: schemes.
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

    # Handle relative URLs using base_url if supplied
    if clean_url.startswith("/") or not urllib.parse.urlsplit(clean_url).scheme:
        if base_url:
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

    # 2. Reject URL user-info credentials
    # Check parsed properties and raw netloc for '@'
    if parsed.username or parsed.password or ("@" in parsed.netloc):
        return False, None

    # 3. Check hostname if absolute URL
    host = (parsed.hostname or "").strip().lower()
    if host:
        # Exact match or true subdomain (must be separated by a dot)
        if host == target_host:
            is_valid = True
        elif host.endswith(f".{target_host}"):
            is_valid = True
        else:
            # Lookalike domain e.g. target.test.attacker.test or badtarget.test
            return False, None
    else:
        # If no host was present and no base_url resolved it to an absolute URL,
        # it is a relative path. If base_url was not provided, relative paths
        # are valid only if they start with '/' (representing paths on target).
        if not clean_url.startswith("/"):
            return False, None

    return True, resolved
