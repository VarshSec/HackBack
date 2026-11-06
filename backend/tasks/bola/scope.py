"""
Target Scope Enforcement for BOLA Extraction Pipeline.

Provides centralized URL scope validation to ensure only explicitly authorized
target hosts and approved subdomains are ingested, rejecting lookalike domains,
unrelated external hosts, malformed URLs, unsupported schemes, and URL user-info.
Fails closed on any parsing anomaly or malformed input.
"""
from __future__ import annotations

import urllib.parse
from typing import Iterable, Optional, Set, Tuple


def normalize_target_host(target_domain: str) -> str:
    """
    Extracts, lowercases, and normalizes a target host string.
    Strips schemes, trailing paths, port numbers, and trailing dots.
    Fails closed (returns empty string) on invalid or malformed input.
    """
    if not target_domain or not isinstance(target_domain, str):
        return ""

    domain = target_domain.strip().lower()
    if not domain:
        return ""

    try:
        if "://" in domain:
            parsed = urllib.parse.urlsplit(domain)
            domain = parsed.hostname or domain
        else:
            # Strip trailing path if present
            domain = domain.split("/")[0]
            # Strip port if present (and not an IPv6 literal)
            if ":" in domain and not domain.startswith("["):
                domain = domain.split(":")[0]

        # Strip trailing dot (DNS root) and surrounding whitespace
        return domain.strip().rstrip(".").lower()
    except Exception:
        return ""


def is_genuine_subdomain(subdomain: str, target_host: str) -> bool:
    """
    Validates whether subdomain is a genuine, properly formatted subdomain of target_host.
    Must end with '.{target_host}' and have at least one non-empty subdomain label.
    Rejects unrelated external domains, lookalikes, malformed strings, and userinfo.
    """
    if not subdomain or not target_host:
        return False
    norm_sub = normalize_target_host(subdomain)
    norm_target = normalize_target_host(target_host)
    if not norm_sub or not norm_target:
        return False
    if norm_sub == norm_target:
        return True
    if norm_sub.endswith(f".{norm_target}"):
        prefix = norm_sub[: -(len(norm_target) + 1)]
        if prefix and not prefix.endswith(".") and "@" not in prefix:
            return True
    return False


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
    - Explicitly approved genuine subdomains are allowed (must end in `.{target_host}`).
    - Unapproved subdomains are strictly rejected.
    - Unrelated external domains in allowed_subdomains are strictly rejected.
    - Lookalike domains remain rejected (e.g. target.test.attacker.test, nottarget.test).
    - Hostnames are normalized consistently across case, ports, and trailing dots.
    - Reject URL user-info credentials (e.g. user:pass@target.test).
    - Reject unsupported schemes (only http and https allowed).
    - Reject javascript:, file:, data:, mailto: schemes.
    - Malformed URLs, malformed IPv6, and unparseable inputs fail closed -> (False, None).
    - Resolves relative URLs if base_url is provided and in scope.

    Returns:
        (is_in_scope: bool, resolved_url: Optional[str])
    """
    if not url or not isinstance(url, str):
        return False, None

    clean_url = url.strip()
    if not clean_url:
        return False, None

    try:
        target_host = normalize_target_host(target_domain)
        if not target_host:
            return False, None

        # Construct set of normalized explicitly authorized genuine subdomains
        approved_hosts: Set[str] = set()
        if allowed_subdomains:
            for s in allowed_subdomains:
                if not s or not isinstance(s, str) or "@" in s:
                    continue
                norm_s = normalize_target_host(s)
                # Verify that it is actually a genuine subdomain of target_host
                if is_genuine_subdomain(norm_s, target_host):
                    approved_hosts.add(norm_s)

        # Handle relative URLs using base_url if supplied
        try:
            parsed_initial = urllib.parse.urlsplit(clean_url)
            is_relative = clean_url.startswith("/") or not parsed_initial.scheme
        except Exception:
            return False, None

        if is_relative:
            if base_url:
                try:
                    base_parsed = urllib.parse.urlsplit(base_url)
                    base_host = (base_parsed.hostname or "").strip().rstrip(".").lower()
                    if not base_host or (base_host != target_host and base_host not in approved_hosts):
                        return False, None
                    resolved = urllib.parse.urljoin(base_url, clean_url)
                except Exception:
                    return False, None
            else:
                resolved = clean_url if clean_url.startswith("/") else f"/{clean_url}"
        else:
            resolved = clean_url

        try:
            parsed = urllib.parse.urlsplit(resolved)
        except Exception:
            return False, None

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
            # Exact target host or explicitly approved genuine subdomain
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
    except Exception:
        # Fail closed on any unexpected parsing anomaly
        return False, None
