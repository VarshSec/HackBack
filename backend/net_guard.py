"""SSRF guard for every outbound request a scan makes (finding H1).

The domain the operator submits is validated as a *string* in schemas.py, but a
name can still resolve to a private/loopback/link-local/metadata address (DNS
rebinding, `metadata.google.internal`, an attacker A-record -> 169.254.169.254),
and a legitimately-public target can 302 into a private range. This module is
the one place that turns "a host string" into "a safe connection":

  - resolve_public_ips(host): resolve ALL A/AAAA and reject if any is non-public.
  - assert_public_host(host): the dispatch-time gate (used by subprocess-tool
    modules that resolve internally - nmap/nuclei/ffuf/etc; a small resolve->
    connect TOCTOU window remains for those, documented at the call site).
  - guarded_get(url): resolve + validate + PIN the validated IP for the actual
    connection (defeats rebinding), and re-validate every redirect hop. This is
    what the requests-based modules use instead of raw requests.get.

Note: subprocess tools (nmap, whatweb, nuclei, ffuf, testssl...) do their
own DNS at connect time, so they get the dispatch-time assert_public_host gate,
not per-connection pinning - closing that fully means teaching each tool to
target-by-IP-with-Host, which is a much larger change. The pin is applied to
every client we control directly (plain `requests`).

The pin is a CONNECTION-level pin, not a URL rewrite: a mounted HTTPAdapter
connects the socket to the validated IP while keeping the URL/SNI/Host as the
real hostname (via urllib3's server_hostname). Rewriting the URL host to the IP
would send SNI=IP, which SNI-routing CDNs (Vercel/Cloudflare/Fastly/Netlify)
can't route - they return a generic 403/edge page stripped of the real site's
headers, producing false "missing header"/wrong-status findings on most of the
HTTPS web. Same approach ssl_tls.py and routers/verify.py already use.
"""

import ipaddress
import socket
from urllib.parse import urlsplit

import requests
from requests.adapters import HTTPAdapter
from urllib3 import HTTPConnectionPool, HTTPSConnectionPool


# Networks ipaddress' category flags don't all cover: CGNAT, IETF protocol
# assignments, benchmarking. is_private/is_loopback/is_link_local/is_reserved/
# is_multicast/is_unspecified handle the rest (incl. IPv6 ULA/loopback/ll).
_EXTRA_BLOCKED = [
    ipaddress.ip_network("100.64.0.0/10"),   # CGNAT (RFC 6598)
    ipaddress.ip_network("192.0.0.0/24"),    # IETF protocol assignments
    ipaddress.ip_network("198.18.0.0/15"),   # benchmarking (RFC 2544)
]

# RFC 6052 Well-Known NAT64 Prefix (/96).
# Decode the embedded IPv4 address before applying the existing SSRF checks.
_NAT64_PREFIX = ipaddress.ip_network("64:ff9b::/96")

_REDIRECT_CODES = {301, 302, 303, 307, 308}
_MAX_REDIRECTS = 5


def _pin_sort_key(ip_str: str):
    """IPv4 before IPv6, then lexical. The connection pin takes the [0] of this
    ordering; a plain string sort puts most IPv6 addrs ahead of IPv4, so the pin
    lands on IPv6 and false-fails on IPv4-only networks (same corruption class as
    the SNI bug). Mirrors routers/verify.py's v4-preference. `.split('%')` drops
    the zone id link-local IPv6 can carry (fe80::1%eth0) so ip_address won't choke."""
    return (ipaddress.ip_address(ip_str.split('%')[0]).version, ip_str)


class SsrfBlocked(ValueError):
    """Raised when a host resolves to, or redirects into, a non-public address."""


def _ip_is_disallowed(ip_str: str) -> bool:
    ip = ipaddress.ip_address(ip_str)

    # Unwrap IPv4-mapped IPv6 (::ffff:10.0.0.1 must be judged as 10.0.0.1).
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped

    # Unwrap the RFC 6052 well-known NAT64 prefix (64:ff9b::/96).
    # The embedded IPv4 is then evaluated by the SAME rules as ordinary IPv4.
    elif ip.version == 6 and ip in _NAT64_PREFIX:
        ip = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)

    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
        or any(ip in net for net in _EXTRA_BLOCKED)
    )


def resolve_public_ips(host: str) -> list[str]:
    """Every A/AAAA for `host`, or raise SsrfBlocked if ANY is non-public.
    Accepts an IP literal too (validated directly). Empty resolution -> raise."""
    try:
        ip = ipaddress.ip_address(host)
        if _ip_is_disallowed(str(ip)):
            raise SsrfBlocked(f"{host} is a non-public address")
        return [str(ip)]
    except ValueError:
        pass  # not a literal; resolve it below

    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        raise SsrfBlocked(f"{host} does not resolve ({e})")

    ips = sorted({info[4][0] for info in infos}, key=_pin_sort_key)
    if not ips:
        raise SsrfBlocked(f"{host} does not resolve")

    bad = [ip for ip in ips if _ip_is_disallowed(ip)]
    if bad:
        raise SsrfBlocked(
            f"{host} resolves to non-public address(es): {', '.join(bad)}"
        )
    return ips


def assert_public_host(host: str) -> None:
    """Dispatch-time gate: raise SsrfBlocked unless `host` resolves entirely to
    public addresses. Used by modules whose external tool does its own connect."""
    resolve_public_ips(host)


class _PinnedPoolAdapter(HTTPAdapter):
    """Pins every connection to its host's validated public IP while keeping the
    URL/SNI/Host as the real hostname (rebinding-safe SSRF pin, SNI-correct).

    The guard lives in get_connection, which requests calls once per hop - so
    redirect targets are resolved+validated too, without a manual redirect loop.
    A pool is cached per (scheme, host, port): the FIRST validated IP is reused
    for the life of the session, so a rebind on a later lookup can't move the
    connection to a private address."""

    def __init__(self, *a, **k):
        self._pools = {}
        super().__init__(*a, **k)

    def send(self, request, **kwargs):
        # Force Host to the hostname: the pool connects to an IP, and urllib3
        # would otherwise emit Host: <ip>, which name-vhosts/CDNs reject.
        host = urlsplit(request.url).hostname
        if host:
            request.headers["Host"] = host
        return super().send(request, **kwargs)

    def get_connection(self, url, proxies=None):
        return self.get_connection_with_tls_context(url, verify=None, proxies=proxies)

    def get_connection_with_tls_context(
        self, request_or_url, verify, proxies=None, cert=None
    ):
        url = request_or_url.url if hasattr(request_or_url, "url") else request_or_url
        parsed = urlsplit(url)
        host, scheme = parsed.hostname, parsed.scheme
        if not host:
            raise SsrfBlocked(f"no host in URL: {url!r}")
        port = parsed.port or (443 if scheme == "https" else 80)

        # Resolve effective verify: None defaults to settings
        if verify is None:
            from config import settings
            if getattr(settings, "CA_BUNDLE_PATH", None):
                verify = settings.CA_BUNDLE_PATH
            else:
                verify = getattr(settings, "VERIFY_SSL", True)

        key = (scheme, host, port, verify)
        pool = self._pools.get(key)
        if pool is None:
            ip = resolve_public_ips(host)[0]  # validate + pin; raises if non-public
            if scheme == "https":
                # server_hostname keeps SNI = the real name; connect goes to ip.
                if verify:
                    cert_reqs = "CERT_REQUIRED"
                    assert_hostname = host
                    if isinstance(verify, str) and verify:
                        ca_certs = verify
                    else:
                        from config import settings
                        ca_certs = settings.CA_BUNDLE_PATH if getattr(settings, "CA_BUNDLE_PATH", None) else None
                else:
                    cert_reqs = "CERT_NONE"
                    assert_hostname = False
                    ca_certs = None

                pool = HTTPSConnectionPool(
                    ip,
                    port=port,
                    server_hostname=host,
                    assert_hostname=assert_hostname,
                    cert_reqs=cert_reqs,
                    ca_certs=ca_certs,
                    retries=False,
                )
            else:
                pool = HTTPConnectionPool(ip, port=port, retries=False)
            self._pools[key] = pool
        return pool

    def close(self):
        for pool in self._pools.values():
            try:
                pool.close()
            except Exception:
                pass
        self._pools.clear()
        super().close()


def get_tls_verify() -> bool | str:
    """Return the default TLS verification setting or custom CA bundle path."""
    from config import settings
    if getattr(settings, "CA_BUNDLE_PATH", None):
        return settings.CA_BUNDLE_PATH
    return getattr(settings, "VERIFY_SSL", True)


def guarded_request(
    method: str,
    url: str,
    *,
    session: requests.Session | None = None,
    follow: bool | None = None,
    max_redirects: int = _MAX_REDIRECTS,
    verify: bool | str | None = None,
    **kwargs,
) -> requests.Response:
    """Drop-in for requests.<method> that pins every connection (including each
    redirect hop) to the host's validated public IP while keeping the hostname
    for SNI/cert/Host (see _PinnedPoolAdapter).
    
    TLS certificate verification is enabled by default (VERIFY_SSL=True) or
    configured via CA_BUNDLE_PATH for trusted lab certificates. To explicitly
    scan targets with self-signed or invalid certificates, pass verify=False.
    TLS certificate errors are raised as requests.exceptions.SSLError without
    silent insecure fallback. `follow` defaults to the caller's `allow_redirects`
    (True if unset, matching requests)."""
    if follow is None:
        follow = kwargs.get("allow_redirects", True)
    kwargs["allow_redirects"] = follow

    if verify is None:
        if "verify" in kwargs:
            verify = kwargs.pop("verify")
        else:
            from config import settings
            if getattr(settings, "CA_BUNDLE_PATH", None):
                verify = settings.CA_BUNDLE_PATH
            else:
                verify = getattr(settings, "VERIFY_SSL", True)
    kwargs["verify"] = verify

    own = session is None
    sess = session or requests.Session()
    if not isinstance(sess.get_adapter("https://"), _PinnedPoolAdapter):
        adapter = _PinnedPoolAdapter()
        sess.mount("https://", adapter)
        sess.mount("http://", adapter)
    sess.max_redirects = max_redirects
    try:
        return sess.request(method, url, **kwargs)
    finally:
        if own:
            sess.close()


def guarded_get(url: str, **kwargs) -> requests.Response:
    """GET convenience wrapper over guarded_request (see it for semantics)."""
    return guarded_request("get", url, **kwargs)


def _demo() -> None:
    """Self-check: run `python -m net_guard`. No network needed for the IP logic."""
    bad = [
        "127.0.0.1",
        "10.0.0.5",
        "169.254.169.254",
        "192.168.1.1",
        "::1",
        "fe80::1",
        "100.64.0.1",
        "0.0.0.0",
        "::ffff:10.0.0.1",
        "224.0.0.1",
        # NAT64-encoded private / metadata / loopback IPv4 addresses.
        "64:ff9b::a00:5",       # 10.0.0.5
        "64:ff9b::a9fe:a9fe",   # 169.254.169.254
        "64:ff9b::7f00:1",      # 127.0.0.1
    ]
    good = [
        "8.8.8.8",
        "1.1.1.1",
        "93.184.216.34",
        "2606:2800:220:1:248:1893:25c8:1946",
        # NAT64-encoded public IPv4 addresses.
        "64:ff9b::1739:4a10",   # 23.57.74.16
        "64:ff9b::1739:4a02",   # 23.57.74.2
        "64:ff9b::1740:1e0",    # 23.64.1.224
        "64:ff9b::1740:1e2",    # 23.64.1.226
    ]

    for ip in bad:
        assert _ip_is_disallowed(ip), f"should block {ip}"
    for ip in good:
        assert not _ip_is_disallowed(ip), f"should allow {ip}"

    # Literal path of resolve_public_ips.
    for ip in bad:
        try:
            resolve_public_ips(ip)
            raise AssertionError(f"resolve should reject {ip}")
        except SsrfBlocked:
            pass

    for ip in good:
        assert resolve_public_ips(ip) == [str(ipaddress.ip_address(ip))]

    # IPv4-preference: the pin (caller takes [0]) must pick IPv4 over IPv6.
    mixed = sorted(
        {"2606:2800:220:1::1", "93.184.216.34", "1.1.1.1"},
        key=_pin_sort_key,
    )
    assert mixed[0] == "1.1.1.1", f"IPv4 must pin first, got {mixed}"

    print("net_guard self-check OK")


if __name__ == "__main__":
    _demo()
