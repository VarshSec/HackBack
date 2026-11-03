"""
Dual-Identity Authentication Manager for BOLA / IDOR Verification.

Manages isolated HTTP session states for two independent identities:
- 'primary': Identity A (Resource Owner)
- 'secondary': Identity B (Potential Unauthorized Accessor)
plus an unauthenticated baseline:
- 'anonymous': Clean session without cookies or credentials.

Core Guarantees:
1. Strict Session Isolation: Identity A and Identity B instantiate separate
   requests.Session instances with dedicated, independent CookieJars, connection pools,
   and headers. Mutable session state is NEVER shared across identities.
2. Zero Credential Bleed: Authorization headers and bearer tokens belonging to Identity A
   never enter Identity B's session, and vice versa.
3. Controlled Session Refresh: Handles 401 Unauthorized responses with at most one
   controlled re-authentication attempt per identity per workflow. Never retries
   indiscriminately.
4. Independent Failure Semantics: Failure to authenticate Identity B never invalidates
   Identity A, but explicitly marks two-identity BOLA verification as inconclusive.
5. Secret Redaction: Passwords, bearer tokens, cookies, and authorization headers are
   never logged or exposed in serialized string representations.
"""

from __future__ import annotations

import enum
import logging
import re
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Dict, Optional, Tuple

import requests
import urllib3

from config import settings
import net_guard
from tasks.base_task import mount_retry_adapter
from tasks.auth_login import (
    resolve_login_type,
    fetch_json_auth_token,
    auth_header_from,
)

logger = logging.getLogger(__name__)

# Canonical Identity Constants
IDENTITY_PRIMARY = "primary"
IDENTITY_SECONDARY = "secondary"
IDENTITY_ANONYMOUS = "anonymous"

_TIMEOUT = 30


class AuthOutcome(str, enum.Enum):
    NOT_ATTEMPTED = "not_attempted"
    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    FAILED = "failed"
    ERROR = "error"
    UNCONFIGURED = "unconfigured"


@dataclass
class IdentityAuthState:
    """State tracking for a single identity. Secrets are redacted from string representations."""
    identity: str
    configured: bool = False
    attempted: bool = False
    outcome: AuthOutcome = AuthOutcome.NOT_ATTEMPTED
    detail: Optional[str] = None
    token_header: Optional[str] = None
    _token_val: Optional[str] = field(default=None, repr=False)
    last_login_time: Optional[float] = None
    refresh_count: int = 0

    def __repr__(self) -> str:
        return (
            f"IdentityAuthState(identity='{self.identity}', configured={self.configured}, "
            f"attempted={self.attempted}, outcome='{self.outcome.value}', "
            f"refreshes={self.refresh_count})"
        )

    def __str__(self) -> str:
        return self.__repr__()


class _FormFieldExtractor(HTMLParser):
    """HTML form parser capturing fields and actions of password-bearing login forms."""

    def __init__(self):
        super().__init__()
        self.fields: Dict[str, str] = {}
        self.action: Optional[str] = None
        self.method: Optional[str] = None
        self.found_login_form = False
        self._in_form = False
        self._current_fields: Dict[str, str] = {}
        self._current_action: Optional[str] = None
        self._current_method: Optional[str] = None
        self._current_has_password = False

    def handle_starttag(self, tag: str, attrs: list) -> None:
        attrs_dict = dict(attrs)
        if tag == 'form':
            self._in_form = True
            self._current_fields = {}
            self._current_action = attrs_dict.get('action')
            self._current_method = attrs_dict.get('method')
            self._current_has_password = False
        elif tag == 'input' and self._in_form:
            name = attrs_dict.get('name')
            if name:
                self._current_fields[name] = attrs_dict.get('value', '')
            if (attrs_dict.get('type') or '').lower() == 'password':
                self._current_has_password = True

    def handle_endtag(self, tag: str) -> None:
        if tag == 'form':
            self._in_form = False
            if self._current_has_password:
                self.fields = self._current_fields
                self.action = self._current_action
                self.method = self._current_method
                self.found_login_form = True


def _response_looks_like_login_form(text: str) -> bool:
    extractor = _FormFieldExtractor()
    extractor.feed(text)
    return extractor.found_login_form


def _strip_query(url: str) -> str:
    p = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit((p.scheme, p.netloc, p.path, '', ''))


class SessionIdentityManager:
    """
    Dedicated manager for multi-identity HTTP sessions in BOLA verification.

    Maintains completely isolated session instances for Identity A, Identity B,
    and Anonymous access. Handles controlled login, cookie separation, credential
    redaction, and single-retry session refresh.
    """

    def __init__(
        self,
        primary_auth: Optional[dict] = None,
        secondary_auth: Optional[dict] = None,
        max_refreshes: int = 1,
    ):
        self._auth_configs: Dict[str, Optional[dict]] = {
            IDENTITY_PRIMARY: primary_auth,
            IDENTITY_SECONDARY: secondary_auth,
            IDENTITY_ANONYMOUS: None,
        }
        self._sessions: Dict[str, Optional[requests.Session]] = {
            IDENTITY_PRIMARY: None,
            IDENTITY_SECONDARY: None,
            IDENTITY_ANONYMOUS: None,
        }
        self._states: Dict[str, IdentityAuthState] = {
            IDENTITY_PRIMARY: IdentityAuthState(
                identity=IDENTITY_PRIMARY,
                configured=bool(primary_auth),
            ),
            IDENTITY_SECONDARY: IdentityAuthState(
                identity=IDENTITY_SECONDARY,
                configured=bool(secondary_auth),
            ),
            IDENTITY_ANONYMOUS: IdentityAuthState(
                identity=IDENTITY_ANONYMOUS,
                configured=True,
                outcome=AuthOutcome.CONFIRMED,
                detail="Unauthenticated baseline context",
            ),
        }
        self._max_refreshes = max_refreshes
        self._lock = threading.Lock()

    @classmethod
    def from_scan_id(cls, scan_id: str, max_refreshes: int = 1) -> SessionIdentityManager:
        """Instantiate a SessionIdentityManager from Redis credentials for a scan_id."""
        from tasks.auth_store import get_scan_auth_both
        primary_auth, secondary_auth = get_scan_auth_both(scan_id)
        return cls(primary_auth, secondary_auth, max_refreshes=max_refreshes)

    def is_identity_configured(self, identity: str) -> bool:
        """Check if an identity has credentials configured."""
        if identity == IDENTITY_ANONYMOUS:
            return True
        return bool(self._auth_configs.get(identity))

    def has_two_identities(self) -> bool:
        """Check if both primary (User A) and secondary (User B) credentials are configured."""
        return (
            self.is_identity_configured(IDENTITY_PRIMARY)
            and self.is_identity_configured(IDENTITY_SECONDARY)
        )

    def is_two_identity_ready(self) -> bool:
        """Check if both identities are configured AND both successfully authenticated."""
        if not self.has_two_identities():
            return False
        st_a = self.get_state(IDENTITY_PRIMARY)
        st_b = self.get_state(IDENTITY_SECONDARY)
        valid_outcomes = (AuthOutcome.CONFIRMED, AuthOutcome.PROBABLE)
        return st_a.outcome in valid_outcomes and st_b.outcome in valid_outcomes

    def get_state(self, identity: str) -> IdentityAuthState:
        """Return a copy of the current authentication state for the identity."""
        with self._lock:
            st = self._states.get(identity)
            if not st:
                raise ValueError(f"Unknown identity: {identity}")
            return IdentityAuthState(
                identity=st.identity,
                configured=st.configured,
                attempted=st.attempted,
                outcome=st.outcome,
                detail=st.detail,
                token_header=st.token_header,
                last_login_time=st.last_login_time,
                refresh_count=st.refresh_count,
            )

    def _create_clean_session(self) -> requests.Session:
        """
        Create a completely fresh, isolated requests.Session instance.
        Configures TLS verification, retry adapters, and a clean CookieJar.
        """
        session = requests.Session()
        session.verify = (
            settings.CA_BUNDLE_PATH
            if getattr(settings, 'CA_BUNDLE_PATH', None)
            else getattr(settings, 'VERIFY_SSL', True)
        )
        session.cookies = requests.cookies.RequestsCookieJar()
        mount_retry_adapter(session)
        return session

    def authenticate(self, identity: str) -> bool:
        """
        Execute authentication for the specified identity in strict isolation.
        Returns True if authentication succeeded (confirmed or probable), False otherwise.
        """
        if identity == IDENTITY_ANONYMOUS:
            with self._lock:
                if self._sessions[IDENTITY_ANONYMOUS] is None:
                    self._sessions[IDENTITY_ANONYMOUS] = self._create_clean_session()
                self._states[IDENTITY_ANONYMOUS].attempted = True
                self._states[IDENTITY_ANONYMOUS].outcome = AuthOutcome.CONFIRMED
                return True

        if identity not in (IDENTITY_PRIMARY, IDENTITY_SECONDARY):
            raise ValueError(f"Unknown identity: {identity}")

        with self._lock:
            auth = self._auth_configs.get(identity)
            st = self._states[identity]
            st.attempted = True

            if not auth:
                st.outcome = AuthOutcome.UNCONFIGURED
                st.detail = f"No authentication configuration provided for {identity} identity"
                return False

            # Build a completely fresh session for this identity
            if self._sessions[identity]:
                try:
                    self._sessions[identity].close()
                except Exception:
                    pass
            session = self._create_clean_session()
            self._sessions[identity] = session

            outcome, detail, token_hdr, token_val = self._execute_login(auth, session)
            st.outcome = outcome
            st.detail = detail
            st.token_header = token_hdr
            st._token_val = token_val
            st.last_login_time = time.monotonic()

            success = outcome in (AuthOutcome.CONFIRMED, AuthOutcome.PROBABLE)
            if success:
                logger.info(
                    "BOLA auth manager: %s identity login succeeded (%s)",
                    identity, outcome.value
                )
            else:
                logger.warning(
                    "BOLA auth manager: %s identity login failed (%s): %s",
                    identity, outcome.value, detail
                )
            return success

    def _execute_login(
        self, auth: dict, session: requests.Session
    ) -> Tuple[AuthOutcome, str, Optional[str], Optional[str]]:
        """
        Perform login request(s) using net_guard.guarded_request.
        Never discloses credentials or raw tokens in returned error messages.
        """
        login_url = auth.get("login_url", "")
        login_type = resolve_login_type(auth)

        # 1. JSON-API Login (Bearer Token)
        if login_type == "json":
            try:
                token = fetch_json_auth_token(auth)
                if token:
                    header, value = auth_header_from(auth, token)
                    # Isolated header assignment strictly on this session
                    session.headers[header] = value
                    return (
                        AuthOutcome.CONFIRMED,
                        "JSON login returned a valid bearer authentication token.",
                        header,
                        value,
                    )
                else:
                    return (
                        AuthOutcome.FAILED,
                        "JSON login did not return a valid authentication token.",
                        None,
                        None,
                    )
            except requests.exceptions.SSLError as e:
                logger.warning("JSON login TLS verification failed: %s", e)
                return (AuthOutcome.ERROR, f"TLS certificate verification failed: {e}", None, None)
            except Exception as e:
                logger.warning("JSON login request failed: %s", e)
                return (AuthOutcome.ERROR, f"JSON login request failed: {type(e).__name__}", None, None)

        # 2. Form-Based Login (Cookies + CSRF)
        try:
            login_page = net_guard.guarded_request("get", login_url, session=session, timeout=_TIMEOUT)
            extractor = _FormFieldExtractor()
            extractor.feed(login_page.text)
            form_data = dict(extractor.fields)
            form_data[auth.get("username_field", "username")] = auth.get("username", "")
            form_data[auth.get("password_field", "password")] = auth.get("password", "")

            post_url = (
                urllib.parse.urljoin(login_url, extractor.action)
                if extractor.action
                else login_url
            )

            if (extractor.method or "").lower() == "get":
                resp = net_guard.guarded_request(
                    "get",
                    _strip_query(post_url),
                    session=session,
                    params=form_data,
                    timeout=_TIMEOUT,
                    allow_redirects=True,
                )
            else:
                resp = net_guard.guarded_request(
                    "post",
                    post_url,
                    session=session,
                    data=form_data,
                    timeout=_TIMEOUT,
                    allow_redirects=True,
                )

            indicator = auth.get("logged_in_indicator")
            if indicator:
                if re.search(indicator, resp.text):
                    return (
                        AuthOutcome.CONFIRMED,
                        f"logged_in_indicator matched post-login response.",
                        None,
                        None,
                    )
                else:
                    return (
                        AuthOutcome.FAILED,
                        "logged_in_indicator did not match post-login response.",
                        None,
                        None,
                    )
            else:
                if _response_looks_like_login_form(resp.text):
                    return (
                        AuthOutcome.FAILED,
                        "Post-login response still contains a login form; login likely failed.",
                        None,
                        None,
                    )
                else:
                    return (
                        AuthOutcome.PROBABLE,
                        "Post-login response no longer displays login form (heuristic success).",
                        None,
                        None,
                    )
        except requests.exceptions.SSLError as e:
            logger.warning("Form login TLS certificate verification failed: %s", e)
            return (AuthOutcome.ERROR, f"TLS certificate verification failed: {e}", None, None)
        except Exception as e:
            logger.warning("Form login request failed: %s", e)
            return (AuthOutcome.ERROR, f"Login request failed: {type(e).__name__}", None, None)

    def authenticate_all(self) -> Dict[str, bool]:
        """Attempt authentication for all configured identities."""
        results = {}
        for ident in (IDENTITY_PRIMARY, IDENTITY_SECONDARY, IDENTITY_ANONYMOUS):
            if self.is_identity_configured(ident):
                results[ident] = self.authenticate(ident)
            else:
                results[ident] = False
        return results

    def get_session(self, identity: str, auto_authenticate: bool = True) -> requests.Session:
        """
        Obtain the dedicated requests.Session instance for the given identity.
        If auto_authenticate is True and the session has not attempted login,
        it initiates login automatically.
        """
        if identity not in (IDENTITY_PRIMARY, IDENTITY_SECONDARY, IDENTITY_ANONYMOUS):
            raise ValueError(f"Unknown identity: {identity}")

        with self._lock:
            session = self._sessions[identity]
            st = self._states[identity]

        if session is None and auto_authenticate:
            self.authenticate(identity)
            with self._lock:
                session = self._sessions[identity]

        if session is None:
            # Fallback to an empty isolated session if unconfigured or failed
            with self._lock:
                if self._sessions[identity] is None:
                    self._sessions[identity] = self._create_clean_session()
                session = self._sessions[identity]

        return session

    def handle_response_auth_status(self, identity: str, response: requests.Response) -> bool:
        """
        Controlled session expiration detection and recovery.
        Detects 401 Unauthorized or login redirects for an authenticated identity.
        Permits at most self._max_refreshes (default 1) controlled re-authentication
        attempts per identity.

        Returns True if the session was successfully refreshed (caller may retry request),
        False if unrefreshable or budget exceeded.
        """
        if identity == IDENTITY_ANONYMOUS:
            return False

        if not self.is_identity_configured(identity):
            return False

        # Expiration indicator: 401 Unauthorized or redirect to login endpoint
        is_expired = False
        if response.status_code == 401:
            is_expired = True
        elif response.status_code in (302, 303, 307):
            loc = response.headers.get("Location", "")
            auth = self._auth_configs.get(identity) or {}
            login_url = auth.get("login_url", "")
            if login_url and urllib.parse.urlsplit(login_url).path in loc:
                is_expired = True

        if not is_expired:
            return False

        with self._lock:
            st = self._states[identity]
            if st.refresh_count >= self._max_refreshes:
                logger.warning(
                    "BOLA auth manager: %s identity exceeded max re-authentications (%d/%d)",
                    identity, st.refresh_count, self._max_refreshes
                )
                return False

            st.refresh_count += 1
            logger.info(
                "BOLA auth manager: refreshing expired session for %s identity (attempt %d/%d)",
                identity, st.refresh_count, self._max_refreshes
            )

        # Execute re-authentication
        return self.authenticate(identity)

    def close(self) -> None:
        """Safely close all identity sessions and clear sensitive state."""
        with self._lock:
            for ident, sess in self._sessions.items():
                if sess:
                    try:
                        sess.cookies.clear()
                        sess.headers.clear()
                        sess.close()
                    except Exception:
                        pass
                    self._sessions[ident] = None

    def __enter__(self) -> SessionIdentityManager:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def __repr__(self) -> str:
        return (
            f"SessionIdentityManager(primary_configured={self.is_identity_configured(IDENTITY_PRIMARY)}, "
            f"secondary_configured={self.is_identity_configured(IDENTITY_SECONDARY)})"
        )
