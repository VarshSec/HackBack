"""
Ephemeral, per-scan credential store for authenticated scanning.

Supports both single-identity scans (legacy webscan, owasp) and dual-identity
scans (BOLA / IDOR verification).

The passwords and tokens never become Celery task arguments: Celery's stock logging
(`--loglevel=info`) reprs full task args at INFO for every task-received/task-succeeded
line, so passing credentials as task args would put them in plaintext worker logs on disk.
Instead, credentials are written here once (routers/scan.py's create_scan()) and read
directly by the tasks that need them - never logged, never passed as Celery task args.

Never persisted to PostgreSQL (models.py's Scan table) either - there is no legitimate
reason to retain scan credentials after the scan completes.
Deleted explicitly in scan_orchestrator.py's _finalize(). The TTL below is only a
backstop for paths that skip _finalize() (e.g. the cancel decision).
"""
import json
from typing import Optional, Tuple, Dict, Any

import redis

from config import settings

_TTL_SECONDS = 2400  # comfortably past routers/scan.py's STUCK_SCAN_DEADLINE;
                     # deleted explicitly in _finalize() regardless
_r = redis.Redis.from_url(settings.REDIS_URL)


def _key(scan_id: str) -> str:
    return f"scan_auth:{scan_id}"


def store_scan_auth(
    scan_id: str,
    auth: Optional[dict] = None,
    auth_secondary: Optional[dict] = None,
) -> None:
    """
    Store authentication credentials for a scan in Redis under scan_auth:{scan_id}.
    Supports both legacy single-identity auth and dual-identity (primary + secondary) auth.
    Never persists to PostgreSQL.
    """
    if auth is None and auth_secondary is None:
        return

    # Check if auth is already a dual-identity dict containing 'primary' or 'secondary'
    if isinstance(auth, dict) and ('primary' in auth or 'secondary' in auth):
        payload = {
            'primary': auth.get('primary'),
            'secondary': auth_secondary if auth_secondary is not None else auth.get('secondary'),
        }
    else:
        payload = {
            'primary': auth,
            'secondary': auth_secondary,
        }

    _r.setex(_key(scan_id), _TTL_SECONDS, json.dumps(payload))


def get_scan_auth(scan_id: str, identity: str = 'primary') -> Optional[dict]:
    """
    Fetch authentication config for a scan from Redis.
    Backward compatible with single-identity consumers:
      - Default identity='primary' returns Identity A (primary) config dict.
      - identity='secondary' returns Identity B (secondary) config dict (or None if not set).
      - identity='all' returns {'primary': ..., 'secondary': ...}.
      - If a legacy single-identity payload was stored (no 'primary' key in JSON),
        returns the dict directly for 'primary', and None for 'secondary'.
    """
    raw = _r.get(_key(scan_id))
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except Exception:
        return None

    if not isinstance(data, dict):
        return None

    # Dual-identity payload structure
    if 'primary' in data or 'secondary' in data:
        if identity == 'all':
            return data
        elif identity == 'secondary':
            return data.get('secondary')
        else:  # 'primary' or default
            return data.get('primary')

    # Legacy flat dictionary (single identity)
    if identity == 'secondary':
        return None
    elif identity == 'all':
        return {'primary': data, 'secondary': None}
    return data


def get_scan_auth_both(scan_id: str) -> Tuple[Optional[dict], Optional[dict]]:
    """Convenience helper returning (primary_auth, secondary_auth)."""
    data = get_scan_auth(scan_id, identity='all')
    if not data or not isinstance(data, dict):
        return None, None
    return data.get('primary'), data.get('secondary')


def delete_scan_auth(scan_id: str) -> None:
    """Deletes all authentication credentials associated with the scan."""
    _r.delete(_key(scan_id))
