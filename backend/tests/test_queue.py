"""Hosted scan queue (config.HOSTED_QUEUE_ENABLED).

Unit-style: mocked DB/session, no live Postgres/Redis/Celery - same pattern as
test_scan_modes.py. Covers the two behaviors selected by the flag, the queue
helpers, the reaper exemption, and the self-hosted backward-compat guard.

Run with:
    cd backend && python3 -m pytest tests/test_queue.py -v
"""
import os
import sys
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import HTTPException

from config import settings
from models import ScanStatus
from schemas import ScanRequest
import routers.scan as scan_router
from tasks.queue_scheduler import (
    queue_position, count_occupied_slots, promote_queued_scans,
)


def _mock_db(count=0):
    db = MagicMock()
    chain = db.query.return_value.filter.return_value
    chain.all.return_value = []
    chain.first.return_value = None
    chain.count.return_value = count
    chain.order_by.return_value.all.return_value = []
    chain.order_by.return_value.limit.return_value.all.return_value = []
    chain.order_by.return_value.limit.side_effect = lambda n: chain.order_by.return_value
    # Real Postgres applies the created_at/id defaults on INSERT; db.refresh
    # then loads them. Simulate that so queue_position's created_at comparison
    # has a real value (the mock never actually flushes).
    def _refresh(s):
        if getattr(s, "created_at", None) is None:
            s.created_at = datetime.utcnow()
        if getattr(s, "id", None) is None:
            s.id = uuid4()
    db.refresh.side_effect = _refresh
    return db


def _mock_scan(status=ScanStatus.queued, dispatched_at=None):
    s = MagicMock()
    s.id = uuid4()
    s.domain = "clinkl.in"
    s.status = status
    s.dispatched_at = dispatched_at
    s.created_at = datetime.utcnow()
    s.started_at = None
    s.module_statuses = {}
    s.raw_findings = None
    s.notes = None
    s.scan_type = "full"
    return s


# ── Backward compatibility: flag OFF keeps the 429 (self-hosted default) ──────
class TestFlagOffUnchanged:
    def test_overflow_still_429_when_disabled(self, monkeypatch):
        monkeypatch.setattr(settings, "HOSTED_QUEUE_ENABLED", False)
        monkeypatch.setattr(settings, "MAX_CONCURRENT_SCANS", 3)
        db = _mock_db(count=3)  # active_count == cap
        req = ScanRequest(domain="clinkl.in", authorized=True, mode="full")
        with pytest.raises(HTTPException) as ei:
            scan_router.create_scan(req, MagicMock(), db)
        assert ei.value.status_code == 429
        assert "Maximum concurrent scans" in ei.value.detail

    def test_capacity_free_starts_immediately_when_disabled(self, monkeypatch):
        monkeypatch.setattr(settings, "HOSTED_QUEUE_ENABLED", False)
        monkeypatch.setattr(settings, "MAX_CONCURRENT_SCANS", 3)
        orch = MagicMock()
        monkeypatch.setattr("tasks.scan_orchestrator.scan_orchestrator", orch)
        db = _mock_db(count=0)
        db.refresh.side_effect = lambda s: setattr(s, "id", uuid4())
        req = ScanRequest(domain="clinkl.in", authorized=True, mode="full")
        resp = scan_router.create_scan(req, MagicMock(), db)
        orch.delay.assert_called_once()
        assert resp.queue_position is None


# ── Flag ON: overflow queues instead of 429; free slot starts immediately ─────
class TestFlagOnQueues:
    def test_overflow_is_queued_not_429(self, monkeypatch):
        monkeypatch.setattr(settings, "HOSTED_QUEUE_ENABLED", True)
        monkeypatch.setattr(settings, "MAX_CONCURRENT_SCANS", 3)
        orch = MagicMock()
        monkeypatch.setattr("tasks.scan_orchestrator.scan_orchestrator", orch)
        db = _mock_db(count=3)  # 3 occupied == cap -> queue
        req = ScanRequest(domain="clinkl.in", authorized=True, mode="full")

        resp = scan_router.create_scan(req, MagicMock(), db)  # must NOT raise 429

        assert resp.status == ScanStatus.queued.value
        assert resp.queue_position is not None       # a place in line was returned
        orch.delay.assert_not_called()               # not dispatched while waiting

    def test_free_slot_dispatches_and_sets_dispatched_at(self, monkeypatch):
        monkeypatch.setattr(settings, "HOSTED_QUEUE_ENABLED", True)
        monkeypatch.setattr(settings, "MAX_CONCURRENT_SCANS", 3)
        orch = MagicMock()
        monkeypatch.setattr("tasks.scan_orchestrator.scan_orchestrator", orch)
        db = _mock_db(count=0)  # 0 occupied -> start now
        captured = {}
        db.add.side_effect = lambda s: captured.setdefault("scan", s)
        req = ScanRequest(domain="clinkl.in", authorized=True, mode="full")

        resp = scan_router.create_scan(req, MagicMock(), db)

        orch.delay.assert_called_once()
        assert resp.queue_position is None
        assert captured["scan"].dispatched_at is not None  # slot claimed at accept


# ── Queue helpers ─────────────────────────────────────────────────────────────
class TestQueueHelpers:
    def test_position_is_ahead_plus_one(self):
        db = _mock_db(count=3)  # 3 waiting scans created earlier
        waiting = _mock_scan(status=ScanStatus.queued, dispatched_at=None)
        assert queue_position(db, waiting) == 4

    def test_position_none_when_dispatched(self):
        db = _mock_db(count=3)
        dispatched = _mock_scan(status=ScanStatus.queued, dispatched_at=datetime.utcnow())
        assert queue_position(db, dispatched) is None

    def test_position_none_when_running(self):
        db = _mock_db(count=0)
        running = _mock_scan(status=ScanStatus.running, dispatched_at=datetime.utcnow())
        assert queue_position(db, running) is None

    def test_occupied_counts_dispatched_non_terminal(self):
        db = _mock_db(count=2)
        assert count_occupied_slots(db) == 2

    def test_promote_noop_when_disabled(self, monkeypatch):
        monkeypatch.setattr(settings, "HOSTED_QUEUE_ENABLED", False)
        # Must not touch the DB at all when the feature is off.
        assert promote_queued_scans() == 0


# ── Reaper must not kill a scan that is waiting BY DESIGN ─────────────────────
class TestReaperExemption:
    def test_waiting_scan_not_reaped(self, monkeypatch):
        monkeypatch.setattr(settings, "HOSTED_QUEUE_ENABLED", True)
        waiting = _mock_scan(status=ScanStatus.queued, dispatched_at=None)
        waiting.created_at = datetime.utcnow() - scan_router.STUCK_SCAN_DEADLINE - timedelta(hours=1)
        db = MagicMock()
        db.query.return_value.filter.return_value.all.return_value = [waiting]

        reaped = scan_router._reap_stuck_scans(db)

        assert reaped == 0
        assert waiting.status == ScanStatus.queued  # untouched

    def test_waiting_scan_exceeding_max_queue_wait_is_reaped_and_auth_deleted(self, monkeypatch):
        monkeypatch.setattr(settings, "HOSTED_QUEUE_ENABLED", True)
        waiting = _mock_scan(status=ScanStatus.queued, dispatched_at=None)
        waiting.id = "expired-queue-uuid"
        waiting.created_at = datetime.utcnow() - scan_router.MAX_QUEUE_WAIT_DEADLINE - timedelta(seconds=10)
        db = MagicMock()
        db.query.return_value.filter.return_value.all.return_value = [waiting]

        with patch("tasks.auth_store.delete_scan_auth") as mock_del:
            reaped = scan_router._reap_stuck_scans(db)
            assert reaped == 1
            assert waiting.status == ScanStatus.failed
            assert "exceeded maximum queue wait deadline" in (waiting.notes or "")
            mock_del.assert_called_once_with("expired-queue-uuid")

    def test_waiting_scan_within_max_queue_wait_not_reaped(self, monkeypatch):
        monkeypatch.setattr(settings, "HOSTED_QUEUE_ENABLED", True)
        waiting = _mock_scan(status=ScanStatus.queued, dispatched_at=None)
        waiting.created_at = datetime.utcnow() - timedelta(hours=1)
        db = MagicMock()
        db.query.return_value.filter.return_value.all.return_value = [waiting]

        reaped = scan_router._reap_stuck_scans(db)
        assert reaped == 0
        assert waiting.status == ScanStatus.queued

    def test_dispatched_stuck_scan_still_reaped(self, monkeypatch):
        monkeypatch.setattr(settings, "HOSTED_QUEUE_ENABLED", True)
        stuck = _mock_scan(status=ScanStatus.running, dispatched_at=datetime.utcnow())
        stuck.started_at = datetime.utcnow() - scan_router.STUCK_SCAN_DEADLINE - timedelta(hours=1)
        db = MagicMock()
        db.query.return_value.filter.return_value.all.return_value = [stuck]

        reaped = scan_router._reap_stuck_scans(db)

        assert reaped == 1
        assert stuck.status == ScanStatus.failed


# ── _is_waiting predicate ─────────────────────────────────────────────────────
class TestIsWaiting:
    def test_true_only_when_flag_on_queued_undispatched(self, monkeypatch):
        monkeypatch.setattr(settings, "HOSTED_QUEUE_ENABLED", True)
        assert scan_router._is_waiting(_mock_scan(ScanStatus.queued, None)) is True
        assert scan_router._is_waiting(_mock_scan(ScanStatus.queued, datetime.utcnow())) is False
        assert scan_router._is_waiting(_mock_scan(ScanStatus.running, None)) is False

    def test_false_when_flag_off(self, monkeypatch):
        monkeypatch.setattr(settings, "HOSTED_QUEUE_ENABLED", False)
        assert scan_router._is_waiting(_mock_scan(ScanStatus.queued, None)) is False


class TestQueuePromotionAuthValidation:
    """Verifies queue promotion behavior with valid and expired scan credentials."""

    def test_normal_queue_promotion_preserves_credentials(self, monkeypatch):
        monkeypatch.setattr(settings, "HOSTED_QUEUE_ENABLED", True)
        scan = _mock_scan(status=ScanStatus.queued, dispatched_at=None)
        scan.id = "promo-valid-uuid"
        scan.raw_findings = {"auth_required": True}
        scan.domain = "target.test"
        scan.scan_type = "quick"

        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.count.return_value = 0
        mock_db.query.return_value.filter.return_value.order_by.return_value.all.return_value = [scan]

        with patch("database.SessionLocal", return_value=mock_db), \
             patch("tasks.auth_store.touch_scan_auth", return_value=True) as mock_touch, \
             patch("tasks.scan_orchestrator.scan_orchestrator.delay") as mock_delay:

            from tasks.queue_scheduler import promote_queued_scans
            promoted = promote_queued_scans()

            assert promoted == 1
            mock_touch.assert_called_once_with("promo-valid-uuid")
            mock_delay.assert_called_once_with("promo-valid-uuid", "target.test", "quick")
            assert scan.dispatched_at is not None

    def test_expired_redis_credentials_at_promotion_prevents_dispatch(self, monkeypatch):
        """If required credentials expired in Redis, promotion must NOT dispatch and marks scan failed."""
        monkeypatch.setattr(settings, "HOSTED_QUEUE_ENABLED", True)
        scan = _mock_scan(status=ScanStatus.queued, dispatched_at=None)
        scan.id = "promo-expired-uuid"
        scan.raw_findings = {"auth_required": True}
        scan.domain = "target.test"
        scan.scan_type = "quick"

        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.count.return_value = 0
        mock_db.query.return_value.filter.return_value.order_by.return_value.all.return_value = [scan]

        with patch("database.SessionLocal", return_value=mock_db), \
             patch("tasks.auth_store.touch_scan_auth", return_value=False) as mock_touch, \
             patch("tasks.auth_store.delete_scan_auth") as mock_del, \
             patch("tasks.scan_orchestrator.scan_orchestrator.delay") as mock_delay:

            from tasks.queue_scheduler import promote_queued_scans
            promoted = promote_queued_scans()

            assert promoted == 0
            mock_touch.assert_called_once_with("promo-expired-uuid")
            mock_delay.assert_not_called()
            assert scan.status == ScanStatus.failed
            assert "expired while waiting in queue" in (scan.notes or "")
            assert scan.dispatched_at is None
            mock_del.assert_called_once_with("promo-expired-uuid")

    def test_unauthenticated_scan_promotion_dispatches_without_requiring_credentials(self, monkeypatch):
        """Scans submitted without authentication are promoted normally without checking for auth keys."""
        monkeypatch.setattr(settings, "HOSTED_QUEUE_ENABLED", True)
        scan = _mock_scan(status=ScanStatus.queued, dispatched_at=None)
        scan.id = "unauth-scan-uuid"
        scan.raw_findings = None
        scan.domain = "unauth.test"
        scan.scan_type = "quick"

        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.count.return_value = 0
        mock_db.query.return_value.filter.return_value.order_by.return_value.all.return_value = [scan]

        with patch("database.SessionLocal", return_value=mock_db), \
             patch("tasks.scan_orchestrator.scan_orchestrator.delay") as mock_delay:

            from tasks.queue_scheduler import promote_queued_scans
            promoted = promote_queued_scans()

            assert promoted == 1
            mock_delay.assert_called_once_with("unauth-scan-uuid", "unauth.test", "quick")
            assert scan.dispatched_at is not None

    def test_authenticated_scan_older_than_queue_deadline_failed_and_never_dispatched(self, monkeypatch):
        """1. An authenticated scan older than the queue deadline is failed and never dispatched."""
        monkeypatch.setattr(settings, "HOSTED_QUEUE_ENABLED", True)
        scan = _mock_scan(status=ScanStatus.queued, dispatched_at=None)
        scan.id = "expired-auth-uuid"
        scan.raw_findings = {"auth_required": True}
        scan.created_at = datetime.utcnow() - timedelta(seconds=settings.MAX_QUEUE_WAIT_SECONDS + 100)

        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.count.return_value = 0
        mock_db.query.return_value.filter.return_value.order_by.return_value.all.return_value = [scan]

        with patch("database.SessionLocal", return_value=mock_db), \
             patch("tasks.auth_store.touch_scan_auth") as mock_touch, \
             patch("tasks.auth_store.delete_scan_auth") as mock_del, \
             patch("tasks.scan_orchestrator.scan_orchestrator.delay") as mock_delay:

            from tasks.queue_scheduler import promote_queued_scans
            promoted = promote_queued_scans()

            assert promoted == 0
            assert scan.status == ScanStatus.failed
            assert "expired before promotion" in (scan.notes or "")
            assert scan.dispatched_at is None
            mock_touch.assert_not_called()
            mock_del.assert_called_once_with("expired-auth-uuid")
            mock_delay.assert_not_called()

    def test_unauthenticated_scan_older_than_queue_deadline_failed_and_never_dispatched(self, monkeypatch):
        """2. An unauthenticated scan older than the queue deadline is also failed and never dispatched."""
        monkeypatch.setattr(settings, "HOSTED_QUEUE_ENABLED", True)
        scan = _mock_scan(status=ScanStatus.queued, dispatched_at=None)
        scan.id = "expired-unauth-uuid"
        scan.raw_findings = None
        scan.created_at = datetime.utcnow() - timedelta(seconds=settings.MAX_QUEUE_WAIT_SECONDS + 100)

        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.count.return_value = 0
        mock_db.query.return_value.filter.return_value.order_by.return_value.all.return_value = [scan]

        with patch("database.SessionLocal", return_value=mock_db), \
             patch("tasks.auth_store.touch_scan_auth") as mock_touch, \
             patch("tasks.auth_store.delete_scan_auth") as mock_del, \
             patch("tasks.scan_orchestrator.scan_orchestrator.delay") as mock_delay:

            from tasks.queue_scheduler import promote_queued_scans
            promoted = promote_queued_scans()

            assert promoted == 0
            assert scan.status == ScanStatus.failed
            assert "expired before promotion" in (scan.notes or "")
            assert scan.dispatched_at is None
            mock_touch.assert_not_called()
            mock_del.assert_called_once_with("expired-unauth-uuid")
            mock_delay.assert_not_called()

    def test_missing_created_at_treated_defensively_as_expired(self, monkeypatch):
        """Missing or invalid created_at timestamp is defensively treated as expired."""
        monkeypatch.setattr(settings, "HOSTED_QUEUE_ENABLED", True)
        scan = _mock_scan(status=ScanStatus.queued, dispatched_at=None)
        scan.id = "no-created-uuid"
        scan.created_at = None

        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.count.return_value = 0
        mock_db.query.return_value.filter.return_value.order_by.return_value.all.return_value = [scan]

        with patch("database.SessionLocal", return_value=mock_db), \
             patch("tasks.auth_store.touch_scan_auth") as mock_touch, \
             patch("tasks.auth_store.delete_scan_auth") as mock_del, \
             patch("tasks.scan_orchestrator.scan_orchestrator.delay") as mock_delay:

            from tasks.queue_scheduler import promote_queued_scans
            promoted = promote_queued_scans()

            assert promoted == 0
            assert scan.status == ScanStatus.failed
            assert "missing or invalid creation timestamp" in (scan.notes or "")
            assert scan.dispatched_at is None
            mock_touch.assert_not_called()
            mock_del.assert_called_once_with("no-created-uuid")
            mock_delay.assert_not_called()

    def test_expired_scan_does_not_prevent_subsequent_valid_scan_promotion(self, monkeypatch):
        """7. An expired scan does not prevent a subsequent valid scan from being promoted."""
        monkeypatch.setattr(settings, "HOSTED_QUEUE_ENABLED", True)
        scan_expired = _mock_scan(status=ScanStatus.queued, dispatched_at=None)
        scan_expired.id = "scan-1-expired"
        scan_expired.created_at = datetime.utcnow() - timedelta(seconds=settings.MAX_QUEUE_WAIT_SECONDS + 500)

        scan_valid = _mock_scan(status=ScanStatus.queued, dispatched_at=None)
        scan_valid.id = "scan-2-valid"
        scan_valid.created_at = datetime.utcnow() - timedelta(minutes=5)
        scan_valid.domain = "valid.test"
        scan_valid.scan_type = "quick"

        mock_db = MagicMock()
        # 1 slot available
        mock_db.query.return_value.filter.return_value.count.return_value = settings.MAX_CONCURRENT_SCANS - 1
        mock_db.query.return_value.filter.return_value.order_by.return_value.all.return_value = [
            scan_expired, scan_valid
        ]

        with patch("database.SessionLocal", return_value=mock_db), \
             patch("tasks.scan_orchestrator.scan_orchestrator.delay") as mock_delay:

            from tasks.queue_scheduler import promote_queued_scans
            promoted = promote_queued_scans()

            assert promoted == 1
            assert scan_expired.status == ScanStatus.failed
            assert scan_expired.dispatched_at is None
            assert scan_valid.status == ScanStatus.queued
            assert scan_valid.dispatched_at is not None
            mock_delay.assert_called_once_with("scan-2-valid", "valid.test", "quick")

    def test_queue_expiration_when_auth_ttl_longer_than_max_queue_wait(self, monkeypatch):
        """8. Queue expiration still fires when AUTH_CREDENTIAL_TTL_SECONDS is configured longer than MAX_QUEUE_WAIT_SECONDS."""
        monkeypatch.setattr(settings, "HOSTED_QUEUE_ENABLED", True)
        monkeypatch.setattr(settings, "AUTH_CREDENTIAL_TTL_SECONDS", 86400)  # 24 hours
        monkeypatch.setattr(settings, "MAX_QUEUE_WAIT_SECONDS", 3600)        # 1 hour

        scan = _mock_scan(status=ScanStatus.queued, dispatched_at=None)
        scan.id = "mismatched-ttl-uuid"
        scan.raw_findings = {"auth_required": True}
        # 2 hours old: expired under MAX_QUEUE_WAIT_SECONDS (1h) but within Redis TTL (24h)
        scan.created_at = datetime.utcnow() - timedelta(hours=2)

        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.count.return_value = 0
        mock_db.query.return_value.filter.return_value.order_by.return_value.all.return_value = [scan]

        with patch("database.SessionLocal", return_value=mock_db), \
             patch("tasks.auth_store.touch_scan_auth") as mock_touch, \
             patch("tasks.auth_store.delete_scan_auth") as mock_del, \
             patch("tasks.scan_orchestrator.scan_orchestrator.delay") as mock_delay:

            from tasks.queue_scheduler import promote_queued_scans
            promoted = promote_queued_scans()

            assert promoted == 0
            assert scan.status == ScanStatus.failed
            assert "exceeded maximum queue wait age" in (scan.notes or "")
            assert scan.dispatched_at is None
            mock_touch.assert_not_called()
            mock_del.assert_called_once_with("mismatched-ttl-uuid")
            mock_delay.assert_not_called()
