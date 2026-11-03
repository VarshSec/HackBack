import time
import subprocess
from unittest.mock import MagicMock, patch
import pytest
from celery.exceptions import SoftTimeLimitExceeded

from tasks.webscan import (
    BoundedZAPv2,
    _kill_process_tree,
    scan_webscan,
    _run_katana,
    _run_nikto,
    _ZAP_API_CONNECT_TIMEOUT,
    _ZAP_API_READ_TIMEOUT,
)


class TestBoundedZAPv2:
    def test_zap_api_enforces_timeouts(self):
        client = BoundedZAPv2(
            apikey="test-key",
            proxies={"http": "http://127.0.0.1:8090", "https": "http://127.0.0.1:8090"}
        )
        with patch("requests.Session.request") as mock_req:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {"version": "2.14.0"}
            mock_req.return_value = mock_resp

            client._request("http://zap/JSON/core/view/version/")
            mock_req.assert_called_once()
            _, kwargs = mock_req.call_args
            assert "timeout" in kwargs
            assert kwargs["timeout"] == (_ZAP_API_CONNECT_TIMEOUT, _ZAP_API_READ_TIMEOUT)


class TestProcessTreeCleanup:
    def test_kill_process_tree_handles_none_gracefully(self):
        _kill_process_tree(None)  # Must not raise

    def test_kill_process_tree_terminates_proc(self):
        # Spawn a dummy sleep process
        import sys
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"])
        assert proc.poll() is None
        _kill_process_tree(proc, timeout=1.0)
        assert proc.poll() is not None


class TestWebscanTimeoutAndPartialResults:
    def test_soft_time_limit_exceeded_preserves_findings(self, monkeypatch):
        # If SoftTimeLimitExceeded is raised after finding some items, they must be returned in the envelope
        def mock_run_zap(scan_id, domain, target_url, auth):
            return [{"type": "zap_finding", "severity": "Medium", "evidence": "XSS"}], "2.14.0", False

        def mock_run_katana(scan_id, domain, target_url):
            raise SoftTimeLimitExceeded()

        monkeypatch.setattr("tasks.webscan._run_zap", mock_run_zap)
        monkeypatch.setattr("tasks.webscan._run_katana", mock_run_katana)

        res = scan_webscan("scan-t1", "example.com")
        assert res["status"] in ("partial", "timeout")
        assert res["finding_count"] == 1
        assert res["findings"][0]["evidence"] == "XSS"

    def test_one_scanner_timeout_preserves_other_scanner_findings(self, monkeypatch):
        # When ZAP succeeds and Katana times out, ZAP findings must survive
        def mock_run_zap(scan_id, domain, target_url, auth):
            return [
                {"type": "zap_alert_1", "severity": "High", "evidence": "SQLi | http://target/"},
            ], "2.14.0", False

        def mock_slow_katana(scan_id, domain, target_url):
            time.sleep(10)
            return []

        monkeypatch.setattr("tasks.webscan._run_zap", mock_run_zap)
        monkeypatch.setattr("tasks.webscan._run_katana", mock_slow_katana)
        monkeypatch.setattr("tasks.webscan._WEBSCAN_SOFT_LIMIT", 1)
        monkeypatch.setattr("tasks.webscan._NIKTO_TIMEOUT", 1)

        t0 = time.monotonic()
        res = scan_webscan("scan-t2", "example.com")
        duration = time.monotonic() - t0

        assert duration < 3.0, f"scan_webscan took too long: {duration}s"
        assert res["status"] == "partial"
        assert res["finding_count"] >= 1
        assert res["findings"][0]["type"] == "zap_alert_1"

    def test_deliberately_blocked_worker_returns_within_deadline(self, monkeypatch):
        """
        Regression test: prove that scan_webscan returns strictly within its deadline
        even when a worker thread is deliberately blocked indefinitely (e.g. infinite loop / hung socket).
        """
        def blocked_worker(*args, **kwargs):
            while True:
                time.sleep(0.1)

        monkeypatch.setattr("tasks.webscan._run_zap", blocked_worker)
        monkeypatch.setattr("tasks.webscan._run_katana", lambda *a, **k: [])
        monkeypatch.setattr("tasks.webscan._run_nikto", lambda *a, **k: [])
        monkeypatch.setattr("tasks.webscan._WEBSCAN_SOFT_LIMIT", 1)

        t0 = time.monotonic()
        res = scan_webscan("scan-blocked-1", "example.com")
        elapsed = time.monotonic() - t0

        assert elapsed < 2.5, f"Blocked worker held scan_webscan for {elapsed}s (must be < 2.5s)"
        assert res["status"] in ("timeout", "partial")
        assert "timed out" in res.get("error", "").lower()

    def test_deliberately_blocked_worker_preserves_partial_findings(self, monkeypatch):
        """
        Regression test: prove that when one worker is blocked indefinitely,
        findings from the other finished worker are completely preserved and returned as 'partial'.
        """
        mock_findings = [
            {"type": "zap_finding_1", "severity": "High", "evidence": "SQLi proof", "found_by": ["webscan"]}
        ]

        def fast_zap(*args, **kwargs):
            return mock_findings, "2.14.0", False

        def blocked_katana(*args, **kwargs):
            while True:
                time.sleep(0.1)

        monkeypatch.setattr("tasks.webscan._run_zap", fast_zap)
        monkeypatch.setattr("tasks.webscan._run_katana", blocked_katana)
        monkeypatch.setattr("tasks.webscan._run_nikto", lambda *a, **k: [])
        monkeypatch.setattr("tasks.webscan._WEBSCAN_SOFT_LIMIT", 1)

        t0 = time.monotonic()
        res = scan_webscan("scan-blocked-2", "example.com")
        elapsed = time.monotonic() - t0

        assert elapsed < 2.5, f"Blocked worker held scan_webscan for {elapsed}s (must be < 2.5s)"
        assert res["status"] == "partial"
        assert res["finding_count"] == 1
        assert res["findings"][0]["evidence"] == "SQLi proof"

    def test_clean_scan_status_is_success(self, monkeypatch):
        monkeypatch.setattr("tasks.webscan._run_zap", lambda *a, **k: ([], "2.14.0", False))
        monkeypatch.setattr("tasks.webscan._run_katana", lambda *a, **k: [])
        monkeypatch.setattr("tasks.webscan._run_nikto", lambda *a, **k: [])

        res = scan_webscan("scan-clean", "example.com")
        assert res["status"] == "success"
        assert res["finding_count"] == 0
