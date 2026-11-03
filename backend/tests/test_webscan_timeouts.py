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
        # When ZAP succeeds and Katana future times out, ZAP findings must survive
        def mock_run_zap(scan_id, domain, target_url, auth):
            return [
                {"type": "zap_alert_1", "severity": "High", "evidence": "SQLi | http://target/"},
            ], "2.14.0", False

        def mock_slow_katana(scan_id, domain, target_url):
            time.sleep(2)
            return []

        monkeypatch.setattr("tasks.webscan._run_zap", mock_run_zap)
        monkeypatch.setattr("tasks.webscan._run_katana", mock_slow_katana)
        monkeypatch.setattr("tasks.webscan._WEBSCAN_SOFT_LIMIT", 3)
        monkeypatch.setattr("tasks.webscan._NIKTO_TIMEOUT", 1)

        # Mock concurrent.futures.wait to simulate katana timing out
        import concurrent.futures
        orig_wait = concurrent.futures.wait
        def mock_wait(fs, timeout=None, return_when=None):
            # pretend first future (zap) completed, second (katana) timed out
            fs_list = list(fs)
            return {fs_list[0]}, {fs_list[1]}

        monkeypatch.setattr(concurrent.futures, "wait", mock_wait)

        res = scan_webscan("scan-t2", "example.com")
        assert res["status"] == "partial"
        assert res["finding_count"] >= 1
        assert res["findings"][0]["type"] == "zap_alert_1"

    def test_clean_scan_status_is_success(self, monkeypatch):
        monkeypatch.setattr("tasks.webscan._run_zap", lambda *a, **k: ([], "2.14.0", False))
        monkeypatch.setattr("tasks.webscan._run_katana", lambda *a, **k: [])
        monkeypatch.setattr("tasks.webscan._run_nikto", lambda *a, **k: [])

        res = scan_webscan("scan-clean", "example.com")
        assert res["status"] == "success"
        assert res["finding_count"] == 0
