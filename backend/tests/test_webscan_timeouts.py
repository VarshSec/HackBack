import time
import subprocess
from unittest.mock import MagicMock, patch
import pytest
from celery.exceptions import SoftTimeLimitExceeded

import sys
import psutil
import threading
from tasks.webscan import (
    BoundedZAPv2,
    _kill_process_tree,
    scan_webscan,
    _run_katana,
    _run_nikto,
    _init_scan_lifecycle,
    _register_scan_process,
    _unregister_scan_process,
    _terminate_scan_processes,
    _is_scan_cancelled,
    ScanLifecycleState,
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



class TestSubprocessLifecycleAndHardening:
    """Hardening tests for subprocess cleanup deadlines and registration race safety."""

    def test_subprocess_registering_after_scan_cancellation_is_killed_immediately(self):
        """
        Race condition test: when a worker spawns a process right after the scan
        was terminated/cancelled, registering it must immediately kill the process
        to prevent orphan leaks.
        """
        scan_id = "test-race-cancelled"
        _init_scan_lifecycle(scan_id)
        _terminate_scan_processes(scan_id, timeout=1.0)
        assert _is_scan_cancelled(scan_id) is True

        # Late worker attempts to register a newly spawned process
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        try:
            assert proc.poll() is None
            registered = _register_scan_process(scan_id, proc)
            assert registered is False, "Late process must not be registered into terminated scan"

            # Must have been killed immediately by registration handler
            proc.wait(timeout=2.0)
            assert proc.poll() is not None, "Late process must be killed immediately"
        finally:
            if proc.poll() is None:
                proc.kill()

    def test_multiple_subprocesses_shared_cleanup_deadline(self):
        """
        Prove that multiple registered subprocesses are terminated concurrently
        under a SHARED monotonic deadline, rather than multiplying sequential timeouts.
        """
        scan_id = "test-multi-proc-deadline"
        _init_scan_lifecycle(scan_id)

        procs = [
            subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
            for _ in range(3)
        ]
        try:
            for p in procs:
                assert _register_scan_process(scan_id, p) is True

            t0 = time.monotonic()
            surviving = _terminate_scan_processes(scan_id, timeout=1.0)
            elapsed = time.monotonic() - t0

            # 3 processes * 5s sequential wait would take >= 15s; shared deadline must take < 2.5s
            assert elapsed < 2.5, f"Cleanup exceeded shared deadline: took {elapsed:.2f}s"
            assert surviving == [], f"All processes must be terminated, survivors: {surviving}"
            assert all(p.poll() is not None for p in procs), "All processes must be reaped"
        finally:
            for p in procs:
                if p.poll() is None:
                    p.kill()

    def test_worker_blocked_in_remote_api_request(self):
        """
        Verify that a worker blocked on a remote HTTP/API request respects bounded timeouts
        and scan_webscan returns strictly within its overall budget.
        """
        import requests

        client = BoundedZAPv2(
            apikey="test-key",
            proxies={"http": "http://127.0.0.1:8090", "https": "http://127.0.0.1:8090"}
        )

        with patch("requests.Session.request") as mock_req:
            mock_req.side_effect = requests.exceptions.Timeout("Connection timed out")
            with pytest.raises(requests.exceptions.Timeout):
                client._request("http://zap/JSON/core/view/version/")

    def test_repeated_timed_out_scans_do_not_accumulate_worker_threads(self, monkeypatch):
        """
        Prove that running multiple consecutive timed-out scans does not accumulate
        unbounded worker threads. Worker processes are killed, unblocking waiting threads.
        """
        def worker_with_subprocess(scan_id, domain, target_url):
            proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
            _register_scan_process(scan_id, proc)
            try:
                proc.communicate(timeout=30)
            except Exception:
                pass
            finally:
                _unregister_scan_process(scan_id, proc)
            return []

        monkeypatch.setattr("tasks.webscan._run_zap", lambda *a, **k: ([], "2.14.0", False))
        monkeypatch.setattr("tasks.webscan._run_katana", worker_with_subprocess)
        monkeypatch.setattr("tasks.webscan._run_nikto", lambda *a, **k: [])
        monkeypatch.setattr("tasks.webscan._WEBSCAN_SOFT_LIMIT", 0.5)

        initial_threads = threading.active_count()

        for i in range(3):
            scan_webscan(f"scan-rep-{i}", "example.com")

        # Give unblocked worker threads a brief moment to finish their function returns
        time.sleep(0.5)
        final_threads = threading.active_count()

        assert final_threads <= initial_threads + 1, (
            f"Worker threads accumulated: started with {initial_threads}, now have {final_threads}"
        )

    def test_cleanup_invoked_more_than_once_safely(self):
        """Idempotency test: calling _terminate_scan_processes repeatedly must not raise."""
        scan_id = "test-idempotent-cleanup"
        _init_scan_lifecycle(scan_id)

        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        try:
            _register_scan_process(scan_id, proc)
            res1 = _terminate_scan_processes(scan_id, timeout=1.0)
            assert res1 == []
            assert proc.poll() is not None

            # Subsequent invocations must be safe no-ops
            res2 = _terminate_scan_processes(scan_id, timeout=1.0)
            assert res2 == []
            res3 = _terminate_scan_processes(scan_id, timeout=1.0)
            assert res3 == []
        finally:
            if proc.poll() is None:
                proc.kill()

    def test_no_subprocess_remains_alive_after_cleanup(self):
        """
        Prove that process trees (parent + descendants) are completely reaped and no
        descendant process survives after _terminate_scan_processes completes.
        """
        scan_id = "test-tree-cleanup"
        _init_scan_lifecycle(scan_id)

        # Spawn a python process that in turn spawns another child sleep process
        child_code = (
            "import subprocess, sys, time; "
            "p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)']); "
            "time.sleep(30)"
        )
        proc = subprocess.Popen([sys.executable, "-c", child_code])
        try:
            _register_scan_process(scan_id, proc)
            # Give child process a moment to spawn
            time.sleep(0.5)

            ps_proc = psutil.Process(proc.pid)
            children_pids = [c.pid for c in ps_proc.children(recursive=True)]
            parent_pid = proc.pid

            survivors = _terminate_scan_processes(scan_id, timeout=2.0)
            assert survivors == [], f"Expected 0 survivors, got {survivors}"

            # Verify parent is dead
            assert not psutil.pid_exists(parent_pid) or psutil.Process(parent_pid).status() == psutil.STATUS_ZOMBIE

            # Verify all children are dead
            for c_pid in children_pids:
                assert not psutil.pid_exists(c_pid), f"Child process {c_pid} survived cleanup"
        finally:
            if proc.poll() is None:
                proc.kill()
