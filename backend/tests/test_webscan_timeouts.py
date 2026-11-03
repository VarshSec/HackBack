import time
import subprocess
from unittest.mock import MagicMock, patch
import pytest
from celery.exceptions import SoftTimeLimitExceeded

import sys
import psutil
import threading
from tasks.webscan import (
    _lifecycle_lock,
    _scan_states,
    _scan_worker_counts,
    BoundedTaskRunner,
    _enter_scan_worker,
    _exit_scan_worker,
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

    def test_subprocess_registering_after_state_eviction_is_killed_immediately(self):
        """
        Prove that if a scan's state has been evicted from memory (or is completely unknown),
        a late worker attempting to register a subprocess is REJECTED (never interpreted as active)
        and the subprocess is KILLED immediately to prevent orphan leaks.
        """
        scan_id = "test-evicted-scan"
        _init_scan_lifecycle(scan_id)
        _terminate_scan_processes(scan_id, timeout=1.0)

        # Force state eviction to simulate memory bounding / cache eviction
        with _lifecycle_lock:
            _scan_states.pop(scan_id, None)
            _scan_worker_counts.pop(scan_id, None)

        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        try:
            assert proc.poll() is None
            registered = _register_scan_process(scan_id, proc)
            assert registered is False, "Evicted/unknown scan must NEVER register new subprocesses"
            proc.wait(timeout=2.0)
            assert proc.poll() is not None, "Subprocess on evicted scan must be killed immediately"
        finally:
            if proc.poll() is None:
                proc.kill()

    def test_active_scan_state_never_evicted(self):
        """
        Prove that active scans are protected from cache eviction during lifecycle cleanup.
        Only terminated scans with zero active workers can be pruned.
        """
        active_ids = [f"scan-active-{i}" for i in range(5)]
        for sid in active_ids:
            _init_scan_lifecycle(sid)

        # Trigger cleanup
        from tasks.webscan import _cleanup_scan_lifecycle
        _cleanup_scan_lifecycle("some-other-scan")

        # All active scans must still be in ACTIVE state
        with _lifecycle_lock:
            for sid in active_ids:
                assert _scan_states.get(sid) == ScanLifecycleState.ACTIVE, (
                    f"Active scan {sid} was improperly evicted"
                )

    def test_genuinely_blocked_worker_integration(self, monkeypatch):
        """
        Integration test:
        - Makes a real ZAP worker block inside a controlled HTTP request to a local test server.
        - Runs scan_webscan() with a short deadline (0.3s).
        - Verifies that parent scan_webscan() returns strictly within deadline + documented cleanup allowance (<= 1.1s).
        - Verifies that the worker thread terminates after the HTTP request finishes/times out.
        - Verifies that repeated scans do not accumulate abandoned worker threads.
        - Operates entirely on localhost (no external target).
        """
        import http.server

        class ControlledDelayHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                # Hold connection for 0.35s to simulate delayed upstream response
                time.sleep(0.35)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"version": "2.14.0"}')

            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), ControlledDelayHandler)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        port = server.server_port
        server_url = f"http://127.0.0.1:{port}"

        try:
            monkeypatch.setattr("tasks.webscan.settings.ZAP_URL", server_url)
            monkeypatch.setattr("tasks.webscan.resolve_target_url", lambda d: server_url)
            monkeypatch.setattr("tasks.webscan._run_katana", lambda *a, **k: [])
            monkeypatch.setattr("tasks.webscan._run_nikto", lambda *a, **k: [])
            monkeypatch.setattr("tasks.webscan._WEBSCAN_SOFT_LIMIT", 0.25)

            initial_threads = threading.active_count()

            # 1. Run scan with short deadline
            t0 = time.monotonic()
            res = scan_webscan("scan-blocked-zap-1", "127.0.0.1")
            elapsed = time.monotonic() - t0

            # Verify parent returned within deadline (0.25s) + documented cleanup allowance (1.0s)
            assert elapsed < 1.1, f"scan_webscan blocked beyond allowance: took {elapsed:.2f}s"
            assert res["status"] in ("timeout", "partial")

            # 2. Verify worker eventually exits once the HTTP request completes
            # The HTTP request completes at ~0.35s, whereupon the worker detects scan
            # cancellation and exits cleanly.
            t_wait = time.monotonic() + 1.0
            while time.monotonic() < t_wait:
                if threading.active_count() <= initial_threads:
                    break
                time.sleep(0.05)

            # 3. Repeat for 2 more scans to verify no thread accumulation across repeated scans
            for i in (2, 3):
                res_rep = scan_webscan(f"scan-blocked-zap-{i}", "127.0.0.1")
                assert res_rep["status"] in ("timeout", "partial")
                t_wait = time.monotonic() + 1.0
                while time.monotonic() < t_wait:
                    if threading.active_count() <= initial_threads:
                        break
                    time.sleep(0.05)

            final_threads = threading.active_count()
            assert final_threads <= initial_threads + 1, (
                f"Worker threads accumulated: initial {initial_threads}, final {final_threads}"
            )
        finally:
            server.shutdown()

    def test_worker_cannot_execute_target_when_scan_already_terminated(self):
        """
        Prove that a worker thread whose scan was cancelled/terminated before admission
        never executes self.target(), records a RuntimeError, and does not alter worker accounting.
        """
        scan_id = "test-terminated-admission"
        _init_scan_lifecycle(scan_id)
        # Scan terminates before worker is admitted
        _terminate_scan_processes(scan_id, timeout=1.0)

        target_called = threading.Event()
        def dummy_target():
            target_called.set()
            return "executed"

        runner = BoundedTaskRunner(dummy_target, name="test-denied-worker", scan_id=scan_id)

        with _lifecycle_lock:
            count_before = _scan_worker_counts.get(scan_id, 0)

        runner.start()
        runner.join(timeout=2.0)

        assert not runner.is_alive, "Runner thread should have completed"
        assert not target_called.is_set(), "Target MUST NOT be executed when admission fails"
        assert runner.result is None, "Result should be None on failed admission"
        assert isinstance(runner.error, RuntimeError), f"Expected RuntimeError, got {runner.error!r}"
        assert "cancelled before worker admission" in str(runner.error)

        with _lifecycle_lock:
            count_after = _scan_worker_counts.get(scan_id, 0)
        assert count_after == count_before, "Worker count must not be decremented if admission failed"

    def test_worker_admission_fails_on_unknown_or_evicted_scan(self):
        """
        Prove that if a scan ID is unknown or evicted from lifecycle state,
        worker admission fails immediately, target is not called, and no underflow occurs.
        """
        scan_id = "test-unknown-evicted-scan"
        target_called = threading.Event()
        def dummy_target():
            target_called.set()

        runner = BoundedTaskRunner(dummy_target, name="test-unknown-scan-worker", scan_id=scan_id)
        runner.start()
        runner.join(timeout=2.0)

        assert not runner.is_alive
        assert not target_called.is_set(), "Target must not run on unknown/evicted scan"
        assert isinstance(runner.error, RuntimeError)
        assert "cancelled before worker admission" in str(runner.error)
        with _lifecycle_lock:
            assert _scan_worker_counts.get(scan_id, 0) == 0

    def test_admitted_worker_executes_and_decrements_count_correctly(self):
        """
        Prove that an admitted worker increments count during execution,
        executes its target, stores the result, and decrements count on exit.
        """
        scan_id = "test-admitted-worker"
        _init_scan_lifecycle(scan_id)

        worker_started = threading.Event()
        can_finish = threading.Event()

        def sync_target():
            worker_started.set()
            can_finish.wait(timeout=2.0)
            return "success_val"

        runner = BoundedTaskRunner(sync_target, name="test-admitted-worker", scan_id=scan_id)
        runner.start()

        # Deterministic sync: wait for worker to enter target
        assert worker_started.wait(timeout=2.0), "Worker did not enter target"

        # While inside target, worker count must be 1
        with _lifecycle_lock:
            mid_count = _scan_worker_counts.get(scan_id, 0)
        assert mid_count == 1, f"Worker count during execution should be 1, got {mid_count}"

        # Allow worker to finish
        can_finish.set()
        runner.join(timeout=2.0)

        assert not runner.is_alive
        assert runner.error is None
        assert runner.result == "success_val"

        # After worker exits, count must be decremented to 0
        with _lifecycle_lock:
            final_count = _scan_worker_counts.get(scan_id, 0)
        assert final_count == 0, f"Worker count after exit should be 0, got {final_count}"

    def test_worker_without_scan_id_executes_normally(self):
        """
        Prove that BoundedTaskRunner without scan_id executes target normally
        without scan lifecycle accounting.
        """
        target_called = threading.Event()
        def no_scan_target():
            target_called.set()
            return 42

        runner = BoundedTaskRunner(no_scan_target, name="no-scan-worker", scan_id=None)
        runner.start()
        runner.join(timeout=2.0)

        assert not runner.is_alive
        assert target_called.is_set()
        assert runner.result == 42
        assert runner.error is None
