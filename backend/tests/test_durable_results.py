import pytest
from unittest.mock import MagicMock, patch

from tasks.base_task import (
    persist_module_result,
    get_persisted_module_results,
    build_module_result,
)
from tasks.scan_orchestrator import _reconcile_module_results, _failed_modules


class TestDurableModuleResults:
    def test_persist_module_result_executes_atomic_jsonb_update(self):
        db = MagicMock()
        with patch("database.SessionLocal", return_value=db):
            persist_module_result("scan-123", "owasp", {
                "module": "owasp",
                "status": "success",
                "findings": [{"type": "xss", "severity": "High"}],
                "finding_count": 1,
            })

        db.query.assert_not_called()
        db.execute.assert_called_once()
        sql_text = str(db.execute.call_args.args[0])
        assert "jsonb_set" in sql_text
        assert "interim_results" in sql_text
        db.commit.assert_called_once()
        db.close.assert_called_once()

    def test_get_persisted_module_results_extracts_interim_results(self):
        mock_scan = MagicMock()
        mock_scan.raw_findings = {
            "interim_results": {
                "headers": {"module": "headers", "status": "success", "findings": []},
                "owasp": {"module": "owasp", "status": "success", "findings": [{"type": "sqli"}]},
            }
        }
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = mock_scan

        with patch("database.SessionLocal", return_value=db):
            results = get_persisted_module_results("scan-123")

        assert "headers" in results
        assert "owasp" in results
        assert results["owasp"]["findings"][0]["type"] == "sqli"

    def test_reconcile_module_results_merges_persisted_results(self):
        # Scenario: One module succeeded earlier and was persisted in DB, but was missing from transient chord results
        persisted = {
            "headers": {"module": "headers", "status": "success", "findings": [{"type": "missing_hsts"}]},
            "recon": {"module": "recon", "status": "success", "findings": []},
        }
        chord_results = [
            {"module": "recon", "status": "success", "findings": []},
            {"module": "ssl_tls", "status": "success", "findings": []},
        ]

        with patch("tasks.base_task.get_persisted_module_results", return_value=persisted), \
             patch("tasks.base_task.module_ids_for_mode", return_value=["headers", "recon", "ssl_tls"]):
            reconciled = _reconcile_module_results(chord_results, "scan-456")

        reconciled_by_mod = {r["module"]: r for r in reconciled}
        # headers was recovered from persisted results
        assert "headers" in reconciled_by_mod
        assert reconciled_by_mod["headers"]["status"] == "success"
        assert len(reconciled_by_mod["headers"]["findings"]) == 1

    def test_distinguish_empty_successful_result_from_missing_result(self):
        # Module that ran cleanly with zero findings has status='success'
        clean_result = build_module_result("headers", findings=[], status="success")
        assert clean_result["status"] == "success"
        assert clean_result["findings"] == []

        # Reconcile when a module never returned any result:
        with patch("tasks.base_task.get_persisted_module_results", return_value={}), \
             patch("tasks.base_task.module_ids_for_mode", return_value=["webscan"]):
            reconciled = _reconcile_module_results([], "scan-missing")

        assert len(reconciled) == 1
        assert reconciled[0]["module"] == "webscan"
        assert reconciled[0]["status"] == "failed"
        assert "missing" in reconciled[0]["error"].lower()

    def test_failed_modules_distinguishes_partial_from_failed(self):
        results = [
            {"module": "headers", "status": "success"},
            {"module": "webscan", "status": "partial"},  # partial is not a failure trigger
            {"module": "owasp", "status": "timeout"},
            {"module": "recon", "status": "failed"},
        ]
        failed = _failed_modules(results)
        assert failed == ["owasp", "recon"]
        assert "webscan" not in failed
        assert "headers" not in failed

    def test_dispatch_preserves_partial_findings_on_failure_retry(self, monkeypatch):
        from tasks.dispatch import dispatch_scan

        # Persisted findings exist from an earlier attempt
        persisted_store = {
            "owasp": {
                "module": "owasp",
                "status": "partial",
                "findings": [{"type": "sqli", "severity": "High"}],
            }
        }
        monkeypatch.setattr("tasks.base_task.get_persisted_module_results", lambda s_id: persisted_store)

        saved = []
        def mock_persist(s_id, mod, envelope):
            saved.append(envelope)
        monkeypatch.setattr("tasks.base_task.persist_module_result", mock_persist)

        # Mock pure_fn to fail with empty findings
        monkeypatch.setattr("tasks.dispatch._pure_fn", lambda mod: lambda s_id, dom, auth: build_module_result(mod, [], status="failed"))

        res = dispatch_scan("owasp", "scan-789", "example.com")
        # Previous findings must be recovered and preserved
        assert res["status"] == "partial"
        assert len(res["findings"]) == 1
        assert res["findings"][0]["type"] == "sqli"
        assert len(saved) == 1
        assert saved[0]["findings"][0]["type"] == "sqli"
