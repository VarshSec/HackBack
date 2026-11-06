"""
Integration tests for BOLA Candidate Extraction Pipeline within the scan orchestrator and API router.
"""
import uuid
import pytest
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient

from main import app
from models import Scan, ScanStatus
from tasks.scan_orchestrator import _extract_bola_candidates


client = TestClient(app)


class TestBOLAExtractionIntegration:
    def test_extract_bola_candidates_from_module_results(self):
        scan_id = str(uuid.uuid4())
        domain = "target.test"

        module_results = [
            {
                "module": "webscan",
                "status": "success",
                "findings": [
                    {
                        "module": "webscan",
                        "tool": "katana",
                        "type": "crawled_endpoint_katana",
                        "title": "Endpoint discovered: GET /api/v1/users/42/details",
                        "endpoint": "https://target.test/api/v1/users/42/details?view=full",
                    }
                ],
            },
            {
                "module": "enumeration",
                "status": "success",
                "findings": [
                    {
                        "module": "enumeration",
                        "tool": "ffuf",
                        "type": "exposed_path_200",
                        "title": "Path /api/v1/orders/1001 returned HTTP 200",
                        "evidence": "GET https://target.test/api/v1/orders/1001 -> 200 (150 bytes)",
                    }
                ],
            },
            {
                "module": "owasp",
                "status": "success",
                "findings": [
                    {
                        "module": "owasp",
                        "tool": "crawler",
                        "type": "info",
                        "title": "Discovered URL",
                        "target": "https://target.test/api/v1/documents/507f1f77bcf86cd799439011",
                    }
                ],
            },
        ]

        inventory = _extract_bola_candidates(scan_id, domain, module_results)
        assert inventory["total_candidates"] >= 3
        assert inventory["total_resource_candidates"] >= 3

        templates = [c["route_template"] for c in inventory["candidates"]]
        assert any("/users/{user_id}/details" in t for t in templates)
        assert any("/orders/{order_id}" in t for t in templates)
        assert any("/documents/{document_id}" in t for t in templates)

    def test_error_isolation_never_raises(self):
        # Corrupted input should return empty inventory, never raise
        inventory = _extract_bola_candidates("bad-scan", "target.test", None)
        assert inventory["total_candidates"] == 0

    def test_router_get_candidates_endpoint(self, monkeypatch):
        scan_id = uuid.uuid4()
        mock_scan = MagicMock(spec=Scan)
        mock_scan.id = scan_id
        mock_scan.user_id = None
        mock_scan.status = ScanStatus.complete
        mock_scan.raw_findings = {
            "bola_candidates": {
                "total_candidates": 1,
                "total_resource_candidates": 1,
                "candidates": [
                    {
                        "candidate_id": "cand-001",
                        "method": "GET",
                        "route_template": "/api/users/{user_id}",
                    }
                ]
            }
        }

        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.first.return_value = mock_scan

        with patch("database.get_db", return_value=mock_db), \
             patch("routers.scan.get_owned_scan_or_404", return_value=mock_scan):
            response = client.get(f"/api/scan/{scan_id}/candidates")
            assert response.status_code == 200
            data = response.json()
            assert data["total_candidates"] == 1
            assert data["candidates"][0]["route_template"] == "/api/users/{user_id}"
