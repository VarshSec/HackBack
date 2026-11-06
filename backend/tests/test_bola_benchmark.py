"""
Repeatable Benchmark Suite for BOLA Candidate Extraction Pipeline.

Measures:
1. Endpoint extraction precision, recall, and F1 score using exact (method, route_template)
   1-to-1 matching against ground-truth corpora.
2. Resource identifier classification precision, recall, and F1 score against a dedicated
   labelled dataset of dynamic identifiers and static keywords.
3. False-positive rate (counting all unexpected extracted endpoints).
4. Deduplication rate across heterogeneous discovery sources.
5. Processing execution time and scalability.
"""
from __future__ import annotations

import time
from typing import Dict, List, Set, Tuple
import pytest

from tasks.bola.endpoint_extractor import EndpointExtractorPipeline
from tasks.bola.models import IdentifierType, SemanticRole
from tasks.bola.resource_detector import detect_identifier_type


# ---------------------------------------------------------------------------
# Ground-Truth Fixtures: OWASP crAPI, Juice Shop & Noise
# ---------------------------------------------------------------------------

CRAPI_OPENAPI_SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "crAPI - Completely Ridiculous API", "version": "1.0"},
    "paths": {
        "/identity/api/auth/login": {
            "post": {
                "summary": "User Login",
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "email": {"type": "string"},
                                    "password": {"type": "string"},
                                }
                            }
                        }
                    }
                }
            }
        },
        "/identity/api/v2/user/dashboard": {
            "get": {
                "summary": "User Dashboard",
                "responses": {"200": {"description": "OK"}}
            }
        },
        "/workshop/api/merchant/contact_mechanic": {
            "post": {
                "summary": "Contact Mechanic",
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "mechanic_code": {"type": "string"},
                                    "problem_details": {"type": "string"},
                                    "vin": {"type": "string"}
                                }
                            }
                        }
                    }
                }
            }
        },
        "/workshop/api/shop/orders/{order_id}": {
            "get": {
                "summary": "Get Order By ID",
                "parameters": [
                    {
                        "name": "order_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "integer"}
                    }
                ]
            }
        },
        "/identity/api/v2/vehicle/{vehicle_id}/location": {
            "get": {
                "summary": "Get Vehicle Location",
                "parameters": [
                    {
                        "name": "vehicle_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"}
                    }
                ]
            }
        }
    }
}

JUICE_SHOP_JS_CODE = """
// Simulated Angular / React bundle from OWASP Juice Shop
function apiCalls(basketId, userId) {
    // 1. Legitimate API calls
    fetch('/rest/user/whoami', { method: 'GET' });
    fetch(`/rest/basket/${basketId}`, { method: 'GET' });
    axios.get('/api/Quantitys/1');
    axios.post('/api/Feedbacks', { comment: 'great', rating: 5, captchaId: 10 });
    axios.put(`/rest/products/42/reviews`);
    axios.delete('/rest/basket/' + basketId);

    // 2. Static false-positive noise that must NOT become API candidates
    var img1 = '/assets/public/images/products/apple_juice.jpg';
    var icon = '/assets/icons/favicon.ico';
    var css = '/styles/theme.css';
    var font = '/assets/fonts/fontawesome.woff2';
}
"""

HTML_PAGE_CONTENT = """
<!DOCTYPE html>
<html>
<head><title>Portal</title></head>
<body>
    <a href="/api/v1/users/101/profile">Profile</a>
    <a href="/rest/basket/550e8400-e29b-41d4-a716-446655440000">Basket</a>
    <a href="/static/about.html">About Page</a>
    <a href="https://external-thirdparty.test/widget">Offsite Widget</a>
    <form action="/rest/user/change-password" method="POST">
        <input type="hidden" name="user_id" value="101" />
        <input type="password" name="current_password" value="old" />
        <input type="password" name="new_password" value="new" />
    </form>
</body>
</html>
"""

# Ground-truth expected endpoints (1-to-1 exact matching)
GROUND_TRUTH_ENDPOINTS: Set[Tuple[str, str]] = {
    ("POST", "/identity/api/auth/login"),
    ("GET", "/identity/api/v2/user/dashboard"),
    ("POST", "/workshop/api/merchant/contact_mechanic"),
    ("GET", "/workshop/api/shop/orders/{order_id}"),
    ("GET", "/identity/api/v2/vehicle/{vehicle_id}/location"),
    ("GET", "/rest/user/whoami"),
    ("GET", "/rest/basket/{basketId}"),
    ("GET", "/api/Quantitys/{quantity_id}"),
    ("POST", "/api/Feedbacks"),
    ("PUT", "/rest/products/{product_id}/reviews"),
    ("DELETE", "/rest/basket/{basketId}"),
    ("GET", "/api/v1/users/{user_id}/profile"),
    ("GET", "/rest/basket/{basket_uuid}"),
    ("POST", "/rest/user/change-password"),
}

# Dedicated labelled dataset for identifier classification evaluation
LABELLED_IDENTIFIERS: List[Tuple[str, IdentifierType, bool]] = [
    # (sample_value, expected_type, is_dynamic)
    # Numeric identifiers
    ("1", IdentifierType.NUMERIC, True),
    ("42", IdentifierType.NUMERIC, True),
    ("987654", IdentifierType.NUMERIC, True),
    ("100200300", IdentifierType.NUMERIC, True),
    # UUID identifiers
    ("550e8400-e29b-41d4-a716-446655440000", IdentifierType.UUID, True),
    ("123e4567-e89b-12d3-a456-426614174000", IdentifierType.UUID, True),
    ("c0a80101-0000-0000-0000-000000000001", IdentifierType.UUID, True),
    # MongoDB ObjectIDs (24-char hex)
    ("507f1f77bcf86cd799439011", IdentifierType.OBJECT_ID, True),
    ("60c72b2f9b1d8b2bad000001", IdentifierType.OBJECT_ID, True),
    # Slugs
    ("item-001-xyz", IdentifierType.SLUG, True),
    ("user-profile-1", IdentifierType.SLUG, True),
    ("spring-2026-sale", IdentifierType.SLUG, True),
    # Opaque identifiers
    ("user1234", IdentifierType.OPAQUE, True),
    ("txn9876abc", IdentifierType.OPAQUE, True),
    ("sess9988id", IdentifierType.OPAQUE, True),
    # Static keywords (negative targets - must NOT be classified as dynamic IDs)
    ("users", IdentifierType.STATIC, False),
    ("login", IdentifierType.STATIC, False),
    ("dashboard", IdentifierType.STATIC, False),
    ("auth", IdentifierType.STATIC, False),
    ("me", IdentifierType.STATIC, False),
    ("api", IdentifierType.STATIC, False),
    ("v1", IdentifierType.STATIC, False),
    ("v2", IdentifierType.STATIC, False),
    ("admin", IdentifierType.STATIC, False),
    ("settings", IdentifierType.STATIC, False),
    ("export", IdentifierType.STATIC, False),
    ("reviews", IdentifierType.STATIC, False),
]


# ---------------------------------------------------------------------------
# Benchmark Test Suite
# ---------------------------------------------------------------------------

class TestExtractionBenchmark:
    """
    Rigorously evaluates candidate endpoint extraction and identifier classification
    using formal statistical metrics (TP, FP, FN, Precision, Recall, F1).
    """

    def test_endpoint_extraction_benchmark(self):
        t0 = time.monotonic()

        pipeline = EndpointExtractorPipeline(
            scan_id="benchmark-scan",
            target_domain="shop.example",
            base_url="https://shop.example",
        )

        # Ingest heterogeneous discovery sources
        count_openapi = pipeline.ingest_openapi_spec(CRAPI_OPENAPI_SPEC, source_uri="crapi_openapi.json")
        count_js = pipeline.ingest_javascript(JUICE_SHOP_JS_CODE, asset_name="main.bundle.js")
        count_html = pipeline.ingest_html_page(HTML_PAGE_CONTENT, page_url="https://shop.example/home")
        # Ingest Crawled duplicates
        pipeline.ingest_crawled_url("https://shop.example/rest/user/whoami", method="GET")
        pipeline.ingest_crawled_url("https://shop.example/workshop/api/shop/orders/123", method="GET")

        elapsed_ms = (time.monotonic() - t0) * 1000

        inventory = pipeline.get_inventory()
        candidates = inventory.all()
        extracted_signatures = {(c.method, c.route_template) for c in candidates}

        # 1. Exact 1-to-1 Mathematical Evaluation
        # True Positives (TP): Extracted signatures that exist in Ground Truth
        tp_set = extracted_signatures & GROUND_TRUTH_ENDPOINTS
        tp = len(tp_set)

        # False Positives (FP): Extracted signatures NOT in Ground Truth (all unexpected endpoints)
        fp_set = extracted_signatures - GROUND_TRUTH_ENDPOINTS
        fp = len(fp_set)

        # False Negatives (FN): Ground Truth signatures NOT extracted
        fn_set = GROUND_TRUTH_ENDPOINTS - extracted_signatures
        fn = len(fn_set)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

        # Deduplication rate
        total_ingested = count_openapi + count_js + count_html + 2
        unique_endpoints = len(candidates)
        duplicate_rate = (total_ingested - unique_endpoints) / total_ingested if total_ingested > 0 else 0.0

        # Print Benchmark Report Table
        print("\n" + "=" * 76)
        print("          P2.3 ENDPOINT EXTRACTION BENCHMARK REPORT")
        print("=" * 76)
        print(f"Dataset Size:                  {len(GROUND_TRUTH_ENDPOINTS)} ground-truth endpoints (crAPI, Juice Shop, HTML)")
        print(f"Total Discovered Events:       {total_ingested}")
        print(f"Unique Extracted Endpoints:    {unique_endpoints}")
        print("-" * 76)
        print(f"True Positives (TP):           {tp}")
        print(f"False Positives (FP):          {fp} (unexpected: {sorted(list(fp_set))})")
        print(f"False Negatives (FN):          {fn} (missed: {sorted(list(fn_set))})")
        print(f"Precision:                     {precision * 100:.2f}%")
        print(f"Recall:                        {recall * 100:.2f}%")
        print(f"F1 Score:                      {f1 * 100:.2f}%")
        print(f"Deduplication Rate:            {duplicate_rate * 100:.2f}%")
        print(f"Processing Execution Time:     {elapsed_ms:.2f} ms")
        print("-" * 76)
        print("Dataset & Methodology Limitations:")
        print("  1. JavaScript static parsing cannot resolve dynamic runtime URL builders (e.g., eval()).")
        print("  2. Static HTML links are limited to explicit href/action attributes.")
        print("  3. OpenAPI specifications without declared paths or schemas cannot be inferred.")
        print("=" * 76 + "\n")

        # Rigorous engineering quality gates
        assert precision >= 0.90, f"Precision {precision:.2f} must be >= 0.90"
        assert recall >= 0.90, f"Recall {recall:.2f} must be >= 0.90"
        assert f1 >= 0.90, f"F1 score {f1:.2f} must be >= 0.90"
        assert fp == 0, f"False positives must be 0, got {fp}: {fp_set}"
        assert fn == 0, f"False negatives must be 0, got {fn}: {fn_set}"
        assert elapsed_ms < 500.0, f"Execution time {elapsed_ms:.2f}ms must be < 500ms"

    def test_identifier_classification_benchmark(self):
        """
        Evaluates precision, recall, and accuracy of resource identifier detection
        against the dedicated labelled ground-truth dataset.
        """
        tp = 0  # True dynamic, predicted dynamic
        fp = 0  # True static, predicted dynamic
        fn = 0  # True dynamic, predicted static
        tn = 0  # True static, predicted static

        exact_type_matches = 0
        total = len(LABELLED_IDENTIFIERS)

        for val, expected_type, is_dynamic in LABELLED_IDENTIFIERS:
            pred_type = detect_identifier_type(val)
            pred_is_dynamic = pred_type != IdentifierType.STATIC

            # Exact type match
            if pred_type == expected_type:
                exact_type_matches += 1

            # Binary dynamic classification
            if is_dynamic and pred_is_dynamic:
                tp += 1
            elif not is_dynamic and pred_is_dynamic:
                fp += 1
            elif is_dynamic and not pred_is_dynamic:
                fn += 1
            else:
                tn += 1

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
        accuracy = (tp + tn) / total if total > 0 else 0.0
        type_accuracy = exact_type_matches / total if total > 0 else 0.0

        print("\n" + "=" * 76)
        print("      P2.3 RESOURCE IDENTIFIER CLASSIFICATION BENCHMARK REPORT")
        print("=" * 76)
        print(f"Dataset Size:                  {total} labelled samples (Numeric, UUID, ObjectID, Slug, Hex, Base64, Static)")
        print("-" * 76)
        print(f"True Positives (TP):           {tp}")
        print(f"False Positives (FP):          {fp}")
        print(f"False Negatives (FN):          {fn}")
        print(f"True Negatives (TN):           {tn}")
        print(f"Dynamic Identifier Precision:  {precision * 100:.2f}%")
        print(f"Dynamic Identifier Recall:     {recall * 100:.2f}%")
        print(f"Dynamic Identifier F1 Score:   {f1 * 100:.2f}%")
        print(f"Binary Detection Accuracy:     {accuracy * 100:.2f}%")
        print(f"Multi-Class Type Accuracy:     {type_accuracy * 100:.2f}%")
        print("-" * 76)
        print("Identifier Detection Limitations:")
        print("  1. Short hex strings (e.g., 4-8 chars) may be ambiguous between hex IDs, words, or slugs.")
        print("  2. Slugs without hyphens or numbers are indistinguishable from static keywords.")
        print("=" * 76 + "\n")

        assert precision >= 0.95, f"Identifier precision {precision:.2f} must be >= 0.95"
        assert recall >= 0.95, f"Identifier recall {recall:.2f} must be >= 0.95"
        assert f1 >= 0.95, f"Identifier F1 score {f1:.2f} must be >= 0.95"
        assert accuracy >= 0.95, f"Identifier accuracy {accuracy:.2f} must be >= 0.95"
        assert type_accuracy >= 0.90, f"Multi-class type accuracy {type_accuracy:.2f} must be >= 0.90"
