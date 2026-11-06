"""
Comprehensive unit tests for BOLA discovery adapters, deduplication, and evidence tracking.
"""
import pytest
from tasks.bola.models import (
    CandidateEndpoint,
    IdentifierType,
    ParameterLocation,
    SemanticRole,
)
from tasks.bola.openapi_parser import OpenAPIParser
from tasks.bola.javascript_parser import JavaScriptParser
from tasks.bola.html_parser import HTMLPageParser
from tasks.bola.candidate_store import CandidateStore
from tasks.bola.endpoint_extractor import EndpointExtractorPipeline
from tasks.bola.scope import is_url_in_scope


# ---------------------------------------------------------------------------
# OpenAPI / Swagger Tests
# ---------------------------------------------------------------------------

class TestOpenAPIParser:
    def test_openapi_3_extraction_with_local_refs_and_request_body(self):
        spec = {
            "openapi": "3.0.0",
            "info": {"title": "Test Shop API", "version": "1.0"},
            "paths": {
                "/api/users/{userId}": {
                    "get": {
                        "operationId": "getUser",
                        "summary": "Fetch user by ID",
                        "parameters": [
                            {
                                "name": "userId",
                                "in": "path",
                                "required": True,
                                "schema": {"type": "integer"},
                            },
                            {
                                "name": "include_orders",
                                "in": "query",
                                "schema": {"type": "boolean"},
                            }
                        ],
                    },
                    "put": {
                        "operationId": "updateUser",
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/UserUpdate"}
                                }
                            }
                        }
                    }
                }
            },
            "components": {
                "schemas": {
                    "UserUpdate": {
                        "type": "object",
                        "properties": {
                            "email": {"type": "string"},
                            "profile_id": {"type": "string"},
                            "password": {"type": "string"}
                        }
                    }
                }
            }
        }

        parser = OpenAPIParser(spec, source_uri="spec.json")
        candidates = parser.extract_candidates(scan_id="test-scan", target_domain="shop.example")

        assert len(candidates) == 2

        get_candidate = next(c for c in candidates if c.method == "GET")
        assert get_candidate.route_template == "/api/users/{userId}"
        assert len(get_candidate.parameters) >= 2
        p_user = next(p for p in get_candidate.parameters if p.name == "userId")
        assert p_user.location == ParameterLocation.PATH
        assert p_user.identifier_type == IdentifierType.NUMERIC
        assert p_user.semantic_role in (SemanticRole.USER_IDENTITY, SemanticRole.RESOURCE_IDENTIFIER)

        put_candidate = next(c for c in candidates if c.method == "PUT")
        assert put_candidate.route_template == "/api/users/{userId}"
        # Check body parameter extraction from $ref
        p_profile = next(p for p in put_candidate.parameters if "profile_id" in p.name)
        assert p_profile.location == ParameterLocation.BODY_JSON
        assert p_profile.semantic_role == SemanticRole.USER_IDENTITY

        # Sensitive password field must be redacted
        p_pass = next(p for p in put_candidate.parameters if "password" in p.name)
        assert p_pass.is_redacted is True
        assert p_pass.sample_value is None or p_pass.sample_value == "[REDACTED]"

    def test_swagger_2_extraction(self):
        swagger_spec = """
swagger: "2.0"
info:
  title: "Legacy Store"
  version: "1.0"
paths:
  /orders/{order_id}:
    delete:
      operationId: deleteOrder
      parameters:
        - name: order_id
          in: path
          required: true
          type: string
        - name: admin_token
          in: header
          type: string
"""
        parser = OpenAPIParser(swagger_spec, source_uri="swagger.yaml")
        candidates = parser.extract_candidates(scan_id="test-scan", target_domain="legacy.example")

        assert len(candidates) == 1
        c = candidates[0]
        assert c.method == "DELETE"
        assert c.route_template == "/orders/{order_id}"
        p_token = next(p for p in c.parameters if p.name == "admin_token")
        assert p_token.is_redacted is True
        assert p_token.semantic_role == SemanticRole.SESSION_TOKEN

    def test_remote_external_ref_is_strictly_rejected_ssrf_guard(self):
        spec = {
            "openapi": "3.0.0",
            "paths": {
                "/api/test": {
                    "get": {
                        "parameters": [
                            {"$ref": "http://169.254.169.254/latest/meta-data/"},
                            {"$ref": "https://malicious.evil/steal"},
                            {"$ref": "file:///etc/passwd"}
                        ]
                    }
                }
            }
        }
        parser = OpenAPIParser(spec)
        assert parser.resolve_ref("http://169.254.169.254/latest/meta-data/") is None
        assert parser.resolve_ref("https://malicious.evil/steal") is None
        assert parser.resolve_ref("file:///etc/passwd") is None

    def test_circular_ref_handling_does_not_infinite_loop(self):
        spec = {
            "openapi": "3.0.0",
            "components": {
                "schemas": {
                    "Node": {
                        "type": "object",
                        "properties": {
                            "child": {"$ref": "#/components/schemas/Node"}
                        }
                    }
                }
            }
        }
        parser = OpenAPIParser(spec)
        res = parser.resolve_ref("#/components/schemas/Node")
        assert res is not None

    def test_openapi_security_inheritance_rules(self):
        spec = {
            "openapi": "3.0.0",
            "info": {"title": "Secured API", "version": "1.0"},
            "security": [{"bearerAuth": []}],  # Root-level security
            "paths": {
                "/api/inherited": {
                    "get": {
                        "summary": "Inherits root security",
                        "responses": {"200": {"description": "OK"}},
                    }
                },
                "/api/public": {
                    "get": {
                        "summary": "Explicitly public operation",
                        "security": [],  # Explicit empty security: must be anonymous
                        "responses": {"200": {"description": "OK"}},
                    }
                },
                "/api/custom-auth": {
                    "get": {
                        "summary": "Explicit custom auth",
                        "security": [{"apiKeyAuth": []}],
                        "responses": {"200": {"description": "OK"}},
                    }
                },
            }
        }
        parser = OpenAPIParser(spec)
        candidates = parser.extract_candidates(scan_id="sec-scan", target_domain="sec.example")
        assert len(candidates) == 3

        c_inherited = next(c for c in candidates if c.route_template == "/api/inherited")
        assert c_inherited.authentication_context == "primary"

        c_public = next(c for c in candidates if c.route_template == "/api/public")
        assert c_public.authentication_context == "anonymous"

        c_custom = next(c for c in candidates if c.route_template == "/api/custom-auth")
        assert c_custom.authentication_context == "primary"

        # Case where root has no security
        spec_no_root = {
            "openapi": "3.0.0",
            "paths": {
                "/api/anon": {
                    "get": {
                        "summary": "Default anon when no root security",
                        "responses": {"200": {"description": "OK"}},
                    }
                },
                "/api/protected": {
                    "get": {
                        "summary": "Operation with auth even without root",
                        "security": [{"oauth2": []}],
                        "responses": {"200": {"description": "OK"}},
                    }
                }
            }
        }
        parser_no_root = OpenAPIParser(spec_no_root)
        cands_no_root = parser_no_root.extract_candidates(scan_id="sec-scan", target_domain="sec.example")
        assert len(cands_no_root) == 2

        c_anon = next(c for c in cands_no_root if c.route_template == "/api/anon")
        assert c_anon.authentication_context == "anonymous"

        c_prot = next(c for c in cands_no_root if c.route_template == "/api/protected")
        assert c_prot.authentication_context == "primary"


class TestURLScopeEnforcement:
    def test_scope_allowed_targets(self):
        # 1. Exact target host is allowed
        in_scope, res = is_url_in_scope("https://target.test/api/v1", "target.test")
        assert in_scope is True
        assert res == "https://target.test/api/v1"

        # 2. Explicitly approved subdomain is allowed when listed in configuration
        in_scope, res = is_url_in_scope(
            "https://api.target.test/v1/users", "target.test", allowed_subdomains=["api.target.test"]
        )
        assert in_scope is True
        assert res == "https://api.target.test/v1/users"

        # 3. Trailing-dot and case normalization
        in_scope, res = is_url_in_scope("https://TARGET.TEST.:8080/api/v1", "target.test.")
        assert in_scope is True
        assert "target.test" in (res or "").lower()

        in_scope, res = is_url_in_scope(
            "https://API.TARGET.TEST./v1", "TARGET.TEST", allowed_subdomains=["api.target.test."]
        )
        assert in_scope is True

        # 4. Relative path with valid base_url
        in_scope, res = is_url_in_scope("/api/v1/orders", "target.test", base_url="https://target.test")
        assert in_scope is True
        assert res == "https://target.test/api/v1/orders"

        # 5. Relative path without base_url
        in_scope, res = is_url_in_scope("/api/v1/orders", "target.test")
        assert in_scope is True
        assert res == "/api/v1/orders"

    def test_scope_rejected_targets(self):
        # 1. Unapproved subdomains are strictly rejected (never inferred merely from hostname suffix)
        assert is_url_in_scope("https://api.target.test/v1/users", "target.test")[0] is False
        assert is_url_in_scope(
            "https://unapproved.target.test/v1", "target.test", allowed_subdomains=["api.target.test"]
        )[0] is False

        # 2. Lookalike domains
        assert is_url_in_scope("https://target.test.attacker.test/api", "target.test")[0] is False
        assert is_url_in_scope(
            "https://target.test.attacker.test/api", "target.test", allowed_subdomains=["api.target.test"]
        )[0] is False
        assert is_url_in_scope("https://nottarget.test/api", "target.test")[0] is False
        assert is_url_in_scope("https://target.test.co/api", "target.test")[0] is False

        # 3. Userinfo credentials in URL
        assert is_url_in_scope("https://user:pass@target.test/api", "target.test")[0] is False
        assert is_url_in_scope("https://admin@target.test/api", "target.test")[0] is False

        # 4. Relative URL with base URL pointing outside authorized scope
        assert is_url_in_scope("/api/v1/orders", "target.test", base_url="https://attacker.test")[0] is False

        # 5. Unsupported / dangerous schemes
        assert is_url_in_scope("javascript:alert(1)", "target.test")[0] is False
        assert is_url_in_scope("file:///etc/passwd", "target.test")[0] is False
        assert is_url_in_scope("data:text/html,<html>", "target.test")[0] is False
        assert is_url_in_scope("mailto:admin@target.test", "target.test")[0] is False

        # 6. Empty / non-string / malformed
        assert is_url_in_scope("", "target.test")[0] is False
        assert is_url_in_scope(None, "target.test")[0] is False
        assert is_url_in_scope("   ", "target.test")[0] is False


# ---------------------------------------------------------------------------
# JavaScript Tests
# ---------------------------------------------------------------------------

class TestJavaScriptParser:
    def test_extract_fetch_axios_and_xhr(self):
        js_code = """
        function loadData(userId, orderId) {
            fetch(`/api/v1/users/${userId}/profile`, { method: 'GET' });
            axios.post('/api/v1/orders', { amount: 100, item_id: 'item-999' });
            axios.delete('/api/v1/orders/' + orderId);
            
            var req = new XMLHttpRequest();
            req.open('PUT', '/api/v1/accounts/550e8400-e29b-41d4-a716-446655440000');
            req.send();
        }
        """
        parser = JavaScriptParser(js_code, asset_name="bundle.min.js")
        candidates = parser.extract_candidates(scan_id="scan-js", target_domain="app.example")

        assert len(candidates) >= 4

        # 1. Fetch template literal
        c_fetch = next(c for c in candidates if "/users/{userId}/profile" in c.route_template)
        assert c_fetch.method == "GET"
        assert c_fetch.confidence >= 0.70

        # 2. Axios POST
        c_post = next(c for c in candidates if c.method == "POST" and "/api/v1/orders" in c.route_template)
        assert c_post.route_template == "/api/v1/orders"

        # 3. Axios DELETE with concatenation
        c_del = next(c for c in candidates if c.method == "DELETE")
        assert "/orders/{orderId}" in c_del.route_template or "/orders/{id}" in c_del.route_template

        # 4. XHR PUT with UUID
        c_put = next(c for c in candidates if c.method == "PUT")
        assert "/accounts/{account_uuid}" in c_put.route_template

    def test_filters_false_positive_static_assets(self):
        js_code = """
        const logo = '/assets/images/logo.png';
        const styles = '/static/css/main.css';
        const font = '/fonts/roboto.woff2';
        fetch('/api/valid/endpoint');
        """
        parser = JavaScriptParser(js_code)
        candidates = parser.extract_candidates(scan_id="scan-assets", target_domain="assets.example")
        routes = [c.route_template for c in candidates]
        assert "/api/valid/endpoint" in routes
        assert not any(ext in r for r in routes for ext in [".png", ".css", ".woff2"])


# ---------------------------------------------------------------------------
# HTML Tests
# ---------------------------------------------------------------------------

class TestHTMLPageParser:
    def test_form_and_link_extraction_with_scope_enforcement(self):
        html = """
        <html>
        <body>
            <a href="/api/v1/users/42/details?active=true">User Details</a>
            <a href="https://external.malicious/phishing">External Link</a>
            
            <form action="/api/v1/invoices/update" method="POST">
                <input type="hidden" name="invoice_id" value="inv_2026_01" />
                <input type="text" name="customer_id" value="1002" />
                <input type="password" name="auth_token" value="secret_pass" />
                <input type="submit" value="Submit" />
            </form>
        </body>
        </html>
        """
        parser = HTMLPageParser(html, page_url="https://portal.example/dashboard", target_domain="portal.example")
        candidates = parser.extract_candidates(scan_id="scan-html")

        # External link should be filtered out
        assert not any("external.malicious" in c.original_url for c in candidates)

        # Link candidate
        c_link = next(c for c in candidates if c.method == "GET")
        assert "/api/v1/users/{user_id}/details" in c_link.route_template
        p_user = next(p for p in c_link.parameters if p.name == "user_id")
        assert p_user.identifier_type == IdentifierType.NUMERIC

        # Form candidate
        c_form = next(c for c in candidates if c.method == "POST")
        assert "/api/v1/invoices/update" in c_form.route_template
        assert c_form.content_type == "application/x-www-form-urlencoded"

        p_inv = next(p for p in c_form.parameters if p.name == "invoice_id")
        assert p_inv.semantic_role == SemanticRole.RESOURCE_IDENTIFIER

        p_cust = next(p for p in c_form.parameters if p.name == "customer_id")
        assert p_cust.semantic_role == SemanticRole.USER_IDENTITY

        p_auth = next(p for p in c_form.parameters if p.name == "auth_token")
        assert p_auth.is_redacted is True
        assert p_auth.sample_value == "[REDACTED]"


# ---------------------------------------------------------------------------
# CandidateStore & Deduplication Tests
# ---------------------------------------------------------------------------

class TestCandidateStoreAndPipeline:
    def test_deduplication_merges_sources_and_recalculates_confidence(self):
        store = CandidateStore(scan_id="dedup-scan", target_domain="api.test")

        # Source 1: Discovered via OpenAPI
        c1 = CandidateEndpoint(
            candidate_id=CandidateEndpoint.generate_candidate_id("GET", "/api/users/{id}", "api.test"),
            scan_id="dedup-scan",
            target_domain="api.test",
            method="GET",
            original_url="/api/users/{id}",
            route_template="/api/users/{id}",
            resource_type="users",
            parameters=[],
            discovery_sources=["openapi"],
            confidence=0.70,
        )

        # Source 2: Discovered via live traffic observation with concrete sample value
        c2 = CandidateEndpoint(
            candidate_id=CandidateEndpoint.generate_candidate_id("GET", "/api/users/{id}", "api.test"),
            scan_id="dedup-scan",
            target_domain="api.test",
            method="GET",
            original_url="/api/users/123",
            route_template="/api/users/{id}",
            resource_type="users",
            parameters=[],
            discovery_sources=["traffic"],
            confidence=0.70,
        )

        store.add_candidate(c1)
        assert len(store.all()) == 1
        initial_score = store.all()[0].confidence

        store.add_candidate(c2)
        assert len(store.all()) == 1  # Deduplicated!

        merged = store.all()[0]
        assert set(merged.discovery_sources) == {"openapi", "traffic"}
        # Multi-source corroboration increases confidence
        assert merged.confidence >= initial_score

    def test_pipeline_orchestration_and_serialization(self):
        pipeline = EndpointExtractorPipeline(scan_id="pipe-1", target_domain="target.local")

        # 1. Ingest crawled URL
        pipeline.ingest_crawled_url("https://target.local/api/v1/orders/999?status=pending", method="GET")

        # 2. Ingest traffic observation
        pipeline.ingest_traffic_observation(
            method="POST",
            url="https://target.local/api/v1/orders",
            status_code=201,
            request_body={"customer_id": 5432, "items": [{"id": "item-1"}]}
        )

        inventory = pipeline.get_inventory()
        assert len(inventory.all()) == 2
        resource_candidates = inventory.get_resource_candidates()
        assert len(resource_candidates) >= 1

        # Test dictionary serialization
        data = inventory.to_dict()
        assert data["total_candidates"] == 2
        assert "GET" in data["methods_summary"]
        assert "POST" in data["methods_summary"]

        # Test restoration from dict
        restored_store = CandidateStore.from_dict(data, scan_id="pipe-1", target_domain="target.local")
        assert len(restored_store.all()) == 2
