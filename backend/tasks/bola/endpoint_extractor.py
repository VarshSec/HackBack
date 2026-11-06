"""
Master Candidate Endpoint & Resource Extraction Pipeline Orchestrator.

Architecture & Scope Integration Boundaries:
1. Live Scan Integration:
   - Automated live scans continuously observe HTTP traffic and discovery results
     (Katana crawled endpoints, FFUF brute-forced paths, OWASP spidered endpoints).
   - These are ingested via `ingest_crawled_url` and `ingest_traffic_observation`.
2. Standalone Adapters:
   - OpenAPI specifications, raw JavaScript bundles, and static HTML files are
     supported via dedicated parsers (OpenAPIParser, JavaScriptParser, HTMLPageParser).
   - They provide rich static contract and code intelligence, callable programmatically
     or via targeted scan configurations.
3. Centralized Scope & Safety:
   - All discovery sources enforce `tasks.bola.scope.is_url_in_scope` to prevent
     ingesting out-of-scope, lookalike, or credential-leaking URLs.
"""
from __future__ import annotations

import logging
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from tasks.bola.models import (
    CandidateEndpoint,
    CandidateParameter,
    EvidenceRecord,
    IdentifierType,
    ParameterLocation,
    SemanticRole,
)
from tasks.bola.openapi_parser import OpenAPIParser
from tasks.bola.javascript_parser import JavaScriptParser
from tasks.bola.html_parser import HTMLPageParser
from tasks.bola.candidate_store import CandidateStore
from tasks.bola.route_normalizer import normalize_url_path
from tasks.bola.resource_detector import (
    classify_semantic_role,
    detect_identifier_type,
    extract_json_parameters,
    extract_query_parameters,
)
from tasks.bola.scope import is_url_in_scope

logger = logging.getLogger(__name__)


class EndpointExtractorPipeline:
    """
    Coordinates multi-source extraction, normalization, deduplication,
    and evidence tracking.
    """

    def __init__(
        self,
        scan_id: str,
        target_domain: str,
        base_url: str = "",
        allowed_subdomains: Optional[Any] = None,
    ):
        self.scan_id = scan_id
        self.target_domain = target_domain.strip().lower()
        self.base_url = base_url or f"https://{self.target_domain}"
        self.allowed_subdomains = list(allowed_subdomains) if allowed_subdomains else []
        self.store = CandidateStore(scan_id=scan_id, target_domain=self.target_domain)

    def ingest_openapi_spec(self, raw_spec: str | Dict[str, Any], source_uri: str = "openapi.json") -> int:
        """Parses and ingests an OpenAPI/Swagger specification."""
        try:
            if source_uri.startswith(("http://", "https://")):
                in_scope, _ = is_url_in_scope(
                    source_uri,
                    self.target_domain,
                    base_url=self.base_url,
                    allowed_subdomains=self.allowed_subdomains,
                )
                if not in_scope:
                    logger.warning("EndpointExtractor: OpenAPI source_uri out of scope: %s", source_uri)
                    return 0

            parser = OpenAPIParser(raw_spec, source_uri=source_uri)
            candidates = parser.extract_candidates(scan_id=self.scan_id, target_domain=self.target_domain)
            self.store.add_all(candidates)
            return len(candidates)
        except Exception as e:
            logger.error("EndpointExtractor: OpenAPI parsing failed for %s: %s", source_uri, e)
            return 0

    def ingest_javascript(self, js_code: str, asset_name: str = "app.js") -> int:
        """Statically extracts endpoints from JavaScript code."""
        try:
            parser = JavaScriptParser(js_code, asset_name=asset_name)
            candidates = parser.extract_candidates(
                scan_id=self.scan_id,
                target_domain=self.target_domain,
                allowed_subdomains=self.allowed_subdomains,
            )
            self.store.add_all(candidates)
            return len(candidates)
        except Exception as e:
            logger.error("EndpointExtractor: JS parsing failed for %s: %s", asset_name, e)
            return 0

    def ingest_html_page(self, html_text: str, page_url: str) -> int:
        """Extracts endpoints from HTML links and forms."""
        try:
            parser = HTMLPageParser(
                html_text,
                page_url=page_url,
                target_domain=self.target_domain,
                allowed_subdomains=self.allowed_subdomains,
            )
            candidates = parser.extract_candidates(scan_id=self.scan_id)
            self.store.add_all(candidates)
            return len(candidates)
        except Exception as e:
            logger.error("EndpointExtractor: HTML parsing failed for %s: %s", page_url, e)
            return 0

    def ingest_crawled_url(self, url: str, method: str = "GET", source: str = "katana") -> bool:
        """Ingests a single crawled URL (from Katana, FFUF, or web crawler)."""
        try:
            in_scope, clean_url = is_url_in_scope(
                url,
                self.target_domain,
                base_url=self.base_url,
                allowed_subdomains=self.allowed_subdomains,
            )
            if not in_scope or not clean_url:
                return False

            parsed = urllib.parse.urlsplit(clean_url)
            norm_template, resource_type, path_params = normalize_url_path(parsed.path)
            parameters: List[CandidateParameter] = list(path_params)

            if parsed.query:
                q_params = extract_query_parameters(parsed.query)
                parameters.extend(q_params)

            ev = EvidenceRecord(
                source=source,
                parser="CrawledURLAdapter",
                location=clean_url,
                snippet=f"{method.upper()} {clean_url}",
                confidence_signals=["observed_http_traffic"],
            )

            candidate_id = CandidateEndpoint.generate_candidate_id(method, norm_template, self.target_domain)
            candidate = CandidateEndpoint(
                candidate_id=candidate_id,
                scan_id=self.scan_id,
                target_domain=self.target_domain,
                method=method.upper(),
                original_url=clean_url,
                route_template=norm_template,
                resource_type=resource_type,
                parameters=parameters,
                discovery_sources=[source],
                content_type="application/json",
                confidence=0.70,
                evidence=[ev],
            )
            self.store.add_candidate(candidate)
            return True
        except Exception as e:
            logger.debug("EndpointExtractor: crawled URL ingestion failed for %s: %s", url, e)
            return False

    def ingest_traffic_observation(
        self,
        method: str,
        url: str,
        status_code: int = 200,
        request_body: Optional[Any] = None,
        response_body: Optional[Any] = None,
        auth_context: Optional[str] = None,
    ) -> bool:
        """Ingests an observed HTTP request/response transaction."""
        try:
            in_scope, clean_url = is_url_in_scope(
                url,
                self.target_domain,
                base_url=self.base_url,
                allowed_subdomains=self.allowed_subdomains,
            )
            if not in_scope or not clean_url:
                return False

            parsed = urllib.parse.urlsplit(clean_url)
            norm_template, resource_type, path_params = normalize_url_path(parsed.path)
            parameters: List[CandidateParameter] = list(path_params)

            if parsed.query:
                q_params = extract_query_parameters(parsed.query)
                parameters.extend(q_params)

            if request_body and isinstance(request_body, (dict, list)):
                body_params = extract_json_parameters(request_body)
                parameters.extend(body_params)

            ev = EvidenceRecord(
                source="traffic",
                parser="TrafficObserver",
                location=clean_url,
                snippet=f"{method.upper()} {clean_url} -> HTTP {status_code}",
                confidence_signals=["observed_http_traffic"],
            )

            candidate_id = CandidateEndpoint.generate_candidate_id(method, norm_template, self.target_domain)
            candidate = CandidateEndpoint(
                candidate_id=candidate_id,
                scan_id=self.scan_id,
                target_domain=self.target_domain,
                method=method.upper(),
                original_url=clean_url,
                route_template=norm_template,
                resource_type=resource_type,
                parameters=parameters,
                discovery_sources=["traffic"],
                content_type="application/json",
                authentication_context=auth_context,
                confidence=0.80,
                evidence=[ev],
            )
            self.store.add_candidate(candidate)
            return True
        except Exception as e:
            logger.debug("EndpointExtractor: traffic observation ingestion failed for %s: %s", url, e)
            return False

    def get_inventory(self) -> CandidateStore:
        return self.store
