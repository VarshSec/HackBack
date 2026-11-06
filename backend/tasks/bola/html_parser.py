"""
HTML Link and Form Parser for BOLA extraction.

Extracts endpoints from HTML anchors and forms (including hidden fields and
query parameters) without submitting forms or executing actions.
Enforces target domain scope and normalizes relative URLs.
"""
from __future__ import annotations

import urllib.parse
from html.parser import HTMLParser
from typing import Dict, List, Optional, Set, Tuple

from tasks.bola.models import (
    CandidateEndpoint,
    CandidateParameter,
    EvidenceRecord,
    IdentifierType,
    ParameterLocation,
    SemanticRole,
)
from tasks.bola.route_normalizer import normalize_url_path
from tasks.bola.resource_detector import (
    classify_semantic_role,
    detect_identifier_type,
    extract_query_parameters,
)
from tasks.bola.scope import is_url_in_scope


class _HTMLFormExtractor(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.forms: List[Dict[str, Any]] = []
        self.links: List[str] = []

        self._in_form = False
        self._current_action: Optional[str] = None
        self._current_method: str = "GET"
        self._current_inputs: List[Dict[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list) -> None:
        attrs_dict = dict(attrs)

        if tag == "a":
            href = attrs_dict.get("href")
            if href:
                self.links.append(href)

        elif tag == "form":
            self._in_form = True
            self._current_action = attrs_dict.get("action") or ""
            self._current_method = (attrs_dict.get("method") or "GET").upper()
            self._current_inputs = []

        elif self._in_form and tag in ("input", "select", "textarea"):
            name = attrs_dict.get("name")
            if name:
                self._current_inputs.append({
                    "name": name,
                    "type": (attrs_dict.get("type") or "text").lower(),
                    "value": attrs_dict.get("value") or "",
                })

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._in_form = False
            self.forms.append({
                "action": self._current_action or "",
                "method": self._current_method,
                "inputs": list(self._current_inputs),
            })


class HTMLPageParser:
    """
    Parses HTML content to extract CandidateEndpoints from forms and links.
    """

    def __init__(
        self,
        html_text: str,
        page_url: str,
        target_domain: str,
        allowed_subdomains: Optional[Any] = None,
    ):
        self.html_text = html_text
        self.page_url = page_url
        self.target_domain = target_domain.strip().lower()
        self.allowed_subdomains = list(allowed_subdomains) if allowed_subdomains else []

    def _is_in_scope(self, url: str) -> Tuple[bool, str]:
        """
        Ensures the URL belongs to the target domain scope and returns the normalized path.
        """
        in_scope, resolved = is_url_in_scope(
            url, self.target_domain, base_url=self.page_url, allowed_subdomains=self.allowed_subdomains
        )
        return in_scope, (resolved or "")

    def extract_candidates(self, scan_id: str = "") -> List[CandidateEndpoint]:
        candidates: List[CandidateEndpoint] = []
        seen_keys: Set[Tuple[str, str]] = set()

        if not self.html_text:
            return candidates

        extractor = _HTMLFormExtractor(self.page_url)
        try:
            extractor.feed(self.html_text)
        except Exception:
            return candidates

        # 1. Process HTML Forms
        for form in extractor.forms:
            action = form["action"] or self.page_url
            method = form["method"]
            in_scope, full_url = self._is_in_scope(action)
            if not in_scope or not full_url:
                continue

            parsed = urllib.parse.urlsplit(full_url)
            norm_template, resource_type, path_params = normalize_url_path(parsed.path)
            key = (method, norm_template)
            if key in seen_keys:
                continue
            seen_keys.add(key)

            parameters: List[CandidateParameter] = list(path_params)
            param_loc = ParameterLocation.BODY_FORM if method in ("POST", "PUT", "PATCH") else ParameterLocation.QUERY

            for inp in form["inputs"]:
                name = inp["name"]
                val = inp["value"]
                ident_type = detect_identifier_type(val)
                role = classify_semantic_role(name, param_loc, ident_type, resource_context=resource_type)

                parameters.append(
                    CandidateParameter(
                        name=name,
                        location=param_loc,
                        data_type="string",
                        identifier_type=ident_type,
                        semantic_role=role,
                        sample_value=val if val else None,
                    )
                )

            ev = EvidenceRecord(
                source="html_form",
                parser="HTMLPageParser",
                location=f"{self.page_url}#form[action={action}]",
                snippet=f"<form action='{action}' method='{method}'> with {len(form['inputs'])} inputs",
                confidence_signals=["html_form_action"],
            )

            candidate_id = CandidateEndpoint.generate_candidate_id(method, norm_template, self.target_domain)
            endpoint = CandidateEndpoint(
                candidate_id=candidate_id,
                scan_id=scan_id,
                target_domain=self.target_domain,
                method=method,
                original_url=full_url,
                route_template=norm_template,
                resource_type=resource_type,
                parameters=parameters,
                discovery_sources=["html_form"],
                content_type="application/x-www-form-urlencoded" if method == "POST" else "application/json",
                confidence=0.70,
                evidence=[ev],
            )
            candidates.append(endpoint)

        # 2. Process HTML Links
        for link in extractor.links:
            in_scope, full_url = self._is_in_scope(link)
            if not in_scope or not full_url:
                continue

            parsed = urllib.parse.urlsplit(full_url)
            norm_template, resource_type, path_params = normalize_url_path(parsed.path)
            key = ("GET", norm_template)
            if key in seen_keys:
                continue
            seen_keys.add(key)

            parameters: List[CandidateParameter] = list(path_params)
            if parsed.query:
                query_params = extract_query_parameters(parsed.query)
                parameters.extend(query_params)

            # Only add as candidate if it has path params or query params or looks like an API/resource route
            has_params = len(parameters) > 0
            is_api_like = any(seg in norm_template for seg in ("/api/", "/rest/", "/v1/", "/v2/"))
            if not (has_params or is_api_like):
                continue

            ev = EvidenceRecord(
                source="html_link",
                parser="HTMLPageParser",
                location=f"{self.page_url}#a[href={link}]",
                snippet=f"<a href='{link}'>",
                confidence_signals=["html_anchor_link"],
            )

            candidate_id = CandidateEndpoint.generate_candidate_id("GET", norm_template, self.target_domain)
            endpoint = CandidateEndpoint(
                candidate_id=candidate_id,
                scan_id=scan_id,
                target_domain=self.target_domain,
                method="GET",
                original_url=full_url,
                route_template=norm_template,
                resource_type=resource_type,
                parameters=parameters,
                discovery_sources=["html_link"],
                content_type="application/json",
                confidence=0.60,
                evidence=[ev],
            )
            candidates.append(endpoint)

        return candidates
