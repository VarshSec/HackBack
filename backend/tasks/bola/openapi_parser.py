"""
OpenAPI 3.x and Swagger 2.0 Specification Parser for BOLA extraction.

Extracts endpoints, methods, parameters (path, query, header, body),
request/response schemas, and operations while safely resolving local $ref
references and rejecting remote/external references (SSRF protection).
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional, Set, Tuple
import yaml

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
)

logger = logging.getLogger(__name__)

_MAX_REF_DEPTH = 10


class OpenAPIParser:
    """
    Parser for OpenAPI 3.x and Swagger 2.0 specifications.
    """

    def __init__(self, raw_spec: str | Dict[str, Any], source_uri: str = "openapi.json"):
        self.source_uri = source_uri
        if isinstance(raw_spec, dict):
            self.spec = raw_spec
        else:
            self.spec = self._parse_raw(raw_spec)

    def _parse_raw(self, content: str) -> Dict[str, Any]:
        content = content.strip()
        if not content:
            return {}
        # Try JSON first
        if content.startswith("{") or content.startswith("["):
            try:
                return json.loads(content)
            except Exception:
                pass
        # Fall back to YAML
        try:
            parsed = yaml.safe_load(content)
            return parsed if isinstance(parsed, dict) else {}
        except Exception as e:
            logger.warning("OpenAPIParser: failed to parse spec as JSON or YAML: %s", e)
            return {}

    def resolve_ref(self, ref: str, visited: Optional[Set[str]] = None, depth: int = 0) -> Optional[Dict[str, Any]]:
        """
        Safely resolves a local $ref (e.g. #/components/schemas/User).
        Strictly rejects remote/external URIs (http://, https://, file://) to prevent SSRF.
        """
        if not ref or not isinstance(ref, str):
            return None

        # SSRF Check: only local references starting with '#' are permitted
        if not ref.startswith("#/"):
            logger.warning("OpenAPIParser: rejecting external/remote $ref: %s", ref)
            return None

        if visited is None:
            visited = set()
        if ref in visited or depth > _MAX_REF_DEPTH:
            logger.debug("OpenAPIParser: circular or excessively deep $ref detected: %s", ref)
            return None
        visited.add(ref)

        parts = ref.lstrip("#/").split("/")
        curr = self.spec
        for p in parts:
            # Handle JSON Pointer escaped characters: ~1 is '/', ~0 is '~'
            unescaped = p.replace("~1", "/").replace("~0", "~")
            if isinstance(curr, dict) and unescaped in curr:
                curr = curr[unescaped]
            else:
                return None

        if isinstance(curr, dict) and "$ref" in curr:
            return self.resolve_ref(curr["$ref"], visited=visited, depth=depth + 1)

        return curr if isinstance(curr, dict) else None

    def _resolve_schema(self, schema: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Resolves $ref in schema if present."""
        if not schema or not isinstance(schema, dict):
            return {}
        if "$ref" in schema:
            resolved = self.resolve_ref(schema["$ref"])
            if resolved:
                merged = dict(resolved)
                for k, v in schema.items():
                    if k != "$ref":
                        merged[k] = v
                return merged
        return schema

    def _extract_schema_properties(
        self, schema: Dict[str, Any], location: ParameterLocation, prefix: str = "", depth: int = 0
    ) -> List[CandidateParameter]:
        """Recursively extracts properties from an OpenAPI schema."""
        params: List[CandidateParameter] = []
        if depth > 5 or not isinstance(schema, dict):
            return params

        schema = self._resolve_schema(schema)
        props = schema.get("properties") or {}
        required_props = set(schema.get("required") or [])

        for prop_name, prop_def in props.items():
            if not isinstance(prop_def, dict):
                continue
            prop_def = self._resolve_schema(prop_def)
            full_name = f"{prefix}.{prop_name}" if prefix else prop_name
            p_type = prop_def.get("type", "string")

            if p_type == "object":
                params.extend(
                    self._extract_schema_properties(prop_def, location, prefix=full_name, depth=depth + 1)
                )
            elif p_type == "array":
                items = self._resolve_schema(prop_def.get("items") or {})
                if items.get("type") == "object":
                    params.extend(
                        self._extract_schema_properties(items, location, prefix=f"{full_name}[]", depth=depth + 1)
                    )
                else:
                    ident_type = detect_identifier_type(None, schema_type=items.get("type"))
                    role = classify_semantic_role(prop_name, location, ident_type)
                    params.append(
                        CandidateParameter(
                            name=full_name,
                            location=location,
                            data_type=f"array[{items.get('type', 'string')}]",
                            identifier_type=ident_type,
                            semantic_role=role,
                            required=prop_name in required_props,
                        )
                    )
            else:
                ident_type = detect_identifier_type(None, schema_type=p_type)
                role = classify_semantic_role(prop_name, location, ident_type)
                params.append(
                    CandidateParameter(
                        name=full_name,
                        location=location,
                        data_type=p_type,
                        identifier_type=ident_type,
                        semantic_role=role,
                        required=prop_name in required_props,
                    )
                )

        return params

    def extract_candidates(self, scan_id: str = "", target_domain: str = "") -> List[CandidateEndpoint]:
        """
        Parses all paths and operations in the specification and returns CandidateEndpoint objects.
        """
        candidates: List[CandidateEndpoint] = []
        if not self.spec or not isinstance(self.spec, dict):
            return candidates

        paths = self.spec.get("paths") or {}
        if not isinstance(paths, dict):
            return candidates

        # Check for global security declarations
        has_global_security = bool(self.spec.get("security"))

        for path_str, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue

            # Path-level parameters
            path_level_params = path_item.get("parameters") or []

            # Normalize route template
            norm_template, resource_type, norm_path_params = normalize_url_path(path_str)

            for method in ["get", "post", "put", "delete", "patch", "options", "head"]:
                op = path_item.get(method)
                if not op or not isinstance(op, dict):
                    continue

                operation_id = op.get("operationId", "")
                summary = op.get("summary") or op.get("description") or ""

                # Security context
                op_security = op.get("security")
                is_authenticated = bool(op_security) or (has_global_security and op_security is not [])
                auth_context = "primary" if is_authenticated else "anonymous"

                # Combine path-level and operation-level parameters
                all_params_def = list(path_level_params) + list(op.get("parameters") or [])
                parsed_params: List[CandidateParameter] = list(norm_path_params)
                seen_names = {p.name for p in parsed_params}

                for p in all_params_def:
                    if "$ref" in p:
                        p = self.resolve_ref(p["$ref"]) or {}
                    p_name = p.get("name")
                    p_in = p.get("in")
                    if not p_name:
                        continue

                    location = ParameterLocation.QUERY
                    if p_in == "path":
                        location = ParameterLocation.PATH
                    elif p_in == "header":
                        location = ParameterLocation.HEADER
                    elif p_in in ("formData", "body"):
                        location = ParameterLocation.BODY_FORM

                    p_schema = self._resolve_schema(p.get("schema") or {})
                    p_type = p_schema.get("type") or p.get("type", "string")

                    ident_type = detect_identifier_type(None, schema_type=p_type)
                    role = classify_semantic_role(p_name, location, ident_type, resource_context=resource_type)

                    if p_name in seen_names:
                        for existing_p in parsed_params:
                            if existing_p.name == p_name:
                                existing_p.data_type = p_type
                                if ident_type != IdentifierType.STATIC:
                                    existing_p.identifier_type = ident_type
                                if role != SemanticRole.UNCLASSIFIED:
                                    existing_p.semantic_role = role
                                if "required" in p:
                                    existing_p.required = bool(p.get("required"))
                        continue

                    parsed_params.append(
                        CandidateParameter(
                            name=p_name,
                            location=location,
                            data_type=p_type,
                            identifier_type=ident_type,
                            semantic_role=role,
                            required=bool(p.get("required", False)),
                        )
                    )
                    seen_names.add(p_name)

                # OpenAPI 3 requestBody handling
                req_body = op.get("requestBody") or {}
                if "$ref" in req_body:
                    req_body = self.resolve_ref(req_body["$ref"]) or {}
                content = req_body.get("content") or {}
                for mime_type, media_obj in content.items():
                    if "json" in mime_type:
                        b_schema = media_obj.get("schema") or {}
                        body_params = self._extract_schema_properties(b_schema, ParameterLocation.BODY_JSON)
                        for bp in body_params:
                            if bp.name not in seen_names:
                                parsed_params.append(bp)
                                seen_names.add(bp.name)

                # Evidence record
                ev = EvidenceRecord(
                    source="openapi",
                    parser="OpenAPIParser",
                    location=f"{self.source_uri}#/paths/{path_str}/{method}",
                    snippet=f"operationId: {operation_id} | summary: {summary[:100]}",
                    confidence_signals=["explicit_openapi_contract"],
                )

                candidate_id = CandidateEndpoint.generate_candidate_id(method, norm_template, target_domain)
                endpoint = CandidateEndpoint(
                    candidate_id=candidate_id,
                    scan_id=scan_id,
                    target_domain=target_domain,
                    method=method.upper(),
                    original_url=path_str,
                    route_template=norm_template,
                    resource_type=resource_type,
                    parameters=parsed_params,
                    discovery_sources=["openapi"],
                    content_type="application/json",
                    authentication_context=auth_context,
                    confidence=0.85,
                    evidence=[ev],
                )
                candidates.append(endpoint)

        return candidates
