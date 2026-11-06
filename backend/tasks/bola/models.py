"""
Candidate endpoint and resource models for BOLA / IDOR extraction pipeline.

Defines structured schemas for parameters, evidence records, candidate endpoints,
and classification enumerations. Enforces strict secret redaction across all fields.
"""
from __future__ import annotations

import enum
import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator, model_validator

from tasks.bola.sanitizer import (
    sanitize_url,
    sanitize_snippet,
    sanitize_sample_value,
    sanitize_schema_dict,
    is_sensitive_key,
)


class ParameterLocation(str, enum.Enum):
    PATH = "path"
    QUERY = "query"
    HEADER = "header"
    BODY_JSON = "body_json"
    BODY_FORM = "body_form"


class IdentifierType(str, enum.Enum):
    NUMERIC = "numeric"
    UUID = "uuid"
    OBJECT_ID = "object_id"
    SLUG = "slug"
    OPAQUE = "opaque"
    COMPOSITE = "composite"
    STATIC = "static"


class SemanticRole(str, enum.Enum):
    RESOURCE_IDENTIFIER = "resource_identifier"
    PARENT_RESOURCE_IDENTIFIER = "parent_resource_identifier"
    USER_IDENTITY = "user_identity"
    FOREIGN_KEY = "foreign_key"
    SESSION_TOKEN = "session_token"
    ACTION_FLAG = "action_flag"
    UNCLASSIFIED = "unclassified"


class DiscoverySource(str, enum.Enum):
    OPENAPI = "openapi"
    JAVASCRIPT = "javascript"
    HTML_FORM = "html_form"
    HTML_LINK = "html_link"
    TRAFFIC = "traffic"
    KATANA = "katana"
    FFUF = "ffuf"
    OTHER = "other"


class CandidateParameter(BaseModel):
    """Represents a discovered parameter within a route, query, or payload."""
    name: str
    location: ParameterLocation
    data_type: str = "string"
    identifier_type: IdentifierType = IdentifierType.STATIC
    semantic_role: SemanticRole = SemanticRole.UNCLASSIFIED
    sample_value: Optional[str] = None
    required: bool = False
    is_redacted: bool = False

    @model_validator(mode="after")
    def redact_secrets(self) -> CandidateParameter:
        sanitized_val, redacted = sanitize_sample_value(self.name, self.sample_value)
        if redacted:
            self.is_redacted = True
            self.sample_value = sanitized_val or "[REDACTED]"
            if self.semantic_role == SemanticRole.UNCLASSIFIED:
                self.semantic_role = SemanticRole.SESSION_TOKEN
        elif self.sample_value is not None:
            self.sample_value = str(sanitized_val)
        return self


    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")


class EvidenceRecord(BaseModel):
    """Evidence provenance tracing source, location, parser, and confidence factors."""
    source: str
    parser: str
    location: str
    snippet: Optional[str] = None
    extracted_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    confidence_signals: List[str] = Field(default_factory=list)

    @field_validator("location")
    @classmethod
    def sanitize_evidence_location(cls, v: str) -> str:
        if not v:
            return ""
        # If location contains a URL or query string, sanitize credentials
        if "://" in v or "?" in v:
            return sanitize_url(v)
        return v

    @field_validator("snippet")
    @classmethod
    def sanitize_evidence_snippet(cls, v: Optional[str]) -> Optional[str]:
        return sanitize_snippet(v)

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")


class CandidateEndpoint(BaseModel):
    """
    Structured endpoint/resource candidate inventory record.
    """
    candidate_id: str
    scan_id: str
    target_domain: str
    method: str
    original_url: str
    route_template: str
    resource_type: str
    parameters: List[CandidateParameter] = Field(default_factory=list)
    discovery_sources: List[str] = Field(default_factory=list)
    content_type: Optional[str] = "application/json"
    authentication_context: Optional[str] = None
    response_schema: Optional[Dict[str, Any]] = None
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    evidence: List[EvidenceRecord] = Field(default_factory=list)
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("original_url")
    @classmethod
    def sanitize_original_url(cls, v: str) -> str:
        return sanitize_url(v)

    @field_validator("authentication_context")
    @classmethod
    def validate_auth_context(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        valid_contexts = {"primary", "secondary", "anonymous"}
        if v not in valid_contexts:
            # Never allow raw tokens or credentials to be stored as auth context
            return "anonymous"
        return v

    @field_validator("response_schema")
    @classmethod
    def sanitize_response_schema(cls, v: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if v is None:
            return None
        return sanitize_schema_dict(v)

    @classmethod
    def generate_candidate_id(cls, method: str, route_template: str, target_domain: str = "") -> str:
        """Deterministic stable candidate identifier."""
        norm_method = method.strip().upper()
        norm_route = route_template.strip()
        norm_domain = target_domain.strip().lower()
        key = f"{norm_method}:{norm_domain}:{norm_route}"
        return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]

    def add_source(self, source: str) -> None:
        if source and source not in self.discovery_sources:
            self.discovery_sources.append(source)

    def add_evidence(self, ev: EvidenceRecord) -> None:
        self.evidence.append(ev)
        self.add_source(ev.source)
        self.last_seen = datetime.now(timezone.utc)

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")
