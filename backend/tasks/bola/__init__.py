"""
BOLA / IDOR Verification Engine package.
Provides modular dual-identity authentication, resource discovery,
candidate extraction, ownership mapping, semantic differential verification,
and evidence generation.
"""

from tasks.bola.auth_manager import (
    SessionIdentityManager,
    IDENTITY_PRIMARY,
    IDENTITY_SECONDARY,
    IDENTITY_ANONYMOUS,
    AuthOutcome,
    IdentityAuthState,
)
from tasks.bola.models import (
    CandidateEndpoint,
    CandidateParameter,
    EvidenceRecord,
    IdentifierType,
    ParameterLocation,
    SemanticRole,
    DiscoverySource,
)
from tasks.bola.route_normalizer import normalize_url_path
from tasks.bola.resource_detector import (
    detect_identifier_type,
    classify_semantic_role,
    extract_query_parameters,
    extract_json_parameters,
)
from tasks.bola.openapi_parser import OpenAPIParser
from tasks.bola.javascript_parser import JavaScriptParser
from tasks.bola.html_parser import HTMLPageParser
from tasks.bola.candidate_store import CandidateStore
from tasks.bola.endpoint_extractor import EndpointExtractorPipeline

__all__ = [
    "SessionIdentityManager",
    "IDENTITY_PRIMARY",
    "IDENTITY_SECONDARY",
    "IDENTITY_ANONYMOUS",
    "AuthOutcome",
    "IdentityAuthState",
    "CandidateEndpoint",
    "CandidateParameter",
    "EvidenceRecord",
    "IdentifierType",
    "ParameterLocation",
    "SemanticRole",
    "DiscoverySource",
    "normalize_url_path",
    "detect_identifier_type",
    "classify_semantic_role",
    "extract_query_parameters",
    "extract_json_parameters",
    "OpenAPIParser",
    "JavaScriptParser",
    "HTMLPageParser",
    "CandidateStore",
    "EndpointExtractorPipeline",
]
