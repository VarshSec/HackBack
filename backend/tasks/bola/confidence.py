"""
Deterministic Confidence Scoring for Candidate Endpoints and Resources.

Calculates an explainable, reproducible score between 0.0 and 1.0 based on
corroborating signals from contracts, live observations, naming patterns, and code usage.
"""
from __future__ import annotations

from typing import List, Tuple
from tasks.bola.models import (
    CandidateEndpoint,
    IdentifierType,
    ParameterLocation,
    SemanticRole,
)

# Base signal weights
SIGNAL_WEIGHTS = {
    "explicit_openapi_contract": 0.40,
    "observed_http_traffic": 0.35,
    "html_form_action": 0.20,
    "js_fetch_call": 0.25,
    "js_axios_method_call": 0.25,
    "js_axios_config_call": 0.20,
    "js_xhr_open_call": 0.20,
    "js_jquery_ajax_call": 0.15,
    "html_anchor_link": 0.15,
    "api_string_literal": 0.10,
    "multi_source_corroboration": 0.15,
    "has_resource_identifier": 0.20,
    "has_user_identity": 0.15,
    "unnamed_numeric_segment": -0.15,
    "ambiguous_string": -0.20,
}


def score_candidate(candidate: CandidateEndpoint) -> Tuple[float, List[str]]:
    """
    Computes a deterministic confidence score [0.0, 1.0] and returns (score, signals_applied).
    """
    signals: List[str] = []
    score = 0.0

    # 1. Evaluate discovery sources and evidence signals
    ev_signals = {sig for ev in candidate.evidence for sig in ev.confidence_signals}

    for sig, weight in SIGNAL_WEIGHTS.items():
        if sig in ev_signals:
            score += weight
            signals.append(f"{sig} ({'+' if weight > 0 else ''}{weight:.2f})")

    # 2. Multi-source bonus
    if len(candidate.discovery_sources) >= 2 and "multi_source_corroboration" not in ev_signals:
        bonus = SIGNAL_WEIGHTS["multi_source_corroboration"]
        score += bonus
        signals.append(f"multi_source_corroboration (+{bonus:.2f})")

    # 3. Structural parameter signals
    has_res_id = any(
        p.semantic_role in (SemanticRole.RESOURCE_IDENTIFIER, SemanticRole.PARENT_RESOURCE_IDENTIFIER)
        and p.identifier_type != IdentifierType.STATIC
        for p in candidate.parameters
    )
    if has_res_id:
        bonus = SIGNAL_WEIGHTS["has_resource_identifier"]
        score += bonus
        signals.append(f"has_resource_identifier (+{bonus:.2f})")

    has_user_id = any(
        p.semantic_role == SemanticRole.USER_IDENTITY
        for p in candidate.parameters
    )
    if has_user_id:
        bonus = SIGNAL_WEIGHTS["has_user_identity"]
        score += bonus
        signals.append(f"has_user_identity (+{bonus:.2f})")

    # 4. Check for unclassified or ambiguous path segments
    if "{" in candidate.route_template:
        for p in candidate.parameters:
            if p.location == ParameterLocation.PATH and p.identifier_type == IdentifierType.NUMERIC and p.name in ("id", "id_1"):
                penalty = SIGNAL_WEIGHTS["unnamed_numeric_segment"]
                score += penalty
                signals.append(f"unnamed_numeric_segment ({penalty:.2f})")
                break

    # Bound between 0.05 and 0.99 (1.0 reserved for confirmed verified findings in P2.4)
    bounded_score = max(0.05, min(0.99, score))
    return round(bounded_score, 2), signals
