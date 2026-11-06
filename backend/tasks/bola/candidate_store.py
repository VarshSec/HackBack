"""
Structured Candidate Store and Deduplication Engine for BOLA candidates.

Manages indexing, deduplication across multiple discovery sources,
evidence merging, parameter union, and serialization.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from tasks.bola.models import (
    CandidateEndpoint,
    CandidateParameter,
    EvidenceRecord,
    IdentifierType,
    SemanticRole,
)
from tasks.bola.confidence import score_candidate


class CandidateStore:
    """
    In-memory and persistent inventory of CandidateEndpoints.
    """

    def __init__(self, scan_id: str = "", target_domain: str = ""):
        self.scan_id = scan_id
        self.target_domain = target_domain
        self._candidates: Dict[str, CandidateEndpoint] = {}

    def add_candidate(self, candidate: CandidateEndpoint) -> None:
        """
        Adds a candidate or merges it with an existing matching candidate.
        """
        cid = candidate.candidate_id
        if cid not in self._candidates:
            # Score candidate upon initial registration
            score, _ = score_candidate(candidate)
            candidate.confidence = score
            self._candidates[cid] = candidate
            return

        existing = self._candidates[cid]

        # 1. Merge discovery sources
        for src in candidate.discovery_sources:
            existing.add_source(src)

        # 2. Merge evidence records
        for ev in candidate.evidence:
            existing.evidence.append(ev)

        # 3. Merge parameters
        param_map: Dict[str, CandidateParameter] = {p.name: p for p in existing.parameters}
        for new_p in candidate.parameters:
            if new_p.name in param_map:
                curr = param_map[new_p.name]
                # If new parameter has a sample value and current doesn't, update it
                if not curr.sample_value and new_p.sample_value:
                    curr.sample_value = new_p.sample_value
                # If new parameter has more specific identifier type, update it
                if curr.identifier_type == IdentifierType.STATIC and new_p.identifier_type != IdentifierType.STATIC:
                    curr.identifier_type = new_p.identifier_type
                # If current semantic role is unclassified, update it
                if curr.semantic_role == SemanticRole.UNCLASSIFIED and new_p.semantic_role != SemanticRole.UNCLASSIFIED:
                    curr.semantic_role = new_p.semantic_role
            else:
                existing.parameters.append(new_p)
                param_map[new_p.name] = new_p

        # 4. Update timestamps
        existing.last_seen = datetime.now(timezone.utc)

        # 5. Recalculate confidence score after merging sources and signals
        score, _ = score_candidate(existing)
        existing.confidence = score

    def add_all(self, candidates: List[CandidateEndpoint]) -> None:
        for c in candidates:
            self.add_candidate(c)

    def get(self, candidate_id: str) -> Optional[CandidateEndpoint]:
        return self._candidates.get(candidate_id)

    def all(self) -> List[CandidateEndpoint]:
        return list(self._candidates.values())

    def get_resource_candidates(self) -> List[CandidateEndpoint]:
        """Returns candidates that possess at least one dynamic resource identifier or user identity."""
        res = []
        for c in self._candidates.values():
            has_id = any(
                p.semantic_role in (SemanticRole.RESOURCE_IDENTIFIER, SemanticRole.PARENT_RESOURCE_IDENTIFIER, SemanticRole.USER_IDENTITY)
                and p.identifier_type != IdentifierType.STATIC
                for p in c.parameters
            )
            if has_id or "{" in c.route_template:
                res.append(c)
        return res

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the candidate inventory to a dictionary for JSONB storage."""
        candidates_data = [c.model_dump(mode="json") for c in self._candidates.values()]
        sources_summary: Dict[str, int] = {}
        methods_summary: Dict[str, int] = {}

        for c in self._candidates.values():
            methods_summary[c.method] = methods_summary.get(c.method, 0) + 1
            for s in c.discovery_sources:
                sources_summary[s] = sources_summary.get(s, 0) + 1

        return {
            "total_candidates": len(candidates_data),
            "total_resource_candidates": len(self.get_resource_candidates()),
            "sources_summary": sources_summary,
            "methods_summary": methods_summary,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "candidates": candidates_data,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any], scan_id: str = "", target_domain: str = "") -> CandidateStore:
        store = cls(scan_id=scan_id, target_domain=target_domain)
        for raw in data.get("candidates", []):
            try:
                candidate = CandidateEndpoint.model_validate(raw)
                store._candidates[candidate.candidate_id] = candidate
            except Exception:
                pass
        return store
