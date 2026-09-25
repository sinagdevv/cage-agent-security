"""Diagnostic API endpoints for information provenance and artifact lineage inspection."""

from uuid import UUID

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from app.gateway.service import default_agent_gateway
from app.provenance.store import default_provenance_store

router = APIRouter(prefix="/artifacts", tags=["Artifacts & Provenance"])


class ArtifactProvenanceResponse(BaseModel):
    """Diagnostic response for artifact provenance.

    SECURITY INVARIANT:
    Raw payloads, raw arguments, and sensitive document bodies are NEVER returned.
    Content digest is excluded by default to prevent correlation attacks on low-entropy secrets.
    """

    model_config = ConfigDict(extra="forbid")

    artifact_id: str
    session_id: str
    source_type: str
    source_resource: str
    direct_trust_level: str
    inherited_trust_levels: list[str]
    data_classifications: list[str]
    parent_artifact_ids: list[str]
    size_bytes: int | None
    mime_type: str | None
    created_at: str
    created_by_action_id: str | None
    consuming_action_ids: list[str] = Field(default_factory=list)
    lineage_depth: int = 0
    ancestor_count: int = 0


@router.get("/{artifact_id}/provenance", response_model=ArtifactProvenanceResponse)
def get_artifact_provenance(
    artifact_id: UUID,
    max_depth: int = Query(default=25, ge=1, le=50),
) -> ArtifactProvenanceResponse:
    """Control-plane diagnostic inspection of artifact metadata and lineage.

    Restricted to metadata only: raw sensitive payloads are never exposed.
    """
    store = default_provenance_store
    artifact = store.get_artifact(artifact_id)
    if not artifact:
        raise HTTPException(status_code=404, detail=f"Artifact '{artifact_id}' not found.")

    # Upstream lineage
    lineage = store.get_lineage(artifact_id, max_depth=max_depth)

    # Query causal graph for consuming actions
    consuming_actions: list[str] = []
    graph = default_agent_gateway.graph_manager.get(artifact.session_id)
    if graph is not None:
        consuming_actions = graph.get_artifact_consumers(str(artifact_id))

    return ArtifactProvenanceResponse(
        artifact_id=str(artifact.artifact_id),
        session_id=artifact.session_id,
        source_type=artifact.source_type.value,
        source_resource=artifact.source_resource,
        direct_trust_level=artifact.direct_trust_level.value,
        inherited_trust_levels=sorted([t.value for t in artifact.inherited_trust_levels]),
        data_classifications=sorted([c.value for c in artifact.data_classifications]),
        parent_artifact_ids=[str(pid) for pid in artifact.parent_artifact_ids],
        size_bytes=artifact.size_bytes,
        mime_type=artifact.mime_type,
        created_at=artifact.created_at.isoformat(),
        created_by_action_id=str(artifact.created_by_action_id)
        if artifact.created_by_action_id
        else None,
        consuming_action_ids=consuming_actions,
        lineage_depth=len(lineage),
        ancestor_count=len(lineage),
    )
