"""Observational benchmarks for Phase 5 provenance store and lineage analysis."""

import time

import pytest

from app.gateway.registry import default_tool_registry
from app.provenance.analyzer import ProvenanceAnalyzer
from app.provenance.models import InformationArtifact
from app.provenance.store import ProvenanceStore
from app.schemas.action import AgentActionProposal
from app.schemas.enums import ArtifactSourceType, DataClassification, TrustLevel


@pytest.mark.benchmark
@pytest.mark.parametrize("artifact_count", [10, 100, 500])
def test_provenance_lineage_and_analysis_benchmarks(artifact_count: int) -> None:
    """Benchmark artifact lookup, lineage traversal, and policy context derivation.

    Distinguishes total session artifacts from artifacts actually traversed in lineage.
    """
    store = ProvenanceStore()
    session_id = f"bench-session-{artifact_count}"

    # 1. Create a chain of artifacts where lineage depth is bounded (up to 20)
    # and remaining artifacts populate session breadth
    artifacts: list[InformationArtifact] = []

    # Root artifact
    root = InformationArtifact(
        session_id=session_id,
        source_type=ArtifactSourceType.DATABASE,
        source_resource="customer-db",
        direct_trust_level=TrustLevel.INTERNAL_TRUSTED,
        data_classifications=frozenset({DataClassification.INTERNAL}),
    )
    store.register_artifact(root, payload="root payload")
    artifacts.append(root)

    prev = root
    chain_depth = min(20, artifact_count)
    for i in range(chain_depth - 1):
        child = InformationArtifact(
            session_id=session_id,
            source_type=ArtifactSourceType.AGENT_GENERATED,
            source_resource="agent-memory",
            direct_trust_level=TrustLevel.AGENT_DERIVED,
            parent_artifact_ids=(prev.artifact_id,),
            data_classifications=frozenset({DataClassification.INTERNAL}),
        )
        store.register_artifact(child, payload=f"chain payload {i}")
        artifacts.append(child)
        prev = child

    leaf_artifact = prev

    # Fill remaining session breadth if artifact_count > chain_depth
    for i in range(len(artifacts), artifact_count):
        broad_art = InformationArtifact(
            session_id=session_id,
            source_type=ArtifactSourceType.EXTERNAL_CONTENT,
            source_resource="public-web",
            direct_trust_level=TrustLevel.EXTERNAL_UNTRUSTED,
            data_classifications=frozenset({DataClassification.PUBLIC}),
        )
        store.register_artifact(broad_art, payload=f"breadth payload {i}")
        artifacts.append(broad_art)

    assert len(store.get_artifacts_for_session(session_id)) == artifact_count

    # 2. Benchmark Lineage Traversal
    t0 = time.perf_counter()
    lineage = store.get_lineage(leaf_artifact.artifact_id, max_depth=25)
    t_lineage = time.perf_counter() - t0

    # 3. Benchmark ProvenanceAnalyzer Policy Context Derivation
    analyzer = ProvenanceAnalyzer(store=store, max_depth=25, max_artifacts=500)
    proposal = AgentActionProposal(
        agent_id="bench-agent",
        session_id=session_id,
        tool_name="external.http_post",
        tool_arguments={
            "destination": "https://api.example.com",
            "body_artifact_id": str(leaf_artifact.artifact_id),
        },
        input_artifact_ids=[leaf_artifact.artifact_id],
    )
    tool_spec = default_tool_registry.get("external.http_post")

    t1 = time.perf_counter()
    context, validated = analyzer.analyze_provenance(proposal, tool_spec)
    t_analysis = time.perf_counter() - t1

    print(
        f"\n[Provenance Benchmark {artifact_count} artifacts]: "
        f"Session artifacts={artifact_count}, Traversed lineage count={len(lineage)}, "
        f"Lineage lookup time={t_lineage * 1000:.3f}ms, Analysis derivation time={t_analysis * 1000:.3f}ms"
    )

    assert context.analysis_complete
    assert context.input_artifact_count == 1
    assert context.ancestor_artifact_count == chain_depth - 1
