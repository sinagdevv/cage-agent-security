from unittest.mock import MagicMock
from uuid import uuid4

import networkx as nx
import pytest
from pydantic import ValidationError

from app.graph.causal_graph import CausalExecutionGraph
from app.provenance.models import InformationArtifact
from app.provenance.store import (
    ArtifactPayloadStore,
    CrossSessionReferenceError,
    MissingArtifactError,
    PayloadSizeLimitExceededError,
    ProvenanceCycleError,
    ProvenanceStore,
)
from app.schemas.enums import (
    ActionType,
    ArtifactSourceType,
    DataClassification,
    GraphNodeType,
    GraphRelation,
    TargetEnvironment,
    TrustLevel,
)


def test_artifact_deep_immutability() -> None:
    """Verify InformationArtifact is frozen and its collections cannot be mutated."""
    art = InformationArtifact(
        session_id="sess-01",
        source_type=ArtifactSourceType.INTERNAL_RESOURCE,
        source_resource="customer-db",
        direct_trust_level=TrustLevel.INTERNAL_TRUSTED,
        inherited_trust_levels=frozenset({TrustLevel.INTERNAL_TRUSTED}),
        data_classifications=frozenset({DataClassification.PII, DataClassification.CONFIDENTIAL}),
        parent_artifact_ids=(uuid4(),),
        mime_type="application/json",
    )

    # 1. Pydantic frozen model raises error on attribute assignment
    with pytest.raises(ValidationError):
        art.direct_trust_level = TrustLevel.EXTERNAL_UNTRUSTED  # type: ignore[misc]

    with pytest.raises(ValidationError):
        art.session_id = "sess-injected"  # type: ignore[misc]

    # 2. Frozen collections cannot be mutated
    with pytest.raises(AttributeError):
        art.data_classifications.add(DataClassification.PUBLIC)  # type: ignore[attr-defined]

    with pytest.raises(AttributeError):
        art.parent_artifact_ids.append(uuid4())  # type: ignore[attr-defined]


def test_artifact_server_generated_id_uniqueness() -> None:
    """Verify each artifact receives a unique, server-generated UUID."""
    art1 = InformationArtifact(
        session_id="sess-01",
        source_type=ArtifactSourceType.DATABASE,
        source_resource="customer-db",
        direct_trust_level=TrustLevel.INTERNAL_TRUSTED,
    )
    art2 = InformationArtifact(
        session_id="sess-01",
        source_type=ArtifactSourceType.DATABASE,
        source_resource="customer-db",
        direct_trust_level=TrustLevel.INTERNAL_TRUSTED,
    )

    assert art1.artifact_id != art2.artifact_id
    assert art1.artifact_id is not None


def test_artifact_payload_store_decoupling_and_limits() -> None:
    """Verify ArtifactPayloadStore decouples raw payload and enforces memory bounds."""
    store = ArtifactPayloadStore(max_payload_bytes=100)
    art_id = uuid4()

    # Successful store of payload under limit
    small_payload = {"user": "alice", "role": "admin"}
    size, digest = store.store_payload(art_id, small_payload)

    assert size > 0
    assert digest is not None
    assert store.has_payload(art_id)
    assert store.get_payload_str(art_id) is not None
    assert "alice" in store.get_payload_str(art_id)

    # Enforce payload memory limit
    large_payload = "X" * 150
    large_id = uuid4()
    with pytest.raises(PayloadSizeLimitExceededError):
        store.store_payload(large_id, large_payload)

    assert not store.has_payload(large_id)


def test_provenance_store_atomic_registration_and_session_isolation() -> None:
    """Verify ProvenanceStore atomic registration, session filtering, and parent validation."""
    prov_store = ProvenanceStore()
    graph = CausalExecutionGraph(session_id="sess-a")

    parent_art = InformationArtifact(
        session_id="sess-a",
        source_type=ArtifactSourceType.EXTERNAL_CONTENT,
        source_resource="public-web",
        direct_trust_level=TrustLevel.EXTERNAL_UNTRUSTED,
        data_classifications=frozenset({DataClassification.PUBLIC}),
    )
    prov_store.register_artifact(parent_art, payload="web research text", graph=graph)

    # Verify retrieval
    retrieved = prov_store.get_artifact(parent_art.artifact_id)
    assert retrieved is not None
    assert retrieved.artifact_id == parent_art.artifact_id
    assert retrieved.session_id == "sess-a"

    # Child artifact deriving from parent
    child_art = InformationArtifact(
        session_id="sess-a",
        source_type=ArtifactSourceType.AGENT_GENERATED,
        source_resource="agent-memory",
        direct_trust_level=TrustLevel.AGENT_DERIVED,
        inherited_trust_levels=frozenset({TrustLevel.EXTERNAL_UNTRUSTED}),
        data_classifications=frozenset({DataClassification.PUBLIC}),
        parent_artifact_ids=(parent_art.artifact_id,),
    )
    prov_store.register_artifact(child_art, payload="synthesized summary", graph=graph)

    # Verify session filtering
    session_arts = prov_store.get_artifacts_for_session("sess-a")
    assert len(session_arts) == 2
    assert prov_store.get_artifacts_for_session("sess-b") == []

    # Verify parent retrieval
    parents = prov_store.get_parent_artifacts(child_art.artifact_id)
    assert len(parents) == 1
    assert parents[0].artifact_id == parent_art.artifact_id


def test_provenance_store_rejects_missing_and_cross_session_parents() -> None:
    """Verify child artifacts cannot reference missing or cross-session parent artifacts."""
    prov_store = ProvenanceStore()

    # Missing parent
    missing_id = uuid4()
    child_missing = InformationArtifact(
        session_id="sess-a",
        source_type=ArtifactSourceType.AGENT_GENERATED,
        source_resource="agent-memory",
        direct_trust_level=TrustLevel.AGENT_DERIVED,
        parent_artifact_ids=(missing_id,),
    )
    with pytest.raises(MissingArtifactError):
        prov_store.register_artifact(child_missing)

    # Parent in session B
    foreign_parent = InformationArtifact(
        session_id="sess-b",
        source_type=ArtifactSourceType.DATABASE,
        source_resource="customer-db",
        direct_trust_level=TrustLevel.INTERNAL_TRUSTED,
    )
    prov_store.register_artifact(foreign_parent)

    # Attempt to reference session B parent from session A
    child_cross_session = InformationArtifact(
        session_id="sess-a",
        source_type=ArtifactSourceType.AGENT_GENERATED,
        source_resource="agent-memory",
        direct_trust_level=TrustLevel.AGENT_DERIVED,
        parent_artifact_ids=(foreign_parent.artifact_id,),
    )
    with pytest.raises(CrossSessionReferenceError):
        prov_store.register_artifact(child_cross_session)


def test_provenance_cycle_detection_and_rollback() -> None:
    """Verify that cyclic derivation raises ProvenanceCycleError and rolls back state."""
    prov_store = ProvenanceStore()
    graph = CausalExecutionGraph(session_id="sess-cycle")

    # Create A
    art_a = InformationArtifact(
        session_id="sess-cycle",
        source_type=ArtifactSourceType.INTERNAL_RESOURCE,
        source_resource="res-a",
        direct_trust_level=TrustLevel.INTERNAL_TRUSTED,
    )
    prov_store.register_artifact(art_a, payload="data A", graph=graph)

    # Create B derived from A
    art_b = InformationArtifact(
        session_id="sess-cycle",
        source_type=ArtifactSourceType.AGENT_GENERATED,
        source_resource="res-b",
        direct_trust_level=TrustLevel.AGENT_DERIVED,
        parent_artifact_ids=(art_a.artifact_id,),
    )
    prov_store.register_artifact(art_b, payload="data B", graph=graph)

    # Attempt to derive A from B (Cycle: A -> B -> A)
    # Re-registering or creating an artifact C that introduces a cycle with B
    art_cycle = InformationArtifact(
        artifact_id=art_a.artifact_id,  # Same as A
        session_id="sess-cycle",
        source_type=ArtifactSourceType.AGENT_GENERATED,
        source_resource="res-cycle",
        direct_trust_level=TrustLevel.AGENT_DERIVED,
        parent_artifact_ids=(art_b.artifact_id,),
    )
    with pytest.raises(ProvenanceCycleError):
        prov_store.register_artifact(art_cycle, payload="data cycle", graph=graph)


def test_injected_failure_rollback_after_node_creation() -> None:
    """Verify rollback removes artifact node, metadata, and payload when produces edge creation fails."""
    prov_store = ProvenanceStore()
    graph = CausalExecutionGraph(session_id="sess-injected-1")
    action_id = uuid4()

    art = InformationArtifact(
        session_id="sess-injected-1",
        created_by_action_id=action_id,
        source_type=ArtifactSourceType.AGENT_GENERATED,
        source_resource="res-fail-1",
        direct_trust_level=TrustLevel.AGENT_DERIVED,
    )

    # Injected failure: mock add_produces_edge to raise RuntimeError
    graph.add_produces_edge = MagicMock(side_effect=RuntimeError("Injected graph edge failure"))

    with pytest.raises(RuntimeError, match="Injected graph edge failure"):
        prov_store.register_artifact(art, payload="secret data", graph=graph)

    # Verify complete rollback
    assert prov_store.get_artifact(art.artifact_id) is None
    assert prov_store.payload_store.get_payload(art.artifact_id) is None
    assert graph._graph.has_node(str(art.artifact_id)) is False


def test_injected_failure_rollback_after_produces_edge() -> None:
    """Verify rollback removes artifact node, PRODUCES edge, metadata, and payload when derived_from edge fails."""
    prov_store = ProvenanceStore()
    graph = CausalExecutionGraph(session_id="sess-injected-2")

    # Action node in graph
    action_id = uuid4()
    from app.schemas.action import AgentAction

    action = AgentAction(
        action_id=action_id,
        agent_id="agent-01",
        session_id="sess-injected-2",
        tool_name="agent.transform",
        action_type=ActionType.TOOL_CALL,
        target_environment=TargetEnvironment.DEVELOPMENT,
        data_classifications=[DataClassification.PUBLIC],
        input_trust_level=TrustLevel.MEDIUM,
    )
    graph.add_action(action)

    parent_art = InformationArtifact(
        session_id="sess-injected-2",
        source_type=ArtifactSourceType.INTERNAL_RESOURCE,
        source_resource="res-parent",
        direct_trust_level=TrustLevel.INTERNAL_TRUSTED,
    )
    prov_store.register_artifact(parent_art, payload="parent", graph=graph)

    child_art = InformationArtifact(
        session_id="sess-injected-2",
        created_by_action_id=action_id,
        source_type=ArtifactSourceType.AGENT_GENERATED,
        source_resource="res-child",
        direct_trust_level=TrustLevel.AGENT_DERIVED,
        parent_artifact_ids=(parent_art.artifact_id,),
    )

    # Injected failure during derived_from edge creation
    graph.add_derived_from_edge = MagicMock(
        side_effect=RuntimeError("Injected derived_from failure")
    )

    with pytest.raises(RuntimeError, match="Injected derived_from failure"):
        prov_store.register_artifact(child_art, payload="child data", graph=graph)

    # Verify complete rollback: node and edges removed
    assert prov_store.get_artifact(child_art.artifact_id) is None
    assert prov_store.payload_store.get_payload(child_art.artifact_id) is None
    assert graph._graph.has_node(str(child_art.artifact_id)) is False
    assert (str(action_id), str(child_art.artifact_id)) not in graph._graph.edges()


def test_oversized_payload_atomicity() -> None:
    """Verify payload exceeding size limit is rejected atomically before any state is committed."""
    prov_store = ProvenanceStore()
    graph = CausalExecutionGraph(session_id="sess-oversize")

    art = InformationArtifact(
        session_id="sess-oversize",
        source_type=ArtifactSourceType.FILE,
        source_resource="huge.bin",
        direct_trust_level=TrustLevel.INTERNAL_TRUSTED,
    )

    # Payload exceeding 10MB limit
    oversized_data = b"X" * (11 * 1024 * 1024)

    with pytest.raises(ValueError, match="exceeds limit"):
        prov_store.register_artifact(art, payload=oversized_data, graph=graph)

    # Verify 100% atomicity: no metadata, no payload, no graph node, no edges
    assert prov_store.get_artifact(art.artifact_id) is None
    assert prov_store.payload_store.get_payload(art.artifact_id) is None
    assert graph._graph.has_node(str(art.artifact_id)) is False
    assert graph.node_count() == 0
    assert graph.edge_count() == 0


def test_action_causality_dag_and_artifact_lineage_dag() -> None:
    """Verify is_action_causality_dag and is_artifact_lineage_dag relation-filtered integrity."""
    graph = CausalExecutionGraph(session_id="sess-subgraph-dag")

    from app.schemas.action import AgentAction

    a1 = AgentAction(
        action_id=uuid4(),
        agent_id="agent-01",
        session_id="sess-subgraph-dag",
        tool_name="web.search",
        action_type=ActionType.TOOL_CALL,
        target_environment=TargetEnvironment.DEVELOPMENT,
        data_classifications=[DataClassification.PUBLIC],
        input_trust_level=TrustLevel.MEDIUM,
    )
    a2 = AgentAction(
        action_id=uuid4(),
        agent_id="agent-01",
        session_id="sess-subgraph-dag",
        tool_name="agent.transform",
        action_type=ActionType.TOOL_CALL,
        target_environment=TargetEnvironment.DEVELOPMENT,
        data_classifications=[DataClassification.PUBLIC],
        input_trust_level=TrustLevel.MEDIUM,
    )
    graph.add_action(a1)
    graph.add_action(a2)
    graph.add_relationship(str(a1.action_id), str(a2.action_id), relation=GraphRelation.CAUSES)

    assert graph.is_action_causality_dag() is True

    # Artifact lineage
    art1_id = str(uuid4())
    art2_id = str(uuid4())
    graph._graph.add_node(art1_id, node_type=GraphNodeType.ARTIFACT.value)
    graph._graph.add_node(art2_id, node_type=GraphNodeType.ARTIFACT.value)
    graph.add_derived_from_edge(art2_id, art1_id)

    assert graph.is_artifact_lineage_dag() is True
    assert graph.is_dag() is True


def test_mixed_graph_semantics_heterogeneous_cycle_accepted() -> None:
    """Verify heterogeneous mixed-cycle structure is accepted while CAUSES and DERIVED_FROM remain DAGs.

    Structure:
    Artifact A --CONSUMES--> Action B --PRODUCES--> Artifact C --DERIVED_FROM--> Artifact A

    In full NetworkX graph: ArtA -> ActB -> ArtC -> ArtA (a directed cycle across relations).
    In semantics:
    - Action causality (CAUSES): DAG (True)
    - Artifact lineage (DERIVED_FROM): DAG (True)
    - Full heterogeneous graph: Not required to be DAG.
    """
    graph = CausalExecutionGraph(session_id="sess-mixed-graph")

    # 1. Action B
    from app.schemas.action import AgentAction

    action_b = AgentAction(
        action_id=uuid4(),
        agent_id="agent-01",
        session_id="sess-mixed-graph",
        tool_name="agent.transform",
        action_type=ActionType.TOOL_CALL,
        target_environment=TargetEnvironment.DEVELOPMENT,
        data_classifications=[DataClassification.PUBLIC],
        input_trust_level=TrustLevel.MEDIUM,
    )
    graph.add_action(action_b)

    # 2. Artifact A
    art_a = InformationArtifact(
        session_id="sess-mixed-graph",
        source_type=ArtifactSourceType.EXTERNAL_CONTENT,
        source_resource="public-web",
        direct_trust_level=TrustLevel.EXTERNAL_UNTRUSTED,
    )
    graph.add_artifact_node(art_a)

    # 3. Artifact C
    art_c = InformationArtifact(
        session_id="sess-mixed-graph",
        created_by_action_id=action_b.action_id,
        source_type=ArtifactSourceType.AGENT_GENERATED,
        source_resource="agent-memory",
        direct_trust_level=TrustLevel.AGENT_DERIVED,
        parent_artifact_ids=(art_a.artifact_id,),
    )
    graph.add_artifact_node(art_c)

    # Link relations:
    # Artifact A --CONSUMES--> Action B
    graph.add_consumes_edge(str(art_a.artifact_id), str(action_b.action_id))

    # Action B --PRODUCES--> Artifact C
    graph.add_produces_edge(str(action_b.action_id), str(art_c.artifact_id))

    # Artifact C --DERIVED_FROM--> Artifact A
    graph.add_derived_from_edge(str(art_c.artifact_id), str(art_a.artifact_id))

    # Assert relation-filtered DAG integrity
    assert graph.is_action_causality_dag() is True
    assert graph.is_artifact_lineage_dag() is True
    assert graph.has_valid_typed_dags() is True

    # Assert that full heterogeneous graph has a directed cycle across relations
    assert nx.is_directed_acyclic_graph(graph._graph) is False


def test_trust_taxonomy_migration_and_provenance_isolation() -> None:
    """Verify legacy trust scores never manufacture provenance origin."""
    from app.provenance.analyzer import ProvenanceAnalyzer
    from app.provenance.factory import ArtifactFactory
    from app.provenance.resources import ResourceSecurityProfileRegistry
    from app.schemas.action import AgentActionProposal
    from app.schemas.enums import LegacyTrustLevel, ProvenanceTrust, normalize_to_provenance_trust
    from app.schemas.policy import PolicyProvenanceContext

    # 1. normalize_to_provenance_trust unit behavior
    # Legacy HIGH without metadata -> UNKNOWN (NOT INTERNAL_TRUSTED)
    assert normalize_to_provenance_trust(TrustLevel.HIGH) == ProvenanceTrust.UNKNOWN
    assert normalize_to_provenance_trust(LegacyTrustLevel.HIGH) == ProvenanceTrust.UNKNOWN

    # Legacy VERIFIED_HUMAN without human-origin evidence -> UNKNOWN (NOT TRUSTED_HUMAN)
    assert normalize_to_provenance_trust(TrustLevel.VERIFIED_HUMAN) == ProvenanceTrust.UNKNOWN

    # Actual trusted human ingestion path -> TRUSTED_HUMAN
    assert (
        normalize_to_provenance_trust(
            TrustLevel.VERIFIED_HUMAN,
            source_type=ArtifactSourceType.HUMAN_INPUT,
            is_trusted_human_origin=True,
        )
        == ProvenanceTrust.TRUSTED_HUMAN
    )

    # Trusted ResourceSecurityProfile (customer-db) -> INTERNAL_TRUSTED
    registry = ResourceSecurityProfileRegistry()
    profile = registry.get_profile("customer-db")
    assert profile is not None
    assert (
        normalize_to_provenance_trust(profile.trust_level, source_type=profile.source_type)
        == ProvenanceTrust.INTERNAL_TRUSTED
    )

    # 2. Integration with ProvenanceAnalyzer
    from app.gateway.registry import ToolSpec

    store = ProvenanceStore()
    analyzer = ProvenanceAnalyzer(store=store)
    write_spec = ToolSpec(name="file.write")

    # Test A: Artifact with legacy HIGH without provenance metadata
    art_high = InformationArtifact(
        session_id="sess-mig-test",
        source_type=ArtifactSourceType.UNKNOWN,
        source_resource="unspecified-res",
        direct_trust_level=TrustLevel.HIGH,
    )
    store.register_artifact(art_high)

    prop_high = AgentActionProposal(
        agent_id="agent-01",
        session_id="sess-mig-test",
        tool_name="file.write",
        tool_arguments={"path": "out.txt", "content": "data"},
        input_artifact_ids=[art_high.artifact_id],
    )
    ctx_high, _ = analyzer.analyze_provenance(prop_high, write_spec)
    assert "UNKNOWN" in ctx_high.input_direct_trust_levels
    assert "INTERNAL_TRUSTED" not in ctx_high.input_direct_trust_levels
    assert "HIGH" not in ctx_high.input_direct_trust_levels

    # Test B: Artifact with legacy VERIFIED_HUMAN without human origin evidence
    art_vh = InformationArtifact(
        session_id="sess-mig-test",
        source_type=ArtifactSourceType.TOOL_RESULT,
        source_resource="external-tool",
        direct_trust_level=TrustLevel.VERIFIED_HUMAN,
    )
    store.register_artifact(art_vh)

    prop_vh = AgentActionProposal(
        agent_id="agent-01",
        session_id="sess-mig-test",
        tool_name="file.write",
        tool_arguments={"path": "out.txt", "content": "data"},
        input_artifact_ids=[art_vh.artifact_id],
    )
    ctx_vh, _ = analyzer.analyze_provenance(prop_vh, write_spec)
    assert "UNKNOWN" in ctx_vh.input_direct_trust_levels
    assert "TRUSTED_HUMAN" not in ctx_vh.input_direct_trust_levels
    assert "VERIFIED_HUMAN" not in ctx_vh.input_direct_trust_levels

    # Test C: Artifact created through actual trusted human ingestion path
    art_human = ArtifactFactory.create_ingested_artifact(
        session_id="sess-mig-test",
        source_resource="operator-prompt",
        source_type=ArtifactSourceType.HUMAN_INPUT,
        direct_trust_level=ProvenanceTrust.TRUSTED_HUMAN,
    )
    store.register_artifact(art_human)

    prop_human = AgentActionProposal(
        agent_id="agent-01",
        session_id="sess-mig-test",
        tool_name="file.write",
        tool_arguments={"path": "out.txt", "content": "data"},
        input_artifact_ids=[art_human.artifact_id],
    )
    ctx_human, _ = analyzer.analyze_provenance(prop_human, write_spec)
    assert "TRUSTED_HUMAN" in ctx_human.input_direct_trust_levels

    # Test D: Artifact created from trusted ResourceSecurityProfile(customer-db)
    art_db = InformationArtifact(
        session_id="sess-mig-test",
        source_type=profile.source_type,
        source_resource=profile.resource_id,
        direct_trust_level=profile.trust_level,
        data_classifications=profile.data_classifications,
    )
    store.register_artifact(art_db)

    prop_db = AgentActionProposal(
        agent_id="agent-01",
        session_id="sess-mig-test",
        tool_name="file.write",
        tool_arguments={"path": "out.txt", "content": "data"},
        input_artifact_ids=[art_db.artifact_id],
    )
    ctx_db, _ = analyzer.analyze_provenance(prop_db, write_spec)
    assert "INTERNAL_TRUSTED" in ctx_db.input_direct_trust_levels

    # Test E: PolicyProvenanceContext validator rejects legacy scores
    with pytest.raises(ValueError, match="Invalid provenance trust level 'HIGH'"):
        PolicyProvenanceContext(input_direct_trust_levels=["HIGH"])

    with pytest.raises(ValueError, match="Invalid provenance trust level 'VERIFIED_HUMAN'"):
        PolicyProvenanceContext(input_direct_trust_levels=["VERIFIED_HUMAN"])
