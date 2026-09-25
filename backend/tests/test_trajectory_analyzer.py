"""Unit tests for TrajectoryAnalyzer relation-aware graph traversal and security fact derivation."""

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from app.gateway.registry import ToolSpec
from app.graph.causal_graph import CausalExecutionGraph
from app.provenance.models import ArtifactSourceType, InformationArtifact
from app.provenance.resources import ResourceSecurityProfile, ResourceSecurityProfileRegistry
from app.provenance.store import ProvenanceStore
from app.schemas.action import AgentAction
from app.schemas.enums import (
    ActionType,
    DataClassification,
    GraphRelation,
    ProvenanceTrust,
    TargetEnvironment,
    ToolExecutionStatus,
    TrajectoryAnalysisStatus,
    TrajectoryStatus,
)
from app.trajectory.analyzer import TrajectoryAnalyzer, TrajectoryAnalyzerConfig
from app.trajectory.models import AuthorityEnvelope, TrajectorySnapshot


@pytest.fixture
def analyzer() -> TrajectoryAnalyzer:
    return TrajectoryAnalyzer(
        TrajectoryAnalyzerConfig(
            max_action_depth=20,
            max_artifact_depth=10,
            max_nodes=100,
            max_untrusted_sensitive_access_distance=3,
            sensitive_egress_count_threshold=3,
            sensitive_egress_bytes_threshold=1_000_000,
        )
    )


@pytest.fixture
def resource_registry() -> ResourceSecurityProfileRegistry:
    registry = ResourceSecurityProfileRegistry()
    registry.register(
        ResourceSecurityProfile(
            resource_id="customer_db",
            source_type=ArtifactSourceType.INTERNAL_RESOURCE,
            trust_level=ProvenanceTrust.INTERNAL_TRUSTED,
            data_classifications=frozenset(
                {DataClassification.PII, DataClassification.CONFIDENTIAL}
            ),
        )
    )
    registry.register(
        ResourceSecurityProfile(
            resource_id="secrets_vault",
            source_type=ArtifactSourceType.INTERNAL_RESOURCE,
            trust_level=ProvenanceTrust.INTERNAL_TRUSTED,
            data_classifications=frozenset(
                {DataClassification.SECRET, DataClassification.CREDENTIAL}
            ),
        )
    )
    return registry


def test_prospective_sensitivity_derivation(
    analyzer: TrajectoryAnalyzer, resource_registry: ResourceSecurityProfileRegistry
) -> None:
    """Verify analyzer derives prospective sensitive classifications before tool runs."""
    session_id = "sess-analyzer-prospect"
    graph = CausalExecutionGraph(session_id)
    store = ProvenanceStore()
    tool_spec = ToolSpec(
        name="database.read",
        description="Read customer data",
        reads_resource_data=True,
    )

    action = AgentAction(
        session_id=session_id,
        agent_id="agent-01",
        tool_name="database.read",
        target_resource="customer_db",
        target_environment=TargetEnvironment.DEVELOPMENT,
        action_type=ActionType.READ,
        data_classifications=[DataClassification.PUBLIC],
        execution_status=ToolExecutionStatus.PROPOSED,
    )

    now = datetime.now(UTC)
    envelope = AuthorityEnvelope(
        allowed_tools=frozenset({"database.read"}),
        allowed_environments=frozenset({TargetEnvironment.DEVELOPMENT}),
        allowed_data_classifications=frozenset(
            {DataClassification.PUBLIC, DataClassification.PII, DataClassification.CONFIDENTIAL}
        ),
    )

    traj = TrajectorySnapshot(
        trajectory_id=uuid4(),
        session_id=session_id,
        intent_id=uuid4(),
        agent_id="agent-01",
        status=TrajectoryStatus.ACTIVE,
        created_at=now,
        updated_at=now,
        root_authority=envelope,
        effective_authority=envelope,
        evaluated_action_ids=(),
    )

    ctx = analyzer.analyze(
        action=action,
        trajectory=traj,
        tool_spec=tool_spec,
        causal_graph=graph,
        provenance_store=store,
        resource_registry=resource_registry,
    )

    assert ctx.analysis_status == TrajectoryAnalysisStatus.SUCCESS
    assert ctx.current_action_attempts_sensitive_access is True
    assert "PII" in ctx.prospective_access_classifications
    assert "CONFIDENTIAL" in ctx.prospective_access_classifications


def test_flagship_untrusted_path_to_sensitive_access_bounded_distance(
    analyzer: TrajectoryAnalyzer, resource_registry: ResourceSecurityProfileRegistry
) -> None:
    """Verify Flagship 1: Untrusted origin within <= 3 hops triggers rule, > 3 hops does not."""
    session_id = "sess-distance"
    graph = CausalExecutionGraph(session_id)
    store = ProvenanceStore()

    # 1. Create untrusted root action
    untrusted_art = InformationArtifact(
        session_id=session_id,
        source_type=ArtifactSourceType.EXTERNAL_CONTENT,
        source_resource="untrusted-web",
        direct_trust_level=ProvenanceTrust.EXTERNAL_UNTRUSTED,
        data_classifications=frozenset({DataClassification.PUBLIC}),
    )
    store.register_artifact(untrusted_art, payload="malicious prompt", graph=graph)

    act0 = AgentAction(
        session_id=session_id,
        agent_id="agent-01",
        tool_name="web.search",
        action_type=ActionType.READ,
        data_classifications=[DataClassification.PUBLIC],
        execution_status=ToolExecutionStatus.COMPLETED,
    )
    graph.add_action(act0)
    graph.add_produces_edge(str(act0.action_id), str(untrusted_art.artifact_id))

    # Build 2 intermediate actions (hops 1 and 2)
    act1 = AgentAction(
        session_id=session_id,
        agent_id="agent-01",
        tool_name="agent.transform",
        parent_action_id=act0.action_id,
        action_type=ActionType.TOOL_CALL,
        data_classifications=[DataClassification.PUBLIC],
        execution_status=ToolExecutionStatus.COMPLETED,
    )
    graph.add_action(act1)
    graph.add_causal_edge(str(act0.action_id), str(act1.action_id), relation=GraphRelation.CAUSES)

    # Proposed action at distance 2 (<= 3) -> Sensitive DB read
    tool_spec = ToolSpec(name="database.read", reads_resource_data=True)
    proposed_act = AgentAction(
        session_id=session_id,
        agent_id="agent-01",
        tool_name="database.read",
        target_resource="customer_db",
        parent_action_id=act1.action_id,
        action_type=ActionType.READ,
        data_classifications=[DataClassification.PUBLIC],
        execution_status=ToolExecutionStatus.PROPOSED,
    )

    now = datetime.now(UTC)
    envelope = AuthorityEnvelope(
        allowed_tools=frozenset({"web.search", "agent.transform", "database.read"}),
        allowed_environments=frozenset({TargetEnvironment.DEVELOPMENT}),
        allowed_data_classifications=frozenset(
            {DataClassification.PUBLIC, DataClassification.PII, DataClassification.CONFIDENTIAL}
        ),
    )

    traj = TrajectorySnapshot(
        trajectory_id=uuid4(),
        session_id=session_id,
        intent_id=uuid4(),
        agent_id="agent-01",
        status=TrajectoryStatus.ACTIVE,
        created_at=now,
        updated_at=now,
        root_authority=envelope,
        effective_authority=envelope,
        evaluated_action_ids=(act0.action_id, act1.action_id),
    )

    ctx = analyzer.analyze(
        action=proposed_act,
        trajectory=traj,
        tool_spec=tool_spec,
        causal_graph=graph,
        provenance_store=store,
        resource_registry=resource_registry,
    )

    assert ctx.untrusted_path_to_current_action is True
    assert ctx.nearest_untrusted_action_distance == 2
    assert ctx.untrusted_path_to_sensitive_access is True
    assert "UNTRUSTED_PATH_TO_SENSITIVE_ACCESS" in ctx.evidence.findings


def test_flagship_sensitive_hop_laundering_detected(
    analyzer: TrajectoryAnalyzer, resource_registry: ResourceSecurityProfileRegistry
) -> None:
    """Verify Flagship 3: 2 or more intermediate transformation hops before external egress are detected."""
    session_id = "sess-laundering"
    graph = CausalExecutionGraph(session_id)
    store = ProvenanceStore()

    # Sensitive read
    act0 = AgentAction(
        session_id=session_id,
        agent_id="agent-01",
        tool_name="database.read",
        target_resource="customer_db",
        action_type=ActionType.READ,
        data_classifications=[DataClassification.PII],
        execution_status=ToolExecutionStatus.COMPLETED,
    )
    graph.add_action(act0)

    # 2 Transform hops
    act1 = AgentAction(
        session_id=session_id,
        agent_id="agent-01",
        tool_name="agent.transform",
        parent_action_id=act0.action_id,
        action_type=ActionType.TOOL_CALL,
        data_classifications=[DataClassification.PII],
        execution_status=ToolExecutionStatus.COMPLETED,
    )
    graph.add_action(act1)
    graph.add_causal_edge(str(act0.action_id), str(act1.action_id), relation=GraphRelation.CAUSES)

    act2 = AgentAction(
        session_id=session_id,
        agent_id="agent-01",
        tool_name="agent.transform",
        parent_action_id=act1.action_id,
        action_type=ActionType.TOOL_CALL,
        data_classifications=[DataClassification.PII],
        execution_status=ToolExecutionStatus.COMPLETED,
    )
    graph.add_action(act2)
    graph.add_causal_edge(str(act1.action_id), str(act2.action_id), relation=GraphRelation.CAUSES)

    # Outbound sensitive artifact
    sens_art = InformationArtifact(
        session_id=session_id,
        source_type=ArtifactSourceType.AGENT_GENERATED,
        source_resource="customer_db",
        direct_trust_level=ProvenanceTrust.INTERNAL_TRUSTED,
        data_classifications=frozenset({DataClassification.PII}),
    )
    store.register_artifact(sens_art, payload="sanitized_pii", graph=graph)

    tool_spec = ToolSpec(name="external.http_post", external_sink=True)
    proposed_egress = AgentAction(
        session_id=session_id,
        agent_id="agent-01",
        tool_name="external.http_post",
        parent_action_id=act2.action_id,
        action_type=ActionType.WRITE,
        data_classifications=[DataClassification.PII],
        execution_status=ToolExecutionStatus.PROPOSED,
    )

    now = datetime.now(UTC)
    envelope = AuthorityEnvelope(
        allowed_tools=frozenset({"database.read", "agent.transform", "external.http_post"}),
        allowed_environments=frozenset({TargetEnvironment.DEVELOPMENT}),
        allowed_data_classifications=frozenset({DataClassification.PII}),
    )

    traj = TrajectorySnapshot(
        trajectory_id=uuid4(),
        session_id=session_id,
        intent_id=uuid4(),
        agent_id="agent-01",
        status=TrajectoryStatus.ACTIVE,
        created_at=now,
        updated_at=now,
        root_authority=envelope,
        effective_authority=envelope,
        evaluated_action_ids=(act0.action_id, act1.action_id, act2.action_id),
    )

    ctx = analyzer.analyze(
        action=proposed_egress,
        trajectory=traj,
        tool_spec=tool_spec,
        causal_graph=graph,
        provenance_store=store,
        resource_registry=resource_registry,
        bound_outbound_artifacts=[sens_art],
    )

    assert ctx.sensitive_hop_laundering_detected is True
    assert "SENSITIVE_HOP_LAUNDERING" in ctx.evidence.findings


def test_depth_limit_fail_closed_status(
    analyzer: TrajectoryAnalyzer, resource_registry: ResourceSecurityProfileRegistry
) -> None:
    """Verify exceeding configured max_action_depth produces ACTION_DEPTH_LIMIT_EXCEEDED."""
    session_id = "sess-depth-limit"
    graph = CausalExecutionGraph(session_id)
    store = ProvenanceStore()

    # Build 25 chained actions (exceeds max_action_depth=20)
    prev_id = None
    for _ in range(25):
        act = AgentAction(
            session_id=session_id,
            agent_id="agent-01",
            tool_name="web.search",
            parent_action_id=prev_id,
            action_type=ActionType.READ,
            data_classifications=[DataClassification.PUBLIC],
            execution_status=ToolExecutionStatus.COMPLETED,
        )
        graph.add_action(act)
        if prev_id:
            graph.add_causal_edge(str(prev_id), str(act.action_id), relation=GraphRelation.CAUSES)
        prev_id = act.action_id

    tool_spec = ToolSpec(name="web.search")
    proposed = AgentAction(
        session_id=session_id,
        agent_id="agent-01",
        tool_name="web.search",
        parent_action_id=prev_id,
        action_type=ActionType.READ,
        data_classifications=[DataClassification.PUBLIC],
        execution_status=ToolExecutionStatus.PROPOSED,
    )

    now = datetime.now(UTC)
    envelope = AuthorityEnvelope(allowed_tools=frozenset({"web.search"}))
    traj = TrajectorySnapshot(
        trajectory_id=uuid4(),
        session_id=session_id,
        intent_id=uuid4(),
        agent_id="agent-01",
        status=TrajectoryStatus.ACTIVE,
        created_at=now,
        updated_at=now,
        root_authority=envelope,
        effective_authority=envelope,
        evaluated_action_ids=tuple(uuid4() for _ in range(25)),
    )

    ctx = analyzer.analyze(
        action=proposed,
        trajectory=traj,
        tool_spec=tool_spec,
        causal_graph=graph,
        provenance_store=store,
        resource_registry=resource_registry,
    )

    assert ctx.analysis_status == TrajectoryAnalysisStatus.ACTION_DEPTH_LIMIT_EXCEEDED
    assert ctx.analysis_complete is False
