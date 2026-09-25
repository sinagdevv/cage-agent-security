"""Tests for safe causal graph query APIs, cycle prevention, and snapshotting."""

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from app.gateway.registry import ToolRegistry, ToolSpec
from app.graph.causal_graph import (
    CausalExecutionGraph,
    GraphCycleError,
)
from app.schemas.action import AgentAction
from app.schemas.enums import (
    ActionType,
    DataClassification,
    GraphNodeType,
    GraphRelation,
    PolicyDecision,
    TargetEnvironment,
    ToolExecutionStatus,
    TrustLevel,
)


def make_test_action(
    tool_name: str,
    target_environment: TargetEnvironment = TargetEnvironment.DEVELOPMENT,
    action_type: ActionType = ActionType.TOOL_CALL,
    data_classifications: list[DataClassification] | None = None,
    parent_action_id: str | None = None,
) -> AgentAction:
    """Helper to construct an authoritative AgentAction."""
    return AgentAction(
        action_id=uuid4(),
        session_id="test-session",
        agent_id="test-agent",
        agent_instance_id="inst-1",
        tool_name=tool_name,
        action_type=action_type,
        target_environment=target_environment,
        data_classifications=data_classifications or [DataClassification.PUBLIC],
        parent_action_id=uuid4() if parent_action_id else None,
        goal="testing",
        current_task="task",
        execution_status=ToolExecutionStatus.AUTHORIZED,
        policy_result=PolicyDecision.ALLOW,
        risk_score=0.1,
        input_trust_level=TrustLevel.HIGH,
        created_at=datetime.now(UTC),
    )


def test_get_parents_and_children():
    """Verify get_parents and get_children correctly follow CAUSES edges."""
    graph = CausalExecutionGraph("session-1")
    act_a = make_test_action("tool.a")
    act_b = make_test_action("tool.b")
    act_c = make_test_action("tool.c")

    graph.add_action(act_a)
    graph.add_action(act_b)
    graph.add_action(act_c)

    id_a = str(act_a.action_id)
    id_b = str(act_b.action_id)
    id_c = str(act_c.action_id)

    graph.add_relationship(id_a, id_b, relation=GraphRelation.CAUSES)
    graph.add_relationship(id_b, id_c, relation=GraphRelation.CAUSES)

    assert graph.get_parents(id_b) == [id_a]
    assert graph.get_parents(id_c) == [id_b]
    assert graph.get_parents(id_a) == []

    assert graph.get_children(id_a) == [id_b]
    assert graph.get_children(id_b) == [id_c]
    assert graph.get_children(id_c) == []


def test_shortest_path_and_has_path():
    """Verify path queries return correct paths and node existence checks."""
    graph = CausalExecutionGraph("session-paths")
    act_a = make_test_action("tool.a")
    act_b = make_test_action("tool.b")
    act_c = make_test_action("tool.c")

    graph.add_action(act_a)
    graph.add_action(act_b)
    graph.add_action(act_c)

    id_a = str(act_a.action_id)
    id_b = str(act_b.action_id)
    id_c = str(act_c.action_id)

    graph.add_relationship(id_a, id_b, relation=GraphRelation.CAUSES)
    graph.add_relationship(id_b, id_c, relation=GraphRelation.CAUSES)

    assert graph.has_path(id_a, id_c) is True
    assert graph.has_path(id_c, id_a) is False
    assert graph.get_shortest_path(id_a, id_c) == [id_a, id_b, id_c]
    assert graph.get_shortest_path(id_c, id_a) == []


def test_get_action_ancestors_topological_order():
    """Verify ancestors are returned in topological order from oldest to newest."""
    graph = CausalExecutionGraph("session-topo")
    act_1 = make_test_action("root.search")
    act_2 = make_test_action("step.read")
    act_3 = make_test_action("step.transform")
    act_4 = make_test_action("leaf.post")

    for act in [act_1, act_2, act_3, act_4]:
        graph.add_action(act)

    ids = [str(a.action_id) for a in [act_1, act_2, act_3, act_4]]
    graph.add_relationship(ids[0], ids[1], relation=GraphRelation.CAUSES)
    graph.add_relationship(ids[1], ids[2], relation=GraphRelation.CAUSES)
    graph.add_relationship(ids[2], ids[3], relation=GraphRelation.CAUSES)

    ancestors = graph.get_action_ancestors(ids[3])
    assert len(ancestors) == 3
    assert [a.tool_name for a in ancestors] == ["root.search", "step.read", "step.transform"]

    history = graph.get_tool_history(ids[3])
    assert history == ["root.search", "step.read", "step.transform"]

    recent = graph.get_recent_ancestor_actions(ids[3], limit=2)
    assert len(recent) == 2
    assert recent[0].tool_name == "step.transform"  # immediate parent
    assert recent[1].tool_name == "step.read"


def test_graph_queries_return_safe_copies_preventing_mutation():
    """Requirement 16: Mutating returned action or data does not modify graph state."""
    graph = CausalExecutionGraph("session-immutable")
    act = make_test_action("safe.tool")
    graph.add_action(act)
    aid = str(act.action_id)

    # 1. Mutate returned get_action
    retrieved = graph.get_action(aid)
    assert retrieved is not None
    retrieved.goal = "TAMPERED_GOAL"
    retrieved.tool_name = "TAMPERED_TOOL"

    fresh = graph.get_action(aid)
    assert fresh is not None
    assert fresh.goal == "testing"
    assert fresh.tool_name == "safe.tool"

    # 2. Mutate returned get_node_data
    node_data = graph.get_node_data(aid)
    assert node_data is not None
    node_data["tool_name"] = "TAMPERED_NODE_TOOL"

    fresh_node_data = graph.get_node_data(aid)
    assert fresh_node_data is not None
    assert fresh_node_data["tool_name"] == "safe.tool"


def test_cycle_detection_at_graph_layer_raises_graph_cycle_error():
    """Requirement 7 & 8: GraphCycleError raised when a relationship would create a cycle."""
    graph = CausalExecutionGraph("session-cycle")
    act_a = make_test_action("tool.a")
    act_b = make_test_action("tool.b")
    act_c = make_test_action("tool.c")

    graph.add_action(act_a)
    graph.add_action(act_b)
    graph.add_action(act_c)

    id_a = str(act_a.action_id)
    id_b = str(act_b.action_id)
    id_c = str(act_c.action_id)

    # A -> B -> C
    graph.add_relationship(id_a, id_b, relation=GraphRelation.CAUSES)
    graph.add_relationship(id_b, id_c, relation=GraphRelation.CAUSES)

    # Attempt C -> A (would create A -> B -> C -> A cycle)
    with pytest.raises(GraphCycleError) as exc_info:
        graph.add_relationship(id_c, id_a, relation=GraphRelation.CAUSES)

    assert "Causal cycle detected" in str(exc_info.value)
    assert graph.is_dag() is True


def test_action_node_metadata_snapshotting():
    """Requirement 8 & 12: Action nodes snapshot security attributes at evaluation time."""
    graph = CausalExecutionGraph("session-snapshot")
    custom_spec = ToolSpec(
        name="custom.admin",
        description="Privileged admin tool",
        known=True,
        privileged=True,
        destructive=True,
        external_sink=True,
        default_classification=DataClassification.CONFIDENTIAL,
    )
    act = make_test_action(
        "custom.admin",
        data_classifications=[DataClassification.CONFIDENTIAL],
    )
    graph.add_action(
        act,
        tool_spec=custom_spec,
        effective_data_classifications=["CONFIDENTIAL", "INTERNAL"],
        policy_version="phase4-v1",
        policy_input_schema_version="cage-policy-input-v2",
    )

    data = graph.get_node_data(str(act.action_id))
    assert data is not None
    assert data["node_type"] == GraphNodeType.ACTION.value
    assert data["tool_known"] is True
    assert data["tool_privileged"] is True
    assert data["tool_destructive"] is True
    assert data["tool_external_sink"] is True
    assert data["policy_version"] == "phase4-v1"
    assert data["policy_input_schema_version"] == "cage-policy-input-v2"
    assert set(data["effective_data_classifications"]) == {"CONFIDENTIAL", "INTERNAL"}


def test_changing_tool_registry_does_not_mutate_historic_node_metadata():
    """Requirement 24: Later changes to ToolRegistry do not alter snapshotted node attributes."""
    registry = ToolRegistry()
    registry.register(
        ToolSpec(
            name="dynamic.tool",
            description="Initially low risk",
            privileged=False,
            destructive=False,
        )
    )

    graph = CausalExecutionGraph("session-registry-drift")
    act = make_test_action("dynamic.tool")

    initial_spec = registry.get("dynamic.tool")
    graph.add_action(act, tool_spec=initial_spec)

    # Later: tool definition changes in registry (e.g. administrator marks it privileged)
    registry.register(
        ToolSpec(
            name="dynamic.tool",
            description="Reclassified as highly privileged",
            privileged=True,
            destructive=True,
        )
    )

    # Historic node in graph must retain the original snapshotted attributes
    node_data = graph.get_node_data(str(act.action_id))
    assert node_data is not None
    assert node_data["tool_privileged"] is False
    assert node_data["tool_destructive"] is False
