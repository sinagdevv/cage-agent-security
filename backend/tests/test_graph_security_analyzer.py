"""Tests for GraphSecurityAnalyzer fact derivation, bounds, and limits."""

from datetime import UTC, datetime
from uuid import uuid4

from app.gateway.registry import ToolSpec
from app.graph.analyzer import GraphSecurityAnalyzer
from app.graph.causal_graph import CausalExecutionGraph
from app.schemas.action import AgentAction
from app.schemas.enums import (
    ActionType,
    DataClassification,
    GraphAnalysisStatus,
    GraphRelation,
    PolicyDecision,
    TargetEnvironment,
    ToolExecutionStatus,
    TrustLevel,
)


def make_action(
    tool_name: str,
    target_env: TargetEnvironment = TargetEnvironment.DEVELOPMENT,
    tool_known: bool = True,
    tool_privileged: bool = False,
    tool_destructive: bool = False,
    tool_external_sink: bool = False,
    classifications: list[str] | None = None,
    decision: PolicyDecision = PolicyDecision.ALLOW,
    status: ToolExecutionStatus = ToolExecutionStatus.AUTHORIZED,
) -> tuple[AgentAction, ToolSpec, list[str]]:
    """Helper to create an AgentAction and its snapshotted node attributes."""
    classes = classifications or ["PUBLIC"]
    action = AgentAction(
        action_id=uuid4(),
        session_id="analyzer-session",
        agent_id="test-agent",
        agent_instance_id="inst-1",
        tool_name=tool_name,
        action_type=ActionType.DESTRUCTIVE if tool_destructive else ActionType.TOOL_CALL,
        target_environment=target_env,
        data_classifications=[DataClassification(c) for c in classes],
        goal="testing",
        current_task="task",
        execution_status=status,
        policy_result=decision,
        risk_score=0.1,
        input_trust_level=TrustLevel.HIGH,
        created_at=datetime.now(UTC),
    )
    spec = ToolSpec(
        name=tool_name,
        description="test tool",
        known=tool_known,
        privileged=tool_privileged,
        destructive=tool_destructive,
        external_sink=tool_external_sink,
    )
    return action, spec, classes


def add_action_to_graph(
    graph: CausalExecutionGraph,
    item: tuple[AgentAction, ToolSpec, list[str]],
) -> AgentAction:
    """Helper to add an action with its snapshotted metadata to graph."""
    act, spec, classes = item
    graph.add_action(act, tool_spec=spec, effective_data_classifications=classes)
    return act


def test_analyzer_root_action_has_empty_ancestors():
    """Requirement 18 & 26: Root action has zero ancestors and empty sequence."""
    graph = CausalExecutionGraph("session-root")
    analyzer = GraphSecurityAnalyzer()

    ctx = analyzer.analyze_action_causality(graph, parent_action_id=None)

    assert ctx.analysis_status == GraphAnalysisStatus.SUCCESS
    assert ctx.analysis_complete is True
    assert ctx.ancestor_count == 0
    assert ctx.causal_depth == 0
    assert ctx.ancestor_action_ids == []
    assert ctx.ancestor_tool_sequence == []
    assert ctx.contains_denied_ancestor is False
    assert ctx.contains_privileged_ancestor is False
    assert ctx.has_lower_environment_ancestor is False
    assert ctx.has_high_environment_ancestor is False


def test_analyzer_excludes_current_action_from_ancestor_metrics():
    """Requirement 4 & 18: Current action is not in ancestor_action_ids or ancestor_tool_sequence."""
    graph = CausalExecutionGraph("session-parent")
    analyzer = GraphSecurityAnalyzer()

    act_1 = add_action_to_graph(graph, make_action("web.search"))

    # Current action proposes act_1 as parent
    ctx = analyzer.analyze_action_causality(graph, parent_action_id=str(act_1.action_id))

    assert ctx.ancestor_count == 1
    assert ctx.causal_depth == 1
    assert ctx.ancestor_action_ids == [str(act_1.action_id)]
    assert ctx.ancestor_tool_sequence == ["web.search"]


def test_analyzer_deterministic_topological_ordering():
    """Requirement 5: Ancestor arrays are ordered from oldest ancestor to immediate parent."""
    graph = CausalExecutionGraph("session-order")
    analyzer = GraphSecurityAnalyzer()

    act_1 = add_action_to_graph(
        graph, make_action("step1.read", TargetEnvironment.LOCAL, classifications=["INTERNAL"])
    )
    act_2 = add_action_to_graph(
        graph,
        make_action(
            "step2.process", TargetEnvironment.DEVELOPMENT, classifications=["CONFIDENTIAL"]
        ),
    )
    act_3 = add_action_to_graph(
        graph, make_action("step3.write", TargetEnvironment.DEVELOPMENT, classifications=["PUBLIC"])
    )

    id_1, id_2, id_3 = str(act_1.action_id), str(act_2.action_id), str(act_3.action_id)
    graph.add_relationship(id_1, id_2, relation=GraphRelation.CAUSES)
    graph.add_relationship(id_2, id_3, relation=GraphRelation.CAUSES)

    ctx = analyzer.analyze_action_causality(graph, parent_action_id=id_3)

    assert ctx.ancestor_count == 3
    assert ctx.causal_depth == 3
    assert ctx.ancestor_action_ids == [id_1, id_2, id_3]
    assert ctx.ancestor_tool_sequence == ["step1.read", "step2.process", "step3.write"]
    assert ctx.ancestor_environments == ["LOCAL", "DEVELOPMENT", "DEVELOPMENT"]
    assert ctx.ancestor_data_classifications == ["CONFIDENTIAL", "INTERNAL", "PUBLIC"]


def test_analyzer_depth_limit_exceeded_sets_status_without_fabrication():
    """Requirement 1 & 24: Depth limit exceeded sets status without fabricating privileged facts."""
    graph = CausalExecutionGraph("session-depth-limit")
    analyzer = GraphSecurityAnalyzer(max_depth=3)

    actions = [add_action_to_graph(graph, make_action(f"tool.{i}")) for i in range(5)]

    for i in range(4):
        graph.add_relationship(
            str(actions[i].action_id),
            str(actions[i + 1].action_id),
            relation=GraphRelation.CAUSES,
        )

    # Traversal from actions[4] backwards: depth will reach 4 > max_depth 3
    ctx = analyzer.analyze_action_causality(graph, parent_action_id=str(actions[4].action_id))

    assert ctx.analysis_status == GraphAnalysisStatus.DEPTH_LIMIT_EXCEEDED
    assert ctx.analysis_complete is False
    # CRITICAL INVARIANT: Facts must not be fabricated!
    assert ctx.contains_privileged_ancestor is False
    assert ctx.contains_destructive_ancestor is False


def test_analyzer_node_limit_exceeded_sets_status_without_fabrication():
    """Requirement 1: Node limit exceeded sets status without fabricating privileged facts."""
    graph = CausalExecutionGraph("session-node-limit")
    analyzer = GraphSecurityAnalyzer(max_depth=10, max_nodes=2)

    act_1 = add_action_to_graph(graph, make_action("t1"))
    act_2 = add_action_to_graph(graph, make_action("t2"))
    act_3 = add_action_to_graph(graph, make_action("t3"))

    graph.add_relationship(
        str(act_1.action_id), str(act_2.action_id), relation=GraphRelation.CAUSES
    )
    graph.add_relationship(
        str(act_2.action_id), str(act_3.action_id), relation=GraphRelation.CAUSES
    )

    ctx = analyzer.analyze_action_causality(graph, parent_action_id=str(act_3.action_id))

    assert ctx.analysis_status == GraphAnalysisStatus.NODE_LIMIT_EXCEEDED
    assert ctx.analysis_complete is False
    assert ctx.contains_privileged_ancestor is False


def test_analyzer_repeated_privilege_probing_consecutive_count():
    """Requirement 9: Privileged probe count walks backwards until non-privileged tool."""
    graph = CausalExecutionGraph("session-probes")
    analyzer = GraphSecurityAnalyzer()

    # Chain: normal -> privileged -> unknown (destructive)
    act_1 = add_action_to_graph(
        graph, make_action("normal.search", tool_known=True, tool_privileged=False)
    )
    act_2 = add_action_to_graph(
        graph, make_action("admin.elevate", tool_known=True, tool_privileged=True)
    )
    act_3 = add_action_to_graph(
        graph,
        make_action("custom.shell", tool_known=False, tool_privileged=False, tool_destructive=True),
    )

    id_1, id_2, id_3 = str(act_1.action_id), str(act_2.action_id), str(act_3.action_id)
    graph.add_relationship(id_1, id_2, relation=GraphRelation.CAUSES)
    graph.add_relationship(id_2, id_3, relation=GraphRelation.CAUSES)

    ctx = analyzer.analyze_action_causality(graph, parent_action_id=id_3)

    # From id_3 backwards: id_3 is probe (count=1), id_2 is probe (count=2), id_1 is normal (stops).
    assert ctx.privileged_probe_count == 2


def test_analyzer_environment_escalation_flags():
    """Requirement 3: Distinguish lower environment from high environment ancestry."""
    graph = CausalExecutionGraph("session-env")
    analyzer = GraphSecurityAnalyzer()

    # Trajectory starting in LOCAL
    act_dev = add_action_to_graph(graph, make_action("dev.tool", TargetEnvironment.LOCAL))

    ctx = analyzer.analyze_action_causality(graph, parent_action_id=str(act_dev.action_id))

    assert ctx.has_lower_environment_ancestor is True
    assert ctx.has_high_environment_ancestor is False
