"""Performance benchmarks and bounded traversal tests for CausalExecutionGraph."""

import time
from datetime import UTC, datetime
from uuid import uuid4

from app.gateway.registry import ToolRegistry, ToolSpec
from app.graph.analyzer import GraphSecurityAnalyzer
from app.graph.causal_graph import CausalExecutionGraph
from app.policies.policy_input import build_cage_policy_input
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


def create_benchmark_action(name: str) -> AgentAction:
    """Helper to create an AgentAction for benchmarking."""
    return AgentAction(
        action_id=uuid4(),
        session_id="benchmark-session",
        agent_id="bench-agent",
        agent_instance_id="inst-1",
        tool_name=name,
        action_type=ActionType.TOOL_CALL,
        target_environment=TargetEnvironment.DEVELOPMENT,
        data_classifications=[DataClassification.PUBLIC],
        goal="benchmark",
        current_task="bench",
        execution_status=ToolExecutionStatus.AUTHORIZED,
        policy_result=PolicyDecision.ALLOW,
        risk_score=0.1,
        input_trust_level=TrustLevel.HIGH,
        created_at=datetime.now(UTC),
    )


def test_benchmark_10_node_linear_chain():
    """Benchmark: 10-node linear causal trajectory."""
    graph = CausalExecutionGraph("bench-10")
    analyzer = GraphSecurityAnalyzer(max_depth=25, max_nodes=500)
    registry = ToolRegistry()
    registry.register(ToolSpec(name="bench.tool", description="Benchmark tool"))

    actions = [create_benchmark_action("bench.tool") for _ in range(10)]
    for a in actions:
        graph.add_action(a)

    for i in range(9):
        graph.add_relationship(
            str(actions[i].action_id),
            str(actions[i + 1].action_id),
            relation=GraphRelation.CAUSES,
        )

    t0 = time.perf_counter()
    ctx = analyzer.analyze_action_causality(graph, parent_action_id=str(actions[9].action_id))
    t1 = time.perf_counter()

    policy_input = build_cage_policy_input(
        action=actions[9],
        tool_registry=registry,
        require_intent=False,
        graph_context=ctx,
    )
    t2 = time.perf_counter()

    analysis_ms = (t1 - t0) * 1000
    input_ms = (t2 - t1) * 1000

    assert ctx.analysis_status == GraphAnalysisStatus.SUCCESS
    assert ctx.ancestor_count == 10
    assert ctx.causal_depth == 10
    assert policy_input.graph.ancestor_count == 10

    print(f"\n[Benchmark 10 Nodes] Analysis: {analysis_ms:.3f}ms | Input: {input_ms:.3f}ms")


def test_benchmark_100_node_shallow_tree():
    """Benchmark: 100-node session graph with broad tree topology (single-parent causal trajectory).

    Clarification: Total session graph contains 101 nodes across 5 branches.
    For the evaluated action (leaf of branch 0), the analyzer inspects exactly
    its direct causal trajectory (21 nodes: root + 20 branch actions).
    """
    graph = CausalExecutionGraph("bench-100")
    analyzer = GraphSecurityAnalyzer(max_depth=25, max_nodes=500)
    registry = ToolRegistry()
    registry.register(ToolSpec(name="bench.tool", description="Benchmark tool"))

    # Construct a tree: root -> 5 branches of depth 20 each = 100 nodes
    root = create_benchmark_action("bench.root")
    graph.add_action(root)

    leaf_id = None
    for branch in range(5):
        parent_id = str(root.action_id)
        for d in range(20):
            act = create_benchmark_action(f"branch_{branch}.tool_{d}")
            graph.add_action(act)
            aid = str(act.action_id)
            graph.add_relationship(parent_id, aid, relation=GraphRelation.CAUSES)
            parent_id = aid
            if branch == 0 and d == 19:
                leaf_id = aid

    assert graph.node_count() == 101

    t0 = time.perf_counter()
    ctx = analyzer.analyze_action_causality(graph, parent_action_id=leaf_id)
    t1 = time.perf_counter()

    analysis_ms = (t1 - t0) * 1000
    assert ctx.analysis_status == GraphAnalysisStatus.SUCCESS
    assert ctx.causal_depth == 21
    assert ctx.ancestor_count == 21

    print(
        f"\n[Benchmark 100 Nodes Session] Analysis: {analysis_ms:.3f}ms "
        f"(Total Session Graph Size: {graph.node_count()}, Traversed Ancestors: {ctx.ancestor_count})"
    )


def test_benchmark_500_node_tree():
    """Benchmark: ~500-node session graph with broad tree topology (single-parent causal trajectory).

    Clarification: Total session graph contains 476 nodes across 25 branches.
    For the evaluated action (leaf of branch 0), the analyzer inspects exactly
    its direct causal trajectory (20 nodes: root + 19 branch actions).
    """
    graph = CausalExecutionGraph("bench-500")
    analyzer = GraphSecurityAnalyzer(max_depth=25, max_nodes=500)

    root = create_benchmark_action("bench.root")
    graph.add_action(root)

    leaf_id = None
    # 25 branches of depth 19 (+ root = 20 depth per branch, 476 total nodes)
    for branch in range(25):
        parent_id = str(root.action_id)
        for d in range(19):
            act = create_benchmark_action(f"b_{branch}.t_{d}")
            graph.add_action(act)
            aid = str(act.action_id)
            graph.add_relationship(parent_id, aid, relation=GraphRelation.CAUSES)
            parent_id = aid
            if branch == 0 and d == 18:
                leaf_id = aid

    t0 = time.perf_counter()
    ctx = analyzer.analyze_action_causality(graph, parent_action_id=leaf_id)
    t1 = time.perf_counter()

    analysis_ms = (t1 - t0) * 1000
    assert ctx.analysis_status == GraphAnalysisStatus.SUCCESS
    assert ctx.causal_depth == 20
    assert ctx.ancestor_count == 20

    print(
        f"\n[Benchmark 500 Nodes Session] Analysis: {analysis_ms:.3f}ms "
        f"(Total Session Graph Size: {graph.node_count()}, Traversed Ancestors: {ctx.ancestor_count})"
    )


def test_deep_linear_chain_exceeding_depth_limit_triggers_fail_closed():
    """Security verification: 30-node linear chain (> 25 depth limit) triggers DEPTH_LIMIT_EXCEEDED."""
    graph = CausalExecutionGraph("bench-deep-overflow")
    analyzer = GraphSecurityAnalyzer(max_depth=25, max_nodes=500)

    actions = [create_benchmark_action(f"chain.{i}") for i in range(30)]
    for a in actions:
        graph.add_action(a)

    for i in range(29):
        graph.add_relationship(
            str(actions[i].action_id),
            str(actions[i + 1].action_id),
            relation=GraphRelation.CAUSES,
        )

    ctx = analyzer.analyze_action_causality(graph, parent_action_id=str(actions[29].action_id))

    assert ctx.analysis_status == GraphAnalysisStatus.DEPTH_LIMIT_EXCEEDED
    assert ctx.analysis_complete is False
    assert ctx.contains_privileged_ancestor is False  # Invariant: No fabricated facts!
