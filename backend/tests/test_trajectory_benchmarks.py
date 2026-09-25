"""Observational benchmarks for Phase 6 trajectory governance and analysis."""

import json
import time
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from app.gateway.registry import ToolRegistry, ToolSpec
from app.graph.causal_graph import CausalExecutionGraph
from app.policies.policy_input import build_cage_policy_input
from app.policies.rules import DeterministicPolicyEvaluator
from app.provenance.resources import ResourceSecurityProfileRegistry
from app.provenance.store import ProvenanceStore
from app.schemas.action import AgentAction
from app.schemas.enums import (
    ActionType,
    DataClassification,
    GraphRelation,
    TargetEnvironment,
    ToolExecutionStatus,
    TrajectoryStatus,
)
from app.schemas.intent import IntentContract
from app.schemas.policy import PolicyProvenanceContext
from app.trajectory.analyzer import TrajectoryAnalyzer, TrajectoryAnalyzerConfig
from app.trajectory.models import AuthorityEnvelope, TrajectorySnapshot


@pytest.mark.benchmark
@pytest.mark.parametrize(
    ("session_actions_count", "active_traj_actions_count"),
    [
        (10, 10),
        (100, 20),
        (500, 20),
    ],
)
def test_trajectory_analysis_benchmarks(
    session_actions_count: int, active_traj_actions_count: int
) -> None:
    """Benchmark trajectory graph traversal, security fact derivation, policy input construction, and evaluation.

    Validates:
    - Retained history is O(n) in graph/store
    - Output PolicyTrajectoryContext is strictly bounded O(1) (<= 20 entries)
    - Measures separate execution phases:
      1. Typed trajectory traversal & analysis
      2. PolicyTrajectoryContext derivation
      3. CagePolicyInput v4 document construction
      4. Python policy evaluation
    """
    session_id = f"bench-traj-{session_actions_count}-{active_traj_actions_count}"
    graph = CausalExecutionGraph(session_id)
    store = ProvenanceStore()
    resource_registry = ResourceSecurityProfileRegistry()
    registry = ToolRegistry()
    registry.register(ToolSpec(name="web.search", known=True))
    registry.register(ToolSpec(name="agent.transform", known=True))
    evaluator = DeterministicPolicyEvaluator(tool_registry=registry)

    analyzer = TrajectoryAnalyzer(
        TrajectoryAnalyzerConfig(
            max_action_depth=20,
            max_artifact_depth=10,
            max_nodes=100,
        )
    )

    # 1. Build session actions in graph (session_actions_count)
    all_action_ids = []
    prev_id = None
    for i in range(session_actions_count):
        act_id = uuid4()
        all_action_ids.append(act_id)
        act = AgentAction(
            action_id=act_id,
            session_id=session_id,
            agent_id="bench-agent",
            tool_name="agent.transform" if i % 2 == 1 else "web.search",
            parent_action_id=prev_id,
            action_type=ActionType.TOOL_CALL,
            data_classifications=[DataClassification.PUBLIC],
            execution_status=ToolExecutionStatus.COMPLETED,
        )
        graph.add_action(act)
        if prev_id:
            graph.add_causal_edge(str(prev_id), str(act.action_id), relation=GraphRelation.CAUSES)
        prev_id = act_id

    # 2. Active trajectory represents the latest active_traj_actions_count actions
    active_action_ids = all_action_ids[-active_traj_actions_count:]
    tip_parent_id = active_action_ids[-1]

    # Proposed next action at the tip
    proposed_act = AgentAction(
        action_id=uuid4(),
        session_id=session_id,
        agent_id="bench-agent",
        tool_name="web.search",
        parent_action_id=tip_parent_id,
        action_type=ActionType.TOOL_CALL,
        data_classifications=[DataClassification.PUBLIC],
        execution_status=ToolExecutionStatus.PROPOSED,
    )

    envelope = AuthorityEnvelope(
        allowed_tools=frozenset({"web.search", "agent.transform"}),
        allowed_environments=frozenset({TargetEnvironment.DEVELOPMENT}),
        allowed_data_classifications=frozenset({DataClassification.PUBLIC}),
    )

    now = datetime.now(UTC)
    intent_id = uuid4()
    traj_snapshot = TrajectorySnapshot(
        trajectory_id=uuid4(),
        session_id=session_id,
        intent_id=intent_id,
        agent_id="bench-agent",
        status=TrajectoryStatus.ACTIVE,
        created_at=now,
        updated_at=now,
        root_authority=envelope,
        effective_authority=envelope,
        evaluated_action_ids=tuple(active_action_ids),
        last_action_id=tip_parent_id,
    )

    tool_spec = ToolSpec(name="web.search")

    contract = IntentContract(
        intent_id=intent_id,
        agent_id="bench-agent",
        session_id=session_id,
        goal="Benchmark task",
        allowed_tools=frozenset({"web.search", "agent.transform"}),
        allowed_environments=frozenset({TargetEnvironment.DEVELOPMENT}),
        allowed_data_classifications=frozenset({DataClassification.PUBLIC}),
        maximum_tool_calls=1000,
    )

    # Phase 1: Typed Trajectory Analysis
    t0 = time.perf_counter()
    ctx = analyzer.analyze(
        action=proposed_act,
        trajectory=traj_snapshot,
        tool_spec=tool_spec,
        causal_graph=graph,
        provenance_store=store,
        resource_registry=resource_registry,
    )
    t1 = time.perf_counter()
    analysis_latency_ms = (t1 - t0) * 1000

    # Phase 2: PolicyTrajectoryContext Derivation & Serialization
    t2 = time.perf_counter()
    context_dict = ctx.model_dump(mode="json")
    context_json = json.dumps(context_dict)
    context_size_bytes = len(context_json.encode("utf-8"))
    t3 = time.perf_counter()
    context_latency_ms = (t3 - t2) * 1000

    # Phase 3: CagePolicyInput v4 Construction
    t4 = time.perf_counter()
    policy_input = build_cage_policy_input(
        action=proposed_act,
        contract=contract,
        tool_registry=registry,
        require_intent=True,
        intent_mismatch=False,
        graph_context=None,
        provenance_context=PolicyProvenanceContext(),
        trajectory_context=ctx,
    )
    t5 = time.perf_counter()
    input_v4_latency_ms = (t5 - t4) * 1000
    assert policy_input is not None

    # Phase 4: Python Policy Evaluation
    t6 = time.perf_counter()
    eval_result = evaluator.evaluate(
        action=proposed_act,
        contract=contract,
        trajectory_context=ctx,
    )
    t7 = time.perf_counter()
    eval_latency_ms = (t7 - t6) * 1000

    total_latency_ms = (
        analysis_latency_ms + context_latency_ms + input_v4_latency_ms + eval_latency_ms
    )

    # Invariants:
    # 1. Bounded O(1) size regardless of history length
    assert len(ctx.trajectory_action_ids) <= 20
    assert len(ctx.trajectory_tool_sequence) <= 20
    assert len(ctx.evidence.causal_path) <= 20
    assert len(ctx.evidence.evaluated_action_ids) <= 20

    # 2. History retained is O(n) in graph
    assert len(graph._graph.nodes) == session_actions_count

    # 3. Decision is valid
    assert eval_result.decision is not None

    # Print observational benchmark metrics
    print(
        f"\n[BENCHMARK RESULT] Session Actions: {session_actions_count}, "
        f"Active Trajectory Actions: {active_traj_actions_count}, "
        f"Graph Nodes Traversed: {min(active_traj_actions_count, 20)}, "
        f"Context Size: {context_size_bytes} bytes | "
        f"Analysis: {analysis_latency_ms:.3f}ms, "
        f"Context Derivation: {context_latency_ms:.3f}ms, "
        f"Input v4 Build: {input_v4_latency_ms:.3f}ms, "
        f"Python Eval: {eval_latency_ms:.3f}ms, "
        f"Total: {total_latency_ms:.3f}ms"
    )
