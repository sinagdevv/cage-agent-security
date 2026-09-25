"""Tests for Phase 6 live OPA evaluation and Python-OPA parity across ALL 13 trajectory rules."""

from uuid import uuid4

import pytest

from app.gateway.registry import ToolRegistry, ToolSpec
from app.policies.engine import PolicyEngine
from app.policies.opa_client import OpaClient
from app.policies.policy_input import build_cage_policy_input
from app.policies.rules import DeterministicPolicyEvaluator
from app.schemas.action import AgentAction
from app.schemas.enums import (
    ActionType,
    DataClassification,
    PolicyBackend,
    PolicyDecision,
    TargetEnvironment,
    TrajectoryAnalysisStatus,
    TrajectoryStatus,
)
from app.schemas.intent import IntentContract, IntentContractCreate
from app.schemas.policy import PolicyTrajectoryContext


@pytest.fixture
def test_setup():
    registry = ToolRegistry()
    registry.register(ToolSpec(name="web.search", known=True))
    registry.register(
        ToolSpec(
            name="database.read",
            known=True,
            reads_resource_data=True,
            default_classification=DataClassification.CONFIDENTIAL,
        )
    )
    registry.register(ToolSpec(name="agent.transform", known=True))
    registry.register(ToolSpec(name="external.http_post", known=True, external_sink=True))
    registry.register(ToolSpec(name="admin.exec_cmd", known=True, privileged=True))
    evaluator = DeterministicPolicyEvaluator(tool_registry=registry)
    opa_client = OpaClient()
    engine = PolicyEngine(
        python_evaluator=evaluator, opa_client=opa_client, backend=PolicyBackend.SHADOW
    )
    contract = IntentContract.from_create(
        IntentContractCreate(
            agent_id="agent-01",
            session_id="sess-opa-parity",
            goal="Test live OPA parity",
            allowed_tools=[
                "web.search",
                "database.read",
                "agent.transform",
                "external.http_post",
                "admin.exec_cmd",
            ],
            allowed_environments=[TargetEnvironment.DEVELOPMENT],
            allowed_data_classifications=[
                DataClassification.PUBLIC,
                DataClassification.CONFIDENTIAL,
                DataClassification.PII,
            ],
            maximum_tool_calls=20,
        )
    )
    return evaluator, opa_client, engine, registry, contract


@pytest.mark.opa
def test_live_rego_trajectory_quarantined_parity(test_setup) -> None:
    """1. RULE_TRAJECTORY_QUARANTINED: Quarantined trajectory denies all actions."""
    evaluator, opa_client, _, registry, contract = test_setup
    action = AgentAction(
        action_id=uuid4(),
        agent_id="agent-01",
        session_id="sess-opa-parity",
        tool_name="web.search",
        action_type=ActionType.TOOL_CALL,
        target_environment=TargetEnvironment.DEVELOPMENT,
        data_classifications=[DataClassification.PUBLIC],
    )
    traj_ctx = PolicyTrajectoryContext(
        trajectory_status=TrajectoryStatus.QUARANTINED,
        analysis_status=TrajectoryAnalysisStatus.SUCCESS,
        analysis_complete=True,
    )

    py_dec = evaluator.evaluate(action=action, contract=contract, trajectory_context=traj_ctx)
    pol_input = build_cage_policy_input(
        action=action,
        contract=contract,
        tool_registry=registry,
        trajectory_context=traj_ctx,
    )
    opa_resp = opa_client.evaluate(pol_input)

    assert py_dec.decision == PolicyDecision.DENY
    opa_rule_ids = [f.rule_id for f in opa_resp.findings]
    opa_decisions = [f.decision for f in opa_resp.findings]
    assert "RULE_TRAJECTORY_QUARANTINED" in py_dec.matched_rules
    assert "RULE_TRAJECTORY_QUARANTINED" in opa_rule_ids
    assert PolicyDecision.DENY in opa_decisions


@pytest.mark.opa
def test_live_rego_trajectory_aborted_parity(test_setup) -> None:
    """2. RULE_TRAJECTORY_ABORTED: Aborted trajectory denies all actions."""
    evaluator, opa_client, _, registry, contract = test_setup
    action = AgentAction(
        action_id=uuid4(),
        agent_id="agent-01",
        session_id="sess-opa-parity",
        tool_name="web.search",
        action_type=ActionType.TOOL_CALL,
        target_environment=TargetEnvironment.DEVELOPMENT,
        data_classifications=[DataClassification.PUBLIC],
    )
    traj_ctx = PolicyTrajectoryContext(
        trajectory_status=TrajectoryStatus.ABORTED,
        analysis_status=TrajectoryAnalysisStatus.SUCCESS,
        analysis_complete=True,
    )

    py_dec = evaluator.evaluate(action=action, contract=contract, trajectory_context=traj_ctx)
    pol_input = build_cage_policy_input(
        action=action,
        contract=contract,
        tool_registry=registry,
        trajectory_context=traj_ctx,
    )
    opa_resp = opa_client.evaluate(pol_input)

    assert py_dec.decision == PolicyDecision.DENY
    opa_rule_ids = [f.rule_id for f in opa_resp.findings]
    opa_decisions = [f.decision for f in opa_resp.findings]
    assert "RULE_TRAJECTORY_ABORTED" in py_dec.matched_rules
    assert "RULE_TRAJECTORY_ABORTED" in opa_rule_ids
    assert PolicyDecision.DENY in opa_decisions


@pytest.mark.opa
def test_live_rego_trajectory_action_depth_limit_parity(test_setup) -> None:
    """3. RULE_TRAJECTORY_ACTION_DEPTH_LIMIT_EXCEEDED: Action depth limit fail-closed."""
    evaluator, opa_client, _, registry, contract = test_setup
    action = AgentAction(
        action_id=uuid4(),
        agent_id="agent-01",
        session_id="sess-opa-parity",
        tool_name="web.search",
        action_type=ActionType.TOOL_CALL,
        target_environment=TargetEnvironment.DEVELOPMENT,
    )
    traj_ctx = PolicyTrajectoryContext(
        trajectory_status=TrajectoryStatus.ACTIVE,
        analysis_status=TrajectoryAnalysisStatus.ACTION_DEPTH_LIMIT_EXCEEDED,
        analysis_complete=False,
    )

    py_dec = evaluator.evaluate(action=action, contract=contract, trajectory_context=traj_ctx)
    pol_input = build_cage_policy_input(
        action=action,
        contract=contract,
        tool_registry=registry,
        trajectory_context=traj_ctx,
    )
    opa_resp = opa_client.evaluate(pol_input)

    assert py_dec.decision == PolicyDecision.DENY
    opa_rule_ids = [f.rule_id for f in opa_resp.findings]
    assert "RULE_TRAJECTORY_ACTION_DEPTH_LIMIT_EXCEEDED" in py_dec.matched_rules
    assert "RULE_TRAJECTORY_ACTION_DEPTH_LIMIT_EXCEEDED" in opa_rule_ids


@pytest.mark.opa
def test_live_rego_trajectory_artifact_depth_limit_parity(test_setup) -> None:
    """4. RULE_TRAJECTORY_ARTIFACT_DEPTH_LIMIT_EXCEEDED: Artifact depth limit fail-closed."""
    evaluator, opa_client, _, registry, contract = test_setup
    action = AgentAction(
        action_id=uuid4(),
        agent_id="agent-01",
        session_id="sess-opa-parity",
        tool_name="web.search",
        action_type=ActionType.TOOL_CALL,
        target_environment=TargetEnvironment.DEVELOPMENT,
    )
    traj_ctx = PolicyTrajectoryContext(
        trajectory_status=TrajectoryStatus.ACTIVE,
        analysis_status=TrajectoryAnalysisStatus.ARTIFACT_DEPTH_LIMIT_EXCEEDED,
        analysis_complete=False,
    )

    py_dec = evaluator.evaluate(action=action, contract=contract, trajectory_context=traj_ctx)
    pol_input = build_cage_policy_input(
        action=action,
        contract=contract,
        tool_registry=registry,
        trajectory_context=traj_ctx,
    )
    opa_resp = opa_client.evaluate(pol_input)

    assert py_dec.decision == PolicyDecision.DENY
    opa_rule_ids = [f.rule_id for f in opa_resp.findings]
    assert "RULE_TRAJECTORY_ARTIFACT_DEPTH_LIMIT_EXCEEDED" in py_dec.matched_rules
    assert "RULE_TRAJECTORY_ARTIFACT_DEPTH_LIMIT_EXCEEDED" in opa_rule_ids


@pytest.mark.opa
def test_live_rego_trajectory_node_limit_parity(test_setup) -> None:
    """5. RULE_TRAJECTORY_NODE_LIMIT_EXCEEDED: Node count limit fail-closed."""
    evaluator, opa_client, _, registry, contract = test_setup
    action = AgentAction(
        action_id=uuid4(),
        agent_id="agent-01",
        session_id="sess-opa-parity",
        tool_name="web.search",
        action_type=ActionType.TOOL_CALL,
        target_environment=TargetEnvironment.DEVELOPMENT,
    )
    traj_ctx = PolicyTrajectoryContext(
        trajectory_status=TrajectoryStatus.ACTIVE,
        analysis_status=TrajectoryAnalysisStatus.NODE_LIMIT_EXCEEDED,
        analysis_complete=False,
    )

    py_dec = evaluator.evaluate(action=action, contract=contract, trajectory_context=traj_ctx)
    pol_input = build_cage_policy_input(
        action=action,
        contract=contract,
        tool_registry=registry,
        trajectory_context=traj_ctx,
    )
    opa_resp = opa_client.evaluate(pol_input)

    assert py_dec.decision == PolicyDecision.DENY
    opa_rule_ids = [f.rule_id for f in opa_resp.findings]
    assert "RULE_TRAJECTORY_NODE_LIMIT_EXCEEDED" in py_dec.matched_rules
    assert "RULE_TRAJECTORY_NODE_LIMIT_EXCEEDED" in opa_rule_ids


@pytest.mark.opa
def test_live_rego_trajectory_invalid_typed_path_parity(test_setup) -> None:
    """6. RULE_TRAJECTORY_INVALID_TYPED_PATH: Invalid typed edge relations fail-closed."""
    evaluator, opa_client, _, registry, contract = test_setup
    action = AgentAction(
        action_id=uuid4(),
        agent_id="agent-01",
        session_id="sess-opa-parity",
        tool_name="web.search",
        action_type=ActionType.TOOL_CALL,
        target_environment=TargetEnvironment.DEVELOPMENT,
    )
    traj_ctx = PolicyTrajectoryContext(
        trajectory_status=TrajectoryStatus.ACTIVE,
        analysis_status=TrajectoryAnalysisStatus.INVALID_TYPED_PATH,
        analysis_complete=False,
    )

    py_dec = evaluator.evaluate(action=action, contract=contract, trajectory_context=traj_ctx)
    pol_input = build_cage_policy_input(
        action=action,
        contract=contract,
        tool_registry=registry,
        trajectory_context=traj_ctx,
    )
    opa_resp = opa_client.evaluate(pol_input)

    assert py_dec.decision == PolicyDecision.DENY
    opa_rule_ids = [f.rule_id for f in opa_resp.findings]
    assert "RULE_TRAJECTORY_INVALID_TYPED_PATH" in py_dec.matched_rules
    assert "RULE_TRAJECTORY_INVALID_TYPED_PATH" in opa_rule_ids


@pytest.mark.opa
def test_live_rego_trajectory_missing_graph_evidence_parity(test_setup) -> None:
    """7. RULE_TRAJECTORY_MISSING_GRAPH_EVIDENCE: Missing graph history nodes fail-closed."""
    evaluator, opa_client, _, registry, contract = test_setup
    action = AgentAction(
        action_id=uuid4(),
        agent_id="agent-01",
        session_id="sess-opa-parity",
        tool_name="web.search",
        action_type=ActionType.TOOL_CALL,
        target_environment=TargetEnvironment.DEVELOPMENT,
    )
    traj_ctx = PolicyTrajectoryContext(
        trajectory_status=TrajectoryStatus.ACTIVE,
        analysis_status=TrajectoryAnalysisStatus.MISSING_GRAPH_EVIDENCE,
        analysis_complete=False,
    )

    py_dec = evaluator.evaluate(action=action, contract=contract, trajectory_context=traj_ctx)
    pol_input = build_cage_policy_input(
        action=action,
        contract=contract,
        tool_registry=registry,
        trajectory_context=traj_ctx,
    )
    opa_resp = opa_client.evaluate(pol_input)

    assert py_dec.decision == PolicyDecision.DENY
    opa_rule_ids = [f.rule_id for f in opa_resp.findings]
    assert "RULE_TRAJECTORY_MISSING_GRAPH_EVIDENCE" in py_dec.matched_rules
    assert "RULE_TRAJECTORY_MISSING_GRAPH_EVIDENCE" in opa_rule_ids


@pytest.mark.opa
def test_live_rego_trajectory_inconsistent_provenance_parity(test_setup) -> None:
    """8. RULE_TRAJECTORY_INCONSISTENT_PROVENANCE: Broken provenance artifact metadata fail-closed."""
    evaluator, opa_client, _, registry, contract = test_setup
    action = AgentAction(
        action_id=uuid4(),
        agent_id="agent-01",
        session_id="sess-opa-parity",
        tool_name="web.search",
        action_type=ActionType.TOOL_CALL,
        target_environment=TargetEnvironment.DEVELOPMENT,
    )
    traj_ctx = PolicyTrajectoryContext(
        trajectory_status=TrajectoryStatus.ACTIVE,
        analysis_status=TrajectoryAnalysisStatus.INCONSISTENT_PROVENANCE,
        analysis_complete=False,
    )

    py_dec = evaluator.evaluate(action=action, contract=contract, trajectory_context=traj_ctx)
    pol_input = build_cage_policy_input(
        action=action,
        contract=contract,
        tool_registry=registry,
        trajectory_context=traj_ctx,
    )
    opa_resp = opa_client.evaluate(pol_input)

    assert py_dec.decision == PolicyDecision.DENY
    opa_rule_ids = [f.rule_id for f in opa_resp.findings]
    assert "RULE_TRAJECTORY_INCONSISTENT_PROVENANCE" in py_dec.matched_rules
    assert "RULE_TRAJECTORY_INCONSISTENT_PROVENANCE" in opa_rule_ids


@pytest.mark.opa
def test_live_rego_trajectory_untrusted_to_sensitive_access_parity(test_setup) -> None:
    """9. RULE_TRAJECTORY_UNTRUSTED_PATH_TO_SENSITIVE_ACCESS: Flagship 1."""
    evaluator, opa_client, _, registry, contract = test_setup
    action = AgentAction(
        action_id=uuid4(),
        agent_id="agent-01",
        session_id="sess-opa-parity",
        tool_name="database.read",
        action_type=ActionType.READ,
        target_resource="customer_db",
        target_environment=TargetEnvironment.DEVELOPMENT,
        data_classifications=[DataClassification.CONFIDENTIAL],
    )
    traj_ctx = PolicyTrajectoryContext(
        trajectory_status=TrajectoryStatus.ACTIVE,
        analysis_status=TrajectoryAnalysisStatus.SUCCESS,
        analysis_complete=True,
        untrusted_path_to_current_action=True,
        current_action_attempts_sensitive_access=True,
        untrusted_path_to_sensitive_access=True,
        prospective_access_classifications=("CONFIDENTIAL",),
    )

    py_dec = evaluator.evaluate(action=action, contract=contract, trajectory_context=traj_ctx)
    pol_input = build_cage_policy_input(
        action=action,
        contract=contract,
        tool_registry=registry,
        trajectory_context=traj_ctx,
    )
    opa_resp = opa_client.evaluate(pol_input)

    assert py_dec.decision == PolicyDecision.REQUIRE_APPROVAL
    opa_rule_ids = [f.rule_id for f in opa_resp.findings]
    opa_decisions = [f.decision for f in opa_resp.findings]
    assert "RULE_TRAJECTORY_UNTRUSTED_PATH_TO_SENSITIVE_ACCESS" in py_dec.matched_rules
    assert "RULE_TRAJECTORY_UNTRUSTED_PATH_TO_SENSITIVE_ACCESS" in opa_rule_ids
    assert PolicyDecision.REQUIRE_APPROVAL in opa_decisions


@pytest.mark.opa
def test_live_rego_trajectory_untrusted_to_sensitive_egress_parity(test_setup) -> None:
    """10. RULE_TRAJECTORY_UNTRUSTED_PATH_TO_SENSITIVE_EGRESS: Flagship 2."""
    evaluator, opa_client, _, registry, contract = test_setup
    action = AgentAction(
        action_id=uuid4(),
        agent_id="agent-01",
        session_id="sess-opa-parity",
        tool_name="external.http_post",
        action_type=ActionType.WRITE,
        target_environment=TargetEnvironment.DEVELOPMENT,
        data_classifications=[DataClassification.CONFIDENTIAL],
    )
    traj_ctx = PolicyTrajectoryContext(
        trajectory_status=TrajectoryStatus.ACTIVE,
        analysis_status=TrajectoryAnalysisStatus.SUCCESS,
        analysis_complete=True,
        untrusted_path_to_current_action=True,
        untrusted_path_to_sensitive_egress=True,
    )

    py_dec = evaluator.evaluate(action=action, contract=contract, trajectory_context=traj_ctx)
    pol_input = build_cage_policy_input(
        action=action,
        contract=contract,
        tool_registry=registry,
        trajectory_context=traj_ctx,
    )
    opa_resp = opa_client.evaluate(pol_input)

    assert py_dec.decision == PolicyDecision.DENY
    opa_rule_ids = [f.rule_id for f in opa_resp.findings]
    opa_decisions = [f.decision for f in opa_resp.findings]
    assert "RULE_TRAJECTORY_UNTRUSTED_PATH_TO_SENSITIVE_EGRESS" in py_dec.matched_rules
    assert "RULE_TRAJECTORY_UNTRUSTED_PATH_TO_SENSITIVE_EGRESS" in opa_rule_ids
    assert PolicyDecision.DENY in opa_decisions


@pytest.mark.opa
def test_live_rego_trajectory_information_cannot_expand_authority_parity(test_setup) -> None:
    """11. RULE_TRAJECTORY_INFORMATION_CANNOT_EXPAND_AUTHORITY: Monotonic authority invariant."""
    evaluator, opa_client, _, registry, contract = test_setup
    action = AgentAction(
        action_id=uuid4(),
        agent_id="agent-01",
        session_id="sess-opa-parity",
        tool_name="admin.exec_cmd",
        action_type=ActionType.EXECUTE,
        target_environment=TargetEnvironment.PRODUCTION,
    )
    traj_ctx = PolicyTrajectoryContext(
        trajectory_status=TrajectoryStatus.ACTIVE,
        analysis_status=TrajectoryAnalysisStatus.SUCCESS,
        analysis_complete=True,
        untrusted_path_to_current_action=True,
        unauthorized_authority_expansion_attempted=True,
    )

    py_dec = evaluator.evaluate(action=action, contract=contract, trajectory_context=traj_ctx)
    pol_input = build_cage_policy_input(
        action=action,
        contract=contract,
        tool_registry=registry,
        trajectory_context=traj_ctx,
    )
    opa_resp = opa_client.evaluate(pol_input)

    assert py_dec.decision == PolicyDecision.DENY
    opa_rule_ids = [f.rule_id for f in opa_resp.findings]
    assert "RULE_TRAJECTORY_INFORMATION_CANNOT_EXPAND_AUTHORITY" in py_dec.matched_rules
    assert "RULE_TRAJECTORY_INFORMATION_CANNOT_EXPAND_AUTHORITY" in opa_rule_ids


@pytest.mark.opa
def test_live_rego_trajectory_split_exfiltration_parity(test_setup) -> None:
    """12. RULE_TRAJECTORY_CUMULATIVE_SENSITIVE_EGRESS: Anti-split exfiltration quarantine."""
    evaluator, opa_client, _, registry, contract = test_setup
    action = AgentAction(
        action_id=uuid4(),
        agent_id="agent-01",
        session_id="sess-opa-parity",
        tool_name="external.http_post",
        action_type=ActionType.WRITE,
        target_environment=TargetEnvironment.DEVELOPMENT,
        data_classifications=[DataClassification.PUBLIC],
    )
    traj_ctx = PolicyTrajectoryContext(
        trajectory_status=TrajectoryStatus.ACTIVE,
        analysis_status=TrajectoryAnalysisStatus.SUCCESS,
        analysis_complete=True,
        split_exfiltration_threshold_exceeded=True,
    )

    py_dec = evaluator.evaluate(action=action, contract=contract, trajectory_context=traj_ctx)
    pol_input = build_cage_policy_input(
        action=action,
        contract=contract,
        tool_registry=registry,
        trajectory_context=traj_ctx,
    )
    opa_resp = opa_client.evaluate(pol_input)

    assert py_dec.decision == PolicyDecision.QUARANTINE
    opa_rule_ids = [f.rule_id for f in opa_resp.findings]
    opa_decisions = [f.decision for f in opa_resp.findings]
    assert "RULE_TRAJECTORY_CUMULATIVE_SENSITIVE_EGRESS" in py_dec.matched_rules
    assert "RULE_TRAJECTORY_CUMULATIVE_SENSITIVE_EGRESS" in opa_rule_ids
    assert PolicyDecision.QUARANTINE in opa_decisions


@pytest.mark.opa
def test_live_rego_trajectory_sensitive_hop_laundering_parity(test_setup) -> None:
    """13. RULE_TRAJECTORY_SENSITIVE_HOP_LAUNDERING: Flagship 3 sensitive laundering detection."""
    evaluator, opa_client, _, registry, contract = test_setup
    action = AgentAction(
        action_id=uuid4(),
        agent_id="agent-01",
        session_id="sess-opa-parity",
        tool_name="external.http_post",
        action_type=ActionType.WRITE,
        target_environment=TargetEnvironment.DEVELOPMENT,
        data_classifications=[DataClassification.PII],
    )
    traj_ctx = PolicyTrajectoryContext(
        trajectory_status=TrajectoryStatus.ACTIVE,
        analysis_status=TrajectoryAnalysisStatus.SUCCESS,
        analysis_complete=True,
        sensitive_hop_laundering_detected=True,
    )

    py_dec = evaluator.evaluate(action=action, contract=contract, trajectory_context=traj_ctx)
    pol_input = build_cage_policy_input(
        action=action,
        contract=contract,
        tool_registry=registry,
        trajectory_context=traj_ctx,
    )
    opa_resp = opa_client.evaluate(pol_input)

    assert py_dec.decision == PolicyDecision.DENY
    opa_rule_ids = [f.rule_id for f in opa_resp.findings]
    assert "RULE_TRAJECTORY_SENSITIVE_HOP_LAUNDERING" in py_dec.matched_rules
    assert "RULE_TRAJECTORY_SENSITIVE_HOP_LAUNDERING" in opa_rule_ids
