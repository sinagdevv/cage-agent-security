"""Integration tests for Trajectory Approval Lifecycle and T2 Authority Revalidation Defenses."""

from datetime import UTC, datetime, timedelta

import pytest

from app.gateway.registry import ToolRegistry, ToolSpec
from app.gateway.service import AgentGateway
from app.graph.causal_graph import SessionGraphManager
from app.intent.service import IntentService
from app.policies.engine import PolicyEngine
from app.policies.rules import DeterministicPolicyEvaluator
from app.provenance.store import ProvenanceStore
from app.schemas.action import AgentActionProposal
from app.schemas.enums import (
    DataClassification,
    IntentStatus,
    PolicyBackend,
    PolicyDecision,
    ToolExecutionStatus,
)
from app.schemas.intent import IntentContractCreate, IntentContractNarrow
from app.trajectory.analyzer import TrajectoryAnalyzer
from app.trajectory.store import TrajectoryStore


@pytest.fixture
def gateway_setup():
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
    registry.register(ToolSpec(name="admin.exec_cmd", known=True, privileged=True))
    registry.register(ToolSpec(name="system.delete_resource", known=True, destructive=True))

    graph_mgr = SessionGraphManager()
    intent_svc = IntentService()
    prov_store = ProvenanceStore()
    traj_store = TrajectoryStore()
    analyzer = TrajectoryAnalyzer()
    evaluator = DeterministicPolicyEvaluator(tool_registry=registry)
    engine = PolicyEngine(python_evaluator=evaluator, backend=PolicyBackend.SHADOW)

    gw = AgentGateway(
        graph_manager=graph_mgr,
        intent_service=intent_svc,
        tool_registry=registry,
        policy_engine=engine,
        provenance_store=prov_store,
        trajectory_store=traj_store,
        trajectory_analyzer=analyzer,
        require_intent=True,
    )
    return gw, intent_svc, traj_store, registry


def test_full_approval_lifecycle_and_successful_resolution(gateway_setup) -> None:
    """Verify full approval lifecycle: REQUIRE_APPROVAL -> pending containment -> human approval -> execution & advance."""
    gateway, intent_service, traj_store, _ = gateway_setup
    session_id = "sess-approval-flow"

    contract = intent_service.create_intent(
        IntentContractCreate(
            agent_id="agent-01",
            session_id=session_id,
            goal="Maintenance",
            allowed_tools=["admin.exec_cmd", "web.search"],
            requires_approval=["admin.exec_cmd"],
            maximum_tool_calls=5,
        )
    )

    # 1. Action requires approval
    proposal = AgentActionProposal(
        agent_id="agent-01",
        session_id=session_id,
        tool_name="admin.exec_cmd",
        tool_arguments={"command": "restart_service"},
    )
    action, decision = gateway.evaluate_proposal(proposal)
    assert decision.decision == PolicyDecision.REQUIRE_APPROVAL
    assert action.execution_status == ToolExecutionStatus.PENDING_APPROVAL

    # Invariant: pending approval is recorded on trajectory
    traj_id = gateway.trajectory_store.get_trajectory_id_for_session(session_id)
    assert traj_id is not None
    snap = gateway.trajectory_store.get_snapshot(traj_id)
    assert snap.pending_approval_action_id == action.action_id

    # 2. Submitting next action while approval is pending is BLOCKED
    next_prop = AgentActionProposal(
        agent_id="agent-01",
        session_id=session_id,
        tool_name="web.search",
        parent_action_id=action.action_id,
    )
    _, block_decision = gateway.evaluate_proposal(next_prop)
    assert block_decision.decision == PolicyDecision.DENY
    assert "RULE_TRAJECTORY_APPROVAL_PENDING" in block_decision.matched_rules

    # 3. Human resolves approval -> APPROVED
    res_action, res_exec = gateway.resolve_pending_approval(action.action_id, approved=True)
    assert res_action.execution_status == ToolExecutionStatus.COMPLETED
    assert res_exec is not None
    assert res_exec["success"] is True

    # Invariant: pending approval cleared, budget consumed
    snap_after = gateway.trajectory_store.get_snapshot(traj_id)
    assert snap_after.pending_approval_action_id is None
    assert snap_after.last_action_id == action.action_id

    updated_contract = intent_service.get_intent(contract.intent_id)
    assert updated_contract.tool_calls_count == 1

    # 4. Now next action can proceed linearly on approved action
    next_action, next_decision = gateway.evaluate_proposal(next_prop)
    assert next_decision.decision == PolicyDecision.ALLOW


def test_t2_authority_revalidation_rejects_expired_contract(gateway_setup) -> None:
    """Requirement: Approval does not resurrect authority - contract expired at T1 blocks execution at T2."""
    gateway, intent_service, _, _ = gateway_setup
    session_id = "sess-expire-t2"

    contract = intent_service.create_intent(
        IntentContractCreate(
            agent_id="agent-01",
            session_id=session_id,
            goal="Expiring task",
            allowed_tools=["admin.exec_cmd"],
            requires_approval=["admin.exec_cmd"],
            expires_at=datetime.now(UTC) + timedelta(seconds=1),
        )
    )

    proposal = AgentActionProposal(
        agent_id="agent-01",
        session_id=session_id,
        tool_name="admin.exec_cmd",
        tool_arguments={"command": "status"},
    )
    action, decision = gateway.evaluate_proposal(proposal)
    assert decision.decision == PolicyDecision.REQUIRE_APPROVAL

    # Simulate T1: Contract expires
    intent = intent_service.get_intent(contract.intent_id)
    intent_service._intents[contract.intent_id] = intent.model_copy(
        update={
            "status": IntentStatus.EXPIRED,
            "expires_at": datetime.now(UTC) - timedelta(seconds=10),
        }
    )

    # T2: Human attempts to approve
    with pytest.raises(ValueError, match="no active Intent Contract"):
        gateway.resolve_pending_approval(action.action_id, approved=True)


def test_t2_authority_revalidation_rejects_narrowed_tool(gateway_setup) -> None:
    """Requirement: Contract narrowed at T1 to exclude tool blocks execution at T2."""
    gateway, intent_service, _, _ = gateway_setup
    session_id = "sess-narrow-t2"

    contract = intent_service.create_intent(
        IntentContractCreate(
            agent_id="agent-01",
            session_id=session_id,
            goal="Narrowing task",
            allowed_tools=["admin.exec_cmd", "web.search"],
            requires_approval=["admin.exec_cmd"],
        )
    )

    proposal = AgentActionProposal(
        agent_id="agent-01",
        session_id=session_id,
        tool_name="admin.exec_cmd",
        tool_arguments={"command": "status"},
    )
    action, decision = gateway.evaluate_proposal(proposal)
    assert decision.decision == PolicyDecision.REQUIRE_APPROVAL

    # T1: Narrow contract to remove admin.exec_cmd
    intent_service.narrow_intent(
        contract.intent_id,
        IntentContractNarrow(allowed_tools=["web.search"]),
    )

    # T2: Human attempts to approve -> Must be rejected because tool is no longer authorized
    with pytest.raises(ValueError, match="is not authorized"):
        gateway.resolve_pending_approval(action.action_id, approved=True)


def test_disapproval_clears_pending_and_advances_trajectory(gateway_setup) -> None:
    """Verify human rejection clears pending approval and records rejection on trajectory."""
    gateway, intent_service, _, _ = gateway_setup
    session_id = "sess-disapprove"

    contract = intent_service.create_intent(
        IntentContractCreate(
            agent_id="agent-01",
            session_id=session_id,
            goal="Disapproval test",
            allowed_tools=["admin.exec_cmd", "web.search"],
            requires_approval=["admin.exec_cmd"],
        )
    )

    proposal = AgentActionProposal(
        agent_id="agent-01",
        session_id=session_id,
        tool_name="admin.exec_cmd",
    )
    action, _ = gateway.evaluate_proposal(proposal)

    # Disapprove
    res_action, res_exec = gateway.resolve_pending_approval(action.action_id, approved=False)
    assert res_action.execution_status == ToolExecutionStatus.DENIED
    assert res_exec is None

    traj_id = gateway.trajectory_store.get_trajectory_id_for_session(session_id)
    snap = gateway.trajectory_store.get_snapshot(traj_id)
    assert snap.pending_approval_action_id is None
    assert snap.last_action_id == action.action_id

    # Invariant: Disapproval consumes NO dispatch budget
    updated_contract = intent_service.get_intent(contract.intent_id)
    assert updated_contract.tool_calls_count == 0


def test_t2_authority_revalidation_rejects_narrowed_resource(gateway_setup) -> None:
    """Requirement: Resource narrowed out at T1 blocks execution at T2."""
    gateway, intent_service, _, _ = gateway_setup
    session_id = "sess-res-narrow"

    contract = intent_service.create_intent(
        IntentContractCreate(
            agent_id="agent-01",
            session_id=session_id,
            goal="Resource narrowing task",
            allowed_tools=["admin.exec_cmd"],
            allowed_resources=["db1", "db2"],
            requires_approval=["admin.exec_cmd"],
        )
    )

    prop = AgentActionProposal(
        agent_id="agent-01",
        session_id=session_id,
        tool_name="admin.exec_cmd",
        target_resource="db2",
    )
    action, dec = gateway.evaluate_proposal(prop)
    assert dec.decision == PolicyDecision.REQUIRE_APPROVAL

    # T1: Narrow allowed_resources to ['db1'] only
    intent_service.narrow_intent(
        contract.intent_id, IntentContractNarrow(allowed_resources=["db1"])
    )

    # T2: Human attempts to approve -> Must fail revalidation
    with pytest.raises(ValueError, match="not authorized under narrowed authority"):
        gateway.resolve_pending_approval(action.action_id, approved=True)

    # Invariant: No budget consumed
    assert intent_service.get_intent(contract.intent_id).tool_calls_count == 0


def test_t2_authority_revalidation_rejects_narrowed_environment(gateway_setup) -> None:
    """Requirement: Environment narrowed out at T1 blocks execution at T2."""
    from app.schemas.enums import TargetEnvironment

    gateway, intent_service, _, _ = gateway_setup
    session_id = "sess-env-narrow"

    contract = intent_service.create_intent(
        IntentContractCreate(
            agent_id="agent-01",
            session_id=session_id,
            goal="Env narrowing task",
            allowed_tools=["admin.exec_cmd"],
            allowed_environments=[TargetEnvironment.DEVELOPMENT, TargetEnvironment.STAGING],
            requires_approval=["admin.exec_cmd"],
        )
    )

    prop = AgentActionProposal(
        agent_id="agent-01",
        session_id=session_id,
        tool_name="admin.exec_cmd",
        target_environment=TargetEnvironment.STAGING,
    )
    action, dec = gateway.evaluate_proposal(prop)
    assert dec.decision == PolicyDecision.REQUIRE_APPROVAL

    # T1: Narrow allowed_environments to DEVELOPMENT only
    intent_service.narrow_intent(
        contract.intent_id,
        IntentContractNarrow(allowed_environments=[TargetEnvironment.DEVELOPMENT]),
    )

    # T2: Human attempts to approve -> Must fail
    with pytest.raises(ValueError, match="not authorized under narrowed authority"):
        gateway.resolve_pending_approval(action.action_id, approved=True)

    assert intent_service.get_intent(contract.intent_id).tool_calls_count == 0


def test_t2_authority_revalidation_rejects_narrowed_data_classification(gateway_setup) -> None:
    """Requirement: Data classification narrowed out at T1 blocks execution at T2."""
    gateway, intent_service, _, _ = gateway_setup
    session_id = "sess-class-narrow"

    contract = intent_service.create_intent(
        IntentContractCreate(
            agent_id="agent-01",
            session_id=session_id,
            goal="Class narrowing task",
            allowed_tools=["admin.exec_cmd"],
            allowed_data_classifications=[
                DataClassification.PUBLIC,
                DataClassification.CONFIDENTIAL,
            ],
            requires_approval=["admin.exec_cmd"],
        )
    )

    prop = AgentActionProposal(
        agent_id="agent-01",
        session_id=session_id,
        tool_name="admin.exec_cmd",
        data_classifications=[DataClassification.CONFIDENTIAL],
    )
    action, dec = gateway.evaluate_proposal(prop)
    assert dec.decision == PolicyDecision.REQUIRE_APPROVAL

    # T1: Narrow to PUBLIC only
    intent_service.narrow_intent(
        contract.intent_id,
        IntentContractNarrow(allowed_data_classifications=[DataClassification.PUBLIC]),
    )

    # T2: Human attempts to approve -> Must fail
    with pytest.raises(ValueError, match="not authorized under narrowed authority"):
        gateway.resolve_pending_approval(action.action_id, approved=True)

    assert intent_service.get_intent(contract.intent_id).tool_calls_count == 0


def test_t2_authority_revalidation_rejects_revoked_or_replaced_intent(gateway_setup) -> None:
    """Requirement: Revoked or replaced Intent at T1 blocks execution at T2."""
    gateway, intent_service, _, _ = gateway_setup
    session_id = "sess-revoked-t2"

    contract = intent_service.create_intent(
        IntentContractCreate(
            agent_id="agent-01",
            session_id=session_id,
            goal="Revocation task",
            allowed_tools=["admin.exec_cmd"],
            requires_approval=["admin.exec_cmd"],
        )
    )

    prop = AgentActionProposal(
        agent_id="agent-01",
        session_id=session_id,
        tool_name="admin.exec_cmd",
    )
    action, _ = gateway.evaluate_proposal(prop)

    # T1: Revoke intent
    intent_service.revoke_intent(contract.intent_id, reason="Security revocation")

    # T2: Human attempts to approve
    with pytest.raises(ValueError, match="no active Intent Contract"):
        gateway.resolve_pending_approval(action.action_id, approved=True)


def test_t2_authority_revalidation_rejects_quarantined_or_aborted_trajectory(gateway_setup) -> None:
    """Requirement: Trajectory transitioned to QUARANTINED or ABORTED at T1 blocks execution at T2."""
    from app.schemas.enums import TrajectoryStatus

    gateway, intent_service, traj_store, _ = gateway_setup

    # Case 1: QUARANTINED
    session_1 = "sess-quarantine-t2"
    _ = intent_service.create_intent(
        IntentContractCreate(
            agent_id="agent-01",
            session_id=session_1,
            goal="Quarantine test",
            allowed_tools=["admin.exec_cmd"],
            requires_approval=["admin.exec_cmd"],
        )
    )
    prop1 = AgentActionProposal(
        agent_id="agent-01", session_id=session_1, tool_name="admin.exec_cmd"
    )
    act1, _ = gateway.evaluate_proposal(prop1)

    traj_id1 = traj_store.get_trajectory_id_for_session(session_1)
    traj_store.update_status(traj_id1, TrajectoryStatus.QUARANTINED)

    with pytest.raises(ValueError, match="Trajectory is QUARANTINED"):
        gateway.resolve_pending_approval(act1.action_id, approved=True)

    # Case 2: ABORTED
    session_2 = "sess-aborted-t2"
    _ = intent_service.create_intent(
        IntentContractCreate(
            agent_id="agent-01",
            session_id=session_2,
            goal="Aborted test",
            allowed_tools=["admin.exec_cmd"],
            requires_approval=["admin.exec_cmd"],
        )
    )
    prop2 = AgentActionProposal(
        agent_id="agent-01", session_id=session_2, tool_name="admin.exec_cmd"
    )
    act2, _ = gateway.evaluate_proposal(prop2)

    traj_id2 = traj_store.get_trajectory_id_for_session(session_2)
    traj_store.update_status(traj_id2, TrajectoryStatus.ABORTED)

    with pytest.raises(ValueError, match="Trajectory is ABORTED"):
        gateway.resolve_pending_approval(act2.action_id, approved=True)


def test_t2_authority_revalidation_rejects_budget_exhaustion(gateway_setup) -> None:
    """Requirement: Exhausted dispatch budget at T2 blocks execution."""
    gateway, intent_service, _, _ = gateway_setup
    session_id = "sess-budget-exhaust"

    contract = intent_service.create_intent(
        IntentContractCreate(
            agent_id="agent-01",
            session_id=session_id,
            goal="Budget task",
            allowed_tools=["admin.exec_cmd"],
            requires_approval=["admin.exec_cmd"],
            maximum_tool_calls=1,
        )
    )

    prop = AgentActionProposal(
        agent_id="agent-01",
        session_id=session_id,
        tool_name="admin.exec_cmd",
    )
    action, _ = gateway.evaluate_proposal(prop)

    # T1: Directly consume remaining budget slot
    intent_service.reserve_tool_execution(contract.intent_id)

    # T2: Human attempts to approve -> Must fail because budget is 0
    with pytest.raises(ValueError, match="Tool execution budget exhausted"):
        gateway.resolve_pending_approval(action.action_id, approved=True)


def test_t2_authority_revalidation_rejects_missing_artifact_payload_or_metadata(
    gateway_setup,
) -> None:
    """Requirement: Removed input artifact metadata or payload at T1 blocks execution at T2."""
    from app.provenance.models import ArtifactSourceType, InformationArtifact
    from app.schemas.enums import ProvenanceTrust

    gateway, intent_service, _, _ = gateway_setup
    session_id = "sess-art-missing"

    _ = intent_service.create_intent(
        IntentContractCreate(
            agent_id="agent-01",
            session_id=session_id,
            goal="Artifact missing task",
            allowed_tools=["admin.exec_cmd"],
            requires_approval=["admin.exec_cmd"],
        )
    )

    art = InformationArtifact(
        session_id=session_id,
        source_type=ArtifactSourceType.INTERNAL_RESOURCE,
        source_resource="local-server",
        direct_trust_level=ProvenanceTrust.INTERNAL_TRUSTED,
    )
    gateway.provenance_store.register_artifact(art, payload="Valid command")

    prop = AgentActionProposal(
        agent_id="agent-01",
        session_id=session_id,
        tool_name="admin.exec_cmd",
        input_artifact_ids=[art.artifact_id],
    )
    action, _ = gateway.evaluate_proposal(prop)

    # T1: Payload is removed/deleted from payload store
    gateway.provenance_store.payload_store._payloads.pop(art.artifact_id, None)

    # T2: Human attempts to approve -> Rejected due to missing payload
    with pytest.raises(ValueError, match="Required artifact payload for .* is missing"):
        gateway.resolve_pending_approval(action.action_id, approved=True)


def test_t2_authority_revalidation_rejects_wrong_pending_action_or_ownership(gateway_setup) -> None:
    """Requirement: Wrong pending action ID or ownership mismatch is rejected."""
    from uuid import uuid4

    gateway, intent_service, _, _ = gateway_setup
    session_id = "sess-ownership"

    _ = intent_service.create_intent(
        IntentContractCreate(
            agent_id="agent-01",
            session_id=session_id,
            goal="Ownership task",
            allowed_tools=["admin.exec_cmd"],
            requires_approval=["admin.exec_cmd"],
        )
    )

    prop = AgentActionProposal(
        agent_id="agent-01",
        session_id=session_id,
        tool_name="admin.exec_cmd",
    )
    action, _ = gateway.evaluate_proposal(prop)

    # Attempt to approve random unknown action ID
    with pytest.raises(KeyError, match="Action .* not found"):
        gateway.resolve_pending_approval(uuid4(), approved=True)
