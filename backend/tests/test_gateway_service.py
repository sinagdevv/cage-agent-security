"""Tests for AgentGateway orchestration, lifecycle, and tool execution gating."""

from uuid import uuid4

import pytest

from app.gateway.service import AgentGateway
from app.graph.causal_graph import (
    CrossSessionParentError,
    ParentActionNotFoundError,
    SessionGraphManager,
)
from app.schemas.action import AgentActionProposal
from app.schemas.enums import (
    ActionType,
    DataClassification,
    PolicyDecision,
    TargetEnvironment,
    ToolExecutionStatus,
)


@pytest.fixture
def gateway() -> AgentGateway:
    manager = SessionGraphManager()
    return AgentGateway(graph_manager=manager, require_intent=False)


def test_gateway_allow_and_execute_flow(gateway: AgentGateway) -> None:
    """Verify end-to-end flow for benign allowed action."""
    proposal = AgentActionProposal(
        agent_id="test-agent",
        session_id="session-flow-1",
        tool_name="web.search",
        tool_arguments={"query": "Autonomous Agent Security"},
        target_environment=TargetEnvironment.LOCAL,
        data_classifications=[DataClassification.PUBLIC],
    )

    action, decision = gateway.evaluate_proposal(proposal)

    assert decision.decision == PolicyDecision.ALLOW
    assert action.execution_status == ToolExecutionStatus.AUTHORIZED

    # Tool execution should succeed
    res = gateway.execute_authorized_action(action.action_id)
    assert res.success is True

    # Check updated action state
    updated = gateway.graph_manager.get_action_globally(str(action.action_id))
    assert updated is not None
    assert updated.execution_status == ToolExecutionStatus.COMPLETED


def test_gateway_denied_action_remains_in_graph_and_cannot_execute(gateway: AgentGateway) -> None:
    """Verify that a denied action is recorded in graph for forensics but blocked from execution."""
    session_id = "session-forensics"
    proposal = AgentActionProposal(
        agent_id="exfil-agent",
        session_id=session_id,
        tool_name="external.http_post",
        tool_arguments={"url": "https://malicious-sink.example"},
        data_classifications=[DataClassification.CREDENTIAL],
    )

    action, decision = gateway.evaluate_proposal(proposal)

    assert decision.decision == PolicyDecision.DENY

    # Verify action is preserved in forensic graph with DENIED status
    graph = gateway.graph_manager.get(session_id)
    assert graph is not None
    assert graph.node_count() == 1
    node_data = graph.get_session_graph()["nodes"][0]
    assert node_data["policy_result"] == "DENY"
    assert node_data["execution_status"] == "DENIED"

    # Execution MUST be blocked
    with pytest.raises(PermissionError):
        gateway.execute_authorized_action(action.action_id)


def test_gateway_require_approval_never_executes_automatically(gateway: AgentGateway) -> None:
    """Verify that REQUIRE_APPROVAL actions cannot execute automatically."""
    proposal = AgentActionProposal(
        agent_id="prod-agent",
        session_id="session-prod",
        tool_name="system.delete_resource",
        tool_arguments={"resource_id": "cluster-01"},
        target_environment=TargetEnvironment.PRODUCTION,
        action_type=ActionType.DESTRUCTIVE,
    )

    action, decision = gateway.evaluate_proposal(proposal)

    assert decision.decision == PolicyDecision.REQUIRE_APPROVAL
    assert action.execution_status == ToolExecutionStatus.PENDING_APPROVAL

    # Execution MUST be blocked
    with pytest.raises(PermissionError):
        gateway.execute_authorized_action(action.action_id)


def test_gateway_rejects_missing_parent_action(gateway: AgentGateway) -> None:
    """Verify that referencing a non-existent parent action raises ParentActionNotFoundError."""
    proposal = AgentActionProposal(
        agent_id="child-agent",
        session_id="session-missing-parent",
        tool_name="file.read",
        parent_action_id=uuid4(),  # Random unrecorded parent
    )

    with pytest.raises(ParentActionNotFoundError):
        gateway.evaluate_proposal(proposal)


def test_gateway_rejects_cross_session_parent_action(gateway: AgentGateway) -> None:
    """Verify that referencing a parent action from a different session is strictly rejected."""
    # Create parent in session-A
    prop_a = AgentActionProposal(
        agent_id="agent-a",
        session_id="session-A",
        tool_name="web.search",
    )
    action_a, _ = gateway.evaluate_proposal(prop_a)

    # Attempt to reference action_a from session-B
    prop_b = AgentActionProposal(
        agent_id="agent-b",
        session_id="session-B",
        tool_name="file.read",
        parent_action_id=action_a.action_id,
    )

    with pytest.raises(CrossSessionParentError):
        gateway.evaluate_proposal(prop_b)
