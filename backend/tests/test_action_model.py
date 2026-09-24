"""Tests for AgentActionProposal and authoritative AgentAction schemas."""

from uuid import UUID

import pytest
from pydantic import ValidationError

from app.schemas.action import AgentAction, AgentActionProposal
from app.schemas.enums import (
    ActionType,
    PolicyDecision,
    TargetEnvironment,
    ToolExecutionStatus,
    TrustLevel,
)


def test_agent_action_proposal_valid() -> None:
    """Verify that a well-formed proposal parses and has expected defaults."""
    proposal = AgentActionProposal(
        agent_id="test-agent",
        session_id="session-001",
        tool_name="web.search",
        tool_arguments={"query": "test query"},
    )
    assert proposal.agent_id == "test-agent"
    assert proposal.session_id == "session-001"
    assert proposal.tool_name == "web.search"
    assert proposal.action_type == ActionType.TOOL_CALL
    assert proposal.target_environment == TargetEnvironment.DEVELOPMENT
    assert proposal.input_trust_level == TrustLevel.MEDIUM
    assert proposal.data_classifications == []


def test_client_cannot_submit_authoritative_policy_result() -> None:
    """Verify that clients cannot inject policy_result into proposals."""
    with pytest.raises(ValidationError) as exc_info:
        AgentActionProposal(
            agent_id="attacker",
            session_id="session-001",
            tool_name="file.read",
            policy_result=PolicyDecision.ALLOW,  # type: ignore[call-arg]
        )
    assert "extra_forbidden" in str(exc_info.value)


def test_client_cannot_submit_authoritative_risk_score() -> None:
    """Verify that clients cannot inject risk_score into proposals."""
    with pytest.raises(ValidationError) as exc_info:
        AgentActionProposal(
            agent_id="attacker",
            session_id="session-001",
            tool_name="file.read",
            risk_score=0.0,  # type: ignore[call-arg]
        )
    assert "extra_forbidden" in str(exc_info.value)


def test_client_cannot_submit_authoritative_execution_status() -> None:
    """Verify that clients cannot inject execution_status into proposals."""
    with pytest.raises(ValidationError) as exc_info:
        AgentActionProposal(
            agent_id="attacker",
            session_id="session-001",
            tool_name="file.read",
            execution_status=ToolExecutionStatus.COMPLETED,  # type: ignore[call-arg]
        )
    assert "extra_forbidden" in str(exc_info.value)


def test_server_generates_action_id() -> None:
    """Verify that AgentAction generates a unique server-side UUID."""
    proposal = AgentActionProposal(
        client_action_id="client-custom-id",
        agent_id="agent-01",
        session_id="session-01",
        tool_name="file.read",
    )
    action = AgentAction.from_proposal(proposal)

    assert isinstance(action.action_id, UUID)
    assert action.client_action_id == "client-custom-id"
    assert action.execution_status == ToolExecutionStatus.PROPOSED
    assert action.policy_result is None
    assert action.created_at is not None


def test_enum_validations() -> None:
    """Verify enum rejection on invalid strings."""
    with pytest.raises(ValidationError):
        AgentActionProposal(
            agent_id="agent-01",
            session_id="session-01",
            tool_name="file.read",
            target_environment="INVALID_ENV",  # type: ignore[arg-type]
        )

    with pytest.raises(ValidationError):
        AgentActionProposal(
            agent_id="agent-01",
            session_id="session-01",
            tool_name="file.read",
            action_type="UNSUPPORTED_ACTION",  # type: ignore[arg-type]
        )
