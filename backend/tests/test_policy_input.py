"""Tests for canonical CagePolicyInput construction and normalization."""

import logging
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.gateway.registry import ToolRegistry, ToolSpec
from app.policies.policy_input import build_cage_policy_input
from app.schemas.action import AgentAction, AgentActionProposal
from app.schemas.enums import (
    ActionType,
    DataClassification,
    TargetEnvironment,
    TrustLevel,
)
from app.schemas.intent import IntentContract, IntentContractCreate
from app.schemas.policy import (
    POLICY_INPUT_SCHEMA_VERSION,
    POLICY_VERSION,
    CagePolicyInput,
)


def test_policy_input_normalization_and_server_control() -> None:
    """Verify CagePolicyInput builds strictly from server-authoritative state."""
    registry = ToolRegistry()
    registry.register(
        ToolSpec(
            name="db.query",
            description="Database query tool",
            destructive=True,
            resource_scoped=True,
            default_classification=DataClassification.RESTRICTED,
        )
    )

    action = AgentAction(
        action_id=uuid4(),
        agent_id="agent-007",
        session_id="session-42",
        tool_name="db.query",
        action_type=ActionType.TOOL_CALL,
        target_resource="db://finance",
        target_environment=TargetEnvironment.PRODUCTION,
        data_classifications=[DataClassification.PUBLIC],
        input_trust_level=TrustLevel.MEDIUM,
    )

    contract = IntentContract.from_create(
        IntentContractCreate(
            agent_id="agent-007",
            session_id="session-42",
            goal="Financial audit",
            allowed_tools=["db.query"],
            allowed_environments=[TargetEnvironment.PRODUCTION],
            allowed_resources=["db://finance"],
        )
    )

    policy_input = build_cage_policy_input(
        action=action,
        contract=contract,
        tool_registry=registry,
        require_intent=True,
        intent_mismatch=False,
    )

    # Verify server-controlled schema version
    assert policy_input.schema_version == POLICY_INPUT_SCHEMA_VERSION
    assert policy_input.schema_version == "cage-policy-input-v2"

    # Verify policy version and schema version remain distinct concepts
    assert POLICY_VERSION != POLICY_INPUT_SCHEMA_VERSION
    assert POLICY_VERSION == "phase4-v1"

    # Verify normalized contexts
    assert policy_input.action.tool_name == "db.query"
    assert policy_input.action.target_environment == "PRODUCTION"
    assert policy_input.agent.agent_id == "agent-007"
    assert policy_input.agent.session_id == "session-42"
    assert policy_input.intent is not None
    assert policy_input.intent.allowed_tools == ["db.query"]
    assert policy_input.tool.destructive is True
    assert policy_input.tool.resource_scoped is True

    # Verify effective classification merges server known RESTRICTED with client declared PUBLIC
    assert "RESTRICTED" in policy_input.data.effective_classifications
    assert "PUBLIC" in policy_input.data.effective_classifications


def test_agent_proposal_cannot_inject_policy_input_fields() -> None:
    """Verify AgentActionProposal forbids client tampering with policy input fields."""
    with pytest.raises(ValidationError):
        AgentActionProposal(
            agent_id="agent-01",
            session_id="sess-01",
            tool_name="web.search",
            schema_version="hacked-v2",  # type: ignore[call-arg]
        )

    with pytest.raises(ValidationError):
        AgentActionProposal(
            agent_id="agent-01",
            session_id="sess-01",
            tool_name="web.search",
            policy_backend="PYTHON",  # type: ignore[call-arg]
        )


def test_cage_policy_input_extra_forbidden() -> None:
    """Verify CagePolicyInput rejects arbitrary unvalidated fields."""
    with pytest.raises(ValidationError):
        CagePolicyInput(
            schema_version="cage-policy-input-v1",
            action=None,  # type: ignore[arg-type]
            agent=None,  # type: ignore[arg-type]
            tool=None,  # type: ignore[arg-type]
            data=None,  # type: ignore[arg-type]
            context=None,  # type: ignore[arg-type]
            arbitrary_field="injected",  # type: ignore[call-arg]
        )


def test_raw_policy_input_not_emitted_in_normal_logs(caplog: pytest.LogCaptureFixture) -> None:
    """Verify that full raw CagePolicyInput is not dumped into standard application logs."""
    from app.gateway.service import AgentGateway

    gateway = AgentGateway(require_intent=False)
    proposal = AgentActionProposal(
        agent_id="agent-01",
        session_id="sess-log-test",
        tool_name="web.search",
        target_resource="https://sensitive.internal.corp/secret",
    )

    with caplog.at_level(logging.INFO):
        gateway.evaluate_proposal(proposal)

    # Confirm normal log contains concise summary rather than raw policy document dump
    log_text = caplog.text
    assert "Action evaluated:" in log_text
    assert "decision=" in log_text
    assert "https://sensitive.internal.corp/secret" not in log_text
