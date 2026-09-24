"""Unit tests for Intent Contract schemas and immutability invariants."""

from uuid import UUID

import pytest
from pydantic import ValidationError

from app.schemas.enums import DataClassification, IntentStatus, TargetEnvironment
from app.schemas.intent import (
    IntentContract,
    IntentContractCreate,
    IntentContractNarrow,
)


def test_intent_contract_create_valid() -> None:
    """Verify that valid IntentContractCreate parses and sets expected defaults."""
    req = IntentContractCreate(
        agent_id="agent-01",
        session_id="session-01",
        goal="Perform web research",
        allowed_tools=["web.search", "file.read"],
    )
    assert req.agent_id == "agent-01"
    assert req.session_id == "session-01"
    assert req.maximum_tool_calls == 20
    assert req.allowed_environments == [TargetEnvironment.LOCAL, TargetEnvironment.DEVELOPMENT]
    assert req.allowed_data_classifications == [DataClassification.PUBLIC]


def test_intent_contract_create_requires_tools() -> None:
    """Verify that allowed_tools cannot be empty in creation request."""
    with pytest.raises(ValidationError):
        IntentContractCreate(
            agent_id="agent-01",
            session_id="session-01",
            goal="Goal without tools",
            allowed_tools=[],  # type: ignore[arg-type]
        )


def test_intent_contract_immutability() -> None:
    """Verify that authoritative IntentContract uses frozensets and is immutable."""
    req = IntentContractCreate(
        agent_id="agent-01",
        session_id="session-01",
        goal="Test immutability",
        allowed_tools=["web.search"],
    )
    contract = IntentContract.from_create(req)

    assert isinstance(contract.intent_id, UUID)
    assert isinstance(contract.allowed_tools, frozenset)
    assert contract.tool_calls_count == 0
    assert contract.status == IntentStatus.ACTIVE

    # Frozen model prevents direct field mutation
    with pytest.raises(ValidationError):
        contract.maximum_tool_calls = 50  # type: ignore[misc]


def test_intent_contract_narrow_extra_forbidden() -> None:
    """Verify that client cannot pass arbitrary fields in narrowing request."""
    with pytest.raises(ValidationError):
        IntentContractNarrow(
            allowed_tools=["web.search"],
            arbitrary_field="malicious",  # type: ignore[call-arg]
        )


def test_client_cannot_modify_authoritative_tool_calls_count() -> None:
    """Verify that clients cannot forge or mutate authoritative tool_calls_count."""
    # 1. Cannot inject in creation
    with pytest.raises(ValidationError):
        IntentContractCreate(
            agent_id="agent-01",
            session_id="session-01",
            goal="Test",
            allowed_tools=["web.search"],
            tool_calls_count=5,  # type: ignore[call-arg]
        )

    # 2. Cannot inject in narrowing
    with pytest.raises(ValidationError):
        IntentContractNarrow(
            tool_calls_count=5,  # type: ignore[call-arg]
        )

    # 3. Cannot mutate directly on stored contract
    contract = IntentContract.from_create(
        IntentContractCreate(
            agent_id="agent-01",
            session_id="session-01",
            goal="Test",
            allowed_tools=["web.search"],
        )
    )
    with pytest.raises(ValidationError):
        contract.tool_calls_count = 10  # type: ignore[misc]

