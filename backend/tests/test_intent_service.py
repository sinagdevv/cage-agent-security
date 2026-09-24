"""Unit tests for IntentService lifecycle, authority narrowing invariants, and session uniqueness."""

import inspect
from datetime import UTC, datetime, timedelta

import pytest

from app.intent.service import (
    ActiveIntentCollisionError,
    AuthorityExpansionError,
    IntentService,
)
from app.schemas.enums import IntentStatus
from app.schemas.intent import IntentContractCreate, IntentContractNarrow


def test_intent_service_has_no_graph_dependency() -> None:
    """Architectural invariant: IntentService must not import or depend on NetworkX or CausalExecutionGraph."""
    import app.intent.service as svc_module

    source = inspect.getsource(svc_module)
    assert "networkx" not in source.lower()
    assert "causalexecutiongraph" not in source.lower()
    assert "graph_manager" not in source.lower()


def test_create_and_get_intent() -> None:
    """Verify creating and retrieving an intent contract."""
    svc = IntentService()
    req = IntentContractCreate(
        agent_id="test-agent",
        session_id="sess-01",
        goal="Test retrieval",
        allowed_tools=["web.search"],
    )
    contract = svc.create_intent(req)
    retrieved = svc.get_intent(contract.intent_id)

    assert retrieved is not None
    assert retrieved.intent_id == contract.intent_id
    assert retrieved.status == IntentStatus.ACTIVE


def test_second_active_intent_for_same_session_rejected() -> None:
    """Verify that only one ACTIVE contract may govern a session."""
    svc = IntentService()
    req1 = IntentContractCreate(
        agent_id="test-agent",
        session_id="sess-unique",
        goal="Task 1",
        allowed_tools=["web.search"],
    )
    svc.create_intent(req1)

    req2 = IntentContractCreate(
        agent_id="test-agent",
        session_id="sess-unique",
        goal="Task 2 (collision)",
        allowed_tools=["file.read"],
    )
    with pytest.raises(ActiveIntentCollisionError):
        svc.create_intent(req2)


def test_revoke_intent() -> None:
    """Verify revoking an intent contract changes status to REVOKED."""
    svc = IntentService()
    req = IntentContractCreate(
        agent_id="test-agent",
        session_id="sess-revoke",
        goal="Task to revoke",
        allowed_tools=["web.search"],
    )
    contract = svc.create_intent(req)
    revoked = svc.revoke_intent(contract.intent_id, reason="Admin revoked")

    assert revoked.status == IntentStatus.REVOKED
    assert revoked.revoked_reason == "Admin revoked"
    assert svc.get_active_intent_for_session("sess-revoke") is None


def test_dynamic_expiration() -> None:
    """Verify that an expired contract dynamically transitions to EXPIRED."""
    svc = IntentService()
    past = datetime.now(UTC) - timedelta(seconds=10)
    req = IntentContractCreate(
        agent_id="test-agent",
        session_id="sess-exp",
        goal="Expiring task",
        allowed_tools=["web.search"],
        expires_at=past,
    )
    contract = svc.create_intent(req)
    retrieved = svc.get_intent(contract.intent_id)

    assert retrieved is not None
    assert retrieved.status == IntentStatus.EXPIRED
    assert svc.get_active_intent_for_session("sess-exp") is None


def test_narrowing_tools_subset_accepted() -> None:
    """Verify narrowing allowed_tools to a subset succeeds."""
    svc = IntentService()
    req = IntentContractCreate(
        agent_id="test-agent",
        session_id="sess-narrow",
        goal="Task with tools",
        allowed_tools=["web.search", "file.read", "file.write"],
    )
    contract = svc.create_intent(req)

    narrowed = svc.narrow_intent(
        contract.intent_id,
        IntentContractNarrow(allowed_tools=["web.search", "file.read"]),
    )
    assert narrowed.allowed_tools == frozenset({"web.search", "file.read"})


def test_narrowing_tools_expansion_rejected() -> None:
    """Verify adding an unauthorized tool during narrowing raises AuthorityExpansionError."""
    svc = IntentService()
    req = IntentContractCreate(
        agent_id="test-agent",
        session_id="sess-expand",
        goal="Task with tools",
        allowed_tools=["web.search"],
    )
    contract = svc.create_intent(req)

    with pytest.raises(AuthorityExpansionError):
        svc.narrow_intent(
            contract.intent_id,
            IntentContractNarrow(allowed_tools=["web.search", "database.read"]),
        )


def test_narrowing_delegation_true_to_false_accepted() -> None:
    """Verify disabling delegation is accepted."""
    svc = IntentService()
    req = IntentContractCreate(
        agent_id="test-agent",
        session_id="sess-delegation",
        goal="Delegation task",
        allowed_tools=["web.search"],
        delegation_allowed=True,
    )
    contract = svc.create_intent(req)
    narrowed = svc.narrow_intent(contract.intent_id, IntentContractNarrow(delegation_allowed=False))
    assert narrowed.delegation_allowed is False


def test_narrowing_delegation_false_to_true_rejected() -> None:
    """Verify enabling delegation on a contract that forbids it is rejected."""
    svc = IntentService()
    req = IntentContractCreate(
        agent_id="test-agent",
        session_id="sess-delegation-forbidden",
        goal="Task",
        allowed_tools=["web.search"],
        delegation_allowed=False,
    )
    contract = svc.create_intent(req)
    with pytest.raises(AuthorityExpansionError):
        svc.narrow_intent(contract.intent_id, IntentContractNarrow(delegation_allowed=True))


def test_narrowing_requires_approval_can_only_become_stricter() -> None:
    """Verify requires_approval can only add requirements, not remove them."""
    svc = IntentService()
    req = IntentContractCreate(
        agent_id="test-agent",
        session_id="sess-appr",
        goal="Task",
        allowed_tools=["web.search", "external.http_post"],
        requires_approval=["external.http_post"],
    )
    contract = svc.create_intent(req)

    # Attempting to remove approval requirement (expansion) must fail
    with pytest.raises(AuthorityExpansionError):
        svc.narrow_intent(contract.intent_id, IntentContractNarrow(requires_approval=[]))

    # Adding approval requirement (stricter) must succeed
    narrowed = svc.narrow_intent(
        contract.intent_id,
        IntentContractNarrow(requires_approval=["external.http_post", "web.search"]),
    )
    assert narrowed.requires_approval == frozenset({"external.http_post", "web.search"})


def test_narrowing_maximum_delegation_depth_may_only_decrease() -> None:
    """Verify maximum_delegation_depth may only decrease, never increase."""
    svc = IntentService()
    req = IntentContractCreate(
        agent_id="test-agent",
        session_id="sess-depth",
        goal="Task",
        allowed_tools=["web.search"],
        maximum_delegation_depth=3,
    )
    contract = svc.create_intent(req)

    # 3 -> 2 (decrease) is accepted
    narrowed = svc.narrow_intent(
        contract.intent_id, IntentContractNarrow(maximum_delegation_depth=2)
    )
    assert narrowed.maximum_delegation_depth == 2

    # 2 -> 3 (increase) is rejected
    with pytest.raises(AuthorityExpansionError):
        svc.narrow_intent(contract.intent_id, IntentContractNarrow(maximum_delegation_depth=3))


def test_narrowing_expiration_cases() -> None:
    """Verify expiration narrowing: earlier accepted, later rejected, removing rejected, adding accepted."""
    svc = IntentService()
    base_time = datetime.now(UTC) + timedelta(hours=10)
    req = IntentContractCreate(
        agent_id="test-agent",
        session_id="sess-exp-narrow",
        goal="Task",
        allowed_tools=["web.search"],
        expires_at=base_time,
    )
    contract = svc.create_intent(req)

    # 1. Changing to earlier expiration: valid
    earlier = base_time - timedelta(hours=2)
    narrowed = svc.narrow_intent(contract.intent_id, IntentContractNarrow(expires_at=earlier))
    assert narrowed.expires_at == earlier

    # 2. Changing to later expiration: rejected
    later = base_time + timedelta(hours=5)
    with pytest.raises(AuthorityExpansionError):
        svc.narrow_intent(contract.intent_id, IntentContractNarrow(expires_at=later))

    # 3. Finite expiration -> no expiration (None): rejected
    with pytest.raises(AuthorityExpansionError):
        svc.narrow_intent(contract.intent_id, IntentContractNarrow(expires_at=None))

    # 4. No expiration -> finite expiration: accepted
    req_infinite = IntentContractCreate(
        agent_id="test-agent",
        session_id="sess-exp-infinite",
        goal="Task",
        allowed_tools=["web.search"],
        expires_at=None,
    )
    contract_infinite = svc.create_intent(req_infinite)
    finite_deadline = datetime.now(UTC) + timedelta(days=1)
    narrowed_finite = svc.narrow_intent(
        contract_infinite.intent_id, IntentContractNarrow(expires_at=finite_deadline)
    )
    assert narrowed_finite.expires_at == finite_deadline


def test_narrowing_maximum_tool_calls_below_usage_rejected() -> None:
    """Verify new maximum_tool_calls cannot be less than already consumed calls."""
    svc = IntentService()
    req = IntentContractCreate(
        agent_id="test-agent",
        session_id="sess-quota",
        goal="Task",
        allowed_tools=["web.search"],
        maximum_tool_calls=10,
    )
    contract = svc.create_intent(req)

    # Simulate 5 consumed tool calls
    for _ in range(5):
        assert svc.reserve_tool_execution(contract.intent_id) is True

    # Reducing to 4 (below consumed 5) must be rejected
    with pytest.raises(AuthorityExpansionError):
        svc.narrow_intent(contract.intent_id, IntentContractNarrow(maximum_tool_calls=4))

    # Reducing to 6 (above consumed 5) is accepted
    narrowed = svc.narrow_intent(contract.intent_id, IntentContractNarrow(maximum_tool_calls=6))
    assert narrowed.maximum_tool_calls == 6
