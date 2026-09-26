"""Tests for DelegationStore thread safety, indexing, chaining, and budget accounting."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from app.delegation.models import DelegationGrant
from app.delegation.store import DelegationStore
from app.schemas.enums import (
    AuthorityScopeMode,
    DataClassification,
    DelegationStatus,
    TargetEnvironment,
)
from app.trajectory.models import AuthorityEnvelope, ResourceAuthorityScope


def _create_sample_grant(
    delegation_id=None,
    parent_delegation_id=None,
    session_id=None,
    root_intent_id=None,
    delegator="agent-a",
    delegatee="agent-b",
    depth=1,
    remaining_depth=1,
    allow_subdelegation=True,
    max_actions=10,
    expires_delta=3600,
) -> DelegationGrant:
    return DelegationGrant(
        delegation_id=delegation_id or uuid4(),
        parent_delegation_id=parent_delegation_id,
        root_intent_id=root_intent_id or uuid4(),
        session_id=session_id or uuid4(),
        issued_from_action_id=uuid4(),
        delegator_agent_id=delegator,
        delegatee_agent_id=delegatee,
        delegated_task_id="test-task",
        authority_envelope=AuthorityEnvelope(
            allowed_tools=frozenset(["web.search", "db.read"]),
            resource_scope=ResourceAuthorityScope(mode=AuthorityScopeMode.UNCONSTRAINED),
            allowed_environments=frozenset([TargetEnvironment.DEVELOPMENT]),
            allowed_data_classifications=frozenset([DataClassification.PUBLIC]),
        ),
        depth=depth,
        remaining_subdelegation_depth=remaining_depth,
        allow_subdelegation=allow_subdelegation,
        max_actions=max_actions,
        expires_at=datetime.now(UTC) + timedelta(seconds=expires_delta),
    )


def test_create_and_get_grant():
    store = DelegationStore()
    grant = _create_sample_grant()
    store.create_grant(grant)

    fetched = store.get_grant(grant.delegation_id)
    assert fetched == grant

    state = store.get_runtime_state(grant.delegation_id)
    assert state is not None
    assert state.status == DelegationStatus.ACTIVE


def test_chain_traversal():
    store = DelegationStore()
    session_id = uuid4()
    root_intent_id = uuid4()

    g1 = _create_sample_grant(
        delegator="root-agent",
        delegatee="agent-a",
        session_id=session_id,
        root_intent_id=root_intent_id,
        depth=1,
    )
    g2 = _create_sample_grant(
        parent_delegation_id=g1.delegation_id,
        delegator="agent-a",
        delegatee="agent-b",
        session_id=session_id,
        root_intent_id=root_intent_id,
        depth=2,
    )
    g3 = _create_sample_grant(
        parent_delegation_id=g2.delegation_id,
        delegator="agent-b",
        delegatee="agent-c",
        session_id=session_id,
        root_intent_id=root_intent_id,
        depth=3,
    )

    store.create_grant(g1)
    store.create_grant(g2)
    store.create_grant(g3)

    chain = store.get_chain(g3.delegation_id)
    assert len(chain) == 3
    assert [g.delegation_id for g in chain] == [
        g1.delegation_id,
        g2.delegation_id,
        g3.delegation_id,
    ]

    children = store.get_children(g1.delegation_id)
    assert len(children) == 1
    assert children[0].delegation_id == g2.delegation_id


def test_revocation_and_closure():
    store = DelegationStore()
    grant = _create_sample_grant()
    store.create_grant(grant)

    # Revoke
    assert (
        store.revoke(
            grant.delegation_id, revoked_by_principal_id="root-agent", reason="Security alert"
        )
        is True
    )
    state = store.get_runtime_state(grant.delegation_id)
    assert state is not None
    assert state.status == DelegationStatus.REVOKED
    assert state.revoked_by_principal_id == "root-agent"

    # Close on revoked grant is no-op
    assert store.close(grant.delegation_id, closed_by_agent_id="agent-b") is True
    state_after = store.get_runtime_state(grant.delegation_id)
    assert state_after.status == DelegationStatus.REVOKED


def test_budget_accounting_and_dispatch():
    store = DelegationStore()
    grant = _create_sample_grant(max_actions=5)
    store.create_grant(grant)

    assert store.remaining_budget(grant.delegation_id) == 5
    store.record_dispatch(grant.delegation_id, count=2)
    assert store.remaining_budget(grant.delegation_id) == 3
    state = store.get_runtime_state(grant.delegation_id)
    assert state.actions_executed_count == 2
    assert state.last_action_at is not None
