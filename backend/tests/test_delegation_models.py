"""Tests for Phase 8 delegation models, schemas, and resource scope normalization."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from app.delegation.models import (
    DelegationGrant,
    DelegationProposal,
    DelegationRuntimeState,
    ResourceAuthorityScopeRequest,
)
from app.schemas.enums import (
    AuthorityScopeMode,
    DataClassification,
    DelegationStatus,
    TargetEnvironment,
)
from app.trajectory.models import AuthorityEnvelope, ResourceAuthorityScope


def test_resource_authority_scope_request_normalization():
    """ResourceAuthorityScopeRequest converts cleanly between unconstrained and allowlist."""
    req_unconstrained = ResourceAuthorityScopeRequest(
        mode=AuthorityScopeMode.UNCONSTRAINED,
        allowed_resources=[],
    )
    auth_unconstrained = req_unconstrained.to_authoritative()
    assert auth_unconstrained.mode == AuthorityScopeMode.UNCONSTRAINED
    assert auth_unconstrained.is_allowed("/any/resource") is True

    req_allowlist = ResourceAuthorityScopeRequest(
        mode=AuthorityScopeMode.ALLOWLIST,
        allowed_resources=["db://customers", "s3://bucket/data"],
    )
    auth_allowlist = req_allowlist.to_authoritative()
    assert auth_allowlist.mode == AuthorityScopeMode.ALLOWLIST
    assert auth_allowlist.is_allowed("db://customers") is True
    assert auth_allowlist.is_allowed("db://salaries") is False


def test_delegation_proposal_schema():
    """DelegationProposal validates untrusted payload fields."""
    session_id = uuid4()
    proposal = DelegationProposal(
        session_id=session_id,
        delegator_agent_id="agent-a",
        delegatee_agent_id="agent-b",
        delegated_task_id="task-123",
        requested_tools=["web.search", "db.read"],
        requested_environments=[TargetEnvironment.DEVELOPMENT],
        requested_classifications=[DataClassification.INTERNAL],
        requested_resource_scope=ResourceAuthorityScopeRequest(
            mode=AuthorityScopeMode.ALLOWLIST,
            allowed_resources=["res://1"],
        ),
        requested_max_actions=5,
        requested_ttl_seconds=3600,
        allow_subdelegation=True,
    )
    assert proposal.session_id == session_id
    assert proposal.delegator_agent_id == "agent-a"
    assert proposal.allow_subdelegation is True
    assert proposal.requested_max_actions == 5


def test_delegation_grant_immutability():
    """DelegationGrant must be deeply frozen and reject mutation."""
    grant = DelegationGrant(
        delegation_id=uuid4(),
        root_intent_id=uuid4(),
        session_id=uuid4(),
        issued_from_action_id=uuid4(),
        delegator_agent_id="agent-a",
        delegatee_agent_id="agent-b",
        delegated_task_id="task-123",
        authority_envelope=AuthorityEnvelope(
            allowed_tools=frozenset(["web.search"]),
            resource_scope=ResourceAuthorityScope(mode=AuthorityScopeMode.UNCONSTRAINED),
            allowed_environments=frozenset([TargetEnvironment.DEVELOPMENT]),
            allowed_data_classifications=frozenset([DataClassification.PUBLIC]),
        ),
        depth=1,
        remaining_subdelegation_depth=2,
        allow_subdelegation=True,
        max_actions=10,
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )

    with pytest.raises((TypeError, AttributeError, ValueError)):
        grant.max_actions = 20  # type: ignore[misc]

    with pytest.raises((TypeError, AttributeError, ValueError)):
        grant.delegator_agent_id = "agent-evil"  # type: ignore[misc]


def test_delegation_runtime_state_defaults():
    """DelegationRuntimeState tracks mutable state separately."""
    del_id = uuid4()
    state = DelegationRuntimeState(delegation_id=del_id)
    assert state.status == DelegationStatus.ACTIVE
    assert state.actions_executed_count == 0
    assert state.revoked_at is None
    assert state.closed_at is None
