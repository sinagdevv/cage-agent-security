"""Tests for DelegationService lifecycle, proposal evaluation, approval resolution, and revocation."""

from uuid import uuid4

import pytest

from app.delegation.models import DelegationProposal, ResourceAuthorityScopeRequest
from app.delegation.service import DelegationService
from app.identity.principal import AgentPrincipal, PrincipalAuthenticationSource
from app.intent.service import IntentService
from app.schemas.enums import (
    AuthorityScopeMode,
    DataClassification,
    PolicyDecision,
    TargetEnvironment,
)
from app.schemas.intent import IntentContractCreate


@pytest.fixture
def delegation_setup():
    intent_service = IntentService()
    service = DelegationService(intent_service=intent_service)
    session_id = uuid4()

    # Create root Intent
    intent = intent_service.create_intent(
        IntentContractCreate(
            session_id=str(session_id),
            agent_id="root-agent",
            user_id="user-1",
            goal="Manage cloud resources",
            allowed_tools=["web.search", "db.read", "file.write", "db.drop"],
            allowed_environments=[TargetEnvironment.DEVELOPMENT],
            allowed_resources=["res://customers", "res://orders"],
            allowed_data_classifications=[DataClassification.PUBLIC, DataClassification.INTERNAL],
            requires_approval=["db.drop"],
            maximum_tool_calls=50,
        )
    )

    return {
        "service": service,
        "intent_service": intent_service,
        "session_id": session_id,
        "intent": intent,
    }


def test_propose_root_delegation_success(delegation_setup):
    service: DelegationService = delegation_setup["service"]
    session_id = delegation_setup["session_id"]

    principal = AgentPrincipal(
        agent_id="root-agent",
        session_id=session_id,
        authentication_source=PrincipalAuthenticationSource.TEST_FIXTURE,
    )

    proposal = DelegationProposal(
        session_id=session_id,
        delegator_agent_id="root-agent",
        delegatee_agent_id="agent-worker-1",
        delegated_task_id="task-scrape-1",
        requested_tools=["web.search", "db.read"],
        requested_environments=[TargetEnvironment.DEVELOPMENT],
        requested_classifications=[DataClassification.PUBLIC],
        requested_resource_scope=ResourceAuthorityScopeRequest(
            mode=AuthorityScopeMode.ALLOWLIST, allowed_resources=["res://customers"]
        ),
        requested_max_actions=10,
        allow_subdelegation=True,
    )

    res = service.propose_delegation(proposal, principal)
    assert res.decision == PolicyDecision.ALLOW
    assert res.delegation_id is not None
    assert res.status == "ACTIVE"

    # Verify grant persisted in store
    grant = service.get_delegation_grant(res.delegation_id)
    assert grant is not None
    assert grant.delegatee_agent_id == "agent-worker-1"
    assert grant.depth == 1
    assert grant.remaining_subdelegation_depth > 0


def test_propose_subdelegation_not_allowed_when_parent_prohibits(delegation_setup):
    service: DelegationService = delegation_setup["service"]
    session_id = delegation_setup["session_id"]

    # 1. Issue parent grant with allow_subdelegation=False
    p_principal = AgentPrincipal(
        agent_id="root-agent",
        session_id=session_id,
        authentication_source=PrincipalAuthenticationSource.TEST_FIXTURE,
    )
    p_proposal = DelegationProposal(
        session_id=session_id,
        delegator_agent_id="root-agent",
        delegatee_agent_id="agent-worker-1",
        delegated_task_id="task-1",
        requested_tools=["web.search"],
        requested_environments=[TargetEnvironment.DEVELOPMENT],
        requested_classifications=[DataClassification.PUBLIC],
        requested_resource_scope=ResourceAuthorityScopeRequest(
            mode=AuthorityScopeMode.ALLOWLIST, allowed_resources=["res://customers"]
        ),
        allow_subdelegation=False,  # Subdelegation prohibited
    )
    p_res = service.propose_delegation(p_proposal, p_principal)
    assert p_res.decision == PolicyDecision.ALLOW

    # 2. Worker 1 attempts to subdelegate to Worker 2
    c_principal = AgentPrincipal(
        agent_id="agent-worker-1",
        session_id=session_id,
        authentication_source=PrincipalAuthenticationSource.TEST_FIXTURE,
    )
    c_proposal = DelegationProposal(
        session_id=session_id,
        delegator_agent_id="agent-worker-1",
        delegatee_agent_id="agent-worker-2",
        parent_delegation_id=p_res.delegation_id,
        delegated_task_id="task-2",
        requested_tools=["web.search"],
        requested_environments=[TargetEnvironment.DEVELOPMENT],
        requested_classifications=[DataClassification.PUBLIC],
        requested_resource_scope=ResourceAuthorityScopeRequest(
            mode=AuthorityScopeMode.ALLOWLIST, allowed_resources=["res://customers"]
        ),
        allow_subdelegation=False,
    )
    c_res = service.propose_delegation(c_proposal, c_principal)
    assert c_res.decision == PolicyDecision.DENY
    assert "RULE_DELEGATION_SUBDELEGATION_NOT_ALLOWED" in c_res.matched_rules
    assert c_res.delegation_id is None


def test_pending_delegation_approval_lifecycle(delegation_setup):
    service: DelegationService = delegation_setup["service"]
    session_id = delegation_setup["session_id"]

    principal = AgentPrincipal(
        agent_id="root-agent",
        session_id=session_id,
        authentication_source=PrincipalAuthenticationSource.TEST_FIXTURE,
    )

    # Propose high-risk tool that requires approval in intent
    proposal = DelegationProposal(
        session_id=session_id,
        delegator_agent_id="root-agent",
        delegatee_agent_id="agent-worker-1",
        delegated_task_id="task-admin",
        requested_tools=["db.drop"],  # requires approval
        requested_environments=[TargetEnvironment.DEVELOPMENT],
        requested_classifications=[DataClassification.INTERNAL],
        requested_resource_scope=ResourceAuthorityScopeRequest(
            mode=AuthorityScopeMode.ALLOWLIST, allowed_resources=["res://customers"]
        ),
    )

    res = service.propose_delegation(proposal, principal)
    assert res.decision == PolicyDecision.REQUIRE_APPROVAL
    assert res.delegation_id is None
    assert res.status == "PENDING_APPROVAL"
    req_id = res.delegation_request_id

    # Resolve approval at T2
    approver = AgentPrincipal(
        agent_id="admin-approver",
        session_id=session_id,
        authentication_source=PrincipalAuthenticationSource.TEST_FIXTURE,
        is_control_plane=True,
    )
    approved_res = service.resolve_delegation_approval(req_id, approver, decision="APPROVED")
    assert approved_res.decision == PolicyDecision.ALLOW
    assert approved_res.delegation_id is not None
    assert approved_res.status == "ACTIVE"


def test_revocation_authorization(delegation_setup):
    service: DelegationService = delegation_setup["service"]
    session_id = delegation_setup["session_id"]

    principal = AgentPrincipal(
        agent_id="root-agent",
        session_id=session_id,
        authentication_source=PrincipalAuthenticationSource.TEST_FIXTURE,
    )

    proposal = DelegationProposal(
        session_id=session_id,
        delegator_agent_id="root-agent",
        delegatee_agent_id="agent-worker-1",
        delegated_task_id="task-1",
        requested_tools=["web.search"],
        requested_environments=[TargetEnvironment.DEVELOPMENT],
        requested_classifications=[DataClassification.PUBLIC],
        requested_resource_scope=ResourceAuthorityScopeRequest(
            mode=AuthorityScopeMode.ALLOWLIST, allowed_resources=["res://customers"]
        ),
    )
    res = service.propose_delegation(proposal, principal)
    grant_id = res.delegation_id

    # Unrelated agent attempts revocation -> Denied
    unrelated = AgentPrincipal(
        agent_id="agent-unrelated",
        session_id=session_id,
        authentication_source=PrincipalAuthenticationSource.TEST_FIXTURE,
    )
    assert service.revoke_delegation(grant_id, unrelated) is False

    # Root intent owner revokes -> Success
    assert service.revoke_delegation(grant_id, principal) is True
    snapshot = service.get_delegation_snapshot(grant_id)
    assert snapshot is not None
    assert snapshot.runtime_status == "REVOKED"
