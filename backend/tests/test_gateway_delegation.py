"""Integration tests for AgentGateway multi-agent delegation authorization."""

from uuid import uuid4

import pytest

from app.delegation.models import DelegationProposal, ResourceAuthorityScopeRequest
from app.delegation.service import DelegationService
from app.gateway.service import AgentGateway
from app.identity.principal import AgentPrincipal, PrincipalAuthenticationSource
from app.intent.service import IntentService
from app.schemas.action import AgentActionProposal
from app.schemas.enums import (
    AuthorityScopeMode,
    DataClassification,
    PolicyDecision,
    TargetEnvironment,
)
from app.schemas.intent import IntentContractCreate


@pytest.fixture
def gateway_delegation_env():
    intent_service = IntentService()
    delegation_service = DelegationService(intent_service=intent_service)
    gateway = AgentGateway(intent_service=intent_service, delegation_service=delegation_service)
    session_id = uuid4()
    session_str = str(session_id)

    # 1. Create root Intent Contract for root-agent
    intent = intent_service.create_intent(
        IntentContractCreate(
            session_id=session_str,
            agent_id="root-agent",
            user_id="user-1",
            goal="Data analysis workflow",
            allowed_tools=["web.search", "db.read", "file.write"],
            allowed_environments=[TargetEnvironment.DEVELOPMENT],
            allowed_resources=["res://dataset1", "res://dataset2"],
            allowed_data_classifications=[DataClassification.PUBLIC, DataClassification.INTERNAL],
            maximum_tool_calls=20,
        )
    )

    # 2. Issue delegation grant from root-agent to worker-agent
    root_principal = AgentPrincipal(
        agent_id="root-agent",
        session_id=session_id,
        authentication_source=PrincipalAuthenticationSource.TEST_FIXTURE,
    )
    proposal = DelegationProposal(
        session_id=session_id,
        delegator_agent_id="root-agent",
        delegatee_agent_id="worker-agent",
        delegated_task_id="scrape-data",
        requested_tools=["web.search", "db.read"],
        requested_environments=[TargetEnvironment.DEVELOPMENT],
        requested_classifications=[DataClassification.PUBLIC],
        requested_resource_scope=ResourceAuthorityScopeRequest(
            mode=AuthorityScopeMode.ALLOWLIST,
            allowed_resources=["res://dataset1"],
        ),
        requested_max_actions=5,
        allow_subdelegation=True,
    )
    grant_res = delegation_service.propose_delegation(proposal, root_principal)
    assert grant_res.decision == PolicyDecision.ALLOW

    return {
        "gateway": gateway,
        "intent_service": intent_service,
        "delegation_service": delegation_service,
        "session_id": session_id,
        "session_str": session_str,
        "grant_id": grant_res.delegation_id,
        "intent": intent,
    }


def test_delegated_action_allowed_in_scope(gateway_delegation_env):
    """Worker agent executing delegated tool within grant authority succeeds."""
    gateway: AgentGateway = gateway_delegation_env["gateway"]
    session_str = gateway_delegation_env["session_str"]
    grant_id = gateway_delegation_env["grant_id"]

    action_prop = AgentActionProposal(
        agent_id="worker-agent",
        session_id=session_str,
        delegation_id=grant_id,
        tool_name="web.search",
        target_resource="res://dataset1",
        target_environment=TargetEnvironment.DEVELOPMENT,
        data_classifications=[DataClassification.PUBLIC],
        parent_action_id=None,  # First action of worker-agent has parent_action_id=None
    )

    action, decision = gateway.evaluate_proposal(action_prop)
    assert decision.decision == PolicyDecision.ALLOW
    assert action.delegation_id == grant_id


def test_delegated_action_denied_out_of_scope_tool(gateway_delegation_env):
    """Worker agent attempting undelegated tool (file.write) is denied."""
    gateway: AgentGateway = gateway_delegation_env["gateway"]
    session_str = gateway_delegation_env["session_str"]
    grant_id = gateway_delegation_env["grant_id"]

    action_prop = AgentActionProposal(
        agent_id="worker-agent",
        session_id=session_str,
        delegation_id=grant_id,
        tool_name="file.write",  # in root intent, but not in worker grant
        target_resource="res://dataset1",
        target_environment=TargetEnvironment.DEVELOPMENT,
        data_classifications=[DataClassification.PUBLIC],
        parent_action_id=None,
    )

    action, decision = gateway.evaluate_proposal(action_prop)
    assert decision.decision == PolicyDecision.DENY
    assert "RULE_DELEGATION_TOOL_NOT_AUTHORIZED" in decision.matched_rules


def test_delegated_action_denied_out_of_scope_resource(gateway_delegation_env):
    """Worker agent attempting resource not in grant allowlist (res://dataset2) is denied."""
    gateway: AgentGateway = gateway_delegation_env["gateway"]
    session_str = gateway_delegation_env["session_str"]
    grant_id = gateway_delegation_env["grant_id"]

    action_prop = AgentActionProposal(
        agent_id="worker-agent",
        session_id=session_str,
        delegation_id=grant_id,
        tool_name="db.read",
        target_resource="res://dataset2",  # in root intent, but not in worker allowlist
        target_environment=TargetEnvironment.DEVELOPMENT,
        data_classifications=[DataClassification.PUBLIC],
        parent_action_id=None,
    )

    action, decision = gateway.evaluate_proposal(action_prop)
    assert decision.decision == PolicyDecision.DENY
    assert "RULE_DELEGATION_RESOURCE_NOT_AUTHORIZED" in decision.matched_rules


def test_delegated_action_denied_principal_mismatch(gateway_delegation_env):
    """Different agent trying to claim worker-agent's grant is denied."""
    gateway: AgentGateway = gateway_delegation_env["gateway"]
    session_str = gateway_delegation_env["session_str"]
    grant_id = gateway_delegation_env["grant_id"]

    action_prop = AgentActionProposal(
        agent_id="attacker-agent",  # Not the delegatee
        session_id=session_str,
        delegation_id=grant_id,
        tool_name="web.search",
        target_resource="res://dataset1",
        target_environment=TargetEnvironment.DEVELOPMENT,
        data_classifications=[DataClassification.PUBLIC],
        parent_action_id=None,
    )

    action, decision = gateway.evaluate_proposal(action_prop)
    assert decision.decision == PolicyDecision.DENY
    assert "RULE_DELEGATION_PRINCIPAL_MISMATCH" in decision.matched_rules


def test_revoked_grant_denies_subsequent_actions(gateway_delegation_env):
    """Revoking grant immediately denies subsequent tool execution attempts."""
    gateway: AgentGateway = gateway_delegation_env["gateway"]
    delegation_service: DelegationService = gateway_delegation_env["delegation_service"]
    session_id = gateway_delegation_env["session_id"]
    session_str = gateway_delegation_env["session_str"]
    grant_id = gateway_delegation_env["grant_id"]

    root_principal = AgentPrincipal(
        agent_id="root-agent",
        session_id=session_id,
        authentication_source=PrincipalAuthenticationSource.TEST_FIXTURE,
    )
    delegation_service.revoke_delegation(grant_id, root_principal, reason="Security review")

    action_prop = AgentActionProposal(
        agent_id="worker-agent",
        session_id=session_str,
        delegation_id=grant_id,
        tool_name="web.search",
        target_resource="res://dataset1",
        target_environment=TargetEnvironment.DEVELOPMENT,
        data_classifications=[DataClassification.PUBLIC],
        parent_action_id=None,
    )

    action, decision = gateway.evaluate_proposal(action_prop)
    assert decision.decision == PolicyDecision.DENY
    assert "RULE_DELEGATION_REVOKED" in decision.matched_rules
