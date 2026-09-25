"""Tests for Intent Contract authorization rules, gateway integration, and graph recording."""

from datetime import UTC, datetime, timedelta

import pytest

from app.gateway.service import AgentGateway
from app.graph.causal_graph import SessionGraphManager
from app.intent.service import IntentService
from app.schemas.action import AgentActionProposal
from app.schemas.enums import (
    DataClassification,
    PolicyDecision,
    TargetEnvironment,
    ToolExecutionStatus,
)
from app.schemas.intent import IntentContractCreate


@pytest.fixture
def intent_service() -> IntentService:
    return IntentService()


@pytest.fixture
def graph_manager() -> SessionGraphManager:
    return SessionGraphManager()


@pytest.fixture
def strict_gateway(
    intent_service: IntentService, graph_manager: SessionGraphManager
) -> AgentGateway:
    return AgentGateway(
        intent_service=intent_service,
        graph_manager=graph_manager,
        require_intent=True,
    )


def test_secure_gateway_defaults_to_requiring_intent(strict_gateway: AgentGateway) -> None:
    """Verify that an unmanaged session without an intent contract is DENIED by default."""
    proposal = AgentActionProposal(
        agent_id="agent-01",
        session_id="unmanaged-session",
        tool_name="web.search",
    )
    action, decision = strict_gateway.evaluate_proposal(proposal)
    assert decision.decision == PolicyDecision.DENY
    assert "RULE_INTENT_MISSING" in decision.matched_rules
    assert action.execution_status == ToolExecutionStatus.DENIED


def test_tool_allowed_by_intent(
    strict_gateway: AgentGateway, intent_service: IntentService
) -> None:
    """Verify an action within intent bounds returns ALLOW and consumes 1 budget slot."""
    session_id = "sess-allowed"
    contract = intent_service.create_intent(
        IntentContractCreate(
            agent_id="agent-01",
            session_id=session_id,
            goal="Research task",
            allowed_tools=["web.search"],
            maximum_tool_calls=5,
        )
    )

    proposal = AgentActionProposal(
        agent_id="agent-01",
        session_id=session_id,
        tool_name="web.search",
    )
    action, decision = strict_gateway.evaluate_proposal(proposal)

    assert decision.decision == PolicyDecision.ALLOW
    assert "RULE_INTENT_ALLOW" in decision.matched_rules
    assert decision.intent_contract_id == contract.intent_id

    # Execution quota check: exactly 1 slot consumed
    updated_contract = intent_service.get_intent(contract.intent_id)
    assert updated_contract is not None
    assert updated_contract.tool_calls_count == 1


def test_tool_outside_intent_denied(
    strict_gateway: AgentGateway, intent_service: IntentService
) -> None:
    """Verify tool outside intent is DENIED and does NOT consume execution budget."""
    session_id = "sess-outside"
    contract = intent_service.create_intent(
        IntentContractCreate(
            agent_id="agent-01",
            session_id=session_id,
            goal="Research task",
            allowed_tools=["web.search"],
            maximum_tool_calls=5,
        )
    )

    proposal = AgentActionProposal(
        agent_id="agent-01",
        session_id=session_id,
        tool_name="database.read",
    )
    action, decision = strict_gateway.evaluate_proposal(proposal)

    assert decision.decision == PolicyDecision.DENY
    assert "RULE_TOOL_OUTSIDE_INTENT" in decision.matched_rules

    # DENY must not consume execution budget
    updated_contract = intent_service.get_intent(contract.intent_id)
    assert updated_contract is not None
    assert updated_contract.tool_calls_count == 0


def test_explicitly_denied_tool(
    strict_gateway: AgentGateway, intent_service: IntentService
) -> None:
    """Verify explicitly blacklisted tool is DENIED."""
    session_id = "sess-explicit-deny"
    intent_service.create_intent(
        IntentContractCreate(
            agent_id="agent-01",
            session_id=session_id,
            goal="Task",
            allowed_tools=["web.search", "system.delete_resource"],
            denied_tools=["system.delete_resource"],
        )
    )

    proposal = AgentActionProposal(
        agent_id="agent-01",
        session_id=session_id,
        tool_name="system.delete_resource",
    )
    _, decision = strict_gateway.evaluate_proposal(proposal)
    assert decision.decision == PolicyDecision.DENY
    assert "RULE_TOOL_EXPLICITLY_DENIED" in decision.matched_rules


def test_environment_outside_intent(
    strict_gateway: AgentGateway, intent_service: IntentService
) -> None:
    """Verify action targeting an unauthorized environment is DENIED."""
    session_id = "sess-env-deny"
    intent_service.create_intent(
        IntentContractCreate(
            agent_id="agent-01",
            session_id=session_id,
            goal="Local only task",
            allowed_tools=["web.search"],
            allowed_environments=[TargetEnvironment.LOCAL],
        )
    )

    proposal = AgentActionProposal(
        agent_id="agent-01",
        session_id=session_id,
        tool_name="web.search",
        target_environment=TargetEnvironment.PRODUCTION,
    )
    _, decision = strict_gateway.evaluate_proposal(proposal)
    assert decision.decision == PolicyDecision.DENY
    assert "RULE_ENVIRONMENT_OUTSIDE_INTENT" in decision.matched_rules


def test_data_scope_violation(strict_gateway: AgentGateway, intent_service: IntentService) -> None:
    """Verify action processing data above authorized sensitivity is DENIED."""
    session_id = "sess-data-deny"
    intent_service.create_intent(
        IntentContractCreate(
            agent_id="agent-01",
            session_id=session_id,
            goal="Public data task",
            allowed_tools=["web.search"],
            allowed_data_classifications=[DataClassification.PUBLIC],
        )
    )

    proposal = AgentActionProposal(
        agent_id="agent-01",
        session_id=session_id,
        tool_name="web.search",
        data_classifications=[DataClassification.CONFIDENTIAL],
    )
    _, decision = strict_gateway.evaluate_proposal(proposal)
    assert decision.decision == PolicyDecision.DENY
    assert "RULE_DATA_SCOPE_VIOLATION" in decision.matched_rules


def test_tool_requiring_approval_does_not_consume_budget(
    strict_gateway: AgentGateway, intent_service: IntentService
) -> None:
    """Verify REQUIRE_APPROVAL decision does not consume execution budget."""
    session_id = "sess-approval"
    contract = intent_service.create_intent(
        IntentContractCreate(
            agent_id="agent-01",
            session_id=session_id,
            goal="Task with approval",
            allowed_tools=["external.http_post"],
            requires_approval=["external.http_post"],
            maximum_tool_calls=5,
        )
    )

    proposal = AgentActionProposal(
        agent_id="agent-01",
        session_id=session_id,
        tool_name="external.http_post",
    )
    _, decision = strict_gateway.evaluate_proposal(proposal)
    assert decision.decision == PolicyDecision.REQUIRE_APPROVAL
    assert "RULE_APPROVAL_TOOL" in decision.matched_rules

    # REQUIRE_APPROVAL does not consume execution budget slot
    updated_contract = intent_service.get_intent(contract.intent_id)
    assert updated_contract is not None
    assert updated_contract.tool_calls_count == 0


def test_expired_and_revoked_contracts_denied(
    strict_gateway: AgentGateway, intent_service: IntentService
) -> None:
    """Verify expired and revoked contracts deny actions."""
    # Expired
    sess_exp = "sess-exp"
    past = datetime.now(UTC) - timedelta(minutes=5)
    intent_service.create_intent(
        IntentContractCreate(
            agent_id="agent-01",
            session_id=sess_exp,
            goal="Expired",
            allowed_tools=["web.search"],
            expires_at=past,
        )
    )
    _, dec_exp = strict_gateway.evaluate_proposal(
        AgentActionProposal(agent_id="agent-01", session_id=sess_exp, tool_name="web.search")
    )
    assert dec_exp.decision == PolicyDecision.DENY
    assert "RULE_INTENT_EXPIRED" in dec_exp.matched_rules

    # Revoked
    sess_rev = "sess-rev"
    c_rev = intent_service.create_intent(
        IntentContractCreate(
            agent_id="agent-01",
            session_id=sess_rev,
            goal="Revoked",
            allowed_tools=["web.search"],
        )
    )
    intent_service.revoke_intent(c_rev.intent_id)
    _, dec_rev = strict_gateway.evaluate_proposal(
        AgentActionProposal(agent_id="agent-01", session_id=sess_rev, tool_name="web.search")
    )
    assert dec_rev.decision == PolicyDecision.DENY
    assert "RULE_INTENT_REVOKED" in dec_rev.matched_rules


def test_contract_cannot_be_borrowed_by_another_session_or_agent(
    strict_gateway: AgentGateway, intent_service: IntentService
) -> None:
    """Verify that an arbitrary contract ID cannot be borrowed across session or agent boundaries."""
    contract = intent_service.create_intent(
        IntentContractCreate(
            agent_id="agent-legit",
            session_id="session-legit",
            goal="Legit task",
            allowed_tools=["web.search"],
        )
    )

    # Different session attempts to claim contract ID
    prop_other_session = AgentActionProposal(
        agent_id="agent-legit",
        session_id="session-attacker",
        intent_contract_id=contract.intent_id,
        tool_name="web.search",
    )
    _, dec1 = strict_gateway.evaluate_proposal(prop_other_session)
    assert dec1.decision == PolicyDecision.DENY
    assert "RULE_INTENT_MISMATCH" in dec1.matched_rules

    # Different agent attempts to claim contract ID
    prop_other_agent = AgentActionProposal(
        agent_id="agent-attacker",
        session_id="session-legit",
        intent_contract_id=contract.intent_id,
        tool_name="web.search",
    )
    _, dec2 = strict_gateway.evaluate_proposal(prop_other_agent)
    assert dec2.decision == PolicyDecision.DENY
    assert "RULE_INTENT_MISMATCH" in dec2.matched_rules


def test_intent_allow_plus_phase1_deny_resolves_to_deny(
    strict_gateway: AgentGateway, intent_service: IntentService
) -> None:
    """Verify runtime policy overrides intent permission (Intent ALLOW + Phase 1 Rule B = DENY)."""
    session_id = "sess-precedence"
    intent_service.create_intent(
        IntentContractCreate(
            agent_id="agent-01",
            session_id=session_id,
            goal="Data export",
            allowed_tools=["external.http_post"],
            allowed_data_classifications=[DataClassification.PUBLIC, DataClassification.CREDENTIAL],
        )
    )

    proposal = AgentActionProposal(
        agent_id="agent-01",
        session_id=session_id,
        tool_name="external.http_post",
        data_classifications=[DataClassification.CREDENTIAL],
    )
    _, decision = strict_gateway.evaluate_proposal(proposal)

    # Runtime policy MUST deny credential external exfiltration even if intent allowed the tool
    assert decision.decision == PolicyDecision.DENY
    assert "RULE_B_CREDENTIAL_EXTERNAL_EXFILTRATION" in decision.matched_rules


def test_causal_graph_records_intent_node_and_governs_edge(
    strict_gateway: AgentGateway,
    intent_service: IntentService,
    graph_manager: SessionGraphManager,
) -> None:
    """Verify graph integration: Intent node exists, governs edge links intent -> action, and denied action remains."""
    session_id = "sess-graph-test"
    contract = intent_service.create_intent(
        IntentContractCreate(
            agent_id="agent-01",
            session_id=session_id,
            goal="Graph verification task",
            allowed_tools=["web.search"],
        )
    )

    # Denied action (out of scope tool)
    proposal = AgentActionProposal(
        agent_id="agent-01",
        session_id=session_id,
        tool_name="database.read",
    )
    action, decision = strict_gateway.evaluate_proposal(proposal)
    assert decision.decision == PolicyDecision.DENY

    graph = graph_manager.get(session_id)
    assert graph is not None
    graph_data = graph.get_session_graph()

    # Intent node exists
    intent_nodes = [n for n in graph_data["nodes"] if n["node_type"] == "intent"]
    assert len(intent_nodes) == 1
    assert intent_nodes[0]["id"] == str(contract.intent_id)
    assert intent_nodes[0]["goal"] == "Graph verification task"

    # Action node exists and is recorded as DENIED
    action_nodes = [n for n in graph_data["nodes"] if n["node_type"] == "action"]
    assert len(action_nodes) == 1
    assert action_nodes[0]["id"] == str(action.action_id)
    assert action_nodes[0]["execution_status"] == "DENIED"

    # Governs edge exists: Intent -> Action
    governs_edges = [
        e
        for e in graph_data["edges"]
        if e["source"] == str(contract.intent_id) and e["target"] == str(action.action_id)
    ]
    assert len(governs_edges) == 1
    assert governs_edges[0]["relation"] == "governs"


def test_deny_does_not_consume_execution_budget(
    strict_gateway: AgentGateway, intent_service: IntentService
) -> None:
    """Verify DENY decisions never consume execution budget."""
    session_id = "sess-deny-budget"
    contract = intent_service.create_intent(
        IntentContractCreate(
            agent_id="agent-01",
            session_id=session_id,
            goal="Budget test",
            allowed_tools=["web.search"],
            maximum_tool_calls=5,
        )
    )

    # Propose unauthorized tool call
    proposal = AgentActionProposal(
        agent_id="agent-01",
        session_id=session_id,
        tool_name="database.write",
    )
    _, decision = strict_gateway.evaluate_proposal(proposal)
    assert decision.decision == PolicyDecision.DENY

    updated = intent_service.get_intent(contract.intent_id)
    assert updated is not None
    assert updated.tool_calls_count == 0


def test_allow_consumes_exactly_one_execution_slot(
    strict_gateway: AgentGateway, intent_service: IntentService
) -> None:
    """Verify ALLOW decisions atomically consume exactly one execution slot."""
    session_id = "sess-allow-budget"
    contract = intent_service.create_intent(
        IntentContractCreate(
            agent_id="agent-01",
            session_id=session_id,
            goal="Budget test",
            allowed_tools=["web.search"],
            maximum_tool_calls=3,
        )
    )

    # First allowed call
    proposal1 = AgentActionProposal(
        agent_id="agent-01",
        session_id=session_id,
        tool_name="web.search",
    )
    _, decision1 = strict_gateway.evaluate_proposal(proposal1)
    assert decision1.decision == PolicyDecision.ALLOW

    updated1 = intent_service.get_intent(contract.intent_id)
    assert updated1 is not None
    assert updated1.tool_calls_count == 1

    # Second allowed call
    proposal2 = AgentActionProposal(
        agent_id="agent-01",
        session_id=session_id,
        tool_name="web.search",
    )
    _, decision2 = strict_gateway.evaluate_proposal(proposal2)
    assert decision2.decision == PolicyDecision.ALLOW

    updated2 = intent_service.get_intent(contract.intent_id)
    assert updated2 is not None
    assert updated2.tool_calls_count == 2


def test_security_decision_uses_authoritative_intent_contract_id(
    strict_gateway: AgentGateway, intent_service: IntentService
) -> None:
    """Verify SecurityDecision assigns authoritative intent_contract_id and does not echo unvalidated client values."""
    session_id = "sess-authoritative-id"
    contract = intent_service.create_intent(
        IntentContractCreate(
            agent_id="agent-01",
            session_id=session_id,
            goal="Authoritative ID test",
            allowed_tools=["web.search"],
        )
    )

    # Call with correct session and matching proposal intent_contract_id
    prop = AgentActionProposal(
        agent_id="agent-01",
        session_id=session_id,
        intent_contract_id=str(contract.intent_id),
        tool_name="web.search",
    )
    _, decision = strict_gateway.evaluate_proposal(prop)
    assert decision.intent_contract_id == contract.intent_id

    # Call without intent_contract_id supplied by client
    prop_no_id = AgentActionProposal(
        agent_id="agent-01",
        session_id=session_id,
        tool_name="web.search",
    )
    _, decision_no_id = strict_gateway.evaluate_proposal(prop_no_id)
    assert decision_no_id.intent_contract_id == contract.intent_id
