"""Parity integration tests comparing Python and live OPA evaluation for Phase 8 delegation rules."""

from uuid import uuid4

import pytest

from app.policies.opa_client import OpaClient
from app.policies.policy_input import build_cage_policy_input
from app.policies.rules import DeterministicPolicyEvaluator
from app.schemas.action import AgentAction
from app.schemas.enums import (
    ActionType,
    DataClassification,
    OpaStatus,
    TargetEnvironment,
)
from app.schemas.intent import IntentContract
from app.schemas.policy import PolicyDelegationContext


@pytest.fixture
def live_opa_client():
    client = OpaClient()
    if not client.check_health():
        pytest.skip(f"Live OPA container not reachable at {client.opa_url}")
    return client


def _create_base_action_and_intent():
    session_id = uuid4()
    intent = IntentContract(
        intent_id=uuid4(),
        session_id=str(session_id),
        agent_id="root-agent",
        user_id="user-1",
        goal="Parity test",
        allowed_tools=["web.search", "db.read"],
        allowed_environments=[TargetEnvironment.DEVELOPMENT],
        allowed_resources=["res://1"],
        allowed_data_classifications=[DataClassification.PUBLIC],
        maximum_tool_calls=10,
    )
    action = AgentAction(
        action_id=uuid4(),
        agent_id="worker-agent",
        session_id=str(session_id),
        tool_name="web.search",
        action_type=ActionType.TOOL_CALL,
        target_environment=TargetEnvironment.DEVELOPMENT,
        data_classifications=[DataClassification.PUBLIC],
    )
    return action, intent


@pytest.mark.opa
def test_delegation_create_parity_caller_not_authorized(live_opa_client: OpaClient):
    """Verify parity for RULE_DELEGATION_CALLER_NOT_AUTHORIZED."""
    action, intent = _create_base_action_and_intent()
    deleg_ctx = PolicyDelegationContext(
        operation="CREATE_GRANT",
        is_delegated=True,
        caller_is_authorized_issuer=False,
    )
    policy_input = build_cage_policy_input(action, contract=intent, delegation_context=deleg_ctx)

    evaluator = DeterministicPolicyEvaluator()
    py_decision = evaluator.evaluate(action, contract=intent, delegation_context=deleg_ctx)
    opa_result = live_opa_client.evaluate(policy_input)

    assert opa_result.status == OpaStatus.SUCCESS
    opa_rules = [f.rule_id for f in opa_result.findings]
    assert "RULE_DELEGATION_CALLER_NOT_AUTHORIZED" in opa_rules
    assert "RULE_DELEGATION_CALLER_NOT_AUTHORIZED" in py_decision.matched_rules


@pytest.mark.opa
def test_delegation_execute_parity_revoked_grant(live_opa_client: OpaClient):
    """Verify parity for RULE_DELEGATION_REVOKED."""
    action, intent = _create_base_action_and_intent()
    deleg_ctx = PolicyDelegationContext(
        operation="EXECUTE_ACTION",
        is_delegated=True,
        principal_matches_delegatee=True,
        effective_status="REVOKED",
        current_tool_within_effective_authority=True,
    )
    policy_input = build_cage_policy_input(action, contract=intent, delegation_context=deleg_ctx)

    evaluator = DeterministicPolicyEvaluator()
    py_decision = evaluator.evaluate(action, contract=intent, delegation_context=deleg_ctx)
    opa_result = live_opa_client.evaluate(policy_input)

    assert opa_result.status == OpaStatus.SUCCESS
    opa_rules = [f.rule_id for f in opa_result.findings]
    assert "RULE_DELEGATION_REVOKED" in opa_rules
    assert "RULE_DELEGATION_REVOKED" in py_decision.matched_rules


@pytest.mark.opa
def test_delegation_execute_parity_tool_not_authorized(live_opa_client: OpaClient):
    """Verify parity for RULE_DELEGATION_TOOL_NOT_AUTHORIZED."""
    action, intent = _create_base_action_and_intent()
    deleg_ctx = PolicyDelegationContext(
        operation="EXECUTE_ACTION",
        is_delegated=True,
        principal_matches_delegatee=True,
        effective_status="ACTIVE",
        current_tool_within_effective_authority=False,
    )
    policy_input = build_cage_policy_input(action, contract=intent, delegation_context=deleg_ctx)

    evaluator = DeterministicPolicyEvaluator()
    py_decision = evaluator.evaluate(action, contract=intent, delegation_context=deleg_ctx)
    opa_result = live_opa_client.evaluate(policy_input)

    assert opa_result.status == OpaStatus.SUCCESS
    opa_rules = [f.rule_id for f in opa_result.findings]
    assert "RULE_DELEGATION_TOOL_NOT_AUTHORIZED" in opa_rules
    assert "RULE_DELEGATION_TOOL_NOT_AUTHORIZED" in py_decision.matched_rules
