"""Integration tests evaluating Rego policies against a live running OPA container.

Marked with @pytest.mark.opa so standard local unit tests run with mocked/offline adapters.
Run via: pytest -m opa
"""

from uuid import uuid4

import pytest

from app.gateway.registry import ToolRegistry, ToolSpec
from app.policies.opa_client import OpaClient
from app.policies.policy_input import build_cage_policy_input
from app.schemas.action import AgentAction
from app.schemas.enums import (
    ActionType,
    DataClassification,
    OpaStatus,
    PolicyDecision,
    TargetEnvironment,
    TrustLevel,
)
from app.schemas.intent import IntentContract, IntentContractCreate


@pytest.fixture
def live_opa_client():
    client = OpaClient()
    if not client.check_health():
        pytest.skip(f"Live OPA container not reachable at {client.opa_url}")
    return client


@pytest.mark.opa
def test_live_rego_intent_allow(live_opa_client: OpaClient) -> None:
    """Verify live OPA evaluates conforming action to RULE_INTENT_ALLOW."""
    action = AgentAction(
        action_id=uuid4(),
        agent_id="agent-01",
        session_id="session-live-1",
        tool_name="web.search",
        action_type=ActionType.TOOL_CALL,
        target_environment=TargetEnvironment.DEVELOPMENT,
        data_classifications=[DataClassification.PUBLIC],
        input_trust_level=TrustLevel.MEDIUM,
    )
    contract = IntentContract.from_create(
        IntentContractCreate(
            agent_id="agent-01",
            session_id="session-live-1",
            goal="Research",
            allowed_tools=["web.search"],
            allowed_environments=[TargetEnvironment.DEVELOPMENT],
            allowed_data_classifications=[DataClassification.PUBLIC],
        )
    )
    policy_input = build_cage_policy_input(action, contract=contract)
    res = live_opa_client.evaluate(policy_input)

    assert res.status == OpaStatus.SUCCESS
    rule_ids = [f.rule_id for f in res.findings]
    assert "RULE_INTENT_ALLOW" in rule_ids
    assert all(f.decision == PolicyDecision.ALLOW for f in res.findings)


@pytest.mark.opa
def test_live_rego_tool_outside_intent(live_opa_client: OpaClient) -> None:
    """Verify live OPA produces RULE_TOOL_OUTSIDE_INTENT for unauthorized tool."""
    action = AgentAction(
        action_id=uuid4(),
        agent_id="agent-01",
        session_id="session-live-2",
        tool_name="database.read",
        action_type=ActionType.TOOL_CALL,
        target_environment=TargetEnvironment.DEVELOPMENT,
        input_trust_level=TrustLevel.MEDIUM,
    )
    contract = IntentContract.from_create(
        IntentContractCreate(
            agent_id="agent-01",
            session_id="session-live-2",
            goal="Research",
            allowed_tools=["web.search"],
        )
    )
    policy_input = build_cage_policy_input(action, contract=contract)
    res = live_opa_client.evaluate(policy_input)

    assert res.status == OpaStatus.SUCCESS
    rule_ids = [f.rule_id for f in res.findings]
    assert "RULE_TOOL_OUTSIDE_INTENT" in rule_ids


@pytest.mark.opa
def test_live_rego_approval_tool(live_opa_client: OpaClient) -> None:
    """Verify live OPA produces RULE_APPROVAL_TOOL."""
    action = AgentAction(
        action_id=uuid4(),
        agent_id="agent-01",
        session_id="session-live-3",
        tool_name="external.http_post",
        action_type=ActionType.TOOL_CALL,
        target_environment=TargetEnvironment.DEVELOPMENT,
        input_trust_level=TrustLevel.MEDIUM,
    )
    contract = IntentContract.from_create(
        IntentContractCreate(
            agent_id="agent-01",
            session_id="session-live-3",
            goal="Dispatch webhook",
            allowed_tools=["external.http_post"],
            requires_approval=["external.http_post"],
        )
    )
    policy_input = build_cage_policy_input(action, contract=contract)
    res = live_opa_client.evaluate(policy_input)

    assert res.status == OpaStatus.SUCCESS
    rule_ids = [f.rule_id for f in res.findings]
    assert "RULE_APPROVAL_TOOL" in rule_ids
    approval_finding = next(f for f in res.findings if f.rule_id == "RULE_APPROVAL_TOOL")
    assert approval_finding.decision == PolicyDecision.REQUIRE_APPROVAL


@pytest.mark.opa
def test_live_rego_credential_external_exfiltration(live_opa_client: OpaClient) -> None:
    """Verify live OPA produces RULE_B_CREDENTIAL_EXTERNAL_EXFILTRATION."""
    registry = ToolRegistry()
    registry.register(
        ToolSpec(
            name="external.http_post",
            description="External HTTP sink",
            external_sink=True,
        )
    )
    action = AgentAction(
        action_id=uuid4(),
        agent_id="agent-01",
        session_id="session-live-4",
        tool_name="external.http_post",
        action_type=ActionType.TOOL_CALL,
        target_environment=TargetEnvironment.DEVELOPMENT,
        data_classifications=[DataClassification.CREDENTIAL],
        input_trust_level=TrustLevel.MEDIUM,
    )
    contract = IntentContract.from_create(
        IntentContractCreate(
            agent_id="agent-01",
            session_id="session-live-4",
            goal="Data transfer",
            allowed_tools=["external.http_post"],
            allowed_data_classifications=[DataClassification.CREDENTIAL],
        )
    )
    policy_input = build_cage_policy_input(action, contract=contract, tool_registry=registry)
    res = live_opa_client.evaluate(policy_input)

    assert res.status == OpaStatus.SUCCESS
    rule_ids = [f.rule_id for f in res.findings]
    assert "RULE_B_CREDENTIAL_EXTERNAL_EXFILTRATION" in rule_ids


@pytest.mark.opa
def test_live_rego_production_destructive(live_opa_client: OpaClient) -> None:
    """Verify live OPA produces RULE_A_PRODUCTION_DESTRUCTIVE."""
    registry = ToolRegistry()
    registry.register(
        ToolSpec(
            name="system.delete_resource",
            description="Destructive deletion",
            destructive=True,
        )
    )
    action = AgentAction(
        action_id=uuid4(),
        agent_id="agent-01",
        session_id="session-live-5",
        tool_name="system.delete_resource",
        action_type=ActionType.DESTRUCTIVE,
        target_environment=TargetEnvironment.PRODUCTION,
        input_trust_level=TrustLevel.MEDIUM,
    )
    contract = IntentContract.from_create(
        IntentContractCreate(
            agent_id="agent-01",
            session_id="session-live-5",
            goal="System cleanup",
            allowed_tools=["system.delete_resource"],
            allowed_environments=[TargetEnvironment.PRODUCTION],
        )
    )
    policy_input = build_cage_policy_input(action, contract=contract, tool_registry=registry)
    res = live_opa_client.evaluate(policy_input)

    assert res.status == OpaStatus.SUCCESS
    rule_ids = [f.rule_id for f in res.findings]
    assert "RULE_A_PRODUCTION_DESTRUCTIVE" in rule_ids
