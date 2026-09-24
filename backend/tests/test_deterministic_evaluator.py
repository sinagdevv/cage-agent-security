"""Tests for deterministic policy rules and precedence resolution."""

from app.gateway.registry import ToolRegistry, ToolSpec
from app.policies.rules import DeterministicPolicyEvaluator
from app.schemas.action import AgentAction, AgentActionProposal
from app.schemas.enums import (
    ActionType,
    DataClassification,
    PolicyDecision,
    TargetEnvironment,
)


def create_action(**kwargs) -> AgentAction:
    defaults = {
        "agent_id": "test-agent",
        "session_id": "sess-eval",
        "tool_name": "web.search",
        "action_type": ActionType.TOOL_CALL,
        "target_environment": TargetEnvironment.DEVELOPMENT,
    }
    defaults.update(kwargs)
    proposal = AgentActionProposal(**defaults)
    return AgentAction.from_proposal(proposal)


def test_rule_d_normal_low_risk_allow() -> None:
    """Verify that a benign tool call receives ALLOW."""
    evaluator = DeterministicPolicyEvaluator()
    action = create_action(
        tool_name="web.search",
        data_classifications=[DataClassification.PUBLIC],
        target_environment=TargetEnvironment.LOCAL,
    )
    decision = evaluator.evaluate(action)
    assert decision.decision == PolicyDecision.ALLOW
    assert "RULE_D_NORMAL_LOW_RISK" in decision.matched_rules
    assert decision.requires_human_approval is False


def test_rule_a_production_destructive_requires_approval() -> None:
    """Verify that a destructive action targeting PRODUCTION requires human approval."""
    evaluator = DeterministicPolicyEvaluator()
    action = create_action(
        tool_name="system.delete_resource",
        target_environment=TargetEnvironment.PRODUCTION,
        action_type=ActionType.DESTRUCTIVE,
    )
    decision = evaluator.evaluate(action)
    assert decision.decision == PolicyDecision.REQUIRE_APPROVAL
    assert "RULE_A_PRODUCTION_DESTRUCTIVE" in decision.matched_rules
    assert decision.requires_human_approval is True


def test_rule_b_credential_external_exfiltration_denied() -> None:
    """Verify that transmitting CREDENTIAL/SECRET to an external sink is DENIED."""
    evaluator = DeterministicPolicyEvaluator()
    action = create_action(
        tool_name="external.http_post",
        data_classifications=[DataClassification.CREDENTIAL],
        target_environment=TargetEnvironment.DEVELOPMENT,
    )
    decision = evaluator.evaluate(action)
    assert decision.decision == PolicyDecision.DENY
    assert "RULE_B_CREDENTIAL_EXTERNAL_EXFILTRATION" in decision.matched_rules
    assert decision.requires_human_approval is False


def test_rule_b_secret_classification_denied() -> None:
    """Verify that SECRET data classification also triggers Rule B denial."""
    evaluator = DeterministicPolicyEvaluator()
    action = create_action(
        tool_name="external.http_post",
        data_classifications=[DataClassification.SECRET],
    )
    decision = evaluator.evaluate(action)
    assert decision.decision == PolicyDecision.DENY
    assert "RULE_B_CREDENTIAL_EXTERNAL_EXFILTRATION" in decision.matched_rules


def test_rule_c_unknown_tool_conservative_default() -> None:
    """Verify that unknown tools default conservatively and require approval."""
    evaluator = DeterministicPolicyEvaluator()
    action = create_action(
        tool_name="custom.unregistered_shell",
        action_type=ActionType.EXECUTE,
    )
    decision = evaluator.evaluate(action)
    assert decision.decision == PolicyDecision.REQUIRE_APPROVAL
    assert "RULE_C_UNKNOWN_TOOL_PRIVILEGED" in decision.matched_rules


def test_precedence_deny_overrides_require_approval() -> None:
    """Verify that when both Rule A (REQUIRE_APPROVAL) and Rule B (DENY) match, DENY wins."""
    # Custom registry tool that is both destructive and external sink
    custom_registry = ToolRegistry()
    custom_registry.register(
        ToolSpec(
            name="exfil_and_wipe",
            known=True,
            privileged=True,
            destructive=True,
            external_sink=True,
        )
    )
    evaluator = DeterministicPolicyEvaluator(tool_registry=custom_registry)

    # Action targeting PRODUCTION with destructive tool AND CREDENTIAL data
    action = create_action(
        tool_name="exfil_and_wipe",
        target_environment=TargetEnvironment.PRODUCTION,
        action_type=ActionType.DESTRUCTIVE,
        data_classifications=[DataClassification.CREDENTIAL],
    )

    decision = evaluator.evaluate(action)
    assert "RULE_A_PRODUCTION_DESTRUCTIVE" in decision.matched_rules
    assert "RULE_B_CREDENTIAL_EXTERNAL_EXFILTRATION" in decision.matched_rules
    # Strict precedence check: DENY must be the resolved decision
    assert decision.decision == PolicyDecision.DENY


def test_expected_effect_cannot_trick_destructive_classification() -> None:
    """Verify that agent-supplied expected_effect cannot bypass destructive classification."""
    evaluator = DeterministicPolicyEvaluator()
    action = create_action(
        tool_name="system.delete_resource",
        target_environment=TargetEnvironment.PRODUCTION,
        expected_effect="Completely safe harmless read-only inspection",  # Adversarial claim
    )
    decision = evaluator.evaluate(action)
    # The trusted registry identifies system.delete_resource as destructive
    assert decision.decision == PolicyDecision.REQUIRE_APPROVAL
    assert "RULE_A_PRODUCTION_DESTRUCTIVE" in decision.matched_rules


def test_external_destination_from_trusted_registry() -> None:
    """Verify external sink status is governed by registry, not target_resource text."""
    evaluator = DeterministicPolicyEvaluator()
    # Benign tool with external looking resource string should NOT be classified as external sink
    action = create_action(
        tool_name="web.search",
        target_resource="https://external.destination.com/api",
        data_classifications=[DataClassification.CREDENTIAL],
    )
    decision = evaluator.evaluate(action)
    # web.search has external_sink=False in trusted registry
    assert decision.decision == PolicyDecision.ALLOW
    assert "RULE_B_CREDENTIAL_EXTERNAL_EXFILTRATION" not in decision.matched_rules
