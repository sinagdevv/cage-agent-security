"""Unit tests for PolicyParityResult, PolicyEngine orchestration, and health semantics."""

from unittest.mock import MagicMock
from uuid import uuid4

import pytest

from app.gateway.registry import default_tool_registry
from app.policies.engine import PolicyEngine
from app.policies.opa_client import OpaClient
from app.policies.parity import compare_policy_parity
from app.policies.policy_input import build_cage_policy_input
from app.policies.rules import DeterministicPolicyEvaluator
from app.schemas.action import AgentAction
from app.schemas.decision import SecurityDecision
from app.schemas.enums import (
    ActionType,
    OpaStatus,
    PolicyBackend,
    PolicyDecision,
    PolicyParityStatus,
    TargetEnvironment,
    TrustLevel,
)
from app.schemas.policy import OpaEvaluationResult, OpaFinding


def test_parity_decision_match_and_rule_match() -> None:
    """Verify exact match when both decisions and rule IDs are identical."""
    opa_res = OpaEvaluationResult(
        status=OpaStatus.SUCCESS,
        findings=[
            OpaFinding(
                rule_id="RULE_INTENT_ALLOW",
                decision=PolicyDecision.ALLOW,
                reason="OK",
                risk_score=0.1,
            )
        ],
    )
    result = compare_policy_parity(
        python_decision=PolicyDecision.ALLOW,
        opa_decision=PolicyDecision.ALLOW,
        python_rules=["RULE_INTENT_ALLOW"],
        opa_rules=["RULE_INTENT_ALLOW"],
        opa_result=opa_res,
    )

    assert result.status == PolicyParityStatus.MATCH
    assert result.decision_match is True
    assert result.rule_match is True
    assert result.missing_in_opa == []
    assert result.extra_in_opa == []


def test_parity_identical_decision_different_rules_produces_divergence() -> None:
    """Verify that identical verdicts with differing rule IDs produce DIVERGENCE."""
    opa_res = OpaEvaluationResult(
        status=OpaStatus.SUCCESS,
        findings=[
            OpaFinding(
                rule_id="RULE_TOOL_OUTSIDE_INTENT",
                decision=PolicyDecision.DENY,
                reason="Outside intent",
                risk_score=0.85,
            )
        ],
    )
    # Python denied due to exfiltration, OPA denied due to tool scope
    result = compare_policy_parity(
        python_decision=PolicyDecision.DENY,
        opa_decision=PolicyDecision.DENY,
        python_rules=["RULE_B_CREDENTIAL_EXTERNAL_EXFILTRATION"],
        opa_rules=["RULE_TOOL_OUTSIDE_INTENT"],
        opa_result=opa_res,
    )

    assert result.status == PolicyParityStatus.DIVERGENCE
    assert result.decision_match is True
    assert result.rule_match is False
    assert result.missing_in_opa == ["RULE_B_CREDENTIAL_EXTERNAL_EXFILTRATION"]
    assert result.extra_in_opa == ["RULE_TOOL_OUTSIDE_INTENT"]


def test_parity_ignores_control_plane_infrastructure_rules() -> None:
    """Verify infrastructure control-plane rules do not pollute semantic rule comparison."""
    opa_res = OpaEvaluationResult(
        status=OpaStatus.SUCCESS,
        findings=[
            OpaFinding(
                rule_id="RULE_INTENT_ALLOW",
                decision=PolicyDecision.ALLOW,
                reason="OK",
                risk_score=0.1,
            )
        ],
    )
    # Python rule list has an infrastructure rule
    result = compare_policy_parity(
        python_decision=PolicyDecision.ALLOW,
        opa_decision=PolicyDecision.ALLOW,
        python_rules=["RULE_INTENT_ALLOW", "RULE_NO_RULES_MATCHED"],
        opa_rules=["RULE_INTENT_ALLOW"],
        opa_result=opa_res,
    )

    assert result.status == PolicyParityStatus.MATCH
    assert result.rule_match is True
    assert result.missing_in_opa == []


def test_shadow_mode_semantic_divergence_keeps_python_enforcement() -> None:
    """Verify that in SHADOW mode, semantic divergence leaves Python as the sole enforcement authority."""
    mock_opa = MagicMock(spec=OpaClient)
    # OPA says ALLOW
    mock_opa.evaluate.return_value = OpaEvaluationResult(
        status=OpaStatus.SUCCESS,
        findings=[
            OpaFinding(
                rule_id="RULE_INTENT_ALLOW",
                decision=PolicyDecision.ALLOW,
                reason="Conforms to intent",
                risk_score=0.1,
            )
        ],
    )

    # Python evaluator says DENY
    mock_py = MagicMock(spec=DeterministicPolicyEvaluator)

    action = AgentAction(
        action_id=uuid4(),
        agent_id="test-agent",
        session_id="test-sess",
        tool_name="database.write",
        action_type=ActionType.TOOL_CALL,
        target_environment=TargetEnvironment.DEVELOPMENT,
        input_trust_level=TrustLevel.MEDIUM,
    )
    policy_input = build_cage_policy_input(
        action=action, contract=None, tool_registry=default_tool_registry, require_intent=False
    )

    py_decision = SecurityDecision(
        action_id=action.action_id,
        session_id=action.session_id,
        decision=PolicyDecision.DENY,
        reason="Python denied action",
        matched_rules=["RULE_TEST_DENY"],
        risk_score=0.9,
    )
    mock_py.evaluate.return_value = py_decision

    engine = PolicyEngine(
        opa_client=mock_opa,
        python_evaluator=mock_py,
        backend=PolicyBackend.SHADOW,
    )

    final_decision, parity = engine.evaluate(policy_input, action, contract=None)

    # In SHADOW mode, Python remains authoritative
    assert final_decision.decision == PolicyDecision.DENY
    assert "RULE_TEST_DENY" in final_decision.matched_rules
    assert final_decision.policy_backend == PolicyBackend.SHADOW
    assert parity is not None
    assert parity.status == PolicyParityStatus.DIVERGENCE
    assert parity.decision_match is False


def test_shadow_mode_opa_infrastructure_failure_blocks_execution() -> None:
    """Verify that in SHADOW mode, OPA infrastructure failure fails-closed to protect runtime."""
    mock_opa = MagicMock(spec=OpaClient)
    mock_opa.evaluate.return_value = OpaEvaluationResult(
        status=OpaStatus.UNAVAILABLE,
        findings=[],
        error_reason="Connection refused at http://opa:8181",
    )

    mock_py = MagicMock(spec=DeterministicPolicyEvaluator)
    action = AgentAction(
        action_id=uuid4(),
        agent_id="test-agent",
        session_id="test-sess",
        tool_name="web.search",
        action_type=ActionType.TOOL_CALL,
        target_environment=TargetEnvironment.DEVELOPMENT,
        input_trust_level=TrustLevel.MEDIUM,
    )
    policy_input = build_cage_policy_input(
        action=action, contract=None, tool_registry=default_tool_registry, require_intent=False
    )

    # Even if Python says ALLOW, infrastructure failure must block execution
    py_decision = SecurityDecision(
        action_id=action.action_id,
        session_id=action.session_id,
        decision=PolicyDecision.ALLOW,
        reason="Low risk",
        matched_rules=["RULE_D_NORMAL_LOW_RISK"],
        risk_score=0.1,
    )
    mock_py.evaluate.return_value = py_decision

    engine = PolicyEngine(
        opa_client=mock_opa,
        python_evaluator=mock_py,
        backend=PolicyBackend.SHADOW,
    )

    final_decision, parity = engine.evaluate(policy_input, action, contract=None)

    assert final_decision.decision == PolicyDecision.DENY
    assert "RULE_POLICY_ENGINE_UNAVAILABLE" in final_decision.matched_rules
    assert parity is not None
    assert parity.status == PolicyParityStatus.OPA_ERROR


@pytest.mark.asyncio
async def test_health_endpoint_mode_semantics(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify health endpoint accurately reflects policy backend requirements and OPA liveness."""
    from app.api.v1.health import health_check
    from app.core.config import settings
    from app.policies.opa_client import default_opa_client

    # 1. PYTHON backend: OPA unreachable does NOT make backend unhealthy
    monkeypatch.setattr(settings, "policy_backend", "PYTHON")
    monkeypatch.setattr(default_opa_client, "check_health", lambda: False)
    resp_python = await health_check()
    assert resp_python.status == "ok"
    assert resp_python.policy_engine is not None
    assert resp_python.policy_engine.status == "healthy"
    assert resp_python.policy_engine.opa_required is False

    # 2. SHADOW backend: OPA unreachable degrades health
    monkeypatch.setattr(settings, "policy_backend", "SHADOW")
    monkeypatch.setattr(default_opa_client, "check_health", lambda: False)
    resp_shadow = await health_check()
    assert resp_shadow.status == "degraded"
    assert resp_shadow.policy_engine is not None
    assert resp_shadow.policy_engine.status == "degraded"
    assert resp_shadow.policy_engine.opa_required is True

    # 3. OPA backend: OPA unreachable makes backend unhealthy
    monkeypatch.setattr(settings, "policy_backend", "OPA")
    monkeypatch.setattr(default_opa_client, "check_health", lambda: False)
    resp_opa = await health_check()
    assert resp_opa.status == "unhealthy"
    assert resp_opa.policy_engine is not None
    assert resp_opa.policy_engine.status == "unhealthy"
    assert resp_opa.policy_engine.opa_required is True

    # 4. OPA reachable: all backends report healthy/ok
    monkeypatch.setattr(default_opa_client, "check_health", lambda: True)
    resp_healthy = await health_check()
    assert resp_healthy.status == "ok"
    assert resp_healthy.policy_engine is not None
    assert resp_healthy.policy_engine.status == "healthy"
