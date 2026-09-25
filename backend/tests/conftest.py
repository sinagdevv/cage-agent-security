"""Pytest configuration and fixtures for CAGE tests."""

from uuid import UUID

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture
def client() -> TestClient:
    """Fixture providing a test client for FastAPI application."""
    return TestClient(app)


@pytest.fixture(autouse=True)
def mock_opa_for_unit_tests(
    monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest
) -> None:
    """Mock OPA client for standard unit tests so tests do not fail when Docker OPA is offline.

    Tests marked with @pytest.mark.opa or tests in test_opa_client / test_policy_parity manage
    their own live connection or specific error mocks.
    """
    if "opa" in request.keywords:
        return

    node_id = request.node.nodeid
    if "test_opa_client" in node_id or "test_policy_parity" in node_id:
        return

    from app.gateway.registry import default_tool_registry
    from app.policies.intent_rules import default_intent_rules_evaluator
    from app.policies.opa_client import default_opa_client
    from app.schemas.action import AgentAction
    from app.schemas.enums import (
        ActionType,
        DataClassification,
        IntentStatus,
        OpaStatus,
        TargetEnvironment,
        TrustLevel,
    )
    from app.schemas.intent import IntentContract
    from app.schemas.policy import CagePolicyInput, OpaEvaluationResult, OpaFinding

    def local_evaluate_adapter(policy_input: CagePolicyInput) -> OpaEvaluationResult:
        # Reconstruct normalized action from policy input
        action = AgentAction(
            action_id=UUID(policy_input.action.action_id),
            agent_id=policy_input.agent.agent_id,
            session_id=policy_input.agent.session_id,
            tool_name=policy_input.action.tool_name,
            action_type=ActionType(policy_input.action.action_type),
            target_resource=policy_input.action.target_resource,
            target_environment=TargetEnvironment(policy_input.action.target_environment),
            data_classifications=[
                DataClassification(c) for c in policy_input.data.effective_classifications
            ],
            input_trust_level=TrustLevel.MEDIUM,
        )

        contract: IntentContract | None = None
        if policy_input.intent is not None:
            contract = IntentContract(
                intent_id=UUID(policy_input.intent.intent_id),
                agent_id=policy_input.agent.agent_id,
                session_id=policy_input.agent.session_id,
                goal="Unit test intent",
                status=IntentStatus(policy_input.intent.status),
                allowed_tools=frozenset(policy_input.intent.allowed_tools),
                denied_tools=frozenset(policy_input.intent.denied_tools),
                allowed_environments=frozenset(
                    [TargetEnvironment(e) for e in policy_input.intent.allowed_environments]
                ),
                allowed_resources=frozenset(policy_input.intent.allowed_resources),
                denied_resources=frozenset(policy_input.intent.denied_resources),
                allowed_data_classifications=frozenset(
                    [
                        DataClassification(c)
                        for c in policy_input.intent.allowed_data_classifications
                    ]
                ),
                requires_approval=frozenset(policy_input.intent.requires_approval),
                maximum_tool_calls=policy_input.intent.maximum_tool_calls,
                tool_calls_count=policy_input.intent.tool_calls_count,
            )

        # Evaluate rules
        intent_matches = default_intent_rules_evaluator.evaluate_intent(
            action=action,
            contract=contract,
            require_intent=policy_input.context.require_intent,
            intent_mismatch=policy_input.context.intent_mismatch,
        )

        # Also evaluate runtime rules
        tool_spec = default_tool_registry.get(action.tool_name)
        runtime_matches = []
        if action.target_environment == TargetEnvironment.PRODUCTION and (
            tool_spec.destructive or action.action_type == ActionType.DESTRUCTIVE
        ):
            from app.policies.rules import MatchedRule, PolicyDecision

            runtime_matches.append(
                MatchedRule(
                    rule_id="RULE_A_PRODUCTION_DESTRUCTIVE",
                    decision=PolicyDecision.REQUIRE_APPROVAL,
                    reason="Production destructive",
                    risk_score=0.75,
                )
            )

        effective_classes = set(action.data_classifications)
        if tool_spec.external_sink and (
            DataClassification.SECRET in effective_classes
            or DataClassification.CREDENTIAL in effective_classes
        ):
            from app.policies.rules import MatchedRule, PolicyDecision

            runtime_matches.append(
                MatchedRule(
                    rule_id="RULE_B_CREDENTIAL_EXTERNAL_EXFILTRATION",
                    decision=PolicyDecision.DENY,
                    reason="Credential exfiltration",
                    risk_score=0.90,
                )
            )

        all_matches = intent_matches + runtime_matches
        if not all_matches:
            from app.policies.rules import MatchedRule, PolicyDecision

            all_matches.append(
                MatchedRule(
                    rule_id="RULE_D_NORMAL_LOW_RISK",
                    decision=PolicyDecision.ALLOW,
                    reason="Low risk baseline",
                    risk_score=0.10,
                )
            )

        findings = [
            OpaFinding(
                rule_id=m.rule_id,
                decision=m.decision,
                reason=m.reason,
                risk_score=m.risk_score,
            )
            for m in all_matches
        ]

        return OpaEvaluationResult(
            status=OpaStatus.SUCCESS,
            findings=findings,
        )

    monkeypatch.setattr(default_opa_client, "evaluate", local_evaluate_adapter)
    monkeypatch.setattr(default_opa_client, "check_health", lambda: True)
