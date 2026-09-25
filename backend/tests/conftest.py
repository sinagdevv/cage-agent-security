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
        tool_spec = getattr(policy_input, "tool", None) or default_tool_registry.get(
            action.tool_name
        )
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

        # Graph rules simulation
        graph_matches = []
        if getattr(policy_input, "graph", None) is not None:
            from app.policies.rules import MatchedRule, PolicyDecision
            from app.schemas.enums import GraphAnalysisStatus

            g = policy_input.graph
            if g.analysis_status == GraphAnalysisStatus.DEPTH_LIMIT_EXCEEDED:
                graph_matches.append(
                    MatchedRule(
                        rule_id="RULE_GRAPH_DEPTH_LIMIT_EXCEEDED",
                        decision=PolicyDecision.DENY,
                        reason="Depth limit exceeded",
                        risk_score=0.95,
                    )
                )
            elif g.analysis_status == GraphAnalysisStatus.NODE_LIMIT_EXCEEDED:
                graph_matches.append(
                    MatchedRule(
                        rule_id="RULE_GRAPH_NODE_LIMIT_EXCEEDED",
                        decision=PolicyDecision.DENY,
                        reason="Node limit exceeded",
                        risk_score=0.95,
                    )
                )
            elif g.analysis_status in (
                GraphAnalysisStatus.INVALID_GRAPH,
                GraphAnalysisStatus.CYCLE_DETECTED,
            ):
                graph_matches.append(
                    MatchedRule(
                        rule_id="RULE_GRAPH_INVALID_DAG",
                        decision=PolicyDecision.DENY,
                        reason="Invalid DAG",
                        risk_score=0.99,
                    )
                )

            sens = {"SECRET", "CREDENTIAL", "CONFIDENTIAL", "RESTRICTED", "PII"}
            if (
                g.analysis_complete
                and tool_spec.external_sink
                and any(c in sens for c in g.ancestor_data_classifications)
            ):
                graph_matches.append(
                    MatchedRule(
                        rule_id="RULE_GRAPH_EXTERNAL_AFTER_SENSITIVE_ACCESS",
                        decision=PolicyDecision.DENY,
                        reason="Sensitive ancestry external transmission",
                        risk_score=0.90,
                    )
                )

            is_priv_dest = (
                tool_spec.privileged
                or tool_spec.destructive
                or action.action_type == ActionType.DESTRUCTIVE
                or action.action_type == ActionType.EXECUTE
            )
            if g.contains_denied_ancestor and is_priv_dest:
                graph_matches.append(
                    MatchedRule(
                        rule_id="RULE_GRAPH_DENIED_ANCESTOR_ESCALATION",
                        decision=PolicyDecision.REQUIRE_APPROVAL,
                        reason="Denied ancestor escalation",
                        risk_score=0.80,
                    )
                )

            is_current_probe = (
                not tool_spec.known
                or tool_spec.privileged
                or tool_spec.destructive
                or action.action_type == ActionType.DESTRUCTIVE
                or action.action_type == ActionType.EXECUTE
            )
            total_probe = g.privileged_probe_count + (1 if is_current_probe else 0)
            if is_current_probe and total_probe >= 3:
                graph_matches.append(
                    MatchedRule(
                        rule_id="RULE_GRAPH_REPEATED_PRIVILEGE_PROBING",
                        decision=PolicyDecision.QUARANTINE,
                        reason="Repeated privilege probing",
                        risk_score=0.95,
                    )
                )

            is_high_env = action.target_environment in (
                TargetEnvironment.PRODUCTION,
                TargetEnvironment.STAGING,
            )
            if (
                g.ancestor_count > 0
                and g.has_lower_environment_ancestor
                and not g.has_high_environment_ancestor
                and is_high_env
                and is_priv_dest
            ):
                graph_matches.append(
                    MatchedRule(
                        rule_id="RULE_GRAPH_ENVIRONMENT_ESCALATION",
                        decision=PolicyDecision.REQUIRE_APPROVAL,
                        reason="Environment escalation",
                        risk_score=0.75,
                    )
                )

        all_matches = intent_matches + runtime_matches + graph_matches
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
