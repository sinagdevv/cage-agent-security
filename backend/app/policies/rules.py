"""Deterministic security rules and precedence-based policy evaluation.

Integrates task-scoped Intent Contract authorization with runtime security policies:
Intent Authorization AND Runtime Security Policy = Final Decision

Precedence resolution:
DENY > QUARANTINE > SANDBOX > REQUIRE_APPROVAL > ALLOW_WITH_LIMITS > ALLOW.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from app.gateway.registry import ToolRegistry, default_tool_registry
from app.schemas.action import AgentAction
from app.schemas.decision import SecurityDecision
from app.schemas.enums import (
    ActionType,
    DataClassification,
    PolicyDecision,
    TargetEnvironment,
)

if TYPE_CHECKING:
    from app.schemas.intent import IntentContract
    from app.schemas.policy import PolicyGraphContext


@dataclass(frozen=True)
class MatchedRule:
    """Individual rule matched during evaluation."""

    rule_id: str
    decision: PolicyDecision
    reason: str
    risk_score: float


class DeterministicPolicyEvaluator:
    """Deterministic policy evaluator for CAGE governance."""

    def __init__(self, tool_registry: ToolRegistry | None = None) -> None:
        self.tool_registry = tool_registry or default_tool_registry

    def evaluate(
        self,
        action: AgentAction,
        contract: IntentContract | None = None,
        require_intent: bool = False,
        intent_mismatch: bool = False,
        graph_context: PolicyGraphContext | None = None,
    ) -> SecurityDecision:
        """Evaluate an authoritative AgentAction against Intent rules and runtime policies.

        Evaluates ALL applicable rules first, then resolves the final verdict deterministically
        according to the severity rank hierarchy:
        DENY > QUARANTINE > SANDBOX > REQUIRE_APPROVAL > ALLOW_WITH_LIMITS > ALLOW.
        """
        tool_spec = self.tool_registry.get(action.tool_name)
        matched_rules: list[MatchedRule] = []

        # =============================================================
        # 1. Intent Scope Evaluation (Task Authority)
        # =============================================================
        from app.policies.intent_rules import default_intent_rules_evaluator

        intent_matched = default_intent_rules_evaluator.evaluate_intent(
            action=action,
            contract=contract,
            require_intent=require_intent,
            intent_mismatch=intent_mismatch,
        )
        matched_rules.extend(intent_matched)

        # =============================================================
        # 2. Runtime Security Policies (Phase 1 Rules)
        # =============================================================

        # -------------------------------------------------------------
        # Rule B: Credential / Secret Exfiltration Prevention
        # Effective classifications combine server_known UNION client_declared
        # -------------------------------------------------------------
        sensitive_classifications = {
            DataClassification.SECRET,
            DataClassification.CREDENTIAL,
        }
        effective_classifications = self.tool_registry.get_effective_classifications(
            action.tool_name, action.data_classifications
        )
        has_sensitive_data = any(c in sensitive_classifications for c in effective_classifications)
        is_external_sink = tool_spec.external_sink

        if has_sensitive_data and is_external_sink:
            matched_rules.append(
                MatchedRule(
                    rule_id="RULE_B_CREDENTIAL_EXTERNAL_EXFILTRATION",
                    decision=PolicyDecision.DENY,
                    reason="Sensitive data (SECRET or CREDENTIAL) cannot be transmitted to external destinations.",
                    risk_score=0.9,
                )
            )

        # -------------------------------------------------------------
        # Rule A: Production Destructive Operation Guard
        # If target_environment == PRODUCTION and tool or action is destructive
        # -------------------------------------------------------------
        is_destructive = tool_spec.destructive or action.action_type == ActionType.DESTRUCTIVE
        if action.target_environment == TargetEnvironment.PRODUCTION and is_destructive:
            matched_rules.append(
                MatchedRule(
                    rule_id="RULE_A_PRODUCTION_DESTRUCTIVE",
                    decision=PolicyDecision.REQUIRE_APPROVAL,
                    reason="Destructive operations targeting PRODUCTION environments require explicit human approval.",
                    risk_score=0.75,
                )
            )

        # -------------------------------------------------------------
        # Rule C: Unknown Tool Privileged Access Guard
        # -------------------------------------------------------------
        if not tool_spec.known:
            if tool_spec.privileged or is_destructive or action.action_type == ActionType.EXECUTE:
                matched_rules.append(
                    MatchedRule(
                        rule_id="RULE_C_UNKNOWN_TOOL_PRIVILEGED",
                        decision=PolicyDecision.REQUIRE_APPROVAL,
                        reason=f"Unknown tool '{action.tool_name}' requesting privileged access requires human approval.",
                        risk_score=0.6,
                    )
                )

        # =============================================================
        # 3. Causal Graph Security Policies (Phase 4 Rules)
        # =============================================================
        if graph_context is not None:
            from app.schemas.enums import GraphAnalysisStatus

            # ---------------------------------------------------------
            # Graph Infrastructure / Traversal Limits (Fail-Closed)
            # ---------------------------------------------------------
            if graph_context.analysis_status == GraphAnalysisStatus.DEPTH_LIMIT_EXCEEDED:
                matched_rules.append(
                    MatchedRule(
                        rule_id="RULE_GRAPH_DEPTH_LIMIT_EXCEEDED",
                        decision=PolicyDecision.DENY,
                        reason="Causal graph traversal depth limit exceeded during analysis. Fail-closed enforced.",
                        risk_score=0.95,
                    )
                )
            elif graph_context.analysis_status == GraphAnalysisStatus.NODE_LIMIT_EXCEEDED:
                matched_rules.append(
                    MatchedRule(
                        rule_id="RULE_GRAPH_NODE_LIMIT_EXCEEDED",
                        decision=PolicyDecision.DENY,
                        reason="Causal graph traversal node limit exceeded during analysis. Fail-closed enforced.",
                        risk_score=0.95,
                    )
                )
            elif graph_context.analysis_status in (
                GraphAnalysisStatus.INVALID_GRAPH,
                GraphAnalysisStatus.CYCLE_DETECTED,
            ):
                matched_rules.append(
                    MatchedRule(
                        rule_id="RULE_GRAPH_INVALID_DAG",
                        decision=PolicyDecision.DENY,
                        reason=f"Causal graph integrity failure ({graph_context.analysis_status.value}). Fail-closed enforced.",
                        risk_score=0.99,
                    )
                )

            # ---------------------------------------------------------
            # Rule: External Transmission After Sensitive Access
            # ---------------------------------------------------------
            sensitive_ancestor_classes = {
                "CONFIDENTIAL",
                "RESTRICTED",
                "PII",
                "SECRET",
                "CREDENTIAL",
            }
            has_sensitive_ancestor = any(
                c in sensitive_ancestor_classes for c in graph_context.ancestor_data_classifications
            )
            if graph_context.analysis_complete and is_external_sink and has_sensitive_ancestor:
                matched_rules.append(
                    MatchedRule(
                        rule_id="RULE_GRAPH_EXTERNAL_AFTER_SENSITIVE_ACCESS",
                        decision=PolicyDecision.DENY,
                        reason="External transmission denied because the validated causal ancestry contains access to sensitive-classified data.",
                        risk_score=0.90,
                    )
                )

            # ---------------------------------------------------------
            # Rule: Denied Ancestor Escalation Guard
            # ---------------------------------------------------------
            is_privileged_or_destructive = (
                tool_spec.privileged
                or tool_spec.destructive
                or action.action_type in (ActionType.DESTRUCTIVE, ActionType.EXECUTE)
            )
            if (
                graph_context.analysis_complete
                and graph_context.contains_denied_ancestor
                and is_privileged_or_destructive
            ):
                matched_rules.append(
                    MatchedRule(
                        rule_id="RULE_GRAPH_DENIED_ANCESTOR_ESCALATION",
                        decision=PolicyDecision.REQUIRE_APPROVAL,
                        reason="Privileged or destructive operation attempted following a previously denied action in the causal trajectory.",
                        risk_score=0.80,
                    )
                )

            # ---------------------------------------------------------
            # Rule: Repeated Privilege Probing Guard
            # ---------------------------------------------------------
            is_current_probe = (
                not tool_spec.known
                or tool_spec.privileged
                or is_destructive
                or action.action_type == ActionType.EXECUTE
            )
            total_probe_count = graph_context.privileged_probe_count + (
                1 if is_current_probe else 0
            )
            if is_current_probe and total_probe_count >= 3:
                matched_rules.append(
                    MatchedRule(
                        rule_id="RULE_GRAPH_REPEATED_PRIVILEGE_PROBING",
                        decision=PolicyDecision.QUARANTINE,
                        reason=f"Repeated privileged or destructive probing detected in causal trajectory ({total_probe_count} attempts >= 3). Action quarantined.",
                        risk_score=0.95,
                    )
                )

            # ---------------------------------------------------------
            # Rule: Environment Escalation Guard
            # ---------------------------------------------------------
            is_high_env = action.target_environment in (
                TargetEnvironment.PRODUCTION,
                TargetEnvironment.STAGING,
            )
            if (
                graph_context.ancestor_count > 0
                and graph_context.has_lower_environment_ancestor
                and not graph_context.has_high_environment_ancestor
                and is_high_env
                and is_privileged_or_destructive
            ):
                matched_rules.append(
                    MatchedRule(
                        rule_id="RULE_GRAPH_ENVIRONMENT_ESCALATION",
                        decision=PolicyDecision.REQUIRE_APPROVAL,
                        reason="Causal trajectory escalated from development to production without prior production lineage.",
                        risk_score=0.75,
                    )
                )

        # -------------------------------------------------------------
        # Rule D: Normal Low-Risk Baseline
        # Applies only if no restrictive rules triggered and intent didn't already match
        # -------------------------------------------------------------
        if not matched_rules:
            matched_rules.append(
                MatchedRule(
                    rule_id="RULE_D_NORMAL_LOW_RISK",
                    decision=PolicyDecision.ALLOW,
                    reason="Action conforms to standard low-risk policy baselines.",
                    risk_score=0.1,
                )
            )

        # =============================================================
        # 3. Precedence Resolution
        # Precedence order: DENY > QUARANTINE > SANDBOX > REQUIRE_APPROVAL > ALLOW_WITH_LIMITS > ALLOW
        # =============================================================
        primary_match = max(matched_rules, key=lambda r: r.decision.severity_rank)
        resolved_decision = primary_match.decision
        resolved_reason = primary_match.reason
        max_risk = max(r.risk_score for r in matched_rules)
        rule_ids = [r.rule_id for r in matched_rules]
        requires_approval = resolved_decision == PolicyDecision.REQUIRE_APPROVAL

        return SecurityDecision(
            action_id=action.action_id,
            session_id=action.session_id,
            intent_contract_id=contract.intent_id if contract else None,
            decision=resolved_decision,
            reason=resolved_reason,
            matched_rules=rule_ids,
            risk_score=round(max_risk, 2),
            requires_human_approval=requires_approval,
        )


# Global default instance
default_policy_evaluator = DeterministicPolicyEvaluator()
