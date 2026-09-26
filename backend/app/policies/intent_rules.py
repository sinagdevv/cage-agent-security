"""Intent Contract rules evaluator.

Evaluates proposed actions against task-scoped authority granted in an Intent Contract.
Default-deny design: any tool, environment, or data classification outside the whitelist is DENIED.
"""

from datetime import UTC, datetime
from typing import Any

from app.gateway.registry import ToolRegistry, default_tool_registry
from app.policies.rules import MatchedRule
from app.schemas.action import AgentAction
from app.schemas.enums import ActionType, IntentStatus, PolicyDecision
from app.schemas.intent import IntentContract


class IntentRulesEvaluator:
    """Evaluates an AgentAction against an authoritative IntentContract."""

    def __init__(self, tool_registry: ToolRegistry | None = None) -> None:
        self.tool_registry = tool_registry or default_tool_registry

    def evaluate_intent(
        self,
        action: AgentAction,
        contract: IntentContract | None,
        require_intent: bool = True,
        intent_mismatch: bool = False,
        delegation_context: Any = None,
    ) -> list[MatchedRule]:
        """Evaluate action against intent constraints, returning all matched intent rules."""
        if intent_mismatch:
            return [
                MatchedRule(
                    rule_id="RULE_INTENT_MISMATCH",
                    decision=PolicyDecision.DENY,
                    reason="Intent Contract binding mismatch: supplied intent reference or session/agent binding does not match authoritative server state.",
                    risk_score=0.95,
                )
            ]

        # 1. Missing Intent Check
        if contract is None:
            if require_intent:
                return [
                    MatchedRule(
                        rule_id="RULE_INTENT_MISSING",
                        decision=PolicyDecision.DENY,
                        reason="Protected session requires a valid, active Intent Contract.",
                        risk_score=0.95,
                    )
                ]
            return []

        matched: list[MatchedRule] = []
        now = datetime.now(UTC)

        # 2. Status & Expiration Checks
        if contract.status == IntentStatus.REVOKED:
            return [
                MatchedRule(
                    rule_id="RULE_INTENT_REVOKED",
                    decision=PolicyDecision.DENY,
                    reason=f"Intent Contract '{contract.intent_id}' has been revoked. ({contract.revoked_reason or 'No reason provided'})",
                    risk_score=0.95,
                )
            ]

        if contract.status == IntentStatus.EXPIRED or (
            contract.expires_at is not None and now >= contract.expires_at
        ):
            return [
                MatchedRule(
                    rule_id="RULE_INTENT_EXPIRED",
                    decision=PolicyDecision.DENY,
                    reason=f"Intent Contract '{contract.intent_id}' expired at {contract.expires_at}.",
                    risk_score=0.95,
                )
            ]

        if contract.status == IntentStatus.COMPLETED:
            return [
                MatchedRule(
                    rule_id="RULE_INTENT_COMPLETED",
                    decision=PolicyDecision.DENY,
                    reason=f"Intent Contract '{contract.intent_id}' is completed and no longer authorizes actions.",
                    risk_score=0.9,
                )
            ]

        # 3. Agent and Session Binding Checks
        # Single-agent path: contract.agent_id == action.agent_id is strictly required.
        # Delegated path: agent mismatch is tolerated ONLY when:
        # - authoritative delegation_id is resolved server-side
        # - delegation grant exists, matches session, and is ACTIVE
        # - caller principal matches delegatee
        # - action is inside live effective authority
        is_valid_delegated = False
        if action.action_type == ActionType.DELEGATION:
            is_valid_delegated = True
        elif action.delegation_id is not None and delegation_context is not None:
            if (
                delegation_context.is_delegated
                and delegation_context.principal_matches_delegatee
                and delegation_context.effective_status == "ACTIVE"
                and delegation_context.current_tool_within_effective_authority
                and delegation_context.current_resource_within_effective_authority
                and delegation_context.current_environment_within_effective_authority
                and delegation_context.current_classification_within_effective_authority
            ):
                is_valid_delegated = True

        if (
            not is_valid_delegated and contract.agent_id != action.agent_id
        ) or contract.session_id != action.session_id:
            return [
                MatchedRule(
                    rule_id="RULE_INTENT_MISMATCH",
                    decision=PolicyDecision.DENY,
                    reason=f"Intent Contract binding mismatch: contract bound to agent '{contract.agent_id}' / session '{contract.session_id}', "
                    f"but action has agent '{action.agent_id}' / session '{action.session_id}'.",
                    risk_score=0.95,
                )
            ]

        # 4. Tool Execution Quota Check
        if action.action_type != ActionType.DELEGATION:
            if contract.tool_calls_count >= contract.maximum_tool_calls:
                return [
                    MatchedRule(
                        rule_id="RULE_TOOL_BUDGET_EXCEEDED",
                        decision=PolicyDecision.DENY,
                        reason=f"Tool call budget exceeded: {contract.tool_calls_count}/{contract.maximum_tool_calls} executions consumed.",
                        risk_score=0.85,
                    )
                ]

            # 5. Explicit Tool Blacklist Check
            if action.tool_name in contract.denied_tools:
                matched.append(
                    MatchedRule(
                        rule_id="RULE_TOOL_EXPLICITLY_DENIED",
                        decision=PolicyDecision.DENY,
                        reason=f"Tool '{action.tool_name}' is explicitly forbidden by Intent Contract.",
                        risk_score=0.9,
                    )
                )

            # 6. Default Deny: Tool Whitelist Check
            if action.tool_name not in contract.allowed_tools:
                matched.append(
                    MatchedRule(
                        rule_id="RULE_TOOL_OUTSIDE_INTENT",
                        decision=PolicyDecision.DENY,
                        reason=f"Tool '{action.tool_name}' is not in authorized tool scope: {sorted(contract.allowed_tools)}.",
                        risk_score=0.85,
                    )
                )

            # 7. Environment Scope Check
            if action.target_environment not in contract.allowed_environments:
                matched.append(
                    MatchedRule(
                        rule_id="RULE_ENVIRONMENT_OUTSIDE_INTENT",
                        decision=PolicyDecision.DENY,
                        reason=f"Environment '{action.target_environment.value}' is outside authorized scope: {[e.value for e in contract.allowed_environments]}.",
                        risk_score=0.85,
                    )
                )

            # 8. Resource Scope Checks
            if action.target_resource is not None:
                if action.target_resource in contract.denied_resources:
                    matched.append(
                        MatchedRule(
                            rule_id="RULE_RESOURCE_EXPLICITLY_DENIED",
                            decision=PolicyDecision.DENY,
                            reason=f"Resource '{action.target_resource}' is explicitly forbidden by Intent Contract.",
                            risk_score=0.9,
                        )
                    )

            tool_spec = self.tool_registry.get(action.tool_name)
            if contract.allowed_resources:
                if tool_spec.resource_scoped and (
                    not action.target_resource
                    or action.target_resource not in contract.allowed_resources
                ):
                    matched.append(
                        MatchedRule(
                            rule_id="RULE_RESOURCE_OUTSIDE_INTENT",
                            decision=PolicyDecision.DENY,
                            reason=f"Resource '{action.target_resource}' is outside authorized resource scope: {sorted(contract.allowed_resources)}.",
                            risk_score=0.85,
                        )
                    )

            # 9. Data Classification Scope Check
            effective_classifications = self.tool_registry.get_effective_classifications(
                action.tool_name, action.data_classifications
            )
            unauthorized_data = [
                c
                for c in effective_classifications
                if c not in contract.allowed_data_classifications
            ]
            if unauthorized_data:
                matched.append(
                    MatchedRule(
                        rule_id="RULE_DATA_SCOPE_VIOLATION",
                        decision=PolicyDecision.DENY,
                        reason=f"Data classifications {[c.value for c in unauthorized_data]} exceed authorized data scope: {[c.value for c in contract.allowed_data_classifications]}.",
                        risk_score=0.85,
                    )
                )

            # 10. Human Approval Requirement
            if action.tool_name in contract.requires_approval:
                matched.append(
                    MatchedRule(
                        rule_id="RULE_APPROVAL_TOOL",
                        decision=PolicyDecision.REQUIRE_APPROVAL,
                        reason=f"Tool '{action.tool_name}' is authorized by Intent Contract but mandates human approval.",
                        risk_score=0.6,
                    )
                )

        # 11. Intent Baseline Match
        if not matched:
            matched.append(
                MatchedRule(
                    rule_id="RULE_INTENT_ALLOW",
                    decision=PolicyDecision.ALLOW,
                    reason="Action conforms to authorized Intent Contract bounds.",
                    risk_score=0.1,
                )
            )

        return matched


default_intent_rules_evaluator = IntentRulesEvaluator()
