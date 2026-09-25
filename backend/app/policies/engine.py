"""Policy engine orchestrating deterministic evaluation across PYTHON, SHADOW, and OPA backends."""

import logging
from typing import TYPE_CHECKING

from app.core.config import settings
from app.policies.opa_client import OpaClient, default_opa_client
from app.policies.parity import compare_policy_parity
from app.policies.resolver import resolve_decision_outcome
from app.policies.rules import DeterministicPolicyEvaluator, default_policy_evaluator
from app.schemas.decision import SecurityDecision
from app.schemas.enums import OpaStatus, PolicyBackend, PolicyDecision
from app.schemas.policy import CagePolicyInput, PolicyParityResult

if TYPE_CHECKING:
    from app.schemas.action import AgentAction
    from app.schemas.intent import IntentContract

logger = logging.getLogger("cage.policy_engine")


class PolicyEngine:
    """Orchestrates deterministic policy evaluation across configured backends."""

    def __init__(
        self,
        opa_client: OpaClient | None = None,
        python_evaluator: DeterministicPolicyEvaluator | None = None,
        backend: PolicyBackend | None = None,
        policy_version: str | None = None,
        schema_version: str | None = None,
    ) -> None:
        self.opa_client = opa_client or default_opa_client
        self.python_evaluator = python_evaluator or default_policy_evaluator
        self.backend = backend or PolicyBackend(settings.policy_backend)
        self.policy_version = policy_version or settings.policy_version
        self.schema_version = schema_version or settings.policy_input_schema_version

    def evaluate(
        self,
        policy_input: CagePolicyInput,
        action: "AgentAction",
        contract: "IntentContract | None" = None,
    ) -> tuple[SecurityDecision, PolicyParityResult | None]:
        """Evaluate action using the configured policy backend.

        Returns:
            (SecurityDecision, PolicyParityResult | None)
        """
        if self.backend == PolicyBackend.PYTHON:
            return self._evaluate_python(policy_input, action, contract)
        elif self.backend == PolicyBackend.OPA:
            return self._evaluate_opa(policy_input, action, contract)
        else:  # PolicyBackend.SHADOW
            return self._evaluate_shadow(policy_input, action, contract)

    def _evaluate_python(
        self,
        policy_input: CagePolicyInput,
        action: "AgentAction",
        contract: "IntentContract | None",
    ) -> tuple[SecurityDecision, None]:
        """Evaluate solely using Python deterministic rules."""
        decision = self.python_evaluator.evaluate(
            action=action,
            contract=contract,
            require_intent=policy_input.context.require_intent,
            intent_mismatch=policy_input.context.intent_mismatch,
            graph_context=policy_input.graph,
            provenance_context=policy_input.provenance,
            trajectory_context=policy_input.trajectory,
        )
        decision.policy_backend = PolicyBackend.PYTHON
        decision.policy_version = self.policy_version
        decision.policy_input_schema_version = self.schema_version
        return decision, None

    def _evaluate_opa(
        self,
        policy_input: CagePolicyInput,
        action: "AgentAction",
        contract: "IntentContract | None",
    ) -> tuple[SecurityDecision, None]:
        """Evaluate authoritatively using OPA Rego policies with fail-closed guarantee."""
        opa_result = self.opa_client.evaluate(policy_input)

        if opa_result.status != OpaStatus.SUCCESS:
            ctrl_rule_id = self._map_opa_error_to_rule_id(opa_result.status)
            decision = SecurityDecision(
                action_id=action.action_id,
                session_id=action.session_id,
                intent_contract_id=contract.intent_id if contract else None,
                decision=PolicyDecision.DENY,
                reason=f"OPA policy engine unavailable ({opa_result.status.value}): {opa_result.error_reason}. Fail-closed enforced.",
                matched_rules=[ctrl_rule_id],
                risk_score=0.95,
                requires_human_approval=False,
                policy_backend=PolicyBackend.OPA,
                policy_version=self.policy_version,
                policy_input_schema_version=self.schema_version,
            )
            return decision, None

        # Resolve OPA findings with CAGE severity resolver
        resolved_dec, resolved_reason, max_risk, req_approval, rule_ids = resolve_decision_outcome(
            opa_result.findings
        )

        decision = SecurityDecision(
            action_id=action.action_id,
            session_id=action.session_id,
            intent_contract_id=contract.intent_id if contract else None,
            decision=resolved_dec,
            reason=resolved_reason,
            matched_rules=rule_ids,
            risk_score=max_risk,
            requires_human_approval=req_approval,
            policy_backend=PolicyBackend.OPA,
            policy_version=self.policy_version,
            policy_input_schema_version=self.schema_version,
        )
        return decision, None

    def _evaluate_shadow(
        self,
        policy_input: CagePolicyInput,
        action: "AgentAction",
        contract: "IntentContract | None",
    ) -> tuple[SecurityDecision, PolicyParityResult]:
        """Run both Python and OPA evaluators, enforce Python authority, and record parity."""
        # 1. Authoritative Python evaluation
        py_decision = self.python_evaluator.evaluate(
            action=action,
            contract=contract,
            require_intent=policy_input.context.require_intent,
            intent_mismatch=policy_input.context.intent_mismatch,
            graph_context=policy_input.graph,
            provenance_context=policy_input.provenance,
            trajectory_context=policy_input.trajectory,
        )

        # 2. Shadow OPA evaluation
        opa_result = self.opa_client.evaluate(policy_input)

        # 3. Resolve OPA outcome if successful
        if opa_result.status == OpaStatus.SUCCESS:
            opa_dec, _, _, _, opa_rule_ids = resolve_decision_outcome(opa_result.findings)
        else:
            opa_dec = PolicyDecision.DENY
            opa_rule_ids = [self._map_opa_error_to_rule_id(opa_result.status)]

        # 4. Compare parity
        parity_result = compare_policy_parity(
            python_decision=py_decision.decision,
            opa_decision=opa_dec,
            python_rules=py_decision.matched_rules,
            opa_rules=opa_rule_ids,
            opa_result=opa_result,
        )

        # 5. Enforce security invariants in SHADOW mode:
        # - Infrastructure failure: fail-closed (blocks execution)
        # - Semantic divergence: Python remains authoritative
        if opa_result.status != OpaStatus.SUCCESS:
            ctrl_rule_id = self._map_opa_error_to_rule_id(opa_result.status)
            logger.error(
                "Policy engine failure in SHADOW mode: %s (%s). Enforcing fail-closed DENY.",
                ctrl_rule_id,
                opa_result.error_reason,
            )
            final_decision = SecurityDecision(
                action_id=action.action_id,
                session_id=action.session_id,
                intent_contract_id=contract.intent_id if contract else None,
                decision=PolicyDecision.DENY,
                reason=f"Policy engine infrastructure failure: {opa_result.error_reason}. Fail-closed enforced.",
                matched_rules=[ctrl_rule_id],
                risk_score=0.95,
                requires_human_approval=False,
                policy_backend=PolicyBackend.SHADOW,
                policy_version=self.policy_version,
                policy_input_schema_version=self.schema_version,
            )
        else:
            # Semantic divergence or match: Python remains authoritative
            final_decision = py_decision.model_copy(
                update={
                    "policy_backend": PolicyBackend.SHADOW,
                    "policy_version": self.policy_version,
                    "policy_input_schema_version": self.schema_version,
                }
            )

        return final_decision, parity_result

    @staticmethod
    def _map_opa_error_to_rule_id(status: OpaStatus) -> str:
        """Map OPA infrastructure failure status to CAGE control plane rule ID."""
        if status == OpaStatus.TIMEOUT:
            return "RULE_POLICY_ENGINE_TIMEOUT"
        elif status == OpaStatus.UNAVAILABLE:
            return "RULE_POLICY_ENGINE_UNAVAILABLE"
        elif status == OpaStatus.INVALID_RESPONSE:
            return "RULE_POLICY_INVALID_RESPONSE"
        else:
            return "RULE_POLICY_EVALUATION_ERROR"


# Global default instance
default_policy_engine = PolicyEngine()
