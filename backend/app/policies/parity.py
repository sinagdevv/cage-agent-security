"""Parity comparison and analysis between Python and OPA policy evaluation outcomes."""

from app.schemas.enums import OpaStatus, PolicyDecision, PolicyParityStatus
from app.schemas.policy import OpaEvaluationResult, PolicyParityResult

# Infrastructure rules that do not represent domain security policies
INFRASTRUCTURE_RULES = frozenset(
    {
        "RULE_POLICY_ENGINE_UNAVAILABLE",
        "RULE_POLICY_ENGINE_TIMEOUT",
        "RULE_POLICY_EVALUATION_ERROR",
        "RULE_POLICY_INVALID_RESPONSE",
        "RULE_NO_RULES_MATCHED",
    }
)


def compare_policy_parity(
    python_decision: PolicyDecision | None,
    opa_decision: PolicyDecision | None,
    python_rules: list[str],
    opa_rules: list[str],
    opa_result: OpaEvaluationResult,
) -> PolicyParityResult:
    """Compare Python and OPA policy evaluation findings, distinguishing semantic divergence

    from OPA infrastructure errors. Excludes engine-specific control plane rules from rule parity.
    """
    # 1. Handle OPA infrastructure/transport error
    if opa_result.status != OpaStatus.SUCCESS:
        return PolicyParityResult(
            status=PolicyParityStatus.OPA_ERROR,
            python_decision=python_decision,
            opa_decision=opa_decision,
            decision_match=False,
            rule_match=False,
            python_rules=python_rules,
            opa_rules=opa_rules,
            missing_in_opa=[],
            extra_in_opa=[],
            error_reason=opa_result.error_reason
            or f"OPA returned status: {opa_result.status.value}",
        )

    # 2. Filter out control-plane infrastructure rules for semantic comparison
    domain_python_rules = [r for r in python_rules if r not in INFRASTRUCTURE_RULES]
    domain_opa_rules = [r for r in opa_rules if r not in INFRASTRUCTURE_RULES]

    py_set = set(domain_python_rules)
    opa_set = set(domain_opa_rules)

    missing_in_opa = sorted(list(py_set - opa_set))
    extra_in_opa = sorted(list(opa_set - py_set))

    decision_match = (
        python_decision == opa_decision
        if (python_decision is not None and opa_decision is not None)
        else False
    )
    rule_match = py_set == opa_set

    # 3. Classify status
    if decision_match and rule_match:
        status = PolicyParityStatus.MATCH
    else:
        status = PolicyParityStatus.DIVERGENCE

    return PolicyParityResult(
        status=status,
        python_decision=python_decision,
        opa_decision=opa_decision,
        decision_match=decision_match,
        rule_match=rule_match,
        python_rules=python_rules,
        opa_rules=opa_rules,
        missing_in_opa=missing_in_opa,
        extra_in_opa=extra_in_opa,
        error_reason=None,
    )
