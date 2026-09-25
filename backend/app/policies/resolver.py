"""Precedence resolution for CAGE policy decisions.

Strict severity hierarchy:
DENY (6) > QUARANTINE (5) > SANDBOX (4) > REQUIRE_APPROVAL (3) > ALLOW_WITH_LIMITS (2) > ALLOW (1).
"""

from app.schemas.enums import PolicyDecision


def resolve_decision_outcome(
    matched_rules: list,  # list of MatchedRule or objects with .decision, .reason, .risk_score, .rule_id
    fallback_rule=None,
) -> tuple[PolicyDecision, str, float, bool, list[str]]:
    """Deterministically resolve a collection of matched rules into a single decision outcome.

    Returns:
        (resolved_decision, resolved_reason, max_risk_score, requires_human_approval, rule_ids)
    """
    if not matched_rules:
        if fallback_rule is not None:
            return (
                fallback_rule.decision,
                fallback_rule.reason,
                round(fallback_rule.risk_score, 2),
                fallback_rule.decision == PolicyDecision.REQUIRE_APPROVAL,
                [fallback_rule.rule_id],
            )
        # Default fail-closed if no rules at all
        return (
            PolicyDecision.DENY,
            "No policy rules matched; fail-closed baseline enforced.",
            0.9,
            False,
            ["RULE_NO_RULES_MATCHED"],
        )

    primary_match = max(matched_rules, key=lambda r: r.decision.severity_rank)
    resolved_decision = primary_match.decision
    resolved_reason = primary_match.reason
    max_risk = max(r.risk_score for r in matched_rules)
    rule_ids = [r.rule_id for r in matched_rules]
    requires_approval = resolved_decision == PolicyDecision.REQUIRE_APPROVAL

    return (
        resolved_decision,
        resolved_reason,
        round(max_risk, 2),
        requires_approval,
        rule_ids,
    )
