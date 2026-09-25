package cage.runtime

# Production Destructive Operation Guard
findings[f] {
    input.action.target_environment == "PRODUCTION"
    is_destructive
    f := {
        "rule_id": "RULE_A_PRODUCTION_DESTRUCTIVE",
        "decision": "REQUIRE_APPROVAL",
        "reason": "Destructive operations targeting PRODUCTION environments require explicit human approval.",
        "risk_score": 0.75
    }
}

is_destructive {
    input.tool.destructive == true
}

is_destructive {
    input.action.action_type == "DESTRUCTIVE"
}

# Unknown Tool Privileged Access Guard
findings[f] {
    input.tool.known == false
    requires_privilege_check
    f := {
        "rule_id": "RULE_C_UNKNOWN_TOOL_PRIVILEGED",
        "decision": "REQUIRE_APPROVAL",
        "reason": sprintf("Unknown tool '%v' requesting privileged access requires human approval.", [input.action.tool_name]),
        "risk_score": 0.60
    }
}

requires_privilege_check {
    input.tool.privileged == true
}

requires_privilege_check {
    is_destructive
}

requires_privilege_check {
    input.action.action_type == "EXECUTE"
}

# Normal Low-Risk Baseline (Applicable when no intent is enforced and no runtime guards match)
findings[f] {
    input.intent == null
    input.context.require_intent == false
    not is_production_destructive
    not is_unknown_privileged
    not is_credential_exfiltration
    f := {
        "rule_id": "RULE_D_NORMAL_LOW_RISK",
        "decision": "ALLOW",
        "reason": "Action conforms to standard low-risk policy baselines.",
        "risk_score": 0.10
    }
}

is_production_destructive {
    input.action.target_environment == "PRODUCTION"
    is_destructive
}

is_unknown_privileged {
    input.tool.known == false
    requires_privilege_check
}

is_credential_exfiltration {
    input.tool.external_sink == true
    c := input.data.effective_classifications[_]
    c == "CREDENTIAL"
}

is_credential_exfiltration {
    input.tool.external_sink == true
    c := input.data.effective_classifications[_]
    c == "SECRET"
}
