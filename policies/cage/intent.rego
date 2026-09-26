package cage.intent

# Explicit blacklist check
findings[f] {
    input.intent != null
    input.action.action_type != "DELEGATION"
    input.action.tool_name == input.intent.denied_tools[_]
    f := {
        "rule_id": "RULE_TOOL_EXPLICITLY_DENIED",
        "decision": "DENY",
        "reason": sprintf("Tool '%v' is explicitly forbidden by Intent Contract.", [input.action.tool_name]),
        "risk_score": 0.90
    }
}

# Default deny: Tool whitelist check
findings[f] {
    input.intent != null
    input.action.action_type != "DELEGATION"
    not tool_in_allowed_tools
    f := {
        "rule_id": "RULE_TOOL_OUTSIDE_INTENT",
        "decision": "DENY",
        "reason": sprintf("Tool '%v' is not in authorized tool scope.", [input.action.tool_name]),
        "risk_score": 0.85
    }
}

tool_in_allowed_tools {
    input.action.tool_name == input.intent.allowed_tools[_]
}

# Environment scope check
findings[f] {
    input.intent != null
    input.action.action_type != "DELEGATION"
    not env_in_allowed_envs
    f := {
        "rule_id": "RULE_ENVIRONMENT_OUTSIDE_INTENT",
        "decision": "DENY",
        "reason": sprintf("Environment '%v' is outside authorized scope.", [input.action.target_environment]),
        "risk_score": 0.85
    }
}

env_in_allowed_envs {
    input.action.target_environment == input.intent.allowed_environments[_]
}

# Approval-required tool check
findings[f] {
    input.intent != null
    input.action.action_type != "DELEGATION"
    input.action.tool_name == input.intent.requires_approval[_]
    f := {
        "rule_id": "RULE_APPROVAL_TOOL",
        "decision": "REQUIRE_APPROVAL",
        "reason": sprintf("Tool '%v' is authorized by Intent Contract but mandates human approval.", [input.action.tool_name]),
        "risk_score": 0.60
    }
}

# Missing Intent Check
findings[f] {
    input.intent == null
    input.context.require_intent == true
    f := {
        "rule_id": "RULE_INTENT_MISSING",
        "decision": "DENY",
        "reason": "Protected session requires a valid, active Intent Contract.",
        "risk_score": 0.95
    }
}

# Intent Mismatch Check
findings[f] {
    input.context.intent_mismatch == true
    f := {
        "rule_id": "RULE_INTENT_MISMATCH",
        "decision": "DENY",
        "reason": "Intent Contract binding mismatch: supplied intent reference or session/agent binding does not match authoritative server state.",
        "risk_score": 0.95
    }
}

# Status checks
findings[f] {
    input.intent != null
    input.intent.status == "REVOKED"
    f := {
        "rule_id": "RULE_INTENT_REVOKED",
        "decision": "DENY",
        "reason": "Intent Contract has been revoked.",
        "risk_score": 0.95
    }
}

findings[f] {
    input.intent != null
    input.intent.status == "EXPIRED"
    f := {
        "rule_id": "RULE_INTENT_EXPIRED",
        "decision": "DENY",
        "reason": "Intent Contract has expired.",
        "risk_score": 0.95
    }
}

findings[f] {
    input.intent != null
    input.action.action_type != "DELEGATION"
    input.intent.tool_calls_count >= input.intent.maximum_tool_calls
    f := {
        "rule_id": "RULE_TOOL_BUDGET_EXCEEDED",
        "decision": "DENY",
        "reason": "Tool call budget exceeded.",
        "risk_score": 0.85
    }
}

# Baseline Allow when all intent checks pass without violations
findings[f] {
    input.intent != null
    input.intent.status == "ACTIVE"
    input.context.intent_mismatch == false
    input.action.action_type != "DELEGATION"
    input.intent.tool_calls_count < input.intent.maximum_tool_calls
    not has_intent_violation
    f := {
        "rule_id": "RULE_INTENT_ALLOW",
        "decision": "ALLOW",
        "reason": "Action conforms to authorized Intent Contract bounds.",
        "risk_score": 0.10
    }
}

has_intent_violation {
    input.action.tool_name == input.intent.denied_tools[_]
}
has_intent_violation {
    not tool_in_allowed_tools
}
has_intent_violation {
    not env_in_allowed_envs
}
has_intent_violation {
    input.action.tool_name == input.intent.requires_approval[_]
}
