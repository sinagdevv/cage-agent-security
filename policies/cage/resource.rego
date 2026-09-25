package cage.resource

# Explicit resource blacklist check
findings[f] {
    input.intent != null
    input.action.target_resource != null
    input.action.target_resource == input.intent.denied_resources[_]
    f := {
        "rule_id": "RULE_RESOURCE_EXPLICITLY_DENIED",
        "decision": "DENY",
        "reason": sprintf("Resource '%v' is explicitly forbidden by Intent Contract.", [input.action.target_resource]),
        "risk_score": 0.90
    }
}

# Resource whitelist check for resource-scoped tools
findings[f] {
    input.intent != null
    count(input.intent.allowed_resources) > 0
    input.tool.resource_scoped == true
    not resource_in_allowed_resources
    f := {
        "rule_id": "RULE_RESOURCE_OUTSIDE_INTENT",
        "decision": "DENY",
        "reason": sprintf("Resource '%v' is outside authorized resource scope.", [input.action.target_resource]),
        "risk_score": 0.85
    }
}

resource_in_allowed_resources {
    input.action.target_resource != null
    input.action.target_resource == input.intent.allowed_resources[_]
}
