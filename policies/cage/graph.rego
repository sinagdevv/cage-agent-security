package cage.graph

# Graph Depth Limit Exceeded (Fail-Closed)
findings[f] {
    input.graph.analysis_status == "DEPTH_LIMIT_EXCEEDED"
    f := {
        "rule_id": "RULE_GRAPH_DEPTH_LIMIT_EXCEEDED",
        "decision": "DENY",
        "reason": "Causal graph traversal depth limit exceeded during analysis. Fail-closed enforced.",
        "risk_score": 0.95
    }
}

# Graph Node Limit Exceeded (Fail-Closed)
findings[f] {
    input.graph.analysis_status == "NODE_LIMIT_EXCEEDED"
    f := {
        "rule_id": "RULE_GRAPH_NODE_LIMIT_EXCEEDED",
        "decision": "DENY",
        "reason": "Causal graph traversal node limit exceeded during analysis. Fail-closed enforced.",
        "risk_score": 0.95
    }
}

# Graph Invalid DAG / Cycle Detected (Fail-Closed)
findings[f] {
    is_invalid_graph
    f := {
        "rule_id": "RULE_GRAPH_INVALID_DAG",
        "decision": "DENY",
        "reason": sprintf("Causal graph integrity failure (%v). Fail-closed enforced.", [input.graph.analysis_status]),
        "risk_score": 0.99
    }
}

is_invalid_graph {
    input.graph.analysis_status == "INVALID_GRAPH"
}

is_invalid_graph {
    input.graph.analysis_status == "CYCLE_DETECTED"
}

# Rule: External Transmission After Sensitive Access Guard
findings[f] {
    input.graph.analysis_complete == true
    input.tool.external_sink == true
    has_sensitive_ancestor_data
    f := {
        "rule_id": "RULE_GRAPH_EXTERNAL_AFTER_SENSITIVE_ACCESS",
        "decision": "DENY",
        "reason": "External transmission denied because the validated causal ancestry contains access to sensitive-classified data.",
        "risk_score": 0.90
    }
}

has_sensitive_ancestor_data {
    c := input.graph.ancestor_data_classifications[_]
    c == "SECRET"
}

has_sensitive_ancestor_data {
    c := input.graph.ancestor_data_classifications[_]
    c == "CREDENTIAL"
}

has_sensitive_ancestor_data {
    c := input.graph.ancestor_data_classifications[_]
    c == "CONFIDENTIAL"
}

has_sensitive_ancestor_data {
    c := input.graph.ancestor_data_classifications[_]
    c == "RESTRICTED"
}

has_sensitive_ancestor_data {
    c := input.graph.ancestor_data_classifications[_]
    c == "PII"
}

# Rule: Denied Ancestor Escalation Guard
findings[f] {
    input.graph.analysis_complete == true
    input.graph.contains_denied_ancestor == true
    is_privileged_or_destructive
    f := {
        "rule_id": "RULE_GRAPH_DENIED_ANCESTOR_ESCALATION",
        "decision": "REQUIRE_APPROVAL",
        "reason": "Privileged or destructive operation attempted following a previously denied action in the causal trajectory.",
        "risk_score": 0.80
    }
}

# Rule: Repeated Privilege Probing Guard
findings[f] {
    is_current_probe
    total_probe_count >= 3
    f := {
        "rule_id": "RULE_GRAPH_REPEATED_PRIVILEGE_PROBING",
        "decision": "QUARANTINE",
        "reason": sprintf("Repeated privileged or destructive probing detected in causal trajectory (%v attempts >= 3). Action quarantined.", [total_probe_count]),
        "risk_score": 0.95
    }
}

is_current_probe {
    input.tool.known == false
}

is_current_probe {
    input.tool.privileged == true
}

is_current_probe {
    input.tool.destructive == true
}

is_current_probe {
    input.action.action_type == "DESTRUCTIVE"
}

is_current_probe {
    input.action.action_type == "EXECUTE"
}

total_probe_count = count {
    is_current_probe
    count := input.graph.privileged_probe_count + 1
}

# Rule: Environment Escalation Guard
findings[f] {
    input.graph.ancestor_count > 0
    input.graph.has_lower_environment_ancestor == true
    input.graph.has_high_environment_ancestor == false
    is_high_environment
    is_privileged_or_destructive
    f := {
        "rule_id": "RULE_GRAPH_ENVIRONMENT_ESCALATION",
        "decision": "REQUIRE_APPROVAL",
        "reason": "Causal trajectory escalated from development to production without prior production lineage.",
        "risk_score": 0.75
    }
}

is_high_environment {
    input.action.target_environment == "PRODUCTION"
}

is_high_environment {
    input.action.target_environment == "STAGING"
}

is_privileged_or_destructive {
    input.tool.privileged == true
}

is_privileged_or_destructive {
    input.tool.destructive == true
}

is_privileged_or_destructive {
    input.action.action_type == "DESTRUCTIVE"
}

is_privileged_or_destructive {
    input.action.action_type == "EXECUTE"
}
