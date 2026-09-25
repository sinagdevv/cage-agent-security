package cage.trajectory

# 1. Trajectory Lifecycle Containment: Quarantined
findings[f] {
    input.trajectory.trajectory_status == "QUARANTINED"
    f := {
        "rule_id": "RULE_TRAJECTORY_QUARANTINED",
        "decision": "DENY",
        "reason": "Action rejected because trajectory is in QUARANTINED containment state.",
        "risk_score": 1.0
    }
}

# 2. Trajectory Lifecycle Containment: Aborted
findings[f] {
    input.trajectory.trajectory_status == "ABORTED"
    f := {
        "rule_id": "RULE_TRAJECTORY_ABORTED",
        "decision": "DENY",
        "reason": "Action rejected because trajectory has been permanently ABORTED.",
        "risk_score": 1.0
    }
}

# 3. Traversal Limits: Action Depth Limit Exceeded (Fail-Closed)
findings[f] {
    input.trajectory.analysis_status == "ACTION_DEPTH_LIMIT_EXCEEDED"
    f := {
        "rule_id": "RULE_TRAJECTORY_ACTION_DEPTH_LIMIT_EXCEEDED",
        "decision": "DENY",
        "reason": "Trajectory action traversal depth exceeded safety limits.",
        "risk_score": 0.95
    }
}

# 4. Traversal Limits: Artifact Depth Limit Exceeded (Fail-Closed)
findings[f] {
    input.trajectory.analysis_status == "ARTIFACT_DEPTH_LIMIT_EXCEEDED"
    f := {
        "rule_id": "RULE_TRAJECTORY_ARTIFACT_DEPTH_LIMIT_EXCEEDED",
        "decision": "DENY",
        "reason": "Trajectory artifact derivation depth exceeded safety limits.",
        "risk_score": 0.95
    }
}

# 5. Traversal Limits: Node Limit Exceeded (Fail-Closed)
findings[f] {
    input.trajectory.analysis_status == "NODE_LIMIT_EXCEEDED"
    f := {
        "rule_id": "RULE_TRAJECTORY_NODE_LIMIT_EXCEEDED",
        "decision": "DENY",
        "reason": "Trajectory graph traversal node limit exceeded safety limits.",
        "risk_score": 0.95
    }
}

# 6. Traversal Error: Invalid Typed Path (Fail-Closed)
findings[f] {
    input.trajectory.analysis_status == "INVALID_TYPED_PATH"
    f := {
        "rule_id": "RULE_TRAJECTORY_INVALID_TYPED_PATH",
        "decision": "DENY",
        "reason": "Trajectory contains invalid or broken typed edge relations.",
        "risk_score": 0.95
    }
}

# 7. Traversal Error: Missing Graph Evidence (Fail-Closed)
findings[f] {
    input.trajectory.analysis_status == "MISSING_GRAPH_EVIDENCE"
    f := {
        "rule_id": "RULE_TRAJECTORY_MISSING_GRAPH_EVIDENCE",
        "decision": "DENY",
        "reason": "Trajectory causal history contains missing or corrupted graph nodes.",
        "risk_score": 0.95
    }
}

# 8. Traversal Error: Inconsistent Provenance (Fail-Closed)
findings[f] {
    input.trajectory.analysis_status == "INCONSISTENT_PROVENANCE"
    f := {
        "rule_id": "RULE_TRAJECTORY_INCONSISTENT_PROVENANCE",
        "decision": "DENY",
        "reason": "Trajectory references inconsistent or missing provenance artifacts.",
        "risk_score": 0.95
    }
}

# 9. Flagship Rule: Untrusted Path to Sensitive Access
findings[f] {
    input.trajectory.analysis_complete == true
    input.trajectory.untrusted_path_to_sensitive_access == true
    f := {
        "rule_id": "RULE_TRAJECTORY_UNTRUSTED_PATH_TO_SENSITIVE_ACCESS",
        "decision": "REQUIRE_APPROVAL",
        "reason": "Externally untrusted information participated in the validated causal trajectory leading to sensitive access.",
        "risk_score": 0.85
    }
}

# 10. Flagship Rule: Untrusted Path to Sensitive Egress
findings[f] {
    input.trajectory.analysis_complete == true
    input.trajectory.untrusted_path_to_sensitive_egress == true
    f := {
        "rule_id": "RULE_TRAJECTORY_UNTRUSTED_PATH_TO_SENSITIVE_EGRESS",
        "decision": "DENY",
        "reason": "Validated causal trajectory connects externally untrusted origin to sensitive external egress sink.",
        "risk_score": 0.95
    }
}

# 11. Flagship Rule: Information Cannot Expand Authority
findings[f] {
    input.trajectory.analysis_complete == true
    input.trajectory.unauthorized_authority_expansion_attempted == true
    input.trajectory.untrusted_path_to_current_action == true
    f := {
        "rule_id": "RULE_TRAJECTORY_INFORMATION_CANNOT_EXPAND_AUTHORITY",
        "decision": "DENY",
        "reason": "Untrusted information on causal trajectory attempted unauthorized authority expansion.",
        "risk_score": 0.90
    }
}

# 12. Flagship Rule: Cumulative Sensitive Egress Attempt Threshold Exceeded
findings[f] {
    input.trajectory.analysis_complete == true
    input.trajectory.split_exfiltration_threshold_exceeded == true
    f := {
        "rule_id": "RULE_TRAJECTORY_CUMULATIVE_SENSITIVE_EGRESS",
        "decision": "QUARANTINE",
        "reason": "Cumulative sensitive egress attempts or volume exceeded safety thresholds; quarantining trajectory.",
        "risk_score": 0.95
    }
}

# 13. Flagship Rule: Sensitive Hop Laundering
findings[f] {
    input.trajectory.analysis_complete == true
    input.trajectory.sensitive_hop_laundering_detected == true
    f := {
        "rule_id": "RULE_TRAJECTORY_SENSITIVE_HOP_LAUNDERING",
        "decision": "DENY",
        "reason": "Sensitive information traversed multi-hop transformation sequence before exiting to external sink.",
        "risk_score": 0.90
    }
}
