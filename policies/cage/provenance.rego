package cage.provenance

# Provenance Depth Limit Exceeded (Fail-Closed)
findings[f] {
    input.provenance.analysis_status == "DEPTH_LIMIT_EXCEEDED"
    f := {
        "rule_id": "RULE_PROVENANCE_DEPTH_LIMIT_EXCEEDED",
        "decision": "DENY",
        "reason": "Provenance analysis failed (DEPTH_LIMIT_EXCEEDED). Fail-closed enforced.",
        "risk_score": 0.95
    }
}

# Provenance Artifact Limit Exceeded (Fail-Closed)
findings[f] {
    input.provenance.analysis_status == "ARTIFACT_LIMIT_EXCEEDED"
    f := {
        "rule_id": "RULE_PROVENANCE_ARTIFACT_LIMIT_EXCEEDED",
        "decision": "DENY",
        "reason": "Provenance analysis failed (ARTIFACT_LIMIT_EXCEEDED). Fail-closed enforced.",
        "risk_score": 0.95
    }
}

# Provenance Missing Artifact Reference (Fail-Closed)
findings[f] {
    input.provenance.analysis_status == "MISSING_ARTIFACT"
    f := {
        "rule_id": "RULE_PROVENANCE_MISSING_ARTIFACT",
        "decision": "DENY",
        "reason": "Provenance analysis failed (MISSING_ARTIFACT). Fail-closed enforced.",
        "risk_score": 0.95
    }
}

# Provenance Cross-Session Reference Forbidden (Fail-Closed)
findings[f] {
    input.provenance.analysis_status == "CROSS_SESSION_REFERENCE"
    f := {
        "rule_id": "RULE_PROVENANCE_CROSS_SESSION_REFERENCE",
        "decision": "DENY",
        "reason": "Provenance analysis failed (CROSS_SESSION_REFERENCE). Fail-closed enforced.",
        "risk_score": 0.95
    }
}

# Provenance Invalid Lineage (Fail-Closed)
findings[f] {
    input.provenance.analysis_status == "INVALID_LINEAGE"
    f := {
        "rule_id": "RULE_PROVENANCE_INVALID_LINEAGE",
        "decision": "DENY",
        "reason": "Provenance analysis failed (INVALID_LINEAGE). Fail-closed enforced.",
        "risk_score": 0.95
    }
}

# Provenance Cycle Detected (Fail-Closed)
findings[f] {
    input.provenance.analysis_status == "CYCLE_DETECTED"
    f := {
        "rule_id": "RULE_PROVENANCE_CYCLE_DETECTED",
        "decision": "DENY",
        "reason": "Provenance analysis failed (CYCLE_DETECTED). Fail-closed enforced.",
        "risk_score": 0.99
    }
}

# Rule: Untracked External Egress Guard
findings[f] {
    input.provenance.analysis_complete == true
    input.tool.external_sink == true
    input.tool.requires_tracked_inputs == true
    input.provenance.payload_binding_required == true
    not input.provenance.payload_binding_satisfied
    f := {
        "rule_id": "RULE_PROVENANCE_UNTRACKED_EGRESS",
        "decision": "DENY",
        "reason": "External egress denied: tool requires tracked input payload binding, but no valid artifact-backed payload was satisfied.",
        "risk_score": 0.95
    }
}

# Rule: Credential to External Sink Guard
findings[f] {
    input.provenance.analysis_complete == true
    input.tool.external_sink == true
    input.provenance.contains_credential_input == true
    f := {
        "rule_id": "RULE_PROVENANCE_CREDENTIAL_TO_EXTERNAL",
        "decision": "DENY",
        "reason": "External transmission denied: consumed input artifacts contain CREDENTIAL classified information.",
        "risk_score": 0.95
    }
}

# Rule: Sensitive Data to External Sink Guard
findings[f] {
    input.provenance.analysis_complete == true
    input.tool.external_sink == true
    input.provenance.contains_sensitive_input == true
    f := {
        "rule_id": "RULE_PROVENANCE_SENSITIVE_TO_EXTERNAL",
        "decision": "DENY",
        "reason": "External transmission denied: consumed input artifacts contain sensitive data classifications.",
        "risk_score": 0.90
    }
}

# Rule: Untrusted Origin to Privileged Action Guard
findings[f] {
    input.provenance.analysis_complete == true
    input.provenance.contains_untrusted_input == true
    is_privileged_or_destructive
    f := {
        "rule_id": "RULE_PROVENANCE_UNTRUSTED_TO_PRIVILEGED",
        "decision": "REQUIRE_APPROVAL",
        "reason": "Privileged or destructive action consumes information with untrusted external provenance.",
        "risk_score": 0.80
    }
}

# Rule: Unknown Origin to Privileged Action Guard
findings[f] {
    input.provenance.analysis_complete == true
    input.provenance.contains_unknown_input == true
    is_privileged_or_destructive
    f := {
        "rule_id": "RULE_PROVENANCE_UNKNOWN_TO_PRIVILEGED",
        "decision": "REQUIRE_APPROVAL",
        "reason": "Privileged or destructive action consumes information with unknown provenance origin.",
        "risk_score": 0.75
    }
}

# Privileged or destructive helper
is_privileged_or_destructive {
    input.tool.privileged == true
}

is_privileged_or_destructive {
    input.tool.destructive == true
}
