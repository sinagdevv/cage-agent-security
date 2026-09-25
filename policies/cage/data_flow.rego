package cage.data_flow

# Credential / Secret Exfiltration Prevention
findings[f] {
    input.tool.external_sink == true
    has_sensitive_data
    f := {
        "rule_id": "RULE_B_CREDENTIAL_EXTERNAL_EXFILTRATION",
        "decision": "DENY",
        "reason": "Sensitive data (SECRET or CREDENTIAL) cannot be transmitted to external destinations.",
        "risk_score": 0.90
    }
}

has_sensitive_data {
    c := input.data.effective_classifications[_]
    c == "SECRET"
}

has_sensitive_data {
    c := input.data.effective_classifications[_]
    c == "CREDENTIAL"
}

# Data Classification Scope Check
findings[f] {
    input.intent != null
    has_unauthorized_data_classification
    f := {
        "rule_id": "RULE_DATA_SCOPE_VIOLATION",
        "decision": "DENY",
        "reason": "Data classifications exceed authorized data scope.",
        "risk_score": 0.85
    }
}

has_unauthorized_data_classification {
    c := input.data.effective_classifications[_]
    not classification_in_allowed(c)
}

classification_in_allowed(c) {
    c == input.intent.allowed_data_classifications[_]
}
