package cage.delegation

# ==========================================
# CREATE_GRANT Rules
# ==========================================

# 1. Caller not authorized to issue delegation
findings[f] {
    input.delegation.operation == "CREATE_GRANT"
    input.delegation.is_delegated == true
    input.delegation.caller_is_authorized_issuer == false
    f := {
        "rule_id": "RULE_DELEGATION_CALLER_NOT_AUTHORIZED",
        "decision": "DENY",
        "reason": "Caller principal is not authorized to issue this delegation grant.",
        "risk_score": 1.0
    }
}

# 2. Invalid parent grant in subdelegation
findings[f] {
    input.delegation.operation == "CREATE_GRANT"
    input.delegation.is_delegated == true
    input.delegation.parent_delegation_id != null
    input.delegation.parent_grant_valid == false
    f := {
        "rule_id": "RULE_DELEGATION_INVALID_PARENT",
        "decision": "DENY",
        "reason": "Referenced parent delegation grant does not exist or is invalid.",
        "risk_score": 1.0
    }
}

# 3. Cross-session delegation
findings[f] {
    input.delegation.operation == "CREATE_GRANT"
    input.delegation.is_delegated == true
    input.delegation.cross_session_match == false
    f := {
        "rule_id": "RULE_DELEGATION_CROSS_SESSION",
        "decision": "DENY",
        "reason": "Delegation proposal references an intent or parent from a different session.",
        "risk_score": 1.0
    }
}

# 4. Subdelegation not allowed by parent
findings[f] {
    input.delegation.operation == "CREATE_GRANT"
    input.delegation.is_delegated == true
    input.delegation.parent_delegation_id != null
    input.delegation.subdelegation_allowed == false
    f := {
        "rule_id": "RULE_DELEGATION_SUBDELEGATION_NOT_ALLOWED",
        "decision": "DENY",
        "reason": "Parent delegation grant explicitly prohibits creating child subdelegations.",
        "risk_score": 0.95
    }
}

# 5. Delegation depth exceeded
findings[f] {
    input.delegation.operation == "CREATE_GRANT"
    input.delegation.is_delegated == true
    input.delegation.depth_within_limits == false
    f := {
        "rule_id": "RULE_DELEGATION_DEPTH_EXCEEDED",
        "decision": "DENY",
        "reason": "Requested delegation depth exceeds maximum allowed session depth.",
        "risk_score": 0.95
    }
}

# 6. Scope exceeds parent
findings[f] {
    input.delegation.operation == "CREATE_GRANT"
    input.delegation.is_delegated == true
    input.delegation.scope_within_parent == false
    f := {
        "rule_id": "RULE_DELEGATION_SCOPE_EXCEEDS_PARENT",
        "decision": "DENY",
        "reason": "Requested delegation authority exceeds parent grant envelope.",
        "risk_score": 1.0
    }
}

# 7. Scope exceeds root
findings[f] {
    input.delegation.operation == "CREATE_GRANT"
    input.delegation.is_delegated == true
    input.delegation.scope_within_root == false
    f := {
        "rule_id": "RULE_DELEGATION_SCOPE_EXCEEDS_ROOT",
        "decision": "DENY",
        "reason": "Requested delegation authority exceeds root Intent Contract scope.",
        "risk_score": 1.0
    }
}

# 8. High-risk delegation requires approval
findings[f] {
    input.delegation.operation == "CREATE_GRANT"
    input.delegation.is_delegated == true
    input.delegation.is_high_risk_delegation == true
    input.delegation.caller_is_authorized_issuer == true
    input.delegation.scope_within_root == true
    input.delegation.scope_within_parent == true
    input.delegation.depth_within_limits == true
    input.delegation.cross_session_match == true
    f := {
        "rule_id": "RULE_DELEGATION_REQUIRE_APPROVAL",
        "decision": "REQUIRE_APPROVAL",
        "reason": "Delegation grants high-risk or approval-required capabilities.",
        "risk_score": 0.7
    }
}

# ==========================================
# EXECUTE_ACTION Rules
# ==========================================

# 9. Principal mismatch
findings[f] {
    input.delegation.operation == "EXECUTE_ACTION"
    input.delegation.is_delegated == true
    input.delegation.principal_matches_delegatee == false
    f := {
        "rule_id": "RULE_DELEGATION_PRINCIPAL_MISMATCH",
        "decision": "DENY",
        "reason": "Authenticated caller principal does not match grant delegatee.",
        "risk_score": 1.0
    }
}

# 10. Grant Revoked
findings[f] {
    input.delegation.operation == "EXECUTE_ACTION"
    input.delegation.is_delegated == true
    input.delegation.effective_status == "REVOKED"
    f := {
        "rule_id": "RULE_DELEGATION_REVOKED",
        "decision": "DENY",
        "reason": "Delegation grant or an ancestor in its chain has been REVOKED.",
        "risk_score": 1.0
    }
}

# 11. Grant Closed
findings[f] {
    input.delegation.operation == "EXECUTE_ACTION"
    input.delegation.is_delegated == true
    input.delegation.effective_status == "CLOSED"
    f := {
        "rule_id": "RULE_DELEGATION_CLOSED",
        "decision": "DENY",
        "reason": "Delegation grant has been CLOSED upon completed task.",
        "risk_score": 0.95
    }
}

# 12. Grant Expired
findings[f] {
    input.delegation.operation == "EXECUTE_ACTION"
    input.delegation.is_delegated == true
    input.delegation.effective_status == "EXPIRED"
    f := {
        "rule_id": "RULE_DELEGATION_EXPIRED",
        "decision": "DENY",
        "reason": "Delegation grant TTL has expired.",
        "risk_score": 0.95
    }
}

# 13. Budget Exhausted / Consumed
findings[f] {
    input.delegation.operation == "EXECUTE_ACTION"
    input.delegation.is_delegated == true
    input.delegation.effective_status == "CONSUMED"
    f := {
        "rule_id": "RULE_DELEGATION_BUDGET_EXHAUSTED",
        "decision": "DENY",
        "reason": "Delegation grant action execution budget has been exhausted.",
        "risk_score": 0.95
    }
}

findings[f] {
    input.delegation.operation == "EXECUTE_ACTION"
    input.delegation.is_delegated == true
    input.delegation.budget_available == false
    f := {
        "rule_id": "RULE_DELEGATION_BUDGET_EXHAUSTED",
        "decision": "DENY",
        "reason": "Action budget on root intent or ancestor grant has been exhausted.",
        "risk_score": 0.95
    }
}

# 14. Root Intent Invalid
findings[f] {
    input.delegation.operation == "EXECUTE_ACTION"
    input.delegation.is_delegated == true
    input.delegation.effective_status == "ROOT_INVALID"
    f := {
        "rule_id": "RULE_DELEGATION_ROOT_INTENT_INVALID",
        "decision": "DENY",
        "reason": "Root Intent Contract is inactive, expired, or revoked.",
        "risk_score": 1.0
    }
}

# 15. Ancestor Invalid
findings[f] {
    input.delegation.operation == "EXECUTE_ACTION"
    input.delegation.is_delegated == true
    input.delegation.effective_status == "ANCESTOR_INVALID"
    f := {
        "rule_id": "RULE_DELEGATION_INVALID_PARENT",
        "decision": "DENY",
        "reason": "An ancestor grant in the delegation hierarchy is expired, consumed, or invalid.",
        "risk_score": 1.0
    }
}

# 16. Tool not authorized
findings[f] {
    input.delegation.operation == "EXECUTE_ACTION"
    input.delegation.is_delegated == true
    input.delegation.current_tool_within_effective_authority == false
    f := {
        "rule_id": "RULE_DELEGATION_TOOL_NOT_AUTHORIZED",
        "decision": "DENY",
        "reason": "Requested tool is not authorized under live effective delegation authority.",
        "risk_score": 1.0
    }
}

# 17. Resource not authorized
findings[f] {
    input.delegation.operation == "EXECUTE_ACTION"
    input.delegation.is_delegated == true
    input.delegation.current_resource_within_effective_authority == false
    f := {
        "rule_id": "RULE_DELEGATION_RESOURCE_NOT_AUTHORIZED",
        "decision": "DENY",
        "reason": "Target resource is not authorized under live effective delegation scope.",
        "risk_score": 1.0
    }
}

# 18. Environment not authorized
findings[f] {
    input.delegation.operation == "EXECUTE_ACTION"
    input.delegation.is_delegated == true
    input.delegation.current_environment_within_effective_authority == false
    f := {
        "rule_id": "RULE_DELEGATION_ENVIRONMENT_NOT_AUTHORIZED",
        "decision": "DENY",
        "reason": "Target environment is not authorized under live effective delegation scope.",
        "risk_score": 1.0
    }
}

# 19. Classification not authorized
findings[f] {
    input.delegation.operation == "EXECUTE_ACTION"
    input.delegation.is_delegated == true
    input.delegation.current_classification_within_effective_authority == false
    f := {
        "rule_id": "RULE_DELEGATION_CLASSIFICATION_NOT_AUTHORIZED",
        "decision": "DENY",
        "reason": "Data classification exceeds live effective delegation limits.",
        "risk_score": 1.0
    }
}

# ==========================================
# RESOLVE_APPROVAL Rules
# ==========================================

# 20. Approval identity mismatch
findings[f] {
    input.delegation.operation == "RESOLVE_APPROVAL"
    input.delegation.approval.approval_context_present == true
    input.delegation.approval.approval_identity_match == false
    f := {
        "rule_id": "RULE_DELEGATION_APPROVAL_IDENTITY_MISMATCH",
        "decision": "DENY",
        "reason": "Approver identity does not match designated approver for delegation checkpoint.",
        "risk_score": 1.0
    }
}

# 21. Approval revalidation failed / Stale authority
findings[f] {
    input.delegation.operation == "RESOLVE_APPROVAL"
    input.delegation.approval.approval_context_present == true
    input.delegation.approval.approval_revalidation_passed == false
    f := {
        "rule_id": "RULE_DELEGATION_APPROVAL_STALE_AUTHORITY",
        "decision": "DENY",
        "reason": "Pre-execution revalidation failed; root intent or parent authority was modified or revoked.",
        "risk_score": 1.0
    }
}

# ==========================================
# REVOKE_GRANT Rules
# ==========================================

# 22. Revocation not authorized
findings[f] {
    input.delegation.operation == "REVOKE_GRANT"
    input.delegation.caller_is_authorized_to_revoke == false
    f := {
        "rule_id": "RULE_DELEGATION_REVOCATION_NOT_AUTHORIZED",
        "decision": "DENY",
        "reason": "Caller is not authorized to revoke this delegation grant.",
        "risk_score": 1.0
    }
}

# ==========================================
# ANALYSIS_FAILURE Rules
# ==========================================

# 23. Delegation analysis failed
findings[f] {
    input.delegation.is_delegated == true
    input.delegation.analysis_status == "FAILED"
    f := {
        "rule_id": "RULE_DELEGATION_ANALYSIS_FAILED",
        "decision": "DENY",
        "reason": "Delegation analysis failed or delegation invariants could not be verified.",
        "risk_score": 1.0
    }
}
