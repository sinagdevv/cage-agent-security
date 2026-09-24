# Baseline CAGE OPA Policy
package cage.authz

# Default to deny (secure by default)
default allow = false
default reason = "No explicit authorization rule matched."

# Allow benign health checks or ping actions
allow {
    input.proposed_action.type == "health_check"
}

# Baseline rule: Action must be causally rooted in verified intent
action_has_verified_intent {
    some ancestor in input.causal_subgraph.ancestors
    ancestor.node_type == "intent"
    ancestor.verified == true
}

# Baseline deny: Prohibit external network dispatch if tainted ancestor exists
deny_tainted_external_dispatch {
    input.proposed_action.category == "network_outbound"
    some ancestor in input.causal_subgraph.ancestors
    ancestor.tainted == true
}
