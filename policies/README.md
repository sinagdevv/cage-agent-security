# CAGE Governance Policies (OPA / Rego)

This directory contains declarative Open Policy Agent (OPA) policies written in Rego.

## Policy Model

CAGE evaluates policies against a unified authorization request payload containing:
- `identity`: Agent and caller identifiers, roles, and delegations.
- `intent`: Attested human intent parameters and constraints.
- `proposed_action`: Tool name, arguments, and destination.
- `causal_subgraph`: Ancestor nodes, data classifications, taint tags, and prior side effects.

## Directory Layout

- `base.rego`: Default deny baseline and shared evaluation helper rules.
- `trajectories/`: Domain-specific rules governing causal trajectory patterns.
