# CAGE Architecture Overview

This document describes the high-level architecture of CAGE.

## Components

1. **CAGE Gateway**: Intercepts tool invocation requests before execution.
2. **Intent Engine**: Establishes human intent baselines and boundaries.
3. **Identity & Delegation**: Validates cryptographic signatures and multi-agent parentage.
4. **Provenance Tracker**: Maintains data lineage and taint propagation flags.
5. **Causal Graph Engine**: Constructs and queries in-memory NetworkX DAGs representing action chains.
6. **Policy Engine**: Evaluates OPA / Rego policies against causal subgraphs.
7. **Audit Logger**: Stores immutable records for compliance and forensic analysis.
