# Attack Scenario: Multi-Agent Delegation Exploits

Evaluates vulnerabilities arising in collaborative, multi-agent systems.

## Attack Flow

1. Low-privilege Agent A receives untrusted input and delegates a subtask to high-privilege Agent B.
2. Agent B executes the requested action believing it was initiated by an authorized administrator (Confused Deputy).

## CAGE Defense Thesis

CAGE tracks causal parentage and cryptographic identity tokens across agent boundaries. The provenance trail of the initiating trigger is preserved, preventing privilege elevation through delegation.
