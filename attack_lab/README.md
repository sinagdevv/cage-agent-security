# CAGE Attack Simulation Lab

The Attack Simulation Lab is a controlled research environment designed to simulate, benchmark, and evaluate AI agent attack scenarios against causal governance policies.

## Benchmark Scenarios

1. [`normal_agent/`](normal_agent/): Non-malicious control baseline to measure latency, false-positive authorization denial rates, and normal DAG topology.
2. [`indirect_injection/`](indirect_injection/): Indirect prompt injection attacks embedded in untrusted retrieved documents, attempting to redirect agent intent.
3. [`malicious_mcp/`](malicious_mcp/): Roguish or hijacked Model Context Protocol servers attempting tool privilege escalation or unauthorized local resource calls.
4. [`data_exfiltration/`](data_exfiltration/): Multi-step attacks attempting to read sensitive internal records and exfiltrate them via public channels.
5. [`action_chain_bypass/`](action_chain_bypass/): Evasion techniques where forbidden operations are decomposed into disjoint steps that appear benign in isolation.
6. [`multi_agent/`](multi_agent/): Multi-agent delegation confusion, privilege elevation across agent boundaries, and transitive trust exploitation.
