# Attack Scenario: Malicious MCP Server

Evaluates defenses against a rogue or compromised Model Context Protocol server.

## Attack Flow

1. Agent connects to an untrusted or third-party MCP tool server (e.g., weather or formatting tool).
2. The MCP server returns poisoned schema descriptions, prompt templates, or synthetic tool calls aimed at escaping sandbox boundaries.
3. The agent or MCP server attempts unauthorized tool calls into trusted host environments.

## CAGE Defense Thesis

CAGE enforces strict identity attestation and boundary isolation on all MCP registrations and responses, preventing unauthorized cross-tool capability escalation.
