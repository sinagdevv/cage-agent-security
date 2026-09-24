# Model Context Protocol (MCP) Adapter

Adapter connecting CAGE governance to Model Context Protocol (MCP) clients and servers.

## Role in Architecture

- Intercepts JSON-RPC tool invocation messages (`tools/call`).
- Inspects client arguments, session metadata, and tool identity.
- Evaluates the proposed call against CAGE causal authorization policies.
- Passes authorized requests to the target MCP server or injects synthetic denial responses.
