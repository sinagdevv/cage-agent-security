# AI Agent Threat Model

This document outlines the threat landscape for autonomous agents operating in hybrid human-software environments.

## Threat Actors

1. **Untrusted External Content Providers**: Malicious websites, compromised third-party APIs, or untrusted user input embedding prompt injections.
2. **Compromised Tool Providers**: Rogue MCP servers or infected plugins.
3. **Malicious Delegating Agents**: Subordinate or peer agents attempting privilege escalation.
4. **Curious or Malicious Insiders**: Internal users attempting to cause unauthorized actions via agent delegation.
