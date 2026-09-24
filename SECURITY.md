# Security Policy

## Reporting Security Issues

The CAGE project takes security seriously. If you discover a vulnerability or security issue within CAGE or any of its reference implementations, please disclose it responsibly.

### How to Report

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report vulnerabilities using one of the following methods:
- **GitHub Private Vulnerability Reporting**: Use the "Report a vulnerability" button under the **Security** tab of this repository.
- **Direct Email**: Send details to `security@cage-agent.dev` (or the maintainer contact specified in the repository).

### Information to Include

When reporting a vulnerability, please provide:
1. A clear description of the potential vulnerability.
2. Steps to reproduce the issue or a minimal Proof of Concept (PoC).
3. The potential impact of exploitation (e.g., policy bypass, unauthorized tool execution, state tampering).
4. Any potential mitigations or patches you have identified.

### Response Timeline

- **Initial Acknowledgment**: Within 48 hours.
- **Assessment & Triage**: Within 5 business days.
- **Fix & Public Advisory**: Coordinated release following validation of the patch.

### Scope

As CAGE is currently an experimental open-source research project:
- Reference attack vectors in `attack_lab/` are intended demonstrations of agent vulnerabilities for benchmarking purposes.
- Vulnerabilities within the CAGE governance engine itself (e.g., authorization bypasses, graph tampering, policy injection) are within scope and high priority.
