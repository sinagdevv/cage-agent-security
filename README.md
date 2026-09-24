# CAGE: Causal Authorization and Governance Engine for AI Agents

> **Experimental Open-Source AI Security Research Platform**

[![Python Version](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Pre--Alpha%20%2F%20Foundation-orange.svg)](#current-development-status)

CAGE (**Causal Authorization and Governance Engine**) is an experimental open-source security platform designed to explore and evaluate authorization mechanisms for autonomous AI agent systems. 

Rather than treating tool executions as isolated API calls, CAGE investigates an authorization paradigm centered on the primary research thesis:

> **"AI agent security should authorize causal action trajectories, not merely individual tool calls."**

---

## 1. What is CAGE?

CAGE is a policy enforcement and runtime governance engine designed specifically for tool-using AI agents (such as agents orchestrated via LangGraph or interacting through the Model Context Protocol - MCP). 

At its core, CAGE observes the full trajectory of an agent's reasoning, tool invocations, data provenance, and delegation chains. Before allowing a potentially sensitive operation to execute, CAGE evaluates not just *what* tool is being called, but *why* it is being called, *what information* influenced that decision, and *what cumulative side effects* have accrued across the entire execution graph.

*Disclaimer: CAGE is an exploratory research project. It does not claim to completely solve AI agent security, nor does it claim that the concept of causal authorization is globally unique. It serves as a testbed for formalizing, implementing, and benchmarking causal governance models in real-world agent workflows.*

---

## 2. The Problem It Attempts to Solve

Existing access control systems (such as RBAC, ABAC, or traditional API rate limiting and scopes) were designed for deterministic, human-driven software. When applied to autonomous, LLM-powered agents, traditional perimeter and tool-level authorization reveals critical limitations:

1. **Per-Call Blindness (Confused Deputy Problem)**:
   A tool invocation like `send_email(to="recipient@example.com", body=...)` or `http_post(url=...)` might look completely benign when inspected in isolation. However, if the agent read a confidential customer file two steps prior as a consequence of an indirect prompt injection from an untrusted webpage, that benign-looking tool call is actually an unauthorized exfiltration.
2. **Loss of Causal Context**:
   Static permissions grant an agent permission to use a tool (e.g., `execute_sql` or `filesystem_read`). Traditional security models cannot determine whether the tool invocation is causally linked to verified human intent or whether an adversary injected instructions mid-trajectory.
3. **Cumulative Blast Radius**:
   Autonomous agents iterate over complex loops. While each step might stay under individual safety thresholds, the cumulative effect of a 20-step loop may lead to resource exhaustion, data mass-harvesting, or unintended cascading system changes.
4. **Agent Delegation & Multi-Agent Confusion**:
   When Agent A delegates subtasks to Agent B via MCP or LangGraph, provenance is easily lost or spoofed unless intermediate states, intents, and identities are cryptographically or causally attested.

---

## 3. The Causal Authorization Idea

CAGE introduces the concept of **Causal Action Trajectory Authorization**:

```
[Human Intent] ──(attested)──> [Agent Task] 
                                    │
    ┌───────────────────────────────┴───────────────────────────────┐
    ▼                                                               ▼
[Step 1: Read Public URL]                                  [Step 2: Read Local File]
    │ (Tainted Input Detected)                                      │ (Sensitive Data)
    ▼                                                               ▼
[Step 3: Intermediate Reasoning / Delegation] ◄─────────────────────┘
    │
    ▼ (Causal Edge: Tainted Data + Sensitive Data Flow)
[Step 4: Network POST / Webhook] 
    │
    ▼
[CAGE Policy Evaluation]:
    - Checks: Did Step 4 consume untrusted external data and sensitive local data?
    - Checks: Does human intent allow external exfiltration of local records?
    - Verdict: DENIED / QUARANTINED (Action blocked before dispatch)
```

In CAGE:
- Every action is represented as a node in a **Directed Acyclic Graph (DAG)** of execution.
- Edges represent **causal dependencies**: data flow, reasoning triggers, delegation parentage, and temporal ordering.
- Policies are defined over **subgraphs and trajectories**, answering queries such as:
  *"Deny any write or network operation if any ancestor node in the causal graph derived from an unverified external source, unless explicit human-in-the-loop confirmation was provided."*

---

## 4. High-Level Architecture

CAGE operates as a mediating governance layer between agents and tools:

```
┌────────────────────────────────────────────────────────┐
│                   Agent Runtime                        │
│       (LangGraph / MCP Client / Custom Agent)          │
└──────────────────────────┬─────────────────────────────┘
                           │ (Tool Request & Context)
                           ▼
┌────────────────────────────────────────────────────────┐
│                   CAGE Gateway                         │
│  ┌───────────────────────┬───────────────────────────┐ │
│  │   Intent Attestation  │   Agent Identity Verifier │ │
│  └───────────────────────┴───────────────────────────┘ │
│  ┌───────────────────────┬───────────────────────────┐ │
│  │  Provenance Tracker   │   Causal Graph Engine     │ │
│  │  (Data Flow Analysis) │   (NetworkX / Trajectory) │ │
│  └───────────────────────┴───────────────────────────┘ │
│  ┌───────────────────────────────────────────────────┐ │
│  │         Policy Engine (Open Policy Agent)         │ │
│  │         - Rego Rules for Causal Graphs            │ │
│  └───────────────────────────────────────────────────┘ │
│  ┌───────────────────────────────────────────────────┐ │
│  │                 Audit & Observability             │ │
│  │         - OpenTelemetry & Cryptographic Log       │ │
│  └───────────────────────────────────────────────────┘ │
└────────────┬─────────────────────────────┬─────────────┘
             │ (Authorized Request)        │ (Denied / Escalated)
             ▼                             ▼
┌────────────────────────┐    ┌──────────────────────────┐
│      Target Tools      │    │  Human-in-the-Loop Queue │
│   (MCP Servers / APIs) │    │  & Security Dashboard    │
└────────────────────────┘    └──────────────────────────┘
```

---

## 5. Planned Technology Stack

To keep the initial research phase focused, reproducible, and lightweight, the tech stack is intentionally composed of proven, modular components:

- **Backend**: Python 3.12+, FastAPI, Pydantic, SQLAlchemy
- **Database**: PostgreSQL (relational state, audit logs, run metadata)
- **Runtime Graph Representation**: NetworkX (in-memory causal trajectory modeling)
- **Policy Enforcement**: Open Policy Agent (OPA) with Rego rules
- **Runtime State & Caching**: Redis (fast session state and pub/sub)
- **Observability**: OpenTelemetry
- **Agent Framework Support**: LangGraph
- **Agent Protocol Support**: Model Context Protocol (MCP)
- **LLM Integrations**: OpenAI-compatible endpoints & Ollama for offline local testing
- **Frontend Dashboard**: React, Vite, TypeScript, React Flow (interactive graph inspection), WebSockets (real-time stream)
- **Testing**: Pytest & pytest-asyncio
- **Infrastructure**: Docker & Docker Compose
- **Continuous Integration**: GitHub Actions

### Explicitly Excluded at this Stage
To prevent premature complexity, the following are **not** used:
- Kubernetes
- Apache Kafka
- Neo4j
- Blockchain
- Black-box ML anomaly detectors
- Complex microservice fabrics

---

## 6. Current Development Status

- **Phase**: **Initialization / Repository Foundation**
- **Implemented Foundation**:
  - Modular backend layout separating gateway, intent, identity, provenance, graph, policies, and audit modules.
  - Python project configuration (`pyproject.toml`) with Pytest and Ruff linting.
  - Development Docker Compose environment supporting backend, frontend, PostgreSQL, Redis, and OPA.
  - React + Vite + TypeScript frontend workspace.
  - GitHub Actions CI pipelines for backend tests, linting, and frontend builds.
  - Standardized research, policy, adapter, and attack lab directories.
- **Next Steps**:
  - Phase 1: Core causal graph data model and minimal gateway proxy.
  - Phase 2: Rego policy definitions for trajectory verification.
  - Phase 3: LangGraph and MCP adapter prototypes.

---

## 7. Research Goals

The project explores three central research questions:

1. **Expressiveness**: Can declarative graph-pattern policies (e.g., using Rego over causal trajectory representations) capture realistic attack classes that per-call policies cannot?
2. **Latency & Overhead**: What is the computational and latency overhead of maintaining and evaluating a causal action DAG synchronously before tool dispatch?
3. **Generalizability**: How well does causal trajectory authorization generalize across diverse agent frameworks (LangGraph, MCP, custom loops) without requiring intrusive modifications to agent code?

---

## 8. Planned Attack Simulation Lab (`attack_lab/`)

To rigorously benchmark CAGE's governance capabilities, the repository includes dedicated research testbeds under `attack_lab/`:

1. `normal_agent/`: Baseline non-malicious tasks establishing normal trajectory benchmarks.
2. `indirect_injection/`: Retrieval-augmented tasks where untrusted third-party content injects malicious instructions into agent reasoning.
3. `malicious_mcp/`: Compromised or hostile Model Context Protocol tool servers attempting privilege escalation.
4. `data_exfiltration/`: Chains designed to read restricted sensitive artifacts and transmit them externally via seemingly harmless operations.
5. `action_chain_bypass/`: Attacks that divide a forbidden action into smaller, seemingly harmless intermediate steps to bypass per-call controls.
6. `multi_agent/`: Multi-agent delegation loops where malicious instructions are passed across agent boundaries to cause confused deputy behavior.

---

## Getting Started

See [CONTRIBUTING.md](CONTRIBUTING.md) for local development setup and guidelines.
For security concerns, please refer to [SECURITY.md](SECURITY.md).

## License

This project is licensed under the [Apache 2.0 License](LICENSE).
