# Contributing to CAGE

Thank you for your interest in contributing to **CAGE (Causal Authorization and Governance Engine for AI Agents)**!

CAGE is an experimental open-source AI security research platform. We welcome contributions ranging from architectural research, threat models, and benchmark scenarios to engine logic, policy rules, and adapter integrations.

---

## Development Workflow

### Prerequisites

- **Python 3.12+**
- **Node.js 20+** and **npm**
- **Docker** and **Docker Compose**
- **Git**

### Repository Layout

- `backend/`: FastAPI core service, authorization gateway, provenance, graph engine, and policy evaluation.
- `frontend/`: React + Vite + TypeScript dashboard for visualizing causal execution graphs.
- `adapters/`: Integration adapters for agent frameworks (LangGraph, Model Context Protocol).
- `sdk/`: Client libraries for integrating agents with CAGE.
- `attack_lab/`: Controlled attack simulations for testing and benchmarking governance capabilities.
- `policies/`: Declarative security policies (Rego / Open Policy Agent).
- `research/`: Threat models, research notes, benchmark datasets, and formal specifications.
- `docs/`: System documentation, architecture diagrams, and security models.

---

## Getting Started

### 1. Clone & Set Up Environment

```bash
git clone https://github.com/sinagdevv/cage-agent-security.git
cd cage-agent-security
cp .env.example .env
```

### 2. Backend Setup

```bash
cd backend
python -m venv .venv
# On Windows:
.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate

pip install -e ".[dev]"
```

Run tests and linting:
```bash
python -m pytest
python -m ruff check .
```

### 3. Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

### 4. Running with Docker Compose

For local end-to-end development with PostgreSQL, Redis, and OPA:
```bash
docker compose up -d
```

---

## Coding Guidelines

- **Python**: Follow PEP 8 via `ruff`. Keep dependencies minimal. Ensure type annotations are used for public APIs.
- **Frontend**: Use TypeScript strict mode and modular Vanilla CSS or CSS modules.
- **Testing**: Every new feature or attack scenario should include corresponding unit or integration tests.
- **Commit Messages**: Write concise, imperative commit messages (e.g., `feat(graph): add trajectory cycle detection`).

---

## Pull Request Process

1. Fork the repository and create your branch from `main`.
2. Ensure existing tests pass and linting reports no errors.
3. Add tests covering any new functionality or bug fixes.
4. Update documentation in `docs/` or inline docstrings when altering architectures or interfaces.
5. Submit your PR with a clear description of the problem, approach, and testing evidence.
