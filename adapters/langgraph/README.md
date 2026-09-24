# LangGraph Adapter

Adapter integrating CAGE with LangGraph state graphs and execution nodes.

## Role in Architecture

- Intercepts state transitions and tool nodes in LangGraph agent workflows.
- Serializes LangGraph state histories into CAGE causal DAG nodes and edges.
- Provides conditional routing edges (`check_cage_authorization`) to gate next-step execution.
