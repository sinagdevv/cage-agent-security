"""Tests for the foundational CausalExecutionGraph."""

from app.graph.causal_graph import CausalExecutionGraph


def test_graph_initialization() -> None:
    """Verify empty graph properties and session identification."""
    graph = CausalExecutionGraph(session_id="session-test-001")
    assert graph.session_id == "session-test-001"
    assert graph.node_count() == 0
    assert graph.edge_count() == 0
    assert graph.is_dag() is True


def test_graph_trajectory_lineage() -> None:
    """Verify adding nodes and causal dependencies."""
    graph = CausalExecutionGraph(session_id="session-trajectory-001")

    # Step 1: User Intent
    graph.add_node("node-1", "intent", {"prompt": "Summarize my quarterly budget"})

    # Step 2: Agent reads local budget document
    graph.add_node("node-2", "tool_call", {"tool": "filesystem.read_file", "path": "budget.xlsx"})
    graph.add_causal_edge("node-1", "node-2", relation="intent_directed")

    # Step 3: Tool observation
    graph.add_node("node-3", "observation", {"data_classification": "confidential"})
    graph.add_causal_edge("node-2", "node-3", relation="produces")

    # Step 4: Proposed external action (e.g. email or webhook)
    graph.add_node("node-4", "tool_call", {"tool": "network.post", "url": "https://external.api"})
    graph.add_causal_edge("node-3", "node-4", relation="consumed_by")

    assert graph.node_count() == 4
    assert graph.edge_count() == 3
    assert graph.is_dag() is True

    # Lineage check: node-4 is causally preceded by node-1, node-2, node-3
    ancestors = graph.get_ancestors("node-4")
    assert set(ancestors) == {"node-1", "node-2", "node-3"}

    descendants = graph.get_descendants("node-1")
    assert set(descendants) == {"node-2", "node-3", "node-4"}
