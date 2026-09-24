"""Causal execution graph foundation using NetworkX.

Represents agent actions, tool invocations, artifacts, and information flows
as a Directed Acyclic Graph (DAG) for trajectory-level policy evaluation.
"""

from typing import Any

import networkx as nx


class CausalExecutionGraph:
    """Foundational graph structure for tracking causal agent trajectories."""

    def __init__(self, session_id: str):
        self.session_id = session_id
        self._graph = nx.DiGraph(session_id=session_id)

    @property
    def graph(self) -> nx.DiGraph:
        """Access underlying NetworkX DiGraph instance."""
        return self._graph

    def add_node(
        self,
        node_id: str,
        node_type: str,
        attributes: dict[str, Any] | None = None,
    ) -> None:
        """Add a node to the causal trajectory (e.g., intent, tool_call, observation)."""
        attrs = attributes or {}
        self._graph.add_node(node_id, node_type=node_type, **attrs)

    def add_causal_edge(
        self,
        source_id: str,
        target_id: str,
        relation: str = "causes",
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Add a directed causal relation between two nodes."""
        meta = metadata or {}
        self._graph.add_edge(source_id, target_id, relation=relation, **meta)

    def get_ancestors(self, node_id: str) -> list[str]:
        """Retrieve all ancestor node IDs that causally influenced the specified node."""
        if not self._graph.has_node(node_id):
            return []
        return list(nx.ancestors(self._graph, node_id))

    def get_descendants(self, node_id: str) -> list[str]:
        """Retrieve all descendant node IDs causally triggered by the specified node."""
        if not self._graph.has_node(node_id):
            return []
        return list(nx.descendants(self._graph, node_id))

    def node_count(self) -> int:
        """Return total number of nodes in the graph."""
        return self._graph.number_of_nodes()

    def edge_count(self) -> int:
        """Return total number of edges in the graph."""
        return self._graph.number_of_edges()

    def is_dag(self) -> bool:
        """Check if the execution graph is a valid Directed Acyclic Graph."""
        return nx.is_directed_acyclic_graph(self._graph)
