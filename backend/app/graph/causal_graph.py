"""Causal execution graph foundation using NetworkX.

Represents agent actions, tool invocations, artifacts, and information flows
as a Directed Acyclic Graph (DAG) for trajectory-level policy evaluation.

PHASE 1 NOTICE:
The SessionGraphManager is an in-memory, process-local registry.
State will be lost upon server restart and is not intended for distributed production.
"""

import threading
from datetime import UTC, datetime
from typing import Any

import networkx as nx

from app.schemas.action import AgentAction
from app.schemas.enums import PolicyDecision, ToolExecutionStatus


class ActionCollisionError(ValueError):
    """Raised when an attempt is made to overwrite an existing action in the graph."""


class ParentActionNotFoundError(ValueError):
    """Raised when a referenced parent action does not exist."""


class CrossSessionParentError(ValueError):
    """Raised when a parent action belongs to a different session."""


class CausalExecutionGraph:
    """Foundational graph structure for tracking causal agent trajectories."""

    def __init__(self, session_id: str):
        self.session_id = session_id
        self._graph = nx.DiGraph(session_id=session_id)
        self._actions: dict[str, AgentAction] = {}

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
        """Add a raw node to the causal trajectory (e.g. intent, observation, artifact)."""
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

    def add_intent_node(
        self,
        intent_id: str,
        goal: str,
        agent_id: str,
        user_id: str | None = None,
        created_at: str | None = None,
    ) -> None:
        """Record an Intent Contract as a root governance node."""
        if not self._graph.has_node(intent_id):
            self._graph.add_node(
                intent_id,
                node_type="intent",
                goal=goal,
                agent_id=agent_id,
                user_id=user_id,
                created_at=created_at or datetime.now(UTC).isoformat(),
            )

    def add_governs_edge(self, intent_id: str, action_id: str) -> None:
        """Link an Intent Contract to an action it governs."""
        if not self._graph.has_node(intent_id):
            raise KeyError(f"Intent node '{intent_id}' does not exist in session graph.")
        if not self._graph.has_node(action_id):
            raise KeyError(f"Action node '{action_id}' does not exist in session graph.")
        self._graph.add_edge(intent_id, action_id, relation="governs")

    def add_action(self, action: AgentAction) -> None:
        """Record an authoritative AgentAction as a node in the causal graph.

        Raises ActionCollisionError if the action_id already exists to prevent
        historical mutation.
        """
        action_key = str(action.action_id)
        if action_key in self._actions or self._graph.has_node(action_key):
            raise ActionCollisionError(
                f"Action '{action_key}' already exists in session '{self.session_id}'."
            )

        self._actions[action_key] = action
        self._graph.add_node(
            action_key,
            node_type="action",
            agent_id=action.agent_id,
            tool_name=action.tool_name,
            action_type=action.action_type.value,
            target_environment=action.target_environment.value,
            execution_status=action.execution_status.value,
            policy_result=action.policy_result.value if action.policy_result else None,
            risk_score=action.risk_score,
            intent_contract_id=str(action.intent_contract_id)
            if action.intent_contract_id
            else None,
            created_at=action.created_at.isoformat(),
        )

    def update_action_state(
        self,
        action_id: str,
        execution_status: ToolExecutionStatus,
        policy_result: PolicyDecision | None = None,
        security_reason: str | None = None,
        matched_rules: list[str] | None = None,
        risk_score: float | None = None,
        execution_result: dict[str, Any] | None = None,
    ) -> None:
        """Update the state of an existing action node following evaluation or execution."""
        if action_id not in self._actions:
            raise KeyError(f"Action '{action_id}' not found in session '{self.session_id}'.")

        action = self._actions[action_id]
        action.execution_status = execution_status
        if policy_result is not None:
            action.policy_result = policy_result
        if security_reason is not None:
            action.security_reason = security_reason
        if matched_rules is not None:
            action.matched_rules = matched_rules
        if risk_score is not None:
            action.risk_score = risk_score
        if execution_result is not None:
            action.execution_result = execution_result
        action.updated_at = datetime.now(UTC)

        # Update NetworkX node attributes
        node_attrs = self._graph.nodes[action_id]
        node_attrs["execution_status"] = execution_status.value
        if policy_result is not None:
            node_attrs["policy_result"] = policy_result.value
        if risk_score is not None:
            node_attrs["risk_score"] = risk_score
        if execution_result is not None:
            node_attrs["has_execution_result"] = True

    def add_relationship(
        self,
        source_id: str,
        target_id: str,
        relation: str = "causes",
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Add a directed causal relation between two existing nodes."""
        if not self._graph.has_node(source_id):
            raise ParentActionNotFoundError(f"Source action '{source_id}' does not exist in graph.")
        if not self._graph.has_node(target_id):
            raise KeyError(f"Target action '{target_id}' does not exist in graph.")

        meta = metadata or {}
        self._graph.add_edge(source_id, target_id, relation=relation, **meta)

    def get_action(self, action_id: str) -> AgentAction | None:
        """Retrieve authoritative AgentAction by ID."""
        return self._actions.get(action_id)

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

    def get_session_graph(self) -> dict[str, Any]:
        """Serialize current session trajectory graph to JSON-friendly representation."""
        nodes = []
        for node_id, data in self._graph.nodes(data=True):
            node_type = data.get("node_type", "action")
            node_info: dict[str, Any] = {
                "id": node_id,
                "node_type": node_type,
                "agent_id": data.get("agent_id"),
                "created_at": data.get("created_at"),
            }
            if node_type == "intent":
                node_info["goal"] = data.get("goal")
                node_info["user_id"] = data.get("user_id")
            else:
                node_info.update(
                    {
                        "tool_name": data.get("tool_name"),
                        "action_type": data.get("action_type"),
                        "target_environment": data.get("target_environment"),
                        "execution_status": data.get("execution_status"),
                        "policy_result": data.get("policy_result"),
                        "risk_score": data.get("risk_score"),
                        "intent_contract_id": data.get("intent_contract_id"),
                    }
                )
            nodes.append(node_info)

        edges = []
        for u, v, data in self._graph.edges(data=True):
            edges.append(
                {
                    "source": u,
                    "target": v,
                    "relation": data.get("relation", "causes"),
                }
            )

        return {
            "session_id": self.session_id,
            "node_count": len(nodes),
            "edge_count": len(edges),
            "is_dag": self.is_dag(),
            "nodes": nodes,
            "edges": edges,
        }


class SessionGraphManager:
    """Thread-safe in-memory manager for session graphs during Phase 1.

    Maintains process-local isolation of session graphs.
    """

    def __init__(self) -> None:
        self._sessions: dict[str, CausalExecutionGraph] = {}
        self._action_to_session: dict[str, str] = {}
        self._lock = threading.Lock()

    def get_or_create(self, session_id: str) -> CausalExecutionGraph:
        """Retrieve existing graph or initialize a new one for session_id."""
        with self._lock:
            if session_id not in self._sessions:
                self._sessions[session_id] = CausalExecutionGraph(session_id)
            return self._sessions[session_id]

    def get(self, session_id: str) -> CausalExecutionGraph | None:
        """Retrieve existing graph for session_id, or None if not found."""
        with self._lock:
            return self._sessions.get(session_id)

    def register_action_session(self, action_id: str, session_id: str) -> None:
        """Map action_id to session_id for global lookup."""
        with self._lock:
            self._action_to_session[action_id] = session_id

    def get_action_globally(self, action_id: str) -> AgentAction | None:
        """Lookup an action across all active sessions by action_id."""
        with self._lock:
            session_id = self._action_to_session.get(action_id)
            if not session_id or session_id not in self._sessions:
                return None
            return self._sessions[session_id].get_action(action_id)

    def session_exists(self, session_id: str) -> bool:
        """Check if session is registered."""
        with self._lock:
            return session_id in self._sessions

    def clear(self) -> None:
        """Clear all session graphs (primarily for test isolation)."""
        with self._lock:
            self._sessions.clear(
                self._action_to_session.clear()  # type: ignore[func-returns-value]
            ) if hasattr(self._action_to_session, "clear") else None
            self._action_to_session.clear()


# Default singleton instance for dependency injection
default_session_graph_manager = SessionGraphManager()
