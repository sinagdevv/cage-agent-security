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
from uuid import UUID

import networkx as nx

from app.schemas.action import AgentAction
from app.schemas.enums import GraphNodeType, GraphRelation, PolicyDecision, ToolExecutionStatus


class ActionCollisionError(ValueError):
    """Raised when an attempt is made to overwrite an existing action in the graph."""


class ParentActionNotFoundError(ValueError):
    """Raised when a referenced parent action does not exist."""


class CrossSessionParentError(ValueError):
    """Raised when a parent action belongs to a different session."""


class GraphCycleError(ValueError):
    """Raised when adding a causal edge would violate the DAG invariant by creating a cycle."""


class GraphTraversalLimitError(ValueError):
    """Raised when a graph traversal exceeds configured depth or node limits."""


class ProvenanceCycleError(ValueError):
    """Raised when an artifact derivation edge would create a cycle in the provenance graph."""


class DelegationCycleError(ValueError):
    """Raised when a subdelegation edge would create a cycle in the delegation hierarchy."""


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

    def has_node(self, node_id: str) -> bool:
        """Check if a node ID exists in the graph."""
        return self._graph.has_node(node_id)

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
        relation: GraphRelation | str = GraphRelation.CAUSES,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Add a directed causal relation between two nodes with cycle prevention."""
        rel_str = relation.value if isinstance(relation, GraphRelation) else str(relation)
        if rel_str in (GraphRelation.CAUSES.value, "causes"):
            causes_graph = nx.subgraph_view(
                self._graph,
                filter_edge=lambda u, v: (
                    self._graph[u][v].get("relation") in (GraphRelation.CAUSES.value, "causes")
                ),
            )
            if causes_graph.has_node(target_id) and causes_graph.has_node(source_id):
                if nx.has_path(causes_graph, target_id, source_id):
                    raise GraphCycleError(
                        f"Causal cycle detected: adding causal edge from '{source_id}' to '{target_id}' "
                        f"would create a directed cycle in session '{self.session_id}'."
                    )
        meta = metadata or {}
        self._graph.add_edge(source_id, target_id, relation=rel_str, **meta)

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
                node_type=GraphNodeType.INTENT.value,
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
        self._graph.add_edge(intent_id, action_id, relation=GraphRelation.GOVERNS.value)

    def add_agent_node(
        self,
        agent_id: str,
        is_control_plane: bool = False,
        session_id: str | None = None,
    ) -> None:
        """Record an Agent identity node in the causal graph."""
        if not self._graph.has_node(agent_id):
            self._graph.add_node(
                agent_id,
                node_type=GraphNodeType.AGENT.value,
                agent_id=agent_id,
                is_control_plane=is_control_plane,
                session_id=session_id or self.session_id,
                created_at=datetime.now(UTC).isoformat(),
            )

    def add_delegation_node(self, grant: Any) -> None:
        """Record a DelegationGrant node in the causal graph."""
        del_id = str(grant.delegation_id)
        if not self._graph.has_node(del_id):
            self._graph.add_node(
                del_id,
                node_type=GraphNodeType.DELEGATION.value,
                delegation_id=del_id,
                parent_delegation_id=str(grant.parent_delegation_id)
                if grant.parent_delegation_id
                else None,
                root_intent_id=str(grant.root_intent_id),
                session_id=str(grant.session_id),
                delegator_agent_id=grant.delegator_agent_id,
                delegatee_agent_id=grant.delegatee_agent_id,
                delegated_task_id=grant.delegated_task_id,
                depth=grant.depth,
                remaining_subdelegation_depth=grant.remaining_subdelegation_depth,
                allow_subdelegation=grant.allow_subdelegation,
                max_actions=grant.max_actions,
                created_at=grant.created_at.isoformat()
                if hasattr(grant.created_at, "isoformat")
                else str(grant.created_at),
                expires_at=grant.expires_at.isoformat()
                if hasattr(grant.expires_at, "isoformat")
                else str(grant.expires_at),
            )

    def add_issues_delegation_edge(self, agent_id: str, delegation_id: str) -> None:
        """Record that an agent issued a delegation: Agent --ISSUES_DELEGATION--> Delegation."""
        if not self._graph.has_node(agent_id):
            self.add_agent_node(agent_id)
        if not self._graph.has_node(delegation_id):
            raise KeyError(f"Delegation node '{delegation_id}' does not exist.")
        self._graph.add_edge(
            agent_id, delegation_id, relation=GraphRelation.ISSUES_DELEGATION.value
        )

    def add_grants_to_edge(self, delegation_id: str, agent_id: str) -> None:
        """Record that a grant authorizes a recipient: Delegation --GRANTS_TO--> Agent."""
        if not self._graph.has_node(delegation_id):
            raise KeyError(f"Delegation node '{delegation_id}' does not exist.")
        if not self._graph.has_node(agent_id):
            self.add_agent_node(agent_id)
        self._graph.add_edge(delegation_id, agent_id, relation=GraphRelation.GRANTS_TO.value)

    def add_subdelegates_edge(self, parent_delegation_id: str, child_delegation_id: str) -> None:
        """Record parent-to-child subdelegation with strict cycle rejection."""
        if not self._graph.has_node(parent_delegation_id):
            raise KeyError(f"Parent delegation node '{parent_delegation_id}' does not exist.")
        if not self._graph.has_node(child_delegation_id):
            raise KeyError(f"Child delegation node '{child_delegation_id}' does not exist.")

        subdel_graph = nx.subgraph_view(
            self._graph,
            filter_edge=lambda u, v: (
                self._graph[u][v].get("relation") == GraphRelation.SUBDELEGATES.value
            ),
        )
        if subdel_graph.has_node(child_delegation_id) and subdel_graph.has_node(
            parent_delegation_id
        ):
            if nx.has_path(subdel_graph, child_delegation_id, parent_delegation_id):
                raise DelegationCycleError(
                    f"Delegation cycle detected: adding subdelegates edge from '{parent_delegation_id}' "
                    f"to '{child_delegation_id}' would create a cycle in session '{self.session_id}'."
                )
        self._graph.add_edge(
            parent_delegation_id,
            child_delegation_id,
            relation=GraphRelation.SUBDELEGATES.value,
        )

    def add_creates_delegation_edge(self, action_id: str, delegation_id: str) -> None:
        """Record action-to-grant creation correlation: Action --CREATES_DELEGATION--> Delegation."""
        if not self._graph.has_node(action_id):
            raise KeyError(f"Action node '{action_id}' does not exist.")
        if not self._graph.has_node(delegation_id):
            raise KeyError(f"Delegation node '{delegation_id}' does not exist.")
        self._graph.add_edge(
            action_id, delegation_id, relation=GraphRelation.CREATES_DELEGATION.value
        )

    def add_delegation_governs_edge(self, delegation_id: str, action_id: str) -> None:
        """Record delegation-level governance: Delegation --GOVERNS--> Action."""
        if not self._graph.has_node(delegation_id):
            raise KeyError(f"Delegation node '{delegation_id}' does not exist.")
        if not self._graph.has_node(action_id):
            raise KeyError(f"Action node '{action_id}' does not exist.")
        self._graph.add_edge(delegation_id, action_id, relation=GraphRelation.GOVERNS.value)

    def add_intent_delegation_governs_edge(self, intent_id: str, delegation_id: str) -> None:
        """Record root intent governance over delegation: Intent --GOVERNS--> Delegation."""
        if not self._graph.has_node(intent_id):
            raise KeyError(f"Intent node '{intent_id}' does not exist.")
        if not self._graph.has_node(delegation_id):
            raise KeyError(f"Delegation node '{delegation_id}' does not exist.")
        self._graph.add_edge(intent_id, delegation_id, relation=GraphRelation.GOVERNS.value)

    def add_artifact_node(self, artifact: Any) -> None:
        """Record an InformationArtifact as an authoritative data provenance node.

        Security: Raw payloads and sensitive content digests are excluded from graph attributes.
        """
        art_id = str(artifact.artifact_id)
        if not self._graph.has_node(art_id):
            self._graph.add_node(
                art_id,
                node_type=GraphNodeType.ARTIFACT.value,
                artifact_id=art_id,
                session_id=artifact.session_id,
                source_type=artifact.source_type.value
                if hasattr(artifact.source_type, "value")
                else str(artifact.source_type),
                source_resource=artifact.source_resource,
                direct_trust_level=artifact.direct_trust_level.value
                if hasattr(artifact.direct_trust_level, "value")
                else str(artifact.direct_trust_level),
                inherited_trust_levels=[
                    t.value if hasattr(t, "value") else str(t)
                    for t in artifact.inherited_trust_levels
                ],
                data_classifications=[
                    c.value if hasattr(c, "value") else str(c)
                    for c in artifact.data_classifications
                ],
                size_bytes=artifact.size_bytes,
                mime_type=artifact.mime_type,
                created_at=artifact.created_at.isoformat()
                if hasattr(artifact.created_at, "isoformat")
                else str(artifact.created_at),
            )

    def add_produces_edge(self, action_id: str, artifact_id: str) -> None:
        """Record that an authorized action generated an artifact: Action --PRODUCES--> Artifact."""
        if not self._graph.has_node(action_id):
            raise KeyError(f"Action node '{action_id}' does not exist in session graph.")
        if not self._graph.has_node(artifact_id):
            raise KeyError(f"Artifact node '{artifact_id}' does not exist in session graph.")
        self._graph.add_edge(action_id, artifact_id, relation=GraphRelation.PRODUCES.value)

    def add_consumes_edge(self, artifact_id: str, action_id: str) -> None:
        """Record that an authorized action consumed an artifact: Artifact --CONSUMES--> Action."""
        if not self._graph.has_node(artifact_id):
            raise KeyError(f"Artifact node '{artifact_id}' does not exist in session graph.")
        if not self._graph.has_node(action_id):
            raise KeyError(f"Action node '{action_id}' does not exist in session graph.")
        self._graph.add_edge(artifact_id, action_id, relation=GraphRelation.CONSUMES.value)

    def add_derived_from_edge(self, child_artifact_id: str, parent_artifact_id: str) -> None:
        """Record derivation lineage: ChildArtifact --DERIVED_FROM--> ParentArtifact.

        Enforces cycle prevention: raises ProvenanceCycleError if parent has a path to child.
        """
        if not self._graph.has_node(child_artifact_id):
            raise KeyError(f"Child artifact node '{child_artifact_id}' does not exist.")
        if not self._graph.has_node(parent_artifact_id):
            raise KeyError(f"Parent artifact node '{parent_artifact_id}' does not exist.")

        derived_graph = nx.subgraph_view(
            self._graph,
            filter_edge=lambda u, v: (
                self._graph[u][v].get("relation") == GraphRelation.DERIVED_FROM.value
            ),
        )
        if nx.has_path(derived_graph, parent_artifact_id, child_artifact_id):
            raise ProvenanceCycleError(
                f"Cyclic derivation detected: adding edge from '{child_artifact_id}' to '{parent_artifact_id}' "
                f"would create a cycle in session '{self.session_id}'."
            )
        self._graph.add_edge(
            child_artifact_id, parent_artifact_id, relation=GraphRelation.DERIVED_FROM.value
        )

    def get_artifact_parents(self, artifact_id: str) -> list[str]:
        """Get immediate parent artifacts via outgoing DERIVED_FROM edges."""
        if not self._graph.has_node(artifact_id):
            return []
        return [
            v
            for _, v, data in self._graph.out_edges(artifact_id, data=True)
            if data.get("relation") == GraphRelation.DERIVED_FROM.value
        ]

    def get_artifact_children(self, artifact_id: str) -> list[str]:
        """Get immediate children derived from this artifact via incoming DERIVED_FROM edges."""
        if not self._graph.has_node(artifact_id):
            return []
        return [
            u
            for u, _, data in self._graph.in_edges(artifact_id, data=True)
            if data.get("relation") == GraphRelation.DERIVED_FROM.value
        ]

    def get_artifact_producer(self, artifact_id: str) -> str | None:
        """Get action that produced this artifact via incoming PRODUCES edge."""
        if not self._graph.has_node(artifact_id):
            return None
        for u, _, data in self._graph.in_edges(artifact_id, data=True):
            if data.get("relation") == GraphRelation.PRODUCES.value:
                return u
        return None

    def get_artifact_consumers(self, artifact_id: str) -> list[str]:
        """Get actions that consumed this artifact via outgoing CONSUMES edges."""
        if not self._graph.has_node(artifact_id):
            return []
        return [
            v
            for _, v, data in self._graph.out_edges(artifact_id, data=True)
            if data.get("relation") == GraphRelation.CONSUMES.value
        ]

    def get_action_inputs(self, action_id: str) -> list[str]:
        """Get artifacts consumed by this action via incoming CONSUMES edges."""
        if not self._graph.has_node(action_id):
            return []
        return [
            u
            for u, _, data in self._graph.in_edges(action_id, data=True)
            if data.get("relation") == GraphRelation.CONSUMES.value
        ]

    def get_action_outputs(self, action_id: str) -> list[str]:
        """Get artifacts produced by this action via outgoing PRODUCES edges."""
        if not self._graph.has_node(action_id):
            return []
        return [
            v
            for _, v, data in self._graph.out_edges(action_id, data=True)
            if data.get("relation") == GraphRelation.PRODUCES.value
        ]

    def has_data_flow_path(self, source_artifact_id: str, target_node_id: str) -> bool:
        """Check if any directed data-flow path exists from source artifact to target."""
        if not self._graph.has_node(source_artifact_id) or not self._graph.has_node(target_node_id):
            return False
        return nx.has_path(self._graph, source_artifact_id, target_node_id)

    def add_action(
        self,
        action: AgentAction,
        tool_spec: Any | None = None,
        effective_data_classifications: list[str] | None = None,
        policy_version: str | None = None,
        policy_input_schema_version: str | None = None,
    ) -> None:
        """Record an authoritative AgentAction with snapshotted security attributes in graph.

        Raises ActionCollisionError if the action_id already exists to prevent
        historical mutation.
        """
        action_key = str(action.action_id)
        if action_key in self._actions or self._graph.has_node(action_key):
            raise ActionCollisionError(
                f"Action '{action_key}' already exists in session '{self.session_id}'."
            )

        self._actions[action_key] = action

        # Snapshot security facts at action ingestion time
        known = tool_spec.known if tool_spec is not None else True
        privileged = tool_spec.privileged if tool_spec is not None else False
        destructive = (
            tool_spec.destructive
            if tool_spec is not None
            else (action.action_type.value == "DESTRUCTIVE")
        )
        external_sink = tool_spec.external_sink if tool_spec is not None else False
        eff_classifications = (
            effective_data_classifications
            if effective_data_classifications is not None
            else [c.value for c in action.data_classifications]
        )

        self._graph.add_node(
            action_key,
            node_type=GraphNodeType.ACTION.value,
            action_id=action_key,
            agent_id=action.agent_id,
            session_id=action.session_id,
            tool_name=action.tool_name,
            tool_known=known,
            tool_privileged=privileged,
            tool_destructive=destructive,
            tool_external_sink=external_sink,
            action_type=action.action_type.value,
            target_resource=action.target_resource,
            target_environment=action.target_environment.value,
            effective_data_classifications=list(eff_classifications),
            execution_status=action.execution_status.value,
            policy_result=action.policy_result.value if action.policy_result else None,
            risk_score=action.risk_score,
            intent_contract_id=str(action.intent_contract_id)
            if action.intent_contract_id
            else None,
            policy_version=policy_version,
            policy_input_schema_version=policy_input_schema_version,
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
        policy_version: str | None = None,
        policy_input_schema_version: str | None = None,
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
        if policy_version is not None:
            node_attrs["policy_version"] = policy_version
        if policy_input_schema_version is not None:
            node_attrs["policy_input_schema_version"] = policy_input_schema_version

    def add_action_output_artifact(self, action_id: str, artifact_id: UUID) -> None:
        """Record an output artifact generated by a successfully executed action."""
        if action_id in self._actions:
            if artifact_id not in self._actions[action_id].output_artifact_ids:
                self._actions[action_id].output_artifact_ids.append(artifact_id)
        if self._graph.has_node(action_id):
            existing = list(self._graph.nodes[action_id].get("output_artifact_ids") or [])
            if str(artifact_id) not in existing:
                existing.append(str(artifact_id))
            self._graph.nodes[action_id]["output_artifact_ids"] = existing

    def add_relationship(
        self,
        source_id: str,
        target_id: str,
        relation: GraphRelation | str = GraphRelation.CAUSES,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Add a directed causal relation between two existing nodes with cycle prevention."""
        if not self._graph.has_node(source_id):
            raise ParentActionNotFoundError(f"Source action '{source_id}' does not exist in graph.")
        if not self._graph.has_node(target_id):
            raise KeyError(f"Target action '{target_id}' does not exist in graph.")

        rel_str = relation.value if isinstance(relation, GraphRelation) else str(relation)
        if rel_str == GraphRelation.CAUSES.value or rel_str == "causes":
            if nx.has_path(self._graph, target_id, source_id):
                raise GraphCycleError(
                    f"Causal cycle detected: adding causal edge from '{source_id}' to '{target_id}' "
                    f"would create a directed cycle in session '{self.session_id}'."
                )

        meta = metadata or {}
        self._graph.add_edge(source_id, target_id, relation=rel_str, **meta)

    def get_action(self, action_id: str) -> AgentAction | None:
        """Retrieve authoritative AgentAction by ID as an immutable safe copy."""
        act = self._actions.get(action_id)
        if act is None:
            return None
        return act.model_copy(deep=True)

    def get_node_data(self, node_id: str) -> dict[str, Any] | None:
        """Retrieve copy of node attributes dictionary."""
        if not self._graph.has_node(node_id):
            return None
        return dict(self._graph.nodes[node_id])

    def get_parents(self, action_id: str) -> list[str]:
        """Retrieve direct causal parent action IDs (incoming edges with relation='causes')."""
        if not self._graph.has_node(action_id):
            return []
        parents = []
        for u, _, data in self._graph.in_edges(action_id, data=True):
            if (
                data.get("relation") == GraphRelation.CAUSES.value
                or data.get("relation") == "causes"
            ):
                parents.append(u)
        return parents

    def get_children(self, action_id: str) -> list[str]:
        """Retrieve direct causal child action IDs (outgoing edges with relation='causes')."""
        if not self._graph.has_node(action_id):
            return []
        children = []
        for _, v, data in self._graph.out_edges(action_id, data=True):
            if (
                data.get("relation") == GraphRelation.CAUSES.value
                or data.get("relation") == "causes"
            ):
                children.append(v)
        return children

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

    def get_shortest_path(self, source_id: str, target_id: str) -> list[str]:
        """Compute shortest directed path node IDs between source and target."""
        if not self._graph.has_node(source_id) or not self._graph.has_node(target_id):
            return []
        try:
            return list(nx.shortest_path(self._graph, source_id, target_id))
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return []

    def has_path(self, source_id: str, target_id: str) -> bool:
        """Check if a directed path exists from source to target."""
        if not self._graph.has_node(source_id) or not self._graph.has_node(target_id):
            return False
        return bool(nx.has_path(self._graph, source_id, target_id))

    def get_action_ancestors(self, action_id: str) -> list[AgentAction]:
        """Retrieve all causal ancestor AgentActions in topological order (oldest to newest).

        Returns safe copies to prevent external mutation of graph history.
        """
        if not self._graph.has_node(action_id):
            return []

        # Find all ancestors reachable via incoming 'causes' edges
        stack = self.get_parents(action_id)
        ancestor_ids = set()

        while stack:
            curr = stack.pop()
            if curr in ancestor_ids:
                continue
            ancestor_ids.add(curr)
            for p in self.get_parents(curr):
                if p not in ancestor_ids:
                    stack.append(p)

        if not ancestor_ids:
            return []

        # Subgraph of ancestors for topological sorting
        sub = self._graph.subgraph(ancestor_ids)
        try:
            ordered_ids = list(nx.topological_sort(sub))
        except nx.NetworkXUnfeasible:
            ordered_ids = sorted(list(ancestor_ids))

        result = []
        for aid in ordered_ids:
            act = self._actions.get(aid)
            if act is not None:
                result.append(act.model_copy(deep=True))
        return result

    def get_tool_history(self, action_id: str) -> list[str]:
        """Retrieve tool names along the causal ancestry path in topological order."""
        ancestor_actions = self.get_action_ancestors(action_id)
        return [act.tool_name for act in ancestor_actions]

    def get_recent_ancestor_actions(self, action_id: str, limit: int = 5) -> list[AgentAction]:
        """Retrieve the most recent N ancestor AgentActions (closest to action_id first)."""
        ancestors = self.get_action_ancestors(action_id)
        # Reverse topological sort gives immediate parent first
        return list(reversed(ancestors))[:limit]

    def node_count(self) -> int:
        """Return total number of nodes in the graph."""
        return self._graph.number_of_nodes()

    def edge_count(self) -> int:
        """Return total number of edges in the graph."""
        return self._graph.number_of_edges()

    def is_action_causality_dag(self) -> bool:
        """Check if the action causality subgraph (CAUSES edges) is an acyclic DAG."""
        causes_graph = nx.subgraph_view(
            self._graph,
            filter_edge=lambda u, v: (
                self._graph[u][v].get("relation") in (GraphRelation.CAUSES.value, "causes")
            ),
        )
        return nx.is_directed_acyclic_graph(causes_graph)

    def is_artifact_lineage_dag(self) -> bool:
        """Check if the artifact derivation lineage subgraph (DERIVED_FROM edges) is an acyclic DAG."""
        derived_graph = nx.subgraph_view(
            self._graph,
            filter_edge=lambda u, v: (
                self._graph[u][v].get("relation") == GraphRelation.DERIVED_FROM.value
            ),
        )
        return nx.is_directed_acyclic_graph(derived_graph)

    def is_subdelegation_dag(self) -> bool:
        """Check if the subdelegation lineage subgraph (SUBDELEGATES edges) is an acyclic DAG."""
        subdel_graph = nx.subgraph_view(
            self._graph,
            filter_edge=lambda u, v: (
                self._graph[u][v].get("relation") == GraphRelation.SUBDELEGATES.value
            ),
        )
        return nx.is_directed_acyclic_graph(subdel_graph)

    def has_valid_typed_dags(self) -> bool:
        """Check that all relation-specific typed subgraphs satisfy DAG invariants.

        Specifically:
        1. Action causality subgraph (CAUSES edges) must be a DAG.
        2. Artifact derivation lineage subgraph (DERIVED_FROM edges) must be a DAG.
        3. Delegation hierarchy subgraph (SUBDELEGATES edges) must be a DAG.
        Note: The full heterogeneous graph is NOT required to be acyclic across different relation types.
        """
        return (
            self.is_action_causality_dag()
            and self.is_artifact_lineage_dag()
            and self.is_subdelegation_dag()
        )

    def is_dag(self) -> bool:
        """Check action causality DAG integrity (action causality subgraph).

        Note: is_dag() validates relation-specific DAG invariants (specifically CAUSES),
        NOT that the complete heterogeneous NetworkX graph is acyclic across distinct semantic relations.
        """
        return self.is_action_causality_dag()

    def get_session_graph(self) -> dict[str, Any]:
        """Serialize current session trajectory graph to JSON-friendly representation."""
        nodes = []
        for node_id, data in self._graph.nodes(data=True):
            node_type = data.get("node_type", GraphNodeType.ACTION.value)
            node_info: dict[str, Any] = {
                "id": node_id,
                "node_type": node_type,
                "agent_id": data.get("agent_id"),
                "created_at": data.get("created_at"),
            }
            if node_type == GraphNodeType.INTENT.value or node_type == "intent":
                node_info["goal"] = data.get("goal")
                node_info["user_id"] = data.get("user_id")
            else:
                node_info.update(
                    {
                        "tool_name": data.get("tool_name"),
                        "tool_known": data.get("tool_known", True),
                        "tool_privileged": data.get("tool_privileged", False),
                        "tool_destructive": data.get("tool_destructive", False),
                        "tool_external_sink": data.get("tool_external_sink", False),
                        "action_type": data.get("action_type"),
                        "target_environment": data.get("target_environment"),
                        "effective_data_classifications": data.get(
                            "effective_data_classifications", []
                        ),
                        "execution_status": data.get("execution_status"),
                        "policy_result": data.get("policy_result"),
                        "risk_score": data.get("risk_score"),
                        "intent_contract_id": data.get("intent_contract_id"),
                        "policy_version": data.get("policy_version"),
                        "policy_input_schema_version": data.get("policy_input_schema_version"),
                    }
                )
            nodes.append(node_info)

        edges = []
        for u, v, data in self._graph.edges(data=True):
            edges.append(
                {
                    "source": u,
                    "target": v,
                    "relation": data.get("relation", GraphRelation.CAUSES.value),
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
