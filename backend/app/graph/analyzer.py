"""Graph security analyzer for deriving runtime causal policy facts."""

import logging
from typing import Any

from app.core.config import settings
from app.graph.causal_graph import CausalExecutionGraph
from app.schemas.enums import GraphAnalysisStatus
from app.schemas.policy import PolicyGraphContext

logger = logging.getLogger("cage.graph_analyzer")


class GraphSecurityAnalyzer:
    """Analyzes causal execution graphs to derive bounded, authoritative security facts.

    This component produces factual signals for policy evaluation.
    It does NOT make authorization decisions (ALLOW/DENY).
    """

    def __init__(
        self,
        max_depth: int | None = None,
        max_nodes: int | None = None,
    ) -> None:
        self.max_depth = max_depth or settings.max_graph_depth
        self.max_nodes = max_nodes or settings.max_graph_nodes_per_analysis

    def analyze_action_causality(
        self,
        graph: CausalExecutionGraph,
        parent_action_id: str | None,
    ) -> PolicyGraphContext:
        """Derive authoritative PolicyGraphContext for an action with the given parent.

        The current proposed action is explicitly excluded from ancestor metrics.
        """
        # Root action with no parent
        if parent_action_id is None:
            return PolicyGraphContext(
                analysis_status=GraphAnalysisStatus.SUCCESS,
                analysis_complete=True,
                causal_depth=0,
                ancestor_count=0,
                ancestor_action_ids=[],
                ancestor_tool_sequence=[],
                ancestor_environments=[],
                ancestor_data_classifications=[],
                contains_denied_ancestor=False,
                contains_approval_ancestor=False,
                contains_external_sink_ancestor=False,
                contains_privileged_ancestor=False,
                contains_destructive_ancestor=False,
                privileged_probe_count=0,
                has_lower_environment_ancestor=False,
                has_high_environment_ancestor=False,
            )

        # Check DAG validity before traversal
        if not graph.is_dag():
            logger.error("Causal graph is not a valid DAG during security analysis.")
            return PolicyGraphContext(
                analysis_status=GraphAnalysisStatus.INVALID_GRAPH,
                analysis_complete=False,
            )

        # Traverse backwards from immediate parent along CAUSES edges
        # In Phase 4, each action has at most one authoritative CAUSES parent
        ancestor_nodes: list[dict[str, Any]] = []
        curr_id: str | None = parent_action_id
        depth = 0
        visited = set()

        while curr_id is not None:
            if curr_id in visited:
                logger.error(
                    "Cycle detected during causal trajectory traversal at node '%s'.", curr_id
                )
                return PolicyGraphContext(
                    analysis_status=GraphAnalysisStatus.CYCLE_DETECTED,
                    analysis_complete=False,
                )

            depth += 1
            if depth > self.max_depth:
                logger.warning(
                    "Causal graph depth limit (%d) exceeded during analysis.",
                    self.max_depth,
                )
                return PolicyGraphContext(
                    analysis_status=GraphAnalysisStatus.DEPTH_LIMIT_EXCEEDED,
                    analysis_complete=False,
                    causal_depth=depth,
                    ancestor_count=len(ancestor_nodes),
                )

            if len(ancestor_nodes) >= self.max_nodes:
                logger.warning(
                    "Causal graph node analysis limit (%d) exceeded.",
                    self.max_nodes,
                )
                return PolicyGraphContext(
                    analysis_status=GraphAnalysisStatus.NODE_LIMIT_EXCEEDED,
                    analysis_complete=False,
                    causal_depth=depth,
                    ancestor_count=len(ancestor_nodes),
                )

            visited.add(curr_id)
            node_data = graph.get_node_data(curr_id)
            if node_data is None:
                break

            ancestor_nodes.append(node_data)

            # Move to next parent along CAUSES relationship
            parents = graph.get_parents(curr_id)
            curr_id = parents[0] if parents else None

        # ancestor_nodes currently lists [parent, grandparent, ...]
        # Reverse to establish topological order from oldest ancestor to immediate parent
        topo_ancestors = list(reversed(ancestor_nodes))

        ancestor_action_ids = [str(n["action_id"]) for n in topo_ancestors if "action_id" in n]
        ancestor_tool_sequence = [str(n["tool_name"]) for n in topo_ancestors if "tool_name" in n]
        ancestor_environments = [
            str(n["target_environment"]) for n in topo_ancestors if "target_environment" in n
        ]

        # Extract classifications
        all_classifications = set()
        for n in topo_ancestors:
            for c in n.get("effective_data_classifications", []):
                all_classifications.add(str(c))
        ancestor_data_classifications = sorted(list(all_classifications))

        # Check verdict flags
        contains_denied = any(
            n.get("policy_result") == "DENY" or n.get("execution_status") == "DENIED"
            for n in topo_ancestors
        )
        contains_approval = any(
            n.get("policy_result") == "REQUIRE_APPROVAL"
            or n.get("execution_status") == "PENDING_APPROVAL"
            for n in topo_ancestors
        )
        contains_external_sink = any(bool(n.get("tool_external_sink")) for n in topo_ancestors)
        contains_privileged = any(bool(n.get("tool_privileged")) for n in topo_ancestors)
        contains_destructive = any(
            bool(n.get("tool_destructive")) or n.get("action_type") == "DESTRUCTIVE"
            for n in topo_ancestors
        )

        # Count consecutive prior privilege/destructive probes walking backwards from immediate parent
        prior_probe_count = 0
        for n in ancestor_nodes:  # starts at immediate parent
            is_probe = (
                not n.get("tool_known", True)
                or bool(n.get("tool_privileged", False))
                or bool(n.get("tool_destructive", False))
                or n.get("action_type") == "DESTRUCTIVE"
                or n.get("action_type") == "EXECUTE"
            )
            if is_probe:
                prior_probe_count += 1
            else:
                break

        # Environment escalation flags
        has_lower = any(env in ("LOCAL", "DEVELOPMENT") for env in ancestor_environments)
        has_high = any(env in ("STAGING", "PRODUCTION") for env in ancestor_environments)

        return PolicyGraphContext(
            analysis_status=GraphAnalysisStatus.SUCCESS,
            analysis_complete=True,
            causal_depth=len(ancestor_nodes),
            ancestor_count=len(ancestor_nodes),
            ancestor_action_ids=ancestor_action_ids,
            ancestor_tool_sequence=ancestor_tool_sequence,
            ancestor_environments=ancestor_environments,
            ancestor_data_classifications=ancestor_data_classifications,
            contains_denied_ancestor=contains_denied,
            contains_approval_ancestor=contains_approval,
            contains_external_sink_ancestor=contains_external_sink,
            contains_privileged_ancestor=contains_privileged,
            contains_destructive_ancestor=contains_destructive,
            privileged_probe_count=prior_probe_count,
            has_lower_environment_ancestor=has_lower,
            has_high_environment_ancestor=has_high,
        )


# Global default instance
default_graph_security_analyzer = GraphSecurityAnalyzer()
