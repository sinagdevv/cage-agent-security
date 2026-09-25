"""Authoritative analyzer for Phase 6 causal trajectory governance."""

from dataclasses import dataclass
from uuid import UUID

from app.core.config import settings
from app.gateway.registry import ToolSpec
from app.graph.causal_graph import CausalExecutionGraph
from app.provenance.models import InformationArtifact
from app.provenance.resources import ResourceSecurityProfileRegistry
from app.provenance.store import ProvenanceStore
from app.schemas.action import AgentAction
from app.schemas.enums import (
    DataClassification,
    ProvenanceTrust,
    TrajectoryAnalysisStatus,
    TrajectoryStatus,
)
from app.schemas.policy import PolicyTrajectoryContext, TrajectoryEvidence
from app.trajectory.models import (
    TrajectorySnapshot,
    compute_trajectory_instance_fingerprint,
)

SENSITIVE_CLASSIFICATIONS: frozenset[DataClassification] = frozenset(
    {
        DataClassification.CONFIDENTIAL,
        DataClassification.RESTRICTED,
        DataClassification.PII,
        DataClassification.SECRET,
        DataClassification.CREDENTIAL,
    }
)


@dataclass(frozen=True)
class TrajectoryAnalyzerConfig:
    """Configurable bounds and thresholds for trajectory analysis."""

    max_action_depth: int = 20
    max_artifact_depth: int = 10
    max_nodes: int = 100
    max_untrusted_sensitive_access_distance: int = 3
    sensitive_egress_count_threshold: int = settings.max_sensitive_egress_attempts
    sensitive_egress_bytes_threshold: int = settings.max_sensitive_egress_bytes


class TrajectoryAnalyzer:
    """Performs relation-aware typed traversal and security fact derivation for trajectories."""

    def __init__(self, config: TrajectoryAnalyzerConfig | None = None) -> None:
        self.config = config or TrajectoryAnalyzerConfig()

    def analyze(
        self,
        action: AgentAction,
        trajectory: TrajectorySnapshot,
        tool_spec: ToolSpec,
        causal_graph: CausalExecutionGraph,
        provenance_store: ProvenanceStore,
        resource_registry: ResourceSecurityProfileRegistry,
        validated_input_artifacts: list[InformationArtifact] | None = None,
        bound_outbound_artifacts: list[InformationArtifact] | None = None,
    ) -> PolicyTrajectoryContext:
        """Derive authoritative, deeply immutable PolicyTrajectoryContext for policy evaluation."""
        validated_inputs = validated_input_artifacts or []
        bound_outbound = bound_outbound_artifacts or []

        # 1. Trajectory lifecycle status check
        if trajectory.status != TrajectoryStatus.ACTIVE:
            fingerprint = compute_trajectory_instance_fingerprint(
                trajectory.trajectory_id,
                trajectory.evaluated_action_ids,
                trajectory.status,
            )
            return PolicyTrajectoryContext(
                trajectory_status=trajectory.status,
                analysis_status=TrajectoryAnalysisStatus.SUCCESS,
                analysis_complete=True,
                trajectory_id=str(trajectory.trajectory_id),
                trajectory_length=len(trajectory.evaluated_action_ids),
                trajectory_instance_fingerprint=fingerprint,
            )

        # 2. Prospective sensitivity derivation for current proposed action
        prospective_classifications: set[DataClassification] = set()
        current_attempts_sensitive_access = False

        if tool_spec.reads_resource_data and action.target_resource:
            profile = resource_registry.get_profile(action.target_resource)
            if profile is not None:
                prospective_classifications.update(profile.data_classifications)
                if any(c in SENSITIVE_CLASSIFICATIONS for c in profile.data_classifications):
                    current_attempts_sensitive_access = True

        if (
            tool_spec.default_classification
            and tool_spec.default_classification in SENSITIVE_CLASSIFICATIONS
        ):
            prospective_classifications.add(tool_spec.default_classification)
            current_attempts_sensitive_access = True

        # 3. Authority violation derivation against effective authority
        all_action_classifications = list(action.data_classifications) + list(
            prospective_classifications
        )
        violations = trajectory.effective_authority.compute_violations(
            tool_name=action.tool_name,
            target_resource=action.target_resource,
            target_environment=action.target_environment,
            classifications=all_action_classifications,
        )
        unauthorized_expansion = len(violations) > 0

        # 4. Typed causal graph traversal
        visited_actions: list[UUID] = []
        action_tool_sequence: list[str] = []
        untrusted_artifact_ids: list[str] = []
        sensitive_artifact_ids: list[str] = []
        findings: list[str] = []

        contains_untrusted_external = False
        contains_sensitive_info = False
        contains_credential_info = False
        contains_external_sink_node = False
        contains_privileged_action_node = False
        contains_destructive_action_node = False

        untrusted_path_to_current = False
        nearest_untrusted_dist: int | None = None

        # Check virtual input artifacts on proposed current action
        for art in validated_inputs:
            if (
                art.direct_trust_level == ProvenanceTrust.EXTERNAL_UNTRUSTED
                or ProvenanceTrust.EXTERNAL_UNTRUSTED in art.inherited_trust_levels
            ):
                untrusted_path_to_current = True
                nearest_untrusted_dist = 0
                untrusted_artifact_ids.append(str(art.artifact_id))
            if any(c in SENSITIVE_CLASSIFICATIONS for c in art.data_classifications):
                contains_sensitive_info = True
                sensitive_artifact_ids.append(str(art.artifact_id))

        # Traverse historical causal ancestry via CAUSES edges
        curr_parent_id = action.parent_action_id
        depth = 0
        nodes_traversed = 0

        while curr_parent_id is not None:
            depth += 1
            nodes_traversed += 1

            if depth > self.config.max_action_depth:
                return self._build_failure_context(
                    trajectory,
                    TrajectoryAnalysisStatus.ACTION_DEPTH_LIMIT_EXCEEDED,
                )
            if nodes_traversed > self.config.max_nodes:
                return self._build_failure_context(
                    trajectory,
                    TrajectoryAnalysisStatus.NODE_LIMIT_EXCEEDED,
                )

            action_data = causal_graph.get_node_data(str(curr_parent_id))
            if action_data is None:
                # Missing graph evidence
                break

            visited_actions.append(curr_parent_id)
            tool_name = action_data.get("tool_name", "")
            action_tool_sequence.append(tool_name)

            if action_data.get("tool_privileged", False) or action_data.get("privileged", False):
                contains_privileged_action_node = True
            if action_data.get("tool_destructive", False) or action_data.get("destructive", False):
                contains_destructive_action_node = True
            if action_data.get("tool_external_sink", False) or action_data.get(
                "external_sink", False
            ):
                contains_external_sink_node = True

            # Inspect artifacts connected to this historical action
            consumed_artifacts = causal_graph.get_action_inputs(str(curr_parent_id))
            produced_artifacts = causal_graph.get_action_outputs(str(curr_parent_id))
            nodes_traversed += len(consumed_artifacts) + len(produced_artifacts)

            action_has_untrusted = False
            for art_id_str in consumed_artifacts + produced_artifacts:
                try:
                    art_uuid = UUID(art_id_str)
                    art = provenance_store.get_artifact(art_uuid)
                except (ValueError, TypeError):
                    art = None
                if art is not None:
                    if (
                        art.direct_trust_level == ProvenanceTrust.EXTERNAL_UNTRUSTED
                        or ProvenanceTrust.EXTERNAL_UNTRUSTED in art.inherited_trust_levels
                    ):
                        action_has_untrusted = True
                        contains_untrusted_external = True
                        untrusted_artifact_ids.append(str(art.artifact_id))
                    if any(c in SENSITIVE_CLASSIFICATIONS for c in art.data_classifications):
                        contains_sensitive_info = True
                        sensitive_artifact_ids.append(str(art.artifact_id))
                    if (
                        DataClassification.CREDENTIAL in art.data_classifications
                        or DataClassification.SECRET in art.data_classifications
                    ):
                        contains_credential_info = True

            # Check legacy trust if present on action
            if action_data.get("input_trust_level") == "EXTERNAL_UNTRUSTED":
                action_has_untrusted = True
                contains_untrusted_external = True

            if action_has_untrusted:
                untrusted_path_to_current = True
                if nearest_untrusted_dist is None or depth < nearest_untrusted_dist:
                    nearest_untrusted_dist = depth

            # Follow CAUSES edge to previous parent
            causes_parents = causal_graph.get_parents(str(curr_parent_id))
            curr_parent_id = UUID(causes_parents[0]) if causes_parents else None

        # 5. Derive Flagship Path Facts
        # Flagship 1: Untrusted path to sensitive access (with causal distance bound)
        untrusted_path_to_sensitive_access = False
        if current_attempts_sensitive_access and untrusted_path_to_current:
            if (
                nearest_untrusted_dist is not None
                and nearest_untrusted_dist <= self.config.max_untrusted_sensitive_access_distance
            ):
                untrusted_path_to_sensitive_access = True
                findings.append("UNTRUSTED_PATH_TO_SENSITIVE_ACCESS")

        # Flagship 2: Untrusted path to sensitive egress
        untrusted_path_to_sensitive_egress = False
        has_bound_sensitive_egress = tool_spec.external_sink and any(
            any(c in SENSITIVE_CLASSIFICATIONS for c in a.data_classifications)
            for a in bound_outbound
        )
        if has_bound_sensitive_egress and untrusted_path_to_current:
            untrusted_path_to_sensitive_egress = True
            findings.append("UNTRUSTED_PATH_TO_SENSITIVE_EGRESS")

        # Flagship 3: Sensitive hop laundering (multi-hop transformation)
        sensitive_hop_laundering = False
        if tool_spec.external_sink and has_bound_sensitive_egress:
            transform_count = sum(1 for t in action_tool_sequence if t == "agent.transform")
            if transform_count >= 2:
                sensitive_hop_laundering = True
                findings.append("SENSITIVE_HOP_LAUNDERING")

        # 6. Cumulative egress threshold checks
        split_exfiltration_exceeded = (
            trajectory.sensitive_egress_attempt_count
            >= self.config.sensitive_egress_count_threshold
            or trajectory.cumulative_sensitive_egress_attempt_bytes
            >= self.config.sensitive_egress_bytes_threshold
        )

        # 7. Bounded Context and Evidence Construction (enforced <= 20 entries)
        full_action_ids = [str(aid) for aid in trajectory.evaluated_action_ids]
        bounded_action_ids = tuple(full_action_ids[-20:])
        bounded_tools = tuple(action_tool_sequence[:20])
        bounded_prospective = tuple(
            c.value if hasattr(c, "value") else str(c)
            for c in list(prospective_classifications)[:20]
        )
        bounded_violations = tuple(
            v.value if hasattr(v, "value") else str(v) for v in violations[:20]
        )

        evidence = TrajectoryEvidence(
            evaluated_action_ids=tuple(full_action_ids[-20:]),
            untrusted_artifact_ids=tuple(list(dict.fromkeys(untrusted_artifact_ids))[:20]),
            sensitive_artifact_ids=tuple(list(dict.fromkeys(sensitive_artifact_ids))[:20]),
            causal_path=tuple(action_tool_sequence[:20]),
            findings=tuple(findings[:20]),
        )

        fingerprint = compute_trajectory_instance_fingerprint(
            trajectory.trajectory_id,
            trajectory.evaluated_action_ids,
            trajectory.status,
        )

        return PolicyTrajectoryContext(
            trajectory_status=trajectory.status,
            analysis_status=TrajectoryAnalysisStatus.SUCCESS,
            analysis_complete=True,
            trajectory_id=str(trajectory.trajectory_id),
            trajectory_length=len(trajectory.evaluated_action_ids),
            trajectory_action_ids=bounded_action_ids,
            trajectory_tool_sequence=bounded_tools,
            contains_untrusted_external_origin=contains_untrusted_external,
            contains_sensitive_information=contains_sensitive_info,
            contains_credential_information=contains_credential_info,
            contains_external_sink=contains_external_sink_node or tool_spec.external_sink,
            contains_privileged_action=contains_privileged_action_node or tool_spec.privileged,
            contains_destructive_action=contains_destructive_action_node or tool_spec.destructive,
            untrusted_path_to_current_action=untrusted_path_to_current,
            nearest_untrusted_action_distance=nearest_untrusted_dist,
            current_action_attempts_sensitive_access=current_attempts_sensitive_access,
            prospective_access_classifications=bounded_prospective,
            untrusted_path_to_sensitive_access=untrusted_path_to_sensitive_access,
            untrusted_path_to_sensitive_egress=untrusted_path_to_sensitive_egress,
            sensitive_hop_laundering_detected=sensitive_hop_laundering,
            unauthorized_authority_expansion_attempted=unauthorized_expansion,
            authority_violation_types=bounded_violations,
            sensitive_egress_attempt_count=trajectory.sensitive_egress_attempt_count,
            cumulative_sensitive_egress_attempt_bytes=trajectory.cumulative_sensitive_egress_attempt_bytes,
            split_exfiltration_threshold_exceeded=split_exfiltration_exceeded,
            evidence=evidence,
            trajectory_instance_fingerprint=fingerprint,
        )

    def _build_failure_context(
        self,
        trajectory: TrajectorySnapshot,
        status: TrajectoryAnalysisStatus,
    ) -> PolicyTrajectoryContext:
        fingerprint = compute_trajectory_instance_fingerprint(
            trajectory.trajectory_id,
            trajectory.evaluated_action_ids,
            trajectory.status,
        )
        return PolicyTrajectoryContext(
            trajectory_status=trajectory.status,
            analysis_status=status,
            analysis_complete=False,
            trajectory_id=str(trajectory.trajectory_id),
            trajectory_length=len(trajectory.evaluated_action_ids),
            trajectory_instance_fingerprint=fingerprint,
        )


# Global default analyzer instance
default_trajectory_analyzer = TrajectoryAnalyzer()
