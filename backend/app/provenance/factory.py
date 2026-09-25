"""Authoritative factory for creating InformationArtifact instances."""

from uuid import UUID, uuid4

from app.gateway.registry import ToolSpec
from app.gateway.tools import ToolResult
from app.provenance.models import InformationArtifact
from app.provenance.resources import ResourceSecurityProfile
from app.schemas.action import AgentAction
from app.schemas.enums import ArtifactSourceType, DataClassification, TrustLevel


class ArtifactFactory:
    """Server-authoritative generator of InformationArtifact metadata.

    Guarantees:
    - Server-generated immutable UUIDs.
    - Deterministic propagation of parent sensitivity classifications (no automatic declassification).
    - Monotonic preservation of parent untrusted origins (anti-laundering).
    - Selective output derivation based on trusted ToolSpec metadata.
    """

    @staticmethod
    def create_output_artifact(
        action: AgentAction,
        tool_spec: ToolSpec,
        result: ToolResult,
        parent_artifacts: list[InformationArtifact] | None = None,
        resource_profile: ResourceSecurityProfile | None = None,
        artifact_id: UUID | None = None,
    ) -> InformationArtifact:
        """Create an authoritative output artifact from a successful tool execution."""
        parents = parent_artifacts or []

        # 1. Source Resource and Source Type
        source_res = (
            result.source_resource
            or action.target_resource
            or (resource_profile.resource_id if resource_profile else tool_spec.name)
        )
        source_type = (
            tool_spec.output_source_type
            if tool_spec.output_source_type != ArtifactSourceType.TOOL_RESULT
            else (
                resource_profile.source_type if resource_profile else ArtifactSourceType.TOOL_RESULT
            )
        )

        # 2. Direct Trust Level
        if tool_spec.output_source_type == ArtifactSourceType.AGENT_GENERATED:
            direct_trust = TrustLevel.AGENT_DERIVED
        elif tool_spec.output_source_type == ArtifactSourceType.EXTERNAL_CONTENT:
            direct_trust = TrustLevel.EXTERNAL_UNTRUSTED
        elif resource_profile is not None:
            direct_trust = resource_profile.trust_level
        elif tool_spec.external_sink:
            direct_trust = TrustLevel.EXTERNAL_UNTRUSTED
        else:
            direct_trust = TrustLevel.INTERNAL_TRUSTED

        # 3. Output Derivation & Lineage
        if tool_spec.output_derives_from_inputs and parents:
            parent_ids = tuple(p.artifact_id for p in parents)

            # Monotonic union of parent trust levels
            inherited_trust = frozenset.union(
                *(p.inherited_trust_levels | {p.direct_trust_level} for p in parents)
            )

            # Classification union: tool/resource base UNION all parent classifications
            base_classifications: set[DataClassification] = set()
            if tool_spec.default_classification is not None:
                base_classifications.add(tool_spec.default_classification)
            if resource_profile is not None:
                base_classifications.update(resource_profile.data_classifications)

            for p in parents:
                base_classifications.update(p.data_classifications)
            effective_classifications = frozenset(base_classifications)
        else:
            parent_ids = tuple()
            inherited_trust = frozenset()
            base_classifications_set: set[DataClassification] = set()
            if tool_spec.default_classification is not None:
                base_classifications_set.add(tool_spec.default_classification)
            if resource_profile is not None:
                base_classifications_set.update(resource_profile.data_classifications)
            effective_classifications = frozenset(base_classifications_set)

        return InformationArtifact(
            artifact_id=artifact_id or uuid4(),
            session_id=action.session_id,
            created_by_action_id=action.action_id,
            source_type=source_type,
            source_resource=source_res,
            direct_trust_level=direct_trust,
            inherited_trust_levels=inherited_trust,
            data_classifications=effective_classifications,
            parent_artifact_ids=parent_ids,
            mime_type=result.mime_type or "application/json",
        )

    @staticmethod
    def create_ingested_artifact(
        session_id: str,
        source_resource: str,
        source_type: ArtifactSourceType = ArtifactSourceType.EXTERNAL_CONTENT,
        direct_trust_level: TrustLevel = TrustLevel.EXTERNAL_UNTRUSTED,
        data_classifications: frozenset[DataClassification] | None = None,
        parent_artifact_ids: tuple[UUID, ...] = tuple(),
        inherited_trust_levels: frozenset[TrustLevel] | None = None,
        mime_type: str = "text/plain",
        artifact_id: UUID | None = None,
    ) -> InformationArtifact:
        """Create a server-authoritative ingested artifact (e.g. initial input or test fixture)."""
        return InformationArtifact(
            artifact_id=artifact_id or uuid4(),
            session_id=session_id,
            created_by_action_id=None,
            source_type=source_type,
            source_resource=source_resource,
            direct_trust_level=direct_trust_level,
            inherited_trust_levels=inherited_trust_levels or frozenset(),
            data_classifications=data_classifications or frozenset(),
            parent_artifact_ids=parent_artifact_ids,
            mime_type=mime_type,
        )


default_artifact_factory = ArtifactFactory()
