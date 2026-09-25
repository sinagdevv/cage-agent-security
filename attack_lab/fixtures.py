"""Simulated tool execution fixtures, registry helpers, and mock environments for Attack Lab."""

from typing import Any
from uuid import UUID

from app.gateway.registry import ToolRegistry, ToolSpec
from app.gateway.tools import ToolExecutor, ToolRequest, ToolResult
from app.provenance.models import InformationArtifact
from app.provenance.resources import ResourceSecurityProfile, ResourceSecurityProfileRegistry
from app.provenance.store import ArtifactPayloadStore, ProvenanceStore
from app.schemas.action import AgentAction
from app.schemas.decision import SecurityDecision
from app.schemas.enums import (
    ArtifactSourceType,
    DataClassification,
    PayloadBindingMode,
    TargetEnvironment,
    TrustLevel,
)
from attack_lab.models import InitialArtifactFixture


class MockExecutionRegistry:
    """Safe, in-memory tool execution recorder.

    Prevents any real network requests, database mutations, or destructive shell executions.
    """

    def __init__(self) -> None:
        self.dispatched_calls: list[dict[str, Any]] = []
        self.side_effects: list[dict[str, Any]] = []
        self._custom_responses: dict[str, Any] = {}

    def set_tool_response(self, tool_name: str, response: Any) -> None:
        self._custom_responses[tool_name] = response

    def execute_tool(self, action: AgentAction, arguments: dict[str, Any]) -> ToolResult:
        call_record = {
            "action_id": action.action_id,
            "tool_name": action.tool_name,
            "target_resource": action.target_resource,
            "arguments": arguments,
        }
        self.dispatched_calls.append(call_record)

        # Record simulated side effects
        if action.tool_name in [
            "database.write",
            "system.delete_resource",
            "http.post",
            "admin.exec",
            "vault.delete",
        ]:
            self.side_effects.append(call_record)

        custom_resp = self._custom_responses.get(action.tool_name)
        payload_data = (
            custom_resp if custom_resp is not None else {"status": "success", "simulated": True}
        )

        return ToolResult(
            tool_name=action.tool_name,
            success=True,
            output=payload_data,
            simulated=True,
            source_resource=action.target_resource,
        )


def build_attack_tool_registry() -> tuple[ToolRegistry, MockExecutionRegistry, ToolExecutor]:
    """Create a standardized ToolRegistry with comprehensive tool profiles for attack simulations."""
    registry = ToolRegistry()
    mock_recorder = MockExecutionRegistry()

    # 1. Public / Ingress Tools
    registry.register(
        ToolSpec(
            name="web.search",
            known=True,
            reads_resource_data=True,
            output_source_type=ArtifactSourceType.EXTERNAL_CONTENT,
            default_classification=DataClassification.PUBLIC,
            description="Simulated public web search returning external untrusted content",
        )
    )
    registry.register(
        ToolSpec(
            name="mcp.fetch_context",
            known=True,
            reads_resource_data=True,
            output_source_type=ArtifactSourceType.EXTERNAL_CONTENT,
            default_classification=DataClassification.PUBLIC,
            description="Simulated MCP server context fetch",
        )
    )

    # 2. Sensitive Database & Storage Tools
    registry.register(
        ToolSpec(
            name="database.read",
            known=True,
            resource_scoped=True,
            reads_resource_data=True,
            default_classification=DataClassification.CONFIDENTIAL,
            output_source_type=ArtifactSourceType.DATABASE,
            description="Simulated confidential database read",
        )
    )
    registry.register(
        ToolSpec(
            name="database.write",
            known=True,
            resource_scoped=True,
            description="Simulated database write",
        )
    )
    registry.register(
        ToolSpec(
            name="secrets.read",
            known=True,
            resource_scoped=True,
            reads_resource_data=True,
            default_classification=DataClassification.SECRET,
            output_source_type=ArtifactSourceType.INTERNAL_RESOURCE,
            description="Simulated secret vault read",
        )
    )

    # 3. File Processing & Transformation Tools
    registry.register(
        ToolSpec(
            name="file.read",
            known=True,
            resource_scoped=True,
            reads_resource_data=True,
            output_source_type=ArtifactSourceType.FILE,
            description="Simulated filesystem read",
        )
    )
    registry.register(
        ToolSpec(
            name="file.write",
            known=True,
            resource_scoped=True,
            output_derives_from_inputs=True,
            output_source_type=ArtifactSourceType.FILE,
            description="Simulated filesystem write with derivation",
        )
    )
    registry.register(
        ToolSpec(
            name="text.summarize",
            known=True,
            output_derives_from_inputs=True,
            output_source_type=ArtifactSourceType.AGENT_GENERATED,
            description="Simulated summarizer maintaining input data lineage",
        )
    )
    registry.register(
        ToolSpec(
            name="text.transform",
            known=True,
            output_derives_from_inputs=True,
            output_source_type=ArtifactSourceType.AGENT_GENERATED,
            description="Simulated transformation maintaining input data lineage",
        )
    )
    registry.register(
        ToolSpec(
            name="encode.base64",
            known=True,
            output_derives_from_inputs=True,
            output_source_type=ArtifactSourceType.AGENT_GENERATED,
            description="Simulated encoding utility maintaining input data lineage",
        )
    )

    # 4. Outbound Egress & Sink Tools
    registry.register(
        ToolSpec(
            name="http.post",
            known=True,
            external_sink=True,
            requires_tracked_inputs=True,
            payload_binding_mode=PayloadBindingMode.ARTIFACT_REQUIRED,
            payload_argument_names=frozenset({"body", "data", "payload", "content"}),
            allowed_destination_paths=frozenset({"", "/", "/api/v1/ingest", "/webhook/events"}),
            description="Simulated outbound HTTP webhook/post sink",
        )
    )
    registry.register(
        ToolSpec(
            name="public.publish",
            known=True,
            external_sink=True,
            requires_tracked_inputs=True,
            payload_binding_mode=PayloadBindingMode.ARTIFACT_REQUIRED,
            payload_argument_names=frozenset({"body", "data", "payload", "content"}),
            allowed_destination_paths=frozenset({"", "/", "/publish"}),
            description="Simulated authorized public publication sink",
        )
    )

    # 5. Privileged & Destructive Tools
    registry.register(
        ToolSpec(
            name="admin.exec",
            known=True,
            privileged=True,
            description="Simulated privileged shell command execution",
        )
    )
    registry.register(
        ToolSpec(
            name="system.delete_resource",
            known=True,
            destructive=True,
            description="Simulated destructive resource deletion",
        )
    )

    # Wrap in ToolExecutor
    class MockToolExecutor(ToolExecutor):
        def __init__(self, recorder: MockExecutionRegistry):
            super().__init__()
            self.recorder = recorder

        def execute(self, request: ToolRequest, decision: SecurityDecision) -> ToolResult:
            synth_action = AgentAction(
                action_id=request.action_id,
                session_id=request.session_id,
                agent_id="test-agent",
                intent_id=decision.intent_contract_id
                or UUID("00000000-0000-0000-0000-000000000000"),
                tool_name=request.tool_name,
                target_resource=None,
                target_environment=TargetEnvironment.PRODUCTION,
                trajectory_id=UUID(request.session_id)
                if isinstance(request.session_id, str) and len(request.session_id) == 36
                else UUID("00000000-0000-0000-0000-000000000000"),
            )
            self.recorder.execute_tool(synth_action, request.arguments)
            custom_resp = self.recorder._custom_responses.get(request.tool_name)
            payload_data = (
                custom_resp if custom_resp is not None else {"status": "success", "simulated": True}
            )
            return ToolResult(
                tool_name=request.tool_name,
                success=True,
                output=payload_data,
                simulated=True,
            )

    executor = MockToolExecutor(mock_recorder)
    return registry, mock_recorder, executor


def build_attack_resource_registry() -> ResourceSecurityProfileRegistry:
    """Create standardized resource security profiles for attack lab testing."""
    registry = ResourceSecurityProfileRegistry()

    # Public web resources
    registry.register(
        ResourceSecurityProfile(
            resource_id="public-web",
            trust_level=TrustLevel.EXTERNAL_UNTRUSTED,
            source_type=ArtifactSourceType.EXTERNAL_CONTENT,
            data_classifications=frozenset({DataClassification.PUBLIC}),
            description="Public World Wide Web content",
        )
    )
    registry.register(
        ResourceSecurityProfile(
            resource_id="untrusted-mcp-server",
            trust_level=TrustLevel.EXTERNAL_UNTRUSTED,
            source_type=ArtifactSourceType.EXTERNAL_CONTENT,
            data_classifications=frozenset({DataClassification.PUBLIC}),
            description="Untrusted external MCP server",
        )
    )

    # Internal Sensitive Databases & Vaults
    registry.register(
        ResourceSecurityProfile(
            resource_id="customer-db",
            trust_level=TrustLevel.INTERNAL_TRUSTED,
            source_type=ArtifactSourceType.DATABASE,
            data_classifications=frozenset(
                {DataClassification.CONFIDENTIAL, DataClassification.PII}
            ),
            description="Customer database",
        )
    )
    registry.register(
        ResourceSecurityProfile(
            resource_id="analytics-db",
            trust_level=TrustLevel.INTERNAL_TRUSTED,
            source_type=ArtifactSourceType.DATABASE,
            data_classifications=frozenset({DataClassification.INTERNAL}),
            description="Analytics database",
        )
    )
    registry.register(
        ResourceSecurityProfile(
            resource_id="vault-secrets",
            trust_level=TrustLevel.INTERNAL_TRUSTED,
            source_type=ArtifactSourceType.INTERNAL_RESOURCE,
            data_classifications=frozenset(
                {DataClassification.SECRET, DataClassification.CREDENTIAL}
            ),
            description="Secrets vault",
        )
    )

    # External Sinks
    registry.register(
        ResourceSecurityProfile(
            resource_id="external-sink",
            trust_level=TrustLevel.EXTERNAL_UNTRUSTED,
            source_type=ArtifactSourceType.EXTERNAL_CONTENT,
            data_classifications=frozenset({DataClassification.PUBLIC}),
            description="External HTTP sink",
        )
    )
    registry.register(
        ResourceSecurityProfile(
            resource_id="public-feed",
            trust_level=TrustLevel.INTERNAL_TRUSTED,
            source_type=ArtifactSourceType.EXTERNAL_CONTENT,
            data_classifications=frozenset({DataClassification.PUBLIC}),
            description="Public publication feed",
        )
    )

    return registry


def seed_initial_artifacts(
    fixtures: list[InitialArtifactFixture],
    session_id: UUID,
    provenance_store: ProvenanceStore,
    payload_store: ArtifactPayloadStore,
) -> dict[str, UUID]:
    """Seed initial artifact fixtures into the ProvenanceStore and return key-to-UUID map."""
    artifact_map: dict[str, UUID] = {}

    # Pass 1: Allocate UUIDs
    for fix in fixtures:
        art_id = UUID(int=len(artifact_map) + 1000)
        artifact_map[fix.key] = art_id

    # Pass 2: Store and register with resolved parent IDs
    for fix in fixtures:
        art_id = artifact_map[fix.key]
        size_bytes, digest = payload_store.store_payload(art_id, fix.content)

        effective_cls = set(fix.classifications)
        if fix.classification:
            effective_cls.add(fix.classification)

        parent_ids = tuple(
            artifact_map[pk] for pk in fix.parent_artifact_keys if pk in artifact_map
        )

        artifact = InformationArtifact(
            artifact_id=art_id,
            session_id=str(session_id),
            source_type=fix.source_type,
            source_resource=fix.source_resource or f"resource-{fix.key}",
            direct_trust_level=fix.trust_level,
            inherited_trust_levels=frozenset({fix.trust_level}),
            data_classifications=frozenset(effective_cls),
            parent_artifact_ids=parent_ids,
            size_bytes=fix.byte_count or size_bytes,
            content_digest=digest,
        )
        # Store in provenance_store to support synthetic test fixtures (including cyclic states)
        provenance_store._artifacts[art_id] = artifact
        sess_key = str(session_id)
        if sess_key not in provenance_store._session_artifacts:
            provenance_store._session_artifacts[sess_key] = set()
        provenance_store._session_artifacts[sess_key].add(art_id)

    return artifact_map
