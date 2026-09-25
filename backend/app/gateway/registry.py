"""Trusted tool registry for authoritative tool capability classification.

Prevents AI agents from spoofing destructive, privileged, or external-sink attributes.
"""

from dataclasses import dataclass

from app.schemas.enums import ArtifactSourceType, DataClassification, PayloadBindingMode

DEFAULT_ALLOWED_DESTINATION_PATHS: frozenset[str] = frozenset(
    {
        "",
        "/",
        "/upload",
        "/submit",
        "/test",
        "/collect",
        "/report",
        "/exfil",
        "/raw",
        "/sink",
    }
)


@dataclass(frozen=True)
class ToolSpec:
    """Authoritative capability specification for a tool."""

    name: str
    known: bool = True
    privileged: bool = False
    destructive: bool = False
    external_sink: bool = False
    resource_scoped: bool = False
    default_classification: DataClassification | None = None
    description: str = ""

    # Phase 5 Information Provenance & Egress Binding Fields
    requires_tracked_inputs: bool = False
    payload_binding_mode: PayloadBindingMode = PayloadBindingMode.NONE
    payload_argument_names: frozenset[str] = frozenset()
    allowed_destination_paths: frozenset[str] = DEFAULT_ALLOWED_DESTINATION_PATHS
    produces_artifact: bool = True
    output_derives_from_inputs: bool = False
    output_source_type: ArtifactSourceType = ArtifactSourceType.TOOL_RESULT

    # Phase 6 Trajectory & Prospective Sensitivity Fields
    reads_resource_data: bool = False


class ToolRegistry:
    """Trusted in-memory registry of known tools and their security characteristics."""

    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}
        self._register_default_tools()

    def _register_default_tools(self) -> None:
        """Register the standard Phase 1 through Phase 5 simulated tools."""
        defaults = [
            ToolSpec(
                name="web.search",
                known=True,
                privileged=False,
                destructive=False,
                external_sink=False,
                resource_scoped=False,
                default_classification=DataClassification.PUBLIC,
                description="Search public web information",
                requires_tracked_inputs=False,
                payload_binding_mode=PayloadBindingMode.NONE,
                produces_artifact=True,
                output_derives_from_inputs=False,
                output_source_type=ArtifactSourceType.EXTERNAL_CONTENT,
            ),
            ToolSpec(
                name="file.read",
                known=True,
                privileged=False,
                destructive=False,
                external_sink=False,
                resource_scoped=True,
                default_classification=None,
                description="Read local file contents",
                requires_tracked_inputs=False,
                payload_binding_mode=PayloadBindingMode.NONE,
                produces_artifact=True,
                output_derives_from_inputs=False,
                output_source_type=ArtifactSourceType.FILE,
            ),
            ToolSpec(
                name="file.write",
                known=True,
                privileged=False,
                destructive=False,
                external_sink=False,
                resource_scoped=True,
                default_classification=None,
                description="Write to local file path",
                requires_tracked_inputs=False,
                payload_binding_mode=PayloadBindingMode.NONE,
                produces_artifact=True,
                output_derives_from_inputs=True,
                output_source_type=ArtifactSourceType.FILE,
            ),
            ToolSpec(
                name="database.read",
                known=True,
                privileged=True,
                destructive=False,
                external_sink=False,
                resource_scoped=True,
                default_classification=DataClassification.INTERNAL,
                description="Query internal database tables",
                requires_tracked_inputs=False,
                payload_binding_mode=PayloadBindingMode.NONE,
                produces_artifact=True,
                output_derives_from_inputs=False,
                output_source_type=ArtifactSourceType.DATABASE,
                reads_resource_data=True,
            ),
            ToolSpec(
                name="external.http_post",
                known=True,
                privileged=False,
                destructive=False,
                external_sink=True,
                resource_scoped=True,
                default_classification=None,
                description="Transmit HTTP payload to external endpoint",
                requires_tracked_inputs=True,
                payload_binding_mode=PayloadBindingMode.ARTIFACT_REQUIRED,
                payload_argument_names=frozenset({"body", "data", "payload", "content"}),
                produces_artifact=False,
                output_derives_from_inputs=False,
                output_source_type=ArtifactSourceType.TOOL_RESULT,
            ),
            ToolSpec(
                name="system.delete_resource",
                known=True,
                privileged=True,
                destructive=True,
                external_sink=False,
                resource_scoped=True,
                default_classification=None,
                description="Delete a system or cloud resource",
                requires_tracked_inputs=False,
                payload_binding_mode=PayloadBindingMode.NONE,
                produces_artifact=False,
                output_derives_from_inputs=False,
                output_source_type=ArtifactSourceType.SYSTEM,
            ),
            ToolSpec(
                name="agent.transform",
                known=True,
                privileged=False,
                destructive=False,
                external_sink=False,
                resource_scoped=False,
                default_classification=None,
                description="Agent summarization and data transformation",
                requires_tracked_inputs=False,
                payload_binding_mode=PayloadBindingMode.NONE,
                produces_artifact=True,
                output_derives_from_inputs=True,
                output_source_type=ArtifactSourceType.AGENT_GENERATED,
            ),
            ToolSpec(
                name="secrets.vault_read",
                known=True,
                privileged=True,
                destructive=False,
                external_sink=False,
                resource_scoped=True,
                default_classification=DataClassification.CREDENTIAL,
                description="Read credentials from internal vault",
                requires_tracked_inputs=False,
                payload_binding_mode=PayloadBindingMode.NONE,
                produces_artifact=True,
                output_derives_from_inputs=False,
                output_source_type=ArtifactSourceType.INTERNAL_RESOURCE,
                reads_resource_data=True,
            ),
        ]
        for spec in defaults:
            self._tools[spec.name] = spec

    def get(self, tool_name: str) -> ToolSpec:
        """Retrieve authoritative ToolSpec.

        Unknown tools default to a conservative classification (untrusted/privileged/resource-scoped).
        """
        if tool_name in self._tools:
            return self._tools[tool_name]
        return ToolSpec(
            name=tool_name,
            known=False,
            privileged=True,
            destructive=False,
            external_sink=False,
            resource_scoped=True,
            description="Unknown tool - defaulting to conservative security bounds",
        )

    def is_known(self, tool_name: str) -> bool:
        """Check if tool is explicitly registered."""
        return tool_name in self._tools

    def register(self, spec: ToolSpec) -> None:
        """Register or override a tool spec (primarily for testing)."""
        self._tools[spec.name] = spec

    def get_effective_classifications(
        self, tool_name: str, client_classifications: list[DataClassification]
    ) -> list[DataClassification]:
        """Compute effective classifications via server_known UNION client_declared.

        Prevents agents from downgrading known sensitive tools/data to PUBLIC.
        """
        spec = self.get(tool_name)
        effective = set(client_classifications)
        if spec.default_classification is not None:
            effective.add(spec.default_classification)
        return list(effective)


# Global default instance
default_tool_registry = ToolRegistry()
