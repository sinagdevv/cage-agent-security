"""Trusted Resource Security Profile Registry for authoritative origin metadata."""

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.enums import ArtifactSourceType, DataClassification, ProvenanceTrust, TrustLevel


class ResourceSecurityProfile(BaseModel):
    """Authoritative security profile for a target resource or data origin."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    resource_id: str
    source_type: ArtifactSourceType
    trust_level: ProvenanceTrust | TrustLevel
    data_classifications: frozenset[DataClassification] = Field(default_factory=frozenset)
    description: str = ""


class ResourceSecurityProfileRegistry:
    """Trusted in-memory registry of known resources and their authoritative security profiles."""

    def __init__(self) -> None:
        self._profiles: dict[str, ResourceSecurityProfile] = {}
        self._register_default_profiles()

    def _register_default_profiles(self) -> None:
        defaults = [
            ResourceSecurityProfile(
                resource_id="public-web",
                source_type=ArtifactSourceType.EXTERNAL_CONTENT,
                trust_level=TrustLevel.EXTERNAL_UNTRUSTED,
                data_classifications=frozenset({DataClassification.PUBLIC}),
                description="Public World Wide Web content and external search results",
            ),
            ResourceSecurityProfile(
                resource_id="customer-db",
                source_type=ArtifactSourceType.INTERNAL_RESOURCE,
                trust_level=TrustLevel.INTERNAL_TRUSTED,
                data_classifications=frozenset(
                    {DataClassification.PII, DataClassification.CONFIDENTIAL}
                ),
                description="Internal customer relational database",
            ),
            ResourceSecurityProfile(
                resource_id="secrets-vault",
                source_type=ArtifactSourceType.INTERNAL_RESOURCE,
                trust_level=TrustLevel.INTERNAL_TRUSTED,
                data_classifications=frozenset(
                    {DataClassification.CREDENTIAL, DataClassification.SECRET}
                ),
                description="Internal cryptographic secrets and credential storage",
            ),
            ResourceSecurityProfile(
                resource_id="internal-docs",
                source_type=ArtifactSourceType.INTERNAL_RESOURCE,
                trust_level=TrustLevel.INTERNAL_TRUSTED,
                data_classifications=frozenset({DataClassification.INTERNAL}),
                description="Internal non-sensitive enterprise documentation",
            ),
            ResourceSecurityProfile(
                resource_id="agent-memory",
                source_type=ArtifactSourceType.AGENT_GENERATED,
                trust_level=TrustLevel.AGENT_DERIVED,
                data_classifications=frozenset(),
                description="Synthesized or derived agent scratchpad data",
            ),
        ]
        for p in defaults:
            self._profiles[p.resource_id] = p

    def get_profile(self, resource_id: str | None) -> ResourceSecurityProfile:
        """Retrieve authoritative ResourceSecurityProfile by exact normalized ID.

        Unknown or missing resources default conservatively to UNKNOWN trust.
        """
        if resource_id and resource_id in self._profiles:
            return self._profiles[resource_id]

        normalized_id = resource_id or "unknown-resource"
        return ResourceSecurityProfile(
            resource_id=normalized_id,
            source_type=ArtifactSourceType.UNKNOWN,
            trust_level=TrustLevel.UNKNOWN,
            data_classifications=frozenset(),
            description="Unknown resource - conservative UNKNOWN security bounds",
        )

    def register(self, profile: ResourceSecurityProfile) -> None:
        """Register a trusted resource security profile."""
        self._profiles[profile.resource_id] = profile


default_resource_registry = ResourceSecurityProfileRegistry()
