"""Authoritative data models for Phase 8 multi-agent delegation."""

from datetime import UTC, datetime
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.enums import (
    AuthorityScopeMode,
    DataClassification,
    DelegationIssuanceSource,
    DelegationStatus,
    EffectiveDelegationStatus,
    PolicyDecision,
    TargetEnvironment,
)
from app.trajectory.models import AuthorityEnvelope, ResourceAuthorityScope


class ResourceAuthorityScopeRequest(BaseModel):
    """Untrusted request representation for resource authority scoping."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    mode: AuthorityScopeMode = AuthorityScopeMode.UNCONSTRAINED
    allowed_resources: list[str] = Field(default_factory=list)

    @classmethod
    def unconstrained(cls) -> "ResourceAuthorityScopeRequest":
        """Build unconstrained resource scope request."""
        return cls(mode=AuthorityScopeMode.UNCONSTRAINED, allowed_resources=[])

    @classmethod
    def allowlist(cls, resources: list[str]) -> "ResourceAuthorityScopeRequest":
        """Build allowlist resource scope request."""
        return cls(mode=AuthorityScopeMode.ALLOWLIST, allowed_resources=resources)

    def to_authoritative(self) -> ResourceAuthorityScope:
        """Convert untrusted request into authoritative ResourceAuthorityScope."""
        if self.mode == AuthorityScopeMode.UNCONSTRAINED:
            return ResourceAuthorityScope(
                mode=AuthorityScopeMode.UNCONSTRAINED,
                allowed_resources=frozenset(),
            )
        return ResourceAuthorityScope(
            mode=AuthorityScopeMode.ALLOWLIST,
            allowed_resources=frozenset(self.allowed_resources),
        )


class DelegationProposal(BaseModel):
    """Untrusted candidate proposal submitted by an agent or client to create a delegation grant."""

    model_config = ConfigDict(extra="forbid")

    session_id: UUID
    delegator_agent_id: str
    delegatee_agent_id: str
    delegated_task_id: str

    parent_delegation_id: UUID | None = None
    root_intent_id: UUID | None = None

    # Requested authority bounds
    requested_tools: list[str] = Field(default_factory=list)
    requested_environments: list[TargetEnvironment] = Field(default_factory=list)
    requested_classifications: list[DataClassification] = Field(default_factory=list)
    requested_resource_scope: ResourceAuthorityScopeRequest = Field(
        default_factory=ResourceAuthorityScopeRequest
    )

    # Requested execution limits
    requested_max_actions: int = Field(default=10, ge=1, le=1000)
    requested_ttl_seconds: int = Field(default=3600, ge=-86400, le=86400 * 7)
    allow_subdelegation: bool = False
    requested_depth: int | None = None
    requested_subdelegation_depth: int | None = None


class DelegationGrant(BaseModel):
    """Deeply immutable, server-authoritative delegation grant definition."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    delegation_id: UUID = Field(default_factory=uuid4)
    parent_delegation_id: UUID | None = None
    root_intent_id: UUID
    session_id: UUID

    # Provenance and action correlation
    issued_from_action_id: UUID
    delegator_agent_id: str
    delegatee_agent_id: str
    mediating_principal_id: str | None = None
    issuance_source: DelegationIssuanceSource = DelegationIssuanceSource.AGENT_DIRECT
    delegated_task_id: str

    # Immutable authority envelope as issued
    authority_envelope: AuthorityEnvelope

    # Depth tracking
    depth: int = Field(default=1, ge=1)
    remaining_subdelegation_depth: int = Field(default=0, ge=0)
    allow_subdelegation: bool = False

    # Action budget cap
    max_actions: int = Field(default=10, ge=1)

    # Lifecycle timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime


class DelegationRuntimeState(BaseModel):
    """Server-owned mutable runtime state for a DelegationGrant.

    Stored and mutated separately from the immutable DelegationGrant.
    """

    model_config = ConfigDict(extra="forbid")

    delegation_id: UUID
    status: DelegationStatus = DelegationStatus.ACTIVE
    actions_executed_count: int = Field(default=0, ge=0)
    revoked_at: datetime | None = None
    revoked_by_principal_id: str | None = None
    revocation_reason: str | None = None
    closed_at: datetime | None = None
    closed_by_agent_id: str | None = None
    last_action_at: datetime | None = None
    state_version: int = Field(default=1, ge=1)


class DelegationSnapshot(BaseModel):
    """Immutable point-in-time snapshot of grant definition and runtime state."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    grant: DelegationGrant
    runtime_status: DelegationStatus
    effective_status: EffectiveDelegationStatus
    actions_executed_count: int
    remaining_actions_count: int
    is_active: bool
    live_effective_authority: AuthorityEnvelope | None = None


class DelegationCreateResponse(BaseModel):
    """Response returned when proposing/creating a delegation grant."""

    model_config = ConfigDict(extra="forbid")

    decision: PolicyDecision
    delegation_id: UUID | None = None  # None if REQUIRE_APPROVAL or DENIED
    delegation_request_id: UUID  # Correlated normalized action ID
    status: str
    matched_rules: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)


class DelegationRevokeRequest(BaseModel):
    """Request payload for revoking a delegation grant."""

    model_config = ConfigDict(extra="forbid")

    reason: str = Field(default="Revoked by authorized principal", max_length=500)


class DelegationCloseRequest(BaseModel):
    """Request payload for closing an active delegation grant upon task completion."""

    model_config = ConfigDict(extra="forbid")

    reason: str = Field(default="Delegated task completed", max_length=500)
