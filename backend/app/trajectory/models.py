"""Authoritative, deeply immutable models for execution trajectory governance (Phase 6)."""

import json
from datetime import datetime
from hashlib import sha256
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.enums import (
    AuthorityScopeMode,
    AuthorityViolationType,
    DataClassification,
    TargetEnvironment,
    TrajectoryStatus,
)


class ControlPlaneAuthContext(BaseModel):
    """Trusted authentication context for administrative control-plane operations."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    user_id: str
    role: str = "ADMIN"
    is_trusted_control_plane: bool = True


class ResourceAuthorityScope(BaseModel):
    """Authoritative representation of resource scope semantics.

    Preserves Intent Contract behavior: an empty allowed_resources denotes
    an UNCONSTRAINED resource scope, rather than no resources allowed.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    mode: AuthorityScopeMode
    allowed_resources: frozenset[str] = frozenset()

    @classmethod
    def from_intent(
        cls, allowed_resources: frozenset[str] | list[str] | None
    ) -> "ResourceAuthorityScope":
        if not allowed_resources:
            return cls(mode=AuthorityScopeMode.UNCONSTRAINED, allowed_resources=frozenset())
        return cls(
            mode=AuthorityScopeMode.ALLOWLIST, allowed_resources=frozenset(allowed_resources)
        )

    def is_allowed(self, target_resource: str | None) -> bool:
        if self.mode == AuthorityScopeMode.UNCONSTRAINED:
            return True
        if target_resource is None:
            return True
        return target_resource in self.allowed_resources or "*" in self.allowed_resources


class AuthorityEnvelope(BaseModel):
    """Immutable snapshot of authoritative agent capabilities."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    allowed_tools: frozenset[str]
    resource_scope: ResourceAuthorityScope = Field(
        default_factory=lambda: ResourceAuthorityScope(
            mode=AuthorityScopeMode.UNCONSTRAINED, allowed_resources=frozenset()
        )
    )
    allowed_environments: frozenset[TargetEnvironment | str] = Field(
        default_factory=lambda: frozenset({TargetEnvironment.LOCAL, TargetEnvironment.DEVELOPMENT})
    )
    allowed_data_classifications: frozenset[DataClassification | str] = Field(
        default_factory=lambda: frozenset({DataClassification.PUBLIC})
    )
    explanation: tuple[str, ...] = ()

    def is_tool_allowed(self, tool_name: str) -> bool:
        return tool_name in self.allowed_tools

    def is_resource_allowed(self, target_resource: str | None) -> bool:
        return self.resource_scope.is_allowed(target_resource)

    def is_environment_allowed(self, env: TargetEnvironment | str) -> bool:
        env_val = env.value if hasattr(env, "value") else str(env)
        allowed_vals = {
            e.value if hasattr(e, "value") else str(e) for e in self.allowed_environments
        }
        return env_val in allowed_vals

    def is_classification_allowed(self, classification: DataClassification | str) -> bool:
        c_val = classification.value if hasattr(classification, "value") else str(classification)
        allowed_vals = {
            c.value if hasattr(c, "value") else str(c) for c in self.allowed_data_classifications
        }
        return c_val in allowed_vals

    def compute_violations(
        self,
        tool_name: str,
        target_resource: str | None,
        target_environment: TargetEnvironment | str,
        classifications: list[DataClassification | str] | frozenset[DataClassification | str],
    ) -> tuple[AuthorityViolationType, ...]:
        """Compute deterministic authority violations against current effective authority."""
        violations: list[AuthorityViolationType] = []

        if not self.is_tool_allowed(tool_name):
            violations.append(AuthorityViolationType.TOOL)

        if not self.is_resource_allowed(target_resource):
            violations.append(AuthorityViolationType.RESOURCE)

        if not self.is_environment_allowed(target_environment):
            violations.append(AuthorityViolationType.ENVIRONMENT)

        for c in classifications:
            if not self.is_classification_allowed(c):
                violations.append(AuthorityViolationType.DATA_CLASSIFICATION)
                break

        return tuple(violations)


def compute_trajectory_instance_fingerprint(
    trajectory_id: UUID,
    evaluated_action_ids: tuple[UUID, ...],
    status: TrajectoryStatus,
) -> str:
    """Compute CAGE deterministic canonical JSON serialization digest for instance audit."""
    payload = {
        "evaluated_action_ids": [str(aid) for aid in evaluated_action_ids],
        "status": status.value,
        "trajectory_id": str(trajectory_id),
    }
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return sha256(canonical).hexdigest()


class TrajectorySnapshot(BaseModel):
    """Deeply immutable snapshot of an authoritative execution trajectory."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    trajectory_id: UUID
    session_id: str
    intent_id: UUID
    agent_id: str
    status: TrajectoryStatus
    created_at: datetime
    updated_at: datetime

    root_authority: AuthorityEnvelope
    effective_authority: AuthorityEnvelope

    evaluated_action_ids: tuple[UUID, ...] = Field(default_factory=tuple)
    executed_action_ids: tuple[UUID, ...] = Field(default_factory=tuple)
    rejected_lineage_attempt_ids: tuple[UUID, ...] = Field(default_factory=tuple)

    last_action_id: UUID | None = None
    pending_approval_action_id: UUID | None = None

    sensitive_egress_attempt_count: int = Field(default=0, ge=0)
    cumulative_sensitive_egress_attempt_bytes: int = Field(default=0, ge=0)
    recorded_egress_action_ids: frozenset[UUID] = Field(default_factory=frozenset)

    def compute_fingerprint(self) -> str:
        """Compute deterministic fingerprint for this trajectory snapshot."""
        return compute_trajectory_instance_fingerprint(
            self.trajectory_id,
            self.evaluated_action_ids,
            self.status,
        )
