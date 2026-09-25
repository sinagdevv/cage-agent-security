"""Thread-safe authoritative store for Phase 6 execution trajectories."""

import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from app.schemas.enums import TrajectoryStatus
from app.schemas.intent import IntentContract
from app.trajectory.models import (
    AuthorityEnvelope,
    ResourceAuthorityScope,
    TrajectorySnapshot,
)


class TrajectoryNotFoundError(KeyError):
    """Raised when a requested trajectory is not found."""


class InvalidTrajectoryContinuationError(ValueError):
    """Raised when an action proposal fails linear trajectory continuation validation."""


class PendingApprovalExistsError(RuntimeError):
    """Raised when attempting to register a pending approval while another is already active."""


@dataclass
class _InternalTrajectoryState:
    """Mutable internal state protected strictly by TrajectoryStore RLock."""

    trajectory_id: UUID
    session_id: str
    intent_id: UUID
    agent_id: str
    status: TrajectoryStatus
    created_at: datetime
    updated_at: datetime

    root_authority: AuthorityEnvelope
    effective_authority: AuthorityEnvelope

    evaluated_action_ids: list[UUID] = field(default_factory=list)
    executed_action_ids: list[UUID] = field(default_factory=list)
    rejected_lineage_attempt_ids: list[UUID] = field(default_factory=list)

    last_action_id: UUID | None = None
    pending_approval_action_id: UUID | None = None

    sensitive_egress_attempt_count: int = 0
    cumulative_sensitive_egress_attempt_bytes: int = 0
    recorded_egress_action_ids: set[UUID] = field(default_factory=set)

    def to_snapshot(self) -> TrajectorySnapshot:
        """Export deeply immutable snapshot."""
        return TrajectorySnapshot(
            trajectory_id=self.trajectory_id,
            session_id=self.session_id,
            intent_id=self.intent_id,
            agent_id=self.agent_id,
            status=self.status,
            created_at=self.created_at,
            updated_at=self.updated_at,
            root_authority=self.root_authority,
            effective_authority=self.effective_authority,
            evaluated_action_ids=tuple(self.evaluated_action_ids),
            executed_action_ids=tuple(self.executed_action_ids),
            rejected_lineage_attempt_ids=tuple(self.rejected_lineage_attempt_ids),
            last_action_id=self.last_action_id,
            pending_approval_action_id=self.pending_approval_action_id,
            sensitive_egress_attempt_count=self.sensitive_egress_attempt_count,
            cumulative_sensitive_egress_attempt_bytes=self.cumulative_sensitive_egress_attempt_bytes,
            recorded_egress_action_ids=frozenset(self.recorded_egress_action_ids),
        )


class TrajectoryStore:
    """Thread-safe authoritative repository managing trajectory lifecycles and snapshots."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._trajectories: dict[UUID, _InternalTrajectoryState] = {}
        # Composite sovereign ownership key: (session_id, intent_id_str, agent_id) -> trajectory_id
        self._ownership_index: dict[tuple[str, str, str], UUID] = {}

    def get_snapshot(self, trajectory_id: UUID) -> TrajectorySnapshot | None:
        """Retrieve an immutable snapshot of the given trajectory."""
        with self._lock:
            state = self._trajectories.get(trajectory_id)
            if state is None:
                return None
            return state.to_snapshot()

    def get_active_trajectory_id(
        self, session_id: str, intent_id: UUID, agent_id: str
    ) -> UUID | None:
        """Lookup active trajectory ID by authoritative ownership tuple."""
        key = (session_id, str(intent_id), agent_id)
        with self._lock:
            traj_id = self._ownership_index.get(key)
            if traj_id is None:
                return None
            state = self._trajectories.get(traj_id)
            if state is not None and state.status == TrajectoryStatus.ACTIVE:
                return traj_id
            return None

    def create_trajectory(
        self,
        session_id: str,
        intent_id: UUID,
        initial_authority: AuthorityEnvelope | None = None,
        agent_id: str = "test-agent",
    ) -> UUID:
        """Explicitly create and register a new trajectory instance."""
        with self._lock:
            traj_id = uuid4()
            now = datetime.now(UTC)
            auth = initial_authority or AuthorityEnvelope(allowed_tools=frozenset())
            state = _InternalTrajectoryState(
                trajectory_id=traj_id,
                session_id=session_id,
                intent_id=intent_id,
                agent_id=agent_id,
                status=TrajectoryStatus.ACTIVE,
                created_at=now,
                updated_at=now,
                root_authority=auth,
                effective_authority=auth,
            )
            self._trajectories[traj_id] = state
            key = (session_id, str(intent_id), agent_id)
            self._ownership_index[key] = traj_id
            return traj_id

    def update_status(self, trajectory_id: UUID, status: TrajectoryStatus) -> TrajectorySnapshot:
        """Update the status of a trajectory."""
        with self._lock:
            state = self._trajectories[trajectory_id]
            state.status = status
            state.updated_at = datetime.now(UTC)
            return state.to_snapshot()

    def validate_linear_continuation(
        self, trajectory_id: UUID, proposed_parent_id: UUID | None
    ) -> tuple[bool, str | None, UUID | None]:
        """Validate proposed parent matches current trajectory tip."""
        with self._lock:
            state = self._trajectories.get(trajectory_id)
            if state is None:
                return False, f"Trajectory '{trajectory_id}' not found.", None
            if state.last_action_id is None:
                if proposed_parent_id is not None:
                    return (
                        False,
                        f"First action must have parent_action_id=None, got '{proposed_parent_id}'.",
                        None,
                    )
                return True, None, None
            if proposed_parent_id != state.last_action_id:
                return (
                    False,
                    f"Invalid linear continuation: parent_action_id '{proposed_parent_id}' does not match expected last_action_id '{state.last_action_id}'.",
                    state.last_action_id,
                )
            return True, None, state.last_action_id

    def record_invalid_continuation_attempt(
        self, trajectory_id: UUID, action_id: UUID
    ) -> TrajectorySnapshot:
        """Record an invalid continuation attempt ID without advancing the valid tip."""
        with self._lock:
            state = self._trajectories[trajectory_id]
            if action_id not in state.rejected_lineage_attempt_ids:
                state.rejected_lineage_attempt_ids.append(action_id)
            state.updated_at = datetime.now(UTC)
            return state.to_snapshot()

    def get_or_create_trajectory(self, intent: IntentContract) -> tuple[TrajectorySnapshot, bool]:
        """Get existing active trajectory or create a fresh one for the Intent Contract.

        If a prior trajectory under this Intent was QUARANTINED or ABORTED,
        creation of a new trajectory is blocked to prevent quarantine escape.
        """
        key = (intent.session_id, str(intent.intent_id), intent.agent_id)
        with self._lock:
            existing_id = self._ownership_index.get(key)
            if existing_id is not None:
                existing = self._trajectories[existing_id]
                # If existing is quarantined or aborted, return it directly without resetting
                if existing.status in (TrajectoryStatus.QUARANTINED, TrajectoryStatus.ABORTED):
                    return existing.to_snapshot(), False
                if existing.status == TrajectoryStatus.ACTIVE:
                    return existing.to_snapshot(), False

            # Create fresh trajectory
            traj_id = uuid4()
            now = datetime.now(UTC)
            envelope = AuthorityEnvelope(
                allowed_tools=intent.allowed_tools,
                resource_scope=ResourceAuthorityScope.from_intent(intent.allowed_resources),
                allowed_environments=intent.allowed_environments,
                allowed_data_classifications=intent.allowed_data_classifications,
                explanation=("Root Intent Authority Scope",),
            )
            state = _InternalTrajectoryState(
                trajectory_id=traj_id,
                session_id=intent.session_id,
                intent_id=intent.intent_id,
                agent_id=intent.agent_id,
                status=TrajectoryStatus.ACTIVE,
                created_at=now,
                updated_at=now,
                root_authority=envelope,
                effective_authority=envelope,
            )
            self._trajectories[traj_id] = state
            self._ownership_index[key] = traj_id
            return state.to_snapshot(), True

    def validate_continuation(
        self,
        trajectory_id: UUID,
        action_id: UUID,
        parent_action_id: UUID | None,
    ) -> tuple[bool, str | None]:
        """Enforce strict linear continuation.

        - Root action (first evaluated): parent_action_id MUST be None.
        - Subsequent actions: parent_action_id MUST equal last_action_id.

        If invalid, the invalid action is recorded in rejected_lineage_attempt_ids,
        and the valid tip (last_action_id) is NOT advanced.
        """
        with self._lock:
            state = self._trajectories.get(trajectory_id)
            if state is None:
                return False, f"Trajectory '{trajectory_id}' not found."

            if state.status == TrajectoryStatus.QUARANTINED:
                return False, "Trajectory is QUARANTINED."
            if state.status == TrajectoryStatus.ABORTED:
                return False, "Trajectory is ABORTED."
            if state.status == TrajectoryStatus.CLOSED:
                return False, "Trajectory is CLOSED."

            if state.last_action_id is None:
                # First action in trajectory
                if parent_action_id is not None:
                    state.rejected_lineage_attempt_ids.append(action_id)
                    state.updated_at = datetime.now(UTC)
                    return (
                        False,
                        f"First action in trajectory must have parent_action_id=None, got '{parent_action_id}'.",
                    )
                return True, None

            # Subsequent actions
            if parent_action_id != state.last_action_id:
                state.rejected_lineage_attempt_ids.append(action_id)
                state.updated_at = datetime.now(UTC)
                return (
                    False,
                    f"Invalid linear continuation: parent_action_id '{parent_action_id}' does not match expected last_action_id '{state.last_action_id}'.",
                )

            return True, None

    def get_trajectory_id_for_session(self, session_id: str) -> UUID | None:
        """Lookup trajectory ID for a given session ID."""
        with self._lock:
            for state in self._trajectories.values():
                if state.session_id == session_id and state.status == TrajectoryStatus.ACTIVE:
                    return state.trajectory_id
            for state in self._trajectories.values():
                if state.session_id == session_id:
                    return state.trajectory_id
            return None

    def record_action_evaluation(
        self, trajectory_id: UUID, action_id: UUID, decision: Any = None
    ) -> TrajectorySnapshot:
        """Atomically record an evaluated action and advance last_action_id."""
        with self._lock:
            state = self._trajectories[trajectory_id]
            if action_id not in state.evaluated_action_ids:
                state.evaluated_action_ids.append(action_id)
            state.last_action_id = action_id
            state.updated_at = datetime.now(UTC)
            return state.to_snapshot()

    def record_action_execution(self, trajectory_id: UUID, action_id: UUID) -> TrajectorySnapshot:
        """Record authorized and executed action."""
        with self._lock:
            state = self._trajectories[trajectory_id]
            if action_id not in state.executed_action_ids:
                state.executed_action_ids.append(action_id)
            state.updated_at = datetime.now(UTC)
            return state.to_snapshot()

    def set_pending_approval(self, trajectory_id: UUID, action_id: UUID) -> TrajectorySnapshot:
        """Set authoritative pending approval checkpoint."""
        with self._lock:
            state = self._trajectories[trajectory_id]
            if (
                state.pending_approval_action_id is not None
                and state.pending_approval_action_id != action_id
            ):
                raise PendingApprovalExistsError(
                    f"Trajectory '{trajectory_id}' already has pending approval for action '{state.pending_approval_action_id}'."
                )
            state.pending_approval_action_id = action_id
            state.last_action_id = action_id
            if action_id not in state.evaluated_action_ids:
                state.evaluated_action_ids.append(action_id)
            state.updated_at = datetime.now(UTC)
            return state.to_snapshot()

    def clear_pending_approval(self, trajectory_id: UUID, action_id: UUID) -> TrajectorySnapshot:
        """Clear pending approval checkpoint upon control-plane resolution."""
        with self._lock:
            state = self._trajectories[trajectory_id]
            if state.pending_approval_action_id == action_id:
                state.pending_approval_action_id = None
            state.updated_at = datetime.now(UTC)
            return state.to_snapshot()

    def record_sensitive_egress_attempt(
        self, trajectory_id: UUID, action_id: UUID, payload_bytes: int
    ) -> tuple[int, int, bool]:
        """Idempotently record a sensitive egress attempt keyed by action_id.

        Returns (sensitive_egress_attempt_count, cumulative_sensitive_egress_attempt_bytes, already_recorded).
        """
        with self._lock:
            state = self._trajectories[trajectory_id]
            if action_id in state.recorded_egress_action_ids:
                return (
                    state.sensitive_egress_attempt_count,
                    state.cumulative_sensitive_egress_attempt_bytes,
                    True,
                )

            state.recorded_egress_action_ids.add(action_id)
            state.sensitive_egress_attempt_count += 1
            state.cumulative_sensitive_egress_attempt_bytes += max(0, payload_bytes)
            state.updated_at = datetime.now(UTC)
            return (
                state.sensitive_egress_attempt_count,
                state.cumulative_sensitive_egress_attempt_bytes,
                False,
            )

    def mark_quarantined(self, trajectory_id: UUID) -> TrajectorySnapshot:
        """Transition trajectory to QUARANTINED."""
        with self._lock:
            state = self._trajectories[trajectory_id]
            state.status = TrajectoryStatus.QUARANTINED
            state.updated_at = datetime.now(UTC)
            return state.to_snapshot()

    def mark_aborted(self, trajectory_id: UUID) -> TrajectorySnapshot:
        """Transition trajectory to ABORTED."""
        with self._lock:
            state = self._trajectories[trajectory_id]
            state.status = TrajectoryStatus.ABORTED
            state.updated_at = datetime.now(UTC)
            return state.to_snapshot()

    def close_trajectory(self, trajectory_id: UUID) -> TrajectorySnapshot:
        """Transition trajectory to CLOSED upon Intent lifecycle conclusion."""
        with self._lock:
            state = self._trajectories[trajectory_id]
            state.status = TrajectoryStatus.CLOSED
            state.updated_at = datetime.now(UTC)
            return state.to_snapshot()

    def update_effective_authority(
        self, trajectory_id: UUID, narrowed_authority: AuthorityEnvelope
    ) -> TrajectorySnapshot:
        """Apply trusted authority narrowing."""
        with self._lock:
            state = self._trajectories[trajectory_id]
            state.effective_authority = narrowed_authority
            state.updated_at = datetime.now(UTC)
            return state.to_snapshot()


# Global default store instance
default_trajectory_store = TrajectoryStore()
