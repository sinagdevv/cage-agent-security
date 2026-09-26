"""Thread-safe storage and index management for Phase 8 delegation grants."""

from datetime import UTC, datetime
from threading import RLock
from uuid import UUID

from app.delegation.models import DelegationGrant, DelegationRuntimeState
from app.schemas.enums import DelegationStatus


class DelegationStore:
    """Thread-safe in-memory store for delegation grants and runtime states."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._grants: dict[UUID, DelegationGrant] = {}
        self._runtime_states: dict[UUID, DelegationRuntimeState] = {}
        self._children_by_parent: dict[UUID, list[UUID]] = {}
        self._grants_by_session: dict[UUID, list[UUID]] = {}
        self._grants_by_delegatee: dict[str, list[UUID]] = {}
        self._grants_by_root_intent: dict[UUID, list[UUID]] = {}

    def create_grant(
        self,
        grant: DelegationGrant,
        initial_state: DelegationRuntimeState | None = None,
    ) -> DelegationGrant:
        """Atomically persist an immutable grant and its initial runtime state."""
        with self._lock:
            if grant.delegation_id in self._grants:
                raise ValueError(f"Delegation grant {grant.delegation_id} already exists.")

            self._grants[grant.delegation_id] = grant
            self._runtime_states[grant.delegation_id] = (
                initial_state
                if initial_state is not None
                else DelegationRuntimeState(
                    delegation_id=grant.delegation_id,
                    status=DelegationStatus.ACTIVE,
                )
            )

            # Update indexes
            if grant.parent_delegation_id:
                self._children_by_parent.setdefault(grant.parent_delegation_id, []).append(
                    grant.delegation_id
                )

            self._grants_by_session.setdefault(grant.session_id, []).append(grant.delegation_id)
            self._grants_by_delegatee.setdefault(grant.delegatee_agent_id, []).append(
                grant.delegation_id
            )
            self._grants_by_root_intent.setdefault(grant.root_intent_id, []).append(
                grant.delegation_id
            )

            return grant

    def get_grant(self, delegation_id: UUID) -> DelegationGrant | None:
        """Retrieve an immutable grant by ID."""
        with self._lock:
            return self._grants.get(delegation_id)

    def get_runtime_state(self, delegation_id: UUID) -> DelegationRuntimeState | None:
        """Retrieve an immutable snapshot copy of runtime state."""
        with self._lock:
            state = self._runtime_states.get(delegation_id)
            if state is None:
                return None
            return state.model_copy()

    def get_chain(self, delegation_id: UUID, max_depth: int = 25) -> list[DelegationGrant]:
        """Retrieve the ancestor chain ordered from root grant to target grant."""
        with self._lock:
            chain: list[DelegationGrant] = []
            current_id: UUID | None = delegation_id
            visited: set[UUID] = set()

            while current_id is not None:
                if current_id in visited:
                    raise ValueError(f"Delegation cycle detected at {current_id}")
                visited.add(current_id)

                grant = self._grants.get(current_id)
                if grant is None:
                    break

                chain.append(grant)
                if len(chain) > max_depth:
                    raise ValueError(f"Delegation chain exceeded max traversal depth {max_depth}")

                current_id = grant.parent_delegation_id

            # Reverse to return [RootGrant, ..., TargetGrant]
            return list(reversed(chain))

    def get_chain_with_states(
        self, delegation_id: UUID, max_depth: int = 25
    ) -> tuple[list[DelegationGrant], list[DelegationRuntimeState]]:
        """Retrieve both grants and snapshot runtime states for the ancestor chain."""
        with self._lock:
            grants = self.get_chain(delegation_id, max_depth=max_depth)
            states: list[DelegationRuntimeState] = []
            for g in grants:
                state = self._runtime_states.get(g.delegation_id)
                if state is not None:
                    states.append(state.model_copy())
                else:
                    states.append(
                        DelegationRuntimeState(
                            delegation_id=g.delegation_id,
                            status=DelegationStatus.ACTIVE,
                        )
                    )
            return grants, states

    def get_children(self, delegation_id: UUID) -> list[DelegationGrant]:
        """Retrieve all direct children grants of a parent grant."""
        with self._lock:
            child_ids = self._children_by_parent.get(delegation_id, [])
            return [self._grants[cid] for cid in child_ids if cid in self._grants]

    def get_grants_by_session(self, session_id: UUID) -> list[DelegationGrant]:
        """Retrieve all grants created in a session."""
        with self._lock:
            grant_ids = self._grants_by_session.get(session_id, [])
            return [self._grants[gid] for gid in grant_ids if gid in self._grants]

    def get_grants_by_delegatee(self, delegatee_agent_id: str) -> list[DelegationGrant]:
        """Retrieve all grants issued to a specific delegatee agent."""
        with self._lock:
            grant_ids = self._grants_by_delegatee.get(delegatee_agent_id, [])
            return [self._grants[gid] for gid in grant_ids if gid in self._grants]

    def get_grants_by_root_intent(self, root_intent_id: UUID) -> list[DelegationGrant]:
        """Retrieve all grants rooted in a specific Intent Contract."""
        with self._lock:
            grant_ids = self._grants_by_root_intent.get(root_intent_id, [])
            return [self._grants[gid] for gid in grant_ids if gid in self._grants]

    def revoke(
        self,
        delegation_id: UUID,
        revoked_by_principal_id: str,
        reason: str | None = None,
    ) -> bool:
        """Atomically mark a grant as REVOKED."""
        with self._lock:
            state = self._runtime_states.get(delegation_id)
            if state is None:
                return False
            if state.status == DelegationStatus.REVOKED:
                return True

            state.status = DelegationStatus.REVOKED
            state.revoked_at = datetime.now(UTC)
            state.revoked_by_principal_id = revoked_by_principal_id
            state.revocation_reason = reason
            state.state_version += 1
            return True

    def close(
        self,
        delegation_id: UUID,
        closed_by_agent_id: str,
        reason: str | None = None,
    ) -> bool:
        """Atomically mark a grant as CLOSED upon task completion."""
        with self._lock:
            state = self._runtime_states.get(delegation_id)
            if state is None:
                return False
            if state.status in (DelegationStatus.REVOKED, DelegationStatus.CLOSED):
                return True

            state.status = DelegationStatus.CLOSED
            state.closed_at = datetime.now(UTC)
            state.closed_by_agent_id = closed_by_agent_id
            state.state_version += 1
            return True

    def get_session_active_grant_count(self, session_id: UUID) -> int:
        """Count currently ACTIVE grants within a session."""
        with self._lock:
            grant_ids = self._grants_by_session.get(session_id, [])
            count = 0
            for gid in grant_ids:
                st = self._runtime_states.get(gid)
                if st is not None and st.status == DelegationStatus.ACTIVE:
                    count += 1
            return count

    def reserve_action_dispatch(self, delegation_id: UUID) -> bool:
        """Atomically reserve one action execution slot across the grant and all ancestors."""
        with self._lock:
            grants = self.get_chain(delegation_id)
            if not grants:
                return False
            now = datetime.now(UTC)
            # 1. Capacity check for target grant and every ancestor
            for g in grants:
                state = self._runtime_states.get(g.delegation_id)
                if state is None or state.status != DelegationStatus.ACTIVE:
                    return False
                if state.actions_executed_count >= g.max_actions:
                    return False

            # 2. Atomically consume slot on all grants in chain
            for g in grants:
                state = self._runtime_states[g.delegation_id]
                state.actions_executed_count += 1
                state.last_action_at = now
                state.state_version += 1
            return True

    def refund_action_dispatch(self, delegation_id: UUID) -> None:
        """Roll back an action reservation if downstream evaluation failed."""
        with self._lock:
            grants = self.get_chain(delegation_id)
            for g in grants:
                state = self._runtime_states.get(g.delegation_id)
                if state is not None and state.actions_executed_count > 0:
                    state.actions_executed_count -= 1
                    state.state_version += 1

    def record_dispatch(self, delegation_id: UUID, count: int = 1) -> bool:
        """Atomically increment the executed actions count for a grant and all its ancestors."""
        with self._lock:
            grants = self.get_chain(delegation_id)
            if not grants:
                return False
            now = datetime.now(UTC)
            for g in grants:
                state = self._runtime_states.get(g.delegation_id)
                if state is not None:
                    state.actions_executed_count += count
                    state.last_action_at = now
                    state.state_version += 1
            return True

    def remaining_budget(self, delegation_id: UUID) -> int:
        """Compute remaining action execution budget for a grant."""
        with self._lock:
            grant = self._grants.get(delegation_id)
            state = self._runtime_states.get(delegation_id)
            if grant is None or state is None:
                return 0
            return max(0, grant.max_actions - state.actions_executed_count)

    def clear(self) -> None:
        """Clear all stored state (primarily for isolated test fixtures)."""
        with self._lock:
            self._grants.clear()
            self._runtime_states.clear()
            self._children_by_parent.clear()
            self._grants_by_session.clear()
            self._grants_by_delegatee.clear()
            self._grants_by_root_intent.clear()
