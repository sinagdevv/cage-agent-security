"""Intent Service managing contract lifecycle, authority narrowing, and atomic tool quotas.

NOTICE:
For Phase 2, storage is thread-safe and process-local.
State resets upon server restart and does not scale across multiple worker processes.
"""

import threading
from datetime import UTC, datetime
from uuid import UUID

from app.schemas.enums import IntentStatus
from app.schemas.intent import (
    IntentContract,
    IntentContractCreate,
    IntentContractNarrow,
)


class ActiveIntentCollisionError(ValueError):
    """Raised when an attempt is made to bind multiple active contracts to the same session."""


class IntentNotFoundError(KeyError):
    """Raised when an Intent Contract is not found."""


class AuthorityExpansionError(ValueError):
    """Raised when an authority narrowing request attempts to expand permissions."""


class IntentService:
    """Thread-safe in-memory domain service managing Intent Contracts."""

    def __init__(self) -> None:
        self._intents: dict[UUID, IntentContract] = {}
        self._session_to_intent: dict[str, UUID] = {}
        self._lock = threading.Lock()

    def create_intent(self, req: IntentContractCreate) -> IntentContract:
        """Create and store a new authoritative Intent Contract.

        Enforces that only one ACTIVE Intent Contract can govern a session.
        """
        with self._lock:
            existing_id = self._session_to_intent.get(req.session_id)
            if existing_id is not None:
                existing = self._intents.get(existing_id)
                if existing is not None and existing.is_active():
                    raise ActiveIntentCollisionError(
                        f"Session '{req.session_id}' already has an active Intent Contract '{existing.intent_id}'. "
                        f"Revoke or complete the existing contract before creating a new one."
                    )

            contract = IntentContract.from_create(req)
            self._intents[contract.intent_id] = contract
            self._session_to_intent[req.session_id] = contract.intent_id
            return contract

    def get_intent(self, intent_id: UUID) -> IntentContract | None:
        """Retrieve an Intent Contract by UUID, updating status dynamically if expired."""
        with self._lock:
            contract = self._intents.get(intent_id)
            if contract is None:
                return None

            # Dynamic expiration check
            now = datetime.now(UTC)
            if (
                contract.status == IntentStatus.ACTIVE
                and contract.expires_at is not None
                and now >= contract.expires_at
            ):
                contract = contract.model_copy(
                    update={
                        "status": IntentStatus.EXPIRED,
                        "updated_at": now,
                    }
                )
                self._intents[intent_id] = contract

            return contract

    def get_intent_for_session(self, session_id: str) -> IntentContract | None:
        """Retrieve the authoritative Intent Contract bound to the given session (updating status if expired)."""
        with self._lock:
            intent_id = self._session_to_intent.get(session_id)
            if intent_id is None:
                return None

            contract = self._intents.get(intent_id)
            if contract is None:
                return None

            now = datetime.now(UTC)
            if (
                contract.status == IntentStatus.ACTIVE
                and contract.expires_at is not None
                and now >= contract.expires_at
            ):
                contract = contract.model_copy(
                    update={
                        "status": IntentStatus.EXPIRED,
                        "updated_at": now,
                    }
                )
                self._intents[intent_id] = contract

            return contract

    def get_active_intent_for_session(self, session_id: str) -> IntentContract | None:
        """Retrieve the authoritative active Intent Contract governing the given session."""
        contract = self.get_intent_for_session(session_id)
        return contract if contract is not None and contract.is_active() else None

    def revoke_intent(
        self, intent_id: UUID, reason: str = "Revoked by trusted authority"
    ) -> IntentContract:
        """Revoke an Intent Contract."""
        with self._lock:
            contract = self._intents.get(intent_id)
            if contract is None:
                raise IntentNotFoundError(f"Intent Contract '{intent_id}' not found.")

            updated = contract.model_copy(
                update={
                    "status": IntentStatus.REVOKED,
                    "revoked_reason": reason,
                    "updated_at": datetime.now(UTC),
                }
            )
            self._intents[intent_id] = updated
            return updated

    def narrow_intent(self, intent_id: UUID, narrow: IntentContractNarrow) -> IntentContract:
        """Narrow an existing contract's authority adhering to: authority_next <= authority_original.

        Rejects any attempted authority expansion with AuthorityExpansionError.
        """
        with self._lock:
            current = self._intents.get(intent_id)
            if current is None:
                raise IntentNotFoundError(f"Intent Contract '{intent_id}' not found.")

            if not current.is_active():
                raise ValueError(
                    f"Cannot narrow inactive Intent Contract '{intent_id}' (Status: {current.status.value})."
                )

            updates: dict = {}

            # 1. allowed_tools (must be a non-empty subset)
            if narrow.allowed_tools is not None:
                new_tools = set(narrow.allowed_tools)
                if not new_tools:
                    raise AuthorityExpansionError("allowed_tools cannot be narrowed to empty.")
                if not new_tools.issubset(current.allowed_tools):
                    expanded = new_tools - current.allowed_tools
                    raise AuthorityExpansionError(
                        f"Cannot expand allowed_tools with unauthorized tools: {expanded}"
                    )
                updates["allowed_tools"] = frozenset(new_tools)

            # 2. denied_tools (must be a superset - adding denials narrows authority)
            if narrow.denied_tools is not None:
                new_denied = set(narrow.denied_tools)
                if not current.denied_tools.issubset(new_denied):
                    removed = current.denied_tools - new_denied
                    raise AuthorityExpansionError(
                        f"Cannot remove tools from denied_tools: {removed}"
                    )
                updates["denied_tools"] = frozenset(new_denied)

            # 3. allowed_resources (must be a subset)
            if narrow.allowed_resources is not None:
                new_resources = set(narrow.allowed_resources)
                if current.allowed_resources and not new_resources.issubset(
                    current.allowed_resources
                ):
                    expanded = new_resources - current.allowed_resources
                    raise AuthorityExpansionError(f"Cannot expand allowed_resources: {expanded}")
                updates["allowed_resources"] = frozenset(new_resources)

            # 4. denied_resources (must be a superset)
            if narrow.denied_resources is not None:
                new_denied_res = set(narrow.denied_resources)
                if not current.denied_resources.issubset(new_denied_res):
                    raise AuthorityExpansionError("Cannot remove resources from denied_resources.")
                updates["denied_resources"] = frozenset(new_denied_res)

            # 5. allowed_environments (must be a subset)
            if narrow.allowed_environments is not None:
                new_envs = set(narrow.allowed_environments)
                if not new_envs.issubset(current.allowed_environments):
                    expanded = new_envs - current.allowed_environments
                    raise AuthorityExpansionError(f"Cannot expand allowed_environments: {expanded}")
                updates["allowed_environments"] = frozenset(new_envs)

            # 6. allowed_data_classifications (must be a subset)
            if narrow.allowed_data_classifications is not None:
                new_classes = set(narrow.allowed_data_classifications)
                if not new_classes.issubset(current.allowed_data_classifications):
                    expanded = new_classes - current.allowed_data_classifications
                    raise AuthorityExpansionError(
                        f"Cannot expand allowed_data_classifications: {expanded}"
                    )
                updates["allowed_data_classifications"] = frozenset(new_classes)

            # 7. requires_approval (adding requirements is stricter; removing is expansion)
            if narrow.requires_approval is not None:
                new_app = set(narrow.requires_approval)
                if not current.requires_approval.issubset(new_app):
                    removed = current.requires_approval - new_app
                    raise AuthorityExpansionError(
                        f"Cannot remove approval requirement from tools: {removed}"
                    )
                effective_allowed = updates.get("allowed_tools", current.allowed_tools)
                if not new_app.issubset(effective_allowed):
                    raise AuthorityExpansionError(
                        "requires_approval tools must exist within allowed_tools."
                    )
                updates["requires_approval"] = frozenset(new_app)

            # 8. maximum_tool_calls (can only decrease, but must be >= current usage)
            if narrow.maximum_tool_calls is not None:
                if narrow.maximum_tool_calls > current.maximum_tool_calls:
                    raise AuthorityExpansionError(
                        f"Cannot increase maximum_tool_calls ({narrow.maximum_tool_calls} > {current.maximum_tool_calls})."
                    )
                if narrow.maximum_tool_calls < current.tool_calls_count:
                    raise AuthorityExpansionError(
                        f"New maximum_tool_calls ({narrow.maximum_tool_calls}) cannot be less than "
                        f"already consumed executions ({current.tool_calls_count})."
                    )
                updates["maximum_tool_calls"] = narrow.maximum_tool_calls

            # 9. delegation_allowed (True -> False permitted, False -> True prohibited)
            if narrow.delegation_allowed is not None:
                if current.delegation_allowed is False and narrow.delegation_allowed is True:
                    raise AuthorityExpansionError("Cannot enable delegation once disabled.")
                updates["delegation_allowed"] = narrow.delegation_allowed

            # 10. maximum_delegation_depth (can only decrease)
            if narrow.maximum_delegation_depth is not None:
                if narrow.maximum_delegation_depth > current.maximum_delegation_depth:
                    raise AuthorityExpansionError("Cannot increase maximum_delegation_depth.")
                updates["maximum_delegation_depth"] = narrow.maximum_delegation_depth

            # 11. expires_at (can only decrease / become sooner; cannot remove or extend)
            if narrow.expires_at is not None:
                if current.expires_at is not None and narrow.expires_at > current.expires_at:
                    raise AuthorityExpansionError("Cannot extend contract expiration deadline.")
                updates["expires_at"] = narrow.expires_at
            elif narrow.expires_at is None and "expires_at" in narrow.model_fields_set:
                if current.expires_at is not None:
                    raise AuthorityExpansionError("Cannot remove contract expiration deadline.")

            updates["updated_at"] = datetime.now(UTC)
            updated = current.model_copy(update=updates)
            self._intents[intent_id] = updated
            return updated

    def reserve_tool_execution(self, intent_id: UUID) -> bool:
        """Atomically reserve/consume one tool execution slot if budget is available.

        Under a mutex lock, verifies that contract is active and tool_calls_count < maximum_tool_calls.
        Returns True if slot reserved, False if quota exhausted.
        """
        with self._lock:
            contract = self._intents.get(intent_id)
            if contract is None or not contract.is_active():
                return False

            if contract.tool_calls_count >= contract.maximum_tool_calls:
                return False

            # Atomically increment counter
            updated = contract.model_copy(
                update={
                    "tool_calls_count": contract.tool_calls_count + 1,
                    "updated_at": datetime.now(UTC),
                }
            )
            self._intents[intent_id] = updated
            return True

    def clear(self) -> None:
        """Clear all stored intent contracts (primarily for test isolation)."""
        with self._lock:
            self._intents.clear()
            self._session_to_intent.clear()


# Default singleton instance
default_intent_service = IntentService()
