"""Authoritative analyzer for delegation chains, live effective authority, and policy facts."""

from datetime import UTC, datetime
from uuid import UUID

from app.delegation.models import (
    DelegationGrant,
    DelegationProposal,
    DelegationRuntimeState,
    ResourceAuthorityScopeRequest,
)
from app.identity.principal import AgentPrincipal
from app.schemas.enums import (
    AuthorityScopeMode,
    DataClassification,
    DelegationStatus,
    EffectiveDelegationStatus,
    IntentStatus,
    TargetEnvironment,
)
from app.schemas.intent import IntentContract
from app.trajectory.models import AuthorityEnvelope, ResourceAuthorityScope


class DelegationAnalyzer:
    """Computes derived facts and evaluates causal invariants for multi-agent delegation."""

    def __init__(
        self,
        max_session_delegation_depth: int = 5,
        max_session_active_grants: int = 50,
    ) -> None:
        self.max_session_delegation_depth = max_session_delegation_depth
        self.max_session_active_grants = max_session_active_grants

    # ----------------------------------------------------------------------
    # 1. Authority Scope Logic
    # ----------------------------------------------------------------------

    @staticmethod
    def is_resource_scope_subset(
        requested: ResourceAuthorityScope | ResourceAuthorityScopeRequest,
        parent: ResourceAuthorityScope,
    ) -> bool:
        """Verify that requested resource scope is a subset of parent resource scope."""
        req_mode = requested.mode
        req_resources = (
            set(requested.allowed_resources)
            if isinstance(requested, ResourceAuthorityScopeRequest)
            else set(requested.allowed_resources)
        )

        if parent.mode == AuthorityScopeMode.UNCONSTRAINED:
            return True

        if req_mode == AuthorityScopeMode.UNCONSTRAINED:
            # Parent is ALLOWLIST, child cannot expand to UNCONSTRAINED
            return False

        # Both are ALLOWLIST: child must be a subset of parent
        return req_resources.issubset(set(parent.allowed_resources))

    @staticmethod
    def intersect_resource_scopes(
        parent_scope: ResourceAuthorityScope,
        child_scope: ResourceAuthorityScope,
    ) -> ResourceAuthorityScope:
        """Compute the intersection of two resource scopes."""
        if (
            parent_scope.mode == AuthorityScopeMode.UNCONSTRAINED
            and child_scope.mode == AuthorityScopeMode.UNCONSTRAINED
        ):
            return ResourceAuthorityScope(
                mode=AuthorityScopeMode.UNCONSTRAINED, allowed_resources=frozenset()
            )

        if (
            parent_scope.mode == AuthorityScopeMode.UNCONSTRAINED
            and child_scope.mode == AuthorityScopeMode.ALLOWLIST
        ):
            return ResourceAuthorityScope(
                mode=AuthorityScopeMode.ALLOWLIST,
                allowed_resources=frozenset(child_scope.allowed_resources),
            )

        if (
            parent_scope.mode == AuthorityScopeMode.ALLOWLIST
            and child_scope.mode == AuthorityScopeMode.UNCONSTRAINED
        ):
            return ResourceAuthorityScope(
                mode=AuthorityScopeMode.ALLOWLIST,
                allowed_resources=frozenset(parent_scope.allowed_resources),
            )

        # Both ALLOWLIST
        intersection = frozenset(parent_scope.allowed_resources).intersection(
            child_scope.allowed_resources
        )
        return ResourceAuthorityScope(
            mode=AuthorityScopeMode.ALLOWLIST, allowed_resources=intersection
        )

    # ----------------------------------------------------------------------
    # 2. Live Effective Authority Derivation
    # ----------------------------------------------------------------------

    def compute_live_effective_authority(
        self,
        grant: DelegationGrant,
        ancestors: list[DelegationGrant],
        root_intent: IntentContract,
    ) -> AuthorityEnvelope:
        """Derive the current live effective authority envelope by intersecting

        the live Root Intent with all ancestor grants and the target grant.
        """
        # Start with root intent capabilities
        effective_tools = set(root_intent.allowed_tools)
        effective_environments = set(root_intent.allowed_environments)
        effective_classifications = set(root_intent.allowed_data_classifications)
        effective_resource_scope = ResourceAuthorityScope.from_intent(root_intent.allowed_resources)

        # Narrow sequentially through ancestors
        for ancestor in ancestors:
            effective_tools.intersection_update(ancestor.authority_envelope.allowed_tools)
            effective_environments.intersection_update(
                ancestor.authority_envelope.allowed_environments
            )
            effective_classifications.intersection_update(
                ancestor.authority_envelope.allowed_data_classifications
            )
            effective_resource_scope = self.intersect_resource_scopes(
                effective_resource_scope, ancestor.authority_envelope.resource_scope
            )

        # Narrow through target grant
        effective_tools.intersection_update(grant.authority_envelope.allowed_tools)
        effective_environments.intersection_update(grant.authority_envelope.allowed_environments)
        effective_classifications.intersection_update(
            grant.authority_envelope.allowed_data_classifications
        )
        effective_resource_scope = self.intersect_resource_scopes(
            effective_resource_scope, grant.authority_envelope.resource_scope
        )

        return AuthorityEnvelope(
            allowed_tools=frozenset(effective_tools),
            resource_scope=effective_resource_scope,
            allowed_environments=frozenset(effective_environments),
            allowed_data_classifications=frozenset(effective_classifications),
        )

    # ----------------------------------------------------------------------
    # 3. Live Effective Status Derivation
    # ----------------------------------------------------------------------

    @staticmethod
    def compute_effective_status(
        grant: DelegationGrant,
        runtime_state: DelegationRuntimeState,
        ancestors: list[DelegationGrant],
        ancestor_states: list[DelegationRuntimeState],
        root_intent: IntentContract,
        now: datetime | None = None,
    ) -> EffectiveDelegationStatus:
        """Compute the live effective authorization status of a grant."""
        current_time = now or datetime.now(UTC)

        # 1. Root Intent checks
        if root_intent.status != IntentStatus.ACTIVE:
            return EffectiveDelegationStatus.ROOT_INVALID
        if root_intent.expires_at is not None and current_time >= root_intent.expires_at:
            return EffectiveDelegationStatus.ROOT_INVALID
        if root_intent.tool_calls_count >= root_intent.maximum_tool_calls:
            return EffectiveDelegationStatus.ROOT_INVALID

        # 2. Ancestor chain checks
        for anc_grant, anc_state in zip(ancestors, ancestor_states, strict=False):
            if anc_state.status == DelegationStatus.REVOKED:
                return EffectiveDelegationStatus.REVOKED
            if anc_state.status == DelegationStatus.CLOSED:
                return EffectiveDelegationStatus.CLOSED
            if current_time >= anc_grant.expires_at:
                return EffectiveDelegationStatus.ANCESTOR_INVALID
            if anc_state.actions_executed_count >= anc_grant.max_actions:
                return EffectiveDelegationStatus.ANCESTOR_INVALID

        # 3. Target grant checks
        if runtime_state.status == DelegationStatus.REVOKED:
            return EffectiveDelegationStatus.REVOKED
        if runtime_state.status == DelegationStatus.CLOSED:
            return EffectiveDelegationStatus.CLOSED
        if current_time >= grant.expires_at:
            return EffectiveDelegationStatus.EXPIRED
        if runtime_state.actions_executed_count >= grant.max_actions:
            return EffectiveDelegationStatus.CONSUMED

        return EffectiveDelegationStatus.ACTIVE

    # ----------------------------------------------------------------------
    # 4. Proposal Validation & Policy Fact Helpers
    # ----------------------------------------------------------------------

    @staticmethod
    def is_authorized_issuer(
        proposal: DelegationProposal,
        principal: AgentPrincipal,
        root_intent: IntentContract,
        parent_grant: DelegationGrant | None,
    ) -> bool:
        """Verify that caller principal is authorized to issue this delegation grant."""
        p_agent = str(principal.agent_id)
        prop_delegator = str(proposal.delegator_agent_id)
        r_agent = str(root_intent.agent_id)
        r_user = str(root_intent.user_id)

        if principal.is_control_plane:
            # Control plane can mediate if delegator matches root owner or parent delegatee
            if parent_grant is None:
                return prop_delegator in (r_agent, r_user)
            return prop_delegator == str(parent_grant.delegatee_agent_id)

        # Direct agent issuance
        if prop_delegator != p_agent:
            return False

        if parent_grant is None:
            return p_agent in (r_agent, r_user)

        return p_agent == str(parent_grant.delegatee_agent_id)

    @staticmethod
    def is_authorized_to_revoke(
        grant: DelegationGrant,
        principal: AgentPrincipal,
        root_intent: IntentContract,
    ) -> bool:
        """Verify that caller principal has permission to revoke the grant."""
        if principal.is_control_plane:
            return str(principal.session_id) == str(grant.session_id)

        p_agent = str(principal.agent_id)
        # Root intent owner can revoke any descendant
        if p_agent in (str(root_intent.agent_id), str(root_intent.user_id)):
            return True

        # Direct delegator can revoke child
        return p_agent == str(grant.delegator_agent_id)

    @staticmethod
    def is_authorized_to_close(
        grant: DelegationGrant,
        principal: AgentPrincipal,
    ) -> bool:
        """Verify that caller principal has permission to close the grant."""
        if principal.is_control_plane:
            return True
        return str(principal.agent_id) == str(grant.delegatee_agent_id)

    def check_depth_limits(
        self,
        proposal: DelegationProposal,
        parent_grant: DelegationGrant | None,
        root_intent: IntentContract,
    ) -> bool:
        """Check whether the requested delegation depth is within allowable limits."""
        if parent_grant is None:
            # Root delegation
            requested_depth = (
                proposal.requested_depth if proposal.requested_depth is not None else 1
            )
            return 0 <= requested_depth <= self.max_session_delegation_depth

        # Subdelegation: parent must have remaining subdelegation slots
        if parent_grant.remaining_subdelegation_depth <= 0:
            return False

        if parent_grant.depth + 1 > self.max_session_delegation_depth:
            return False

        return True

    def check_scope_subset_parent(
        self,
        proposal: DelegationProposal,
        parent_grant: DelegationGrant | None,
    ) -> bool:
        """Verify that proposal capabilities are a subset of parent grant authority."""
        if parent_grant is None:
            return True

        parent_env = parent_grant.authority_envelope
        req_tools = set(proposal.requested_tools)
        if not req_tools.issubset(parent_env.allowed_tools):
            return False

        req_envs = {
            e.value if hasattr(e, "value") else str(e) for e in proposal.requested_environments
        }
        parent_envs = {
            e.value if hasattr(e, "value") else str(e) for e in parent_env.allowed_environments
        }
        if not req_envs.issubset(parent_envs):
            return False

        req_classes = {
            c.value if hasattr(c, "value") else str(c) for c in proposal.requested_classifications
        }
        parent_classes = {
            c.value if hasattr(c, "value") else str(c)
            for c in parent_env.allowed_data_classifications
        }
        if not req_classes.issubset(parent_classes):
            return False

        if proposal.requested_max_actions > parent_grant.max_actions:
            return False

        return self.is_resource_scope_subset(
            proposal.requested_resource_scope, parent_env.resource_scope
        )

    def check_scope_subset_root(
        self,
        proposal: DelegationProposal,
        root_intent: IntentContract,
    ) -> bool:
        """Verify that proposal capabilities are a subset of root Intent Contract."""
        if proposal.requested_max_actions > root_intent.maximum_tool_calls:
            return False

        req_tools = set(proposal.requested_tools)
        if not req_tools.issubset(set(root_intent.allowed_tools)):
            return False

        req_envs = {
            e.value if hasattr(e, "value") else str(e) for e in proposal.requested_environments
        }
        root_envs = {
            e.value if hasattr(e, "value") else str(e) for e in root_intent.allowed_environments
        }
        if not req_envs.issubset(root_envs):
            return False

        req_classes = {
            c.value if hasattr(c, "value") else str(c) for c in proposal.requested_classifications
        }
        root_classes = {
            c.value if hasattr(c, "value") else str(c)
            for c in root_intent.allowed_data_classifications
        }
        if not req_classes.issubset(root_classes):
            return False

        root_scope = ResourceAuthorityScope.from_intent(root_intent.allowed_resources)
        return self.is_resource_scope_subset(proposal.requested_resource_scope, root_scope)

    @staticmethod
    def check_session_match(
        session_id: UUID | str,
        root_intent: IntentContract,
        parent_grant: DelegationGrant | None,
    ) -> bool:
        """Verify that session IDs match across root intent and parent grant."""
        if str(root_intent.session_id) != str(session_id):
            return False
        if parent_grant is not None and str(parent_grant.session_id) != str(session_id):
            return False
        return True

    @staticmethod
    def check_budget_available(
        runtime_state: DelegationRuntimeState,
        ancestor_states: list[DelegationRuntimeState],
        root_intent: IntentContract,
        grant: DelegationGrant | None = None,
        ancestors: list[DelegationGrant] | None = None,
    ) -> bool:
        """Verify that remaining action budget exists on root, ancestors, and target grant."""
        if root_intent.tool_calls_count >= root_intent.maximum_tool_calls:
            return False

        if grant is not None and runtime_state.actions_executed_count >= grant.max_actions:
            return False

        if ancestors and ancestor_states:
            for anc_grant, anc_state in zip(ancestors, ancestor_states, strict=False):
                if anc_state.actions_executed_count >= anc_grant.max_actions:
                    return False

        return True

    @staticmethod
    def is_tool_authorized(tool_name: str, effective_scope: AuthorityEnvelope) -> bool:
        """Check if tool is present in live effective authority."""
        return tool_name in effective_scope.allowed_tools

    @staticmethod
    def is_resource_authorized(
        target_resource: str | None, effective_scope: AuthorityEnvelope
    ) -> bool:
        """Check if resource is authorized under live effective resource scope."""
        return effective_scope.resource_scope.is_allowed(target_resource)

    @staticmethod
    def is_environment_authorized(
        target_env: TargetEnvironment | str, effective_scope: AuthorityEnvelope
    ) -> bool:
        """Check if target environment is authorized under live effective scope."""
        env_str = str(target_env.value if hasattr(target_env, "value") else target_env)
        allowed = {
            str(e.value if hasattr(e, "value") else e) for e in effective_scope.allowed_environments
        }
        return env_str in allowed

    @staticmethod
    def is_classification_authorized(
        data_classifications: list[DataClassification] | list[str],
        effective_scope: AuthorityEnvelope,
    ) -> bool:
        """Check if data classifications are authorized under live effective scope."""
        if not data_classifications:
            return True
        req_classes = {str(c.value if hasattr(c, "value") else c) for c in data_classifications}
        allowed = {
            str(c.value if hasattr(c, "value") else c)
            for c in effective_scope.allowed_data_classifications
        }
        return req_classes.issubset(allowed)
