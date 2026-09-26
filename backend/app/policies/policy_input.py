"""Factory for constructing canonical, server-authoritative CagePolicyInput documents."""

from typing import TYPE_CHECKING, Any

from app.gateway.registry import default_tool_registry

if TYPE_CHECKING:
    from app.gateway.registry import ToolRegistry
from app.schemas.action import AgentAction
from app.schemas.enums import ActionType
from app.schemas.intent import IntentContract
from app.schemas.policy import (
    CagePolicyInput,
    PolicyActionContext,
    PolicyAgentContext,
    PolicyApprovalFactContext,
    PolicyDataContext,
    PolicyDelegationContext,
    PolicyGraphContext,
    PolicyIntentContext,
    PolicyProvenanceContext,
    PolicyRuntimeContext,
    PolicyToolContext,
    PolicyTrajectoryContext,
)


def build_cage_policy_input(
    action: AgentAction,
    contract: IntentContract | None = None,
    tool_registry: "ToolRegistry | None" = None,
    require_intent: bool = True,
    intent_mismatch: bool = False,
    graph_context: PolicyGraphContext | None = None,
    provenance_context: PolicyProvenanceContext | None = None,
    trajectory_context: PolicyTrajectoryContext | None = None,
    delegation_context: PolicyDelegationContext | None = None,
) -> CagePolicyInput:
    """Build the single authoritative CagePolicyInput document for an evaluated action.

    Guarantees that both Python rules and OPA Rego policies evaluate strictly identical,
    server-sanitized policy contexts.
    """
    if tool_registry is not None:
        registry = tool_registry
    else:
        from app.gateway.registry import default_tool_registry

        registry = default_tool_registry
    tool_spec = registry.get(action.tool_name)

    # 1. Action context
    action_ctx = PolicyActionContext(
        action_id=str(action.action_id),
        action_type=action.action_type.value,
        tool_name=action.tool_name,
        target_resource=action.target_resource,
        target_environment=action.target_environment.value,
    )

    # 2. Agent context
    agent_ctx = PolicyAgentContext(
        agent_id=action.agent_id,
        session_id=action.session_id,
        user_id=action.user_id,
    )

    # 3. Intent context
    intent_ctx: PolicyIntentContext | None = None
    if contract is not None:
        intent_ctx = PolicyIntentContext(
            intent_id=str(contract.intent_id),
            status=contract.status.value,
            allowed_tools=sorted(list(contract.allowed_tools)),
            denied_tools=sorted(list(contract.denied_tools)),
            allowed_environments=sorted([e.value for e in contract.allowed_environments]),
            allowed_resources=sorted(list(contract.allowed_resources)),
            denied_resources=sorted(list(contract.denied_resources)),
            allowed_data_classifications=sorted(
                [c.value for c in contract.allowed_data_classifications]
            ),
            requires_approval=sorted(list(contract.requires_approval)),
            maximum_tool_calls=contract.maximum_tool_calls,
            tool_calls_count=contract.tool_calls_count,
        )

    # 4. Tool context
    destructive = tool_spec.destructive or action.action_type == ActionType.DESTRUCTIVE
    server_classifications = (
        [tool_spec.default_classification.value] if tool_spec.default_classification else []
    )
    binding_mode = (
        tool_spec.payload_binding_mode.value
        if hasattr(tool_spec.payload_binding_mode, "value")
        else str(tool_spec.payload_binding_mode)
    )
    tool_ctx = PolicyToolContext(
        known=tool_spec.known,
        privileged=tool_spec.privileged,
        destructive=destructive,
        external_sink=tool_spec.external_sink,
        resource_scoped=tool_spec.resource_scoped,
        server_known_classifications=server_classifications,
        requires_tracked_inputs=tool_spec.requires_tracked_inputs,
        payload_binding_mode=binding_mode,
    )

    # 5. Data context (Server-known UNION client-declared)
    effective = registry.get_effective_classifications(
        action.tool_name, action.data_classifications
    )
    data_ctx = PolicyDataContext(
        effective_classifications=sorted([c.value for c in effective]),
    )

    # 6. Runtime context
    runtime_ctx = PolicyRuntimeContext(
        require_intent=require_intent,
        intent_mismatch=intent_mismatch,
        parent_action_id=str(action.parent_action_id) if action.parent_action_id else None,
        delegation_depth=len(action.delegation_chain),
    )

    graph_ctx = graph_context or PolicyGraphContext()
    prov_ctx = provenance_context or PolicyProvenanceContext()
    traj_ctx = trajectory_context or PolicyTrajectoryContext()
    delegation_ctx = delegation_context or PolicyDelegationContext()

    return CagePolicyInput(
        action=action_ctx,
        agent=agent_ctx,
        intent=intent_ctx,
        tool=tool_ctx,
        data=data_ctx,
        context=runtime_ctx,
        graph=graph_ctx,
        provenance=prov_ctx,
        trajectory=traj_ctx,
        delegation=delegation_ctx,
    )


def build_delegation_create_context(
    proposal: Any,
    principal: Any,
    root_intent: Any,
    parent_grant: Any | None,
    analyzer: Any,
    ancestors: list[Any] | None = None,
) -> PolicyDelegationContext:
    """Build authoritative PolicyDelegationContext strictly for CREATE_GRANT operations."""
    caller_auth = analyzer.is_authorized_issuer(proposal, principal, root_intent, parent_grant)
    parent_valid = parent_grant is not None
    if parent_grant is not None:
        ancestor_list = ancestors or [parent_grant]
        ancestor_agents = {str(root_intent.agent_id)}
        for a in ancestor_list:
            ancestor_agents.add(str(a.delegator_agent_id))
            ancestor_agents.add(str(a.delegatee_agent_id))
        if str(proposal.delegatee_agent_id) in ancestor_agents:
            parent_valid = False
    cross_session = analyzer.check_session_match(proposal.session_id, root_intent, parent_grant)
    subdeleg_allowed = parent_grant.allow_subdelegation if parent_grant else True
    depth_ok = analyzer.check_depth_limits(proposal, parent_grant, root_intent)
    scope_parent = analyzer.check_scope_subset_parent(proposal, parent_grant)
    scope_root = analyzer.check_scope_subset_root(proposal, root_intent)

    # Check if high-risk delegation requiring approval (e.g. destructive/privileged tools or root approval requirement)
    is_high_risk = False
    for tool_name in proposal.requested_tools:
        if tool_name in root_intent.requires_approval:
            is_high_risk = True
            break
        spec = default_tool_registry.get(tool_name)
        if spec.known and (spec.privileged or spec.destructive):
            is_high_risk = True
            break

    return PolicyDelegationContext(
        operation="CREATE_GRANT",
        is_delegated=True,
        delegation_id=None,
        parent_delegation_id=str(parent_grant.delegation_id) if parent_grant else None,
        delegation_depth=(parent_grant.depth + 1) if parent_grant else 1,
        remaining_subdelegation_depth=(
            max(0, parent_grant.remaining_subdelegation_depth - 1) if parent_grant else 0
        ),
        caller_is_authorized_issuer=caller_auth,
        parent_grant_valid=parent_valid or parent_grant is None,
        cross_session_match=cross_session,
        subdelegation_allowed=subdeleg_allowed,
        depth_within_limits=depth_ok,
        scope_within_parent=scope_parent,
        scope_within_root=scope_root,
        is_high_risk_delegation=is_high_risk,
    )


def build_delegated_action_context(
    action: AgentAction,
    principal: Any,
    grant: Any,
    runtime_state: Any,
    root_intent: Any,
    ancestors: list[Any],
    ancestor_states: list[Any],
    analyzer: Any,
) -> PolicyDelegationContext:
    """Build authoritative PolicyDelegationContext strictly for EXECUTE_ACTION operations."""
    effective_status = analyzer.compute_effective_status(
        grant, runtime_state, ancestors, ancestor_states, root_intent
    )
    effective_scope = analyzer.compute_live_effective_authority(grant, ancestors, root_intent)

    principal_matches = principal.agent_id == grant.delegatee_agent_id
    budget_ok = analyzer.check_budget_available(
        runtime_state, ancestor_states, root_intent, grant=grant, ancestors=ancestors
    )
    tool_ok = analyzer.is_tool_authorized(action.tool_name, effective_scope)

    resource_ok = analyzer.is_resource_authorized(action.target_resource, effective_scope)
    env_ok = analyzer.is_environment_authorized(action.target_environment, effective_scope)
    class_ok = analyzer.is_classification_authorized(action.data_classifications, effective_scope)

    return PolicyDelegationContext(
        operation="EXECUTE_ACTION",
        is_delegated=True,
        delegation_id=str(grant.delegation_id),
        parent_delegation_id=str(grant.parent_delegation_id)
        if grant.parent_delegation_id
        else None,
        delegation_depth=grant.depth,
        remaining_subdelegation_depth=grant.remaining_subdelegation_depth,
        principal_matches_delegatee=principal_matches,
        effective_status=effective_status.value
        if hasattr(effective_status, "value")
        else str(effective_status),
        budget_available=budget_ok,
        current_tool_within_effective_authority=tool_ok,
        current_resource_within_effective_authority=resource_ok,
        current_environment_within_effective_authority=env_ok,
        current_classification_within_effective_authority=class_ok,
    )


def build_delegation_approval_context(
    checkpoint: Any,
    approver_principal: Any,
    revalidation_passed: bool,
) -> PolicyDelegationContext:
    """Build authoritative PolicyDelegationContext strictly for RESOLVE_APPROVAL operations."""
    identity_match = (
        approver_principal.agent_id == checkpoint.designated_approver_id
        or approver_principal.is_control_plane
    )
    return PolicyDelegationContext(
        operation="RESOLVE_APPROVAL",
        is_delegated=True,
        approval=PolicyApprovalFactContext(
            approval_context_present=True,
            approval_required=True,
            approval_decision="APPROVED",
            approval_identity_match=identity_match,
            approval_revalidation_passed=revalidation_passed,
        ),
    )


def build_delegation_revocation_context(
    grant: Any,
    principal: Any,
    root_intent: Any,
    analyzer: Any,
) -> PolicyDelegationContext:
    """Build authoritative PolicyDelegationContext strictly for REVOKE_GRANT operations."""
    caller_auth = analyzer.is_authorized_to_revoke(grant, principal, root_intent)
    return PolicyDelegationContext(
        operation="REVOKE_GRANT",
        is_delegated=True,
        delegation_id=str(grant.delegation_id),
        caller_is_authorized_to_revoke=caller_auth,
    )
