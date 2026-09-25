"""Factory for constructing canonical, server-authoritative CagePolicyInput documents."""

from app.gateway.registry import ToolRegistry, default_tool_registry
from app.schemas.action import AgentAction
from app.schemas.enums import ActionType
from app.schemas.intent import IntentContract
from app.schemas.policy import (
    CagePolicyInput,
    PolicyActionContext,
    PolicyAgentContext,
    PolicyDataContext,
    PolicyGraphContext,
    PolicyIntentContext,
    PolicyRuntimeContext,
    PolicyToolContext,
)


def build_cage_policy_input(
    action: AgentAction,
    contract: IntentContract | None = None,
    tool_registry: ToolRegistry | None = None,
    require_intent: bool = True,
    intent_mismatch: bool = False,
    graph_context: PolicyGraphContext | None = None,
) -> CagePolicyInput:
    """Build the single authoritative CagePolicyInput document for an evaluated action.

    Guarantees that both Python rules and OPA Rego policies evaluate strictly identical,
    server-sanitized policy contexts.
    """
    registry = tool_registry or default_tool_registry
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
    tool_ctx = PolicyToolContext(
        known=tool_spec.known,
        privileged=tool_spec.privileged,
        destructive=destructive,
        external_sink=tool_spec.external_sink,
        resource_scoped=tool_spec.resource_scoped,
        server_known_classifications=server_classifications,
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

    return CagePolicyInput(
        action=action_ctx,
        agent=agent_ctx,
        intent=intent_ctx,
        tool=tool_ctx,
        data=data_ctx,
        context=runtime_ctx,
        graph=graph_ctx,
    )
