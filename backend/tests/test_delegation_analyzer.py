"""Tests for DelegationAnalyzer live effective authority derivation, scope narrowing, and effective status."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from app.delegation.analyzer import DelegationAnalyzer
from app.delegation.models import (
    DelegationGrant,
    DelegationRuntimeState,
    ResourceAuthorityScopeRequest,
)
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


def _create_sample_intent(
    tools=None,
    resources=None,
    environments=None,
    classifications=None,
    status=IntentStatus.ACTIVE,
    max_calls=100,
    calls_count=0,
    intent_id=None,
    session_id=None,
) -> IntentContract:
    if tools is None:
        tools = ["web.search", "db.read", "file.write"]
    if resources is None:
        resources = ["res://1", "res://2"]
    if environments is None:
        environments = [TargetEnvironment.DEVELOPMENT]
    if classifications is None:
        classifications = [DataClassification.PUBLIC, DataClassification.INTERNAL]
    return IntentContract(
        intent_id=intent_id or uuid4(),
        session_id=session_id or str(uuid4()),
        agent_id="root-agent",
        user_id="user-1",
        goal="Test multi-agent goal",
        allowed_tools=tools,
        allowed_environments=environments,
        allowed_resources=resources,
        allowed_data_classifications=classifications,
        maximum_tool_calls=max_calls,
        tool_calls_count=calls_count,
        status=status,
    )


def test_resource_scope_subset_logic():
    analyzer = DelegationAnalyzer()

    parent_unconstrained = ResourceAuthorityScope(mode=AuthorityScopeMode.UNCONSTRAINED)
    parent_allowlist = ResourceAuthorityScope(
        mode=AuthorityScopeMode.ALLOWLIST, allowed_resources=frozenset(["res://1", "res://2"])
    )

    child_unconstrained = ResourceAuthorityScopeRequest(mode=AuthorityScopeMode.UNCONSTRAINED)
    child_subset = ResourceAuthorityScopeRequest(
        mode=AuthorityScopeMode.ALLOWLIST, allowed_resources=["res://1"]
    )
    child_superset = ResourceAuthorityScopeRequest(
        mode=AuthorityScopeMode.ALLOWLIST, allowed_resources=["res://1", "res://3"]
    )

    # UNCONSTRAINED parent allows any child
    assert analyzer.is_resource_scope_subset(child_unconstrained, parent_unconstrained) is True
    assert analyzer.is_resource_scope_subset(child_subset, parent_unconstrained) is True

    # ALLOWLIST parent denies UNCONSTRAINED child
    assert analyzer.is_resource_scope_subset(child_unconstrained, parent_allowlist) is False

    # ALLOWLIST parent allows subset
    assert analyzer.is_resource_scope_subset(child_subset, parent_allowlist) is True

    # ALLOWLIST parent denies non-subset
    assert analyzer.is_resource_scope_subset(child_superset, parent_allowlist) is False


def test_live_effective_authority_intersection_and_narrowing():
    """Live effective authority dynamically reflects live Root Intent narrowing without grant mutation."""
    analyzer = DelegationAnalyzer()
    root_intent = _create_sample_intent(
        tools=["web.search", "db.read"],
        resources=["res://1", "res://2"],
    )

    grant = DelegationGrant(
        delegation_id=uuid4(),
        root_intent_id=root_intent.intent_id,
        session_id=root_intent.session_id,
        issued_from_action_id=uuid4(),
        delegator_agent_id="root-agent",
        delegatee_agent_id="agent-b",
        delegated_task_id="task-1",
        authority_envelope=AuthorityEnvelope(
            allowed_tools=frozenset(["web.search", "db.read"]),
            resource_scope=ResourceAuthorityScope(
                mode=AuthorityScopeMode.ALLOWLIST,
                allowed_resources=frozenset(["res://1", "res://2"]),
            ),
            allowed_environments=frozenset([TargetEnvironment.DEVELOPMENT]),
            allowed_data_classifications=frozenset([DataClassification.PUBLIC]),
        ),
        depth=1,
        remaining_subdelegation_depth=1,
        allow_subdelegation=True,
        max_actions=10,
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )

    # Initial live authority contains web.search and db.read
    eff1 = analyzer.compute_live_effective_authority(grant, ancestors=[], root_intent=root_intent)
    assert eff1.allowed_tools == frozenset(["web.search", "db.read"])

    # Root Intent narrows at T1 to remove db.read
    narrowed_root = _create_sample_intent(
        tools=["web.search"],
        resources=["res://1"],
        intent_id=root_intent.intent_id,
        session_id=root_intent.session_id,
    )

    eff2 = analyzer.compute_live_effective_authority(grant, ancestors=[], root_intent=narrowed_root)
    assert eff2.allowed_tools == frozenset(["web.search"])
    assert eff2.resource_scope.allowed_resources == frozenset(["res://1"])


def test_effective_status_lazy_propagation():
    """Ancestor revocation or closure dynamically invalidates descendant live effective status."""
    analyzer = DelegationAnalyzer()
    root_intent = _create_sample_intent()

    g_parent = DelegationGrant(
        delegation_id=uuid4(),
        root_intent_id=root_intent.intent_id,
        session_id=root_intent.session_id,
        issued_from_action_id=uuid4(),
        delegator_agent_id="root-agent",
        delegatee_agent_id="agent-a",
        delegated_task_id="task-p",
        authority_envelope=AuthorityEnvelope(
            allowed_tools=frozenset(["web.search"]),
            resource_scope=ResourceAuthorityScope(mode=AuthorityScopeMode.UNCONSTRAINED),
            allowed_environments=frozenset([TargetEnvironment.DEVELOPMENT]),
            allowed_data_classifications=frozenset([DataClassification.PUBLIC]),
        ),
        depth=1,
        remaining_subdelegation_depth=1,
        allow_subdelegation=True,
        max_actions=10,
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    state_parent = DelegationRuntimeState(
        delegation_id=g_parent.delegation_id, status=DelegationStatus.REVOKED
    )

    g_child = DelegationGrant(
        delegation_id=uuid4(),
        parent_delegation_id=g_parent.delegation_id,
        root_intent_id=root_intent.intent_id,
        session_id=root_intent.session_id,
        issued_from_action_id=uuid4(),
        delegator_agent_id="agent-a",
        delegatee_agent_id="agent-b",
        delegated_task_id="task-c",
        authority_envelope=AuthorityEnvelope(
            allowed_tools=frozenset(["web.search"]),
            resource_scope=ResourceAuthorityScope(mode=AuthorityScopeMode.UNCONSTRAINED),
            allowed_environments=frozenset([TargetEnvironment.DEVELOPMENT]),
            allowed_data_classifications=frozenset([DataClassification.PUBLIC]),
        ),
        depth=2,
        remaining_subdelegation_depth=0,
        allow_subdelegation=False,
        max_actions=5,
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    state_child = DelegationRuntimeState(
        delegation_id=g_child.delegation_id, status=DelegationStatus.ACTIVE
    )

    # Child's stored state is ACTIVE, but ancestor is REVOKED -> Effective is REVOKED
    eff_status = analyzer.compute_effective_status(
        grant=g_child,
        runtime_state=state_child,
        ancestors=[g_parent],
        ancestor_states=[state_parent],
        root_intent=root_intent,
    )
    assert eff_status == EffectiveDelegationStatus.REVOKED
