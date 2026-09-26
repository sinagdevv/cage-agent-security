"""Tests for Phase 8 delegation approval-time live revalidation (Blocker 2).

Validates that before grant issuance, all authoritative state is revalidated:
- root revoked
- root narrowed
- parent revoked
- parent closed
- parent expired
- subdelegation disabled
- depth exhausted
- session mismatch
- principal mismatch
- request payload changed
- trajectory quarantined
- budget exhausted

For every stale failure:
- no DelegationGrant created
- no delegation_id issued
- no dispatch
- no child authority created
"""

from uuid import UUID, uuid4

from app.delegation.models import DelegationProposal, ResourceAuthorityScopeRequest
from app.delegation.service import DelegationService
from app.delegation.store import DelegationStore
from app.identity.principal import AgentPrincipal, PrincipalAuthenticationSource
from app.intent.service import IntentService
from app.schemas.enums import (
    DataClassification,
    PolicyDecision,
    TargetEnvironment,
)
from app.schemas.intent import IntentContractCreate, IntentContractNarrow
from app.trajectory.store import TrajectoryStore


def _make_principal(
    agent_id: str, session_id: UUID, is_control_plane: bool = False
) -> AgentPrincipal:
    return AgentPrincipal(
        agent_id=agent_id,
        session_id=session_id,
        authentication_source=PrincipalAuthenticationSource.HOSTING_RUNTIME,
        is_control_plane=is_control_plane,
    )


def _setup_service() -> tuple[
    DelegationService, IntentService, DelegationStore, TrajectoryStore, UUID, UUID, str
]:
    """Helper fixture setup."""
    intent_service = IntentService()
    store = DelegationStore()
    traj_store = TrajectoryStore()
    service = DelegationService(
        store=store,
        intent_service=intent_service,
        trajectory_store=traj_store,
    )
    session_id = uuid4()
    agent_a_id = "agent-a"
    intent = intent_service.create_intent(
        IntentContractCreate(
            session_id=str(session_id),
            agent_id=agent_a_id,
            user_id="user-1",
            goal="Test delegation revalidation",
            allowed_tools=["database.read", "web.search"],
            allowed_resources=["customer-db", "public-data"],
            allowed_environments=[TargetEnvironment.PRODUCTION],
            allowed_data_classifications=[DataClassification.INTERNAL],
            maximum_tool_calls=10,
        )
    )
    traj_store.create_trajectory(
        session_id=str(session_id),
        intent_id=intent.intent_id,
        agent_id=agent_a_id,
    )
    return service, intent_service, store, traj_store, session_id, intent.intent_id, agent_a_id


def _make_proposal(
    session_id: UUID,
    root_id: UUID,
    delegator: str,
    delegatee: str,
    task_id: str = "task-db",
    parent_id: UUID | None = None,
    allow_subdel: bool = False,
    depth: int | None = None,
    ttl: int = 3600,
) -> DelegationProposal:
    return DelegationProposal(
        session_id=session_id,
        root_intent_id=root_id,
        parent_delegation_id=parent_id,
        delegator_agent_id=delegator,
        delegatee_agent_id=delegatee,
        delegated_task_id=task_id,
        requested_tools=["database.read"],
        requested_resource_scope=ResourceAuthorityScopeRequest.allowlist(["customer-db"]),
        requested_environments=[TargetEnvironment.PRODUCTION],
        requested_classifications=[DataClassification.INTERNAL],
        allow_subdelegation=allow_subdel,
        requested_depth=depth,
        requested_ttl_seconds=ttl,
    )


def test_stale_approval_root_revoked():
    """Verify that revoking root intent before approval blocks grant issuance."""
    service, intent_service, store, _, session_id, root_id, agent_a_id = _setup_service()
    agent_b_id = "agent-b"

    proposal = _make_proposal(session_id, root_id, agent_a_id, agent_b_id)
    principal = _make_principal(agent_a_id, session_id, is_control_plane=True)

    create_res = service.propose_delegation(proposal, principal)
    assert create_res.decision == PolicyDecision.REQUIRE_APPROVAL
    req_id = create_res.delegation_request_id

    # Mutate root: Revoke
    intent_service.revoke_intent(root_id, reason="Security revocation")

    approver = _make_principal("security-officer", session_id, is_control_plane=True)
    res = service.resolve_delegation_approval(req_id, approver)

    assert res.decision == PolicyDecision.DENY
    assert res.delegation_id is None
    assert "RULE_DELEGATION_APPROVAL_STALE_AUTHORITY" in res.matched_rules
    assert store.get_session_active_grant_count(session_id) == 0


def test_stale_approval_root_narrowed():
    """Verify that narrowing root intent authority before approval blocks grant issuance."""
    service, intent_service, store, _, session_id, root_id, agent_a_id = _setup_service()
    agent_b_id = "agent-b"

    proposal = _make_proposal(session_id, root_id, agent_a_id, agent_b_id)
    principal = _make_principal(agent_a_id, session_id, is_control_plane=True)

    create_res = service.propose_delegation(proposal, principal)
    assert create_res.decision == PolicyDecision.REQUIRE_APPROVAL
    req_id = create_res.delegation_request_id

    # Mutate root: Narrow to only web.search (removing database.read)
    intent_service.narrow_intent(
        root_id,
        IntentContractNarrow(
            allowed_tools=["web.search"],
        ),
    )

    approver = _make_principal("security-officer", session_id, is_control_plane=True)
    res = service.resolve_delegation_approval(req_id, approver)

    assert res.decision == PolicyDecision.DENY
    assert res.delegation_id is None
    assert "RULE_DELEGATION_APPROVAL_STALE_AUTHORITY" in res.matched_rules
    assert store.get_session_active_grant_count(session_id) == 0


def test_stale_approval_parent_revoked():
    """Verify that revoking parent grant before approval blocks child grant issuance."""
    service, _, _, _, session_id, root_id, agent_a_id = _setup_service()
    agent_b_id = "agent-b"
    agent_c_id = "agent-c"

    # Step 1: Create parent grant (Agent A -> Agent B)
    p_prop = _make_proposal(session_id, root_id, agent_a_id, agent_b_id, allow_subdel=True, depth=3)
    p_princ = _make_principal(agent_a_id, session_id, is_control_plane=True)
    p_res = service.propose_delegation(p_prop, p_princ)
    assert p_res.decision == PolicyDecision.REQUIRE_APPROVAL
    p_grant_res = service.resolve_delegation_approval(p_res.delegation_request_id, p_princ)
    assert p_grant_res.decision == PolicyDecision.ALLOW
    parent_id = p_grant_res.delegation_id

    # Step 2: Propose child grant (Agent B -> Agent C)
    c_prop = _make_proposal(session_id, root_id, agent_b_id, agent_c_id, parent_id=parent_id)
    c_princ = _make_principal(agent_b_id, session_id, is_control_plane=False)
    c_res = service.propose_delegation(c_prop, c_princ)
    assert c_res.decision == PolicyDecision.REQUIRE_APPROVAL
    c_req_id = c_res.delegation_request_id

    # Step 3: Revoke parent grant before approval
    service.revoke_delegation(parent_id, principal=p_princ)

    # Step 4: Attempt to approve child
    appr_res = service.resolve_delegation_approval(c_req_id, p_princ)
    assert appr_res.decision == PolicyDecision.DENY
    assert appr_res.delegation_id is None
    assert "RULE_DELEGATION_APPROVAL_STALE_AUTHORITY" in appr_res.matched_rules


def test_stale_approval_parent_closed():
    """Verify that closing parent grant before approval blocks child grant issuance."""
    service, _, _, _, session_id, root_id, agent_a_id = _setup_service()
    agent_b_id = "agent-b"
    agent_c_id = "agent-c"

    # Step 1: Create parent grant
    p_prop = _make_proposal(session_id, root_id, agent_a_id, agent_b_id, allow_subdel=True, depth=3)
    p_princ = _make_principal(agent_a_id, session_id, is_control_plane=True)
    p_res = service.propose_delegation(p_prop, p_princ)
    p_grant_res = service.resolve_delegation_approval(p_res.delegation_request_id, p_princ)
    parent_id = p_grant_res.delegation_id

    # Step 2: Propose child grant
    c_prop = _make_proposal(session_id, root_id, agent_b_id, agent_c_id, parent_id=parent_id)
    c_res = service.propose_delegation(c_prop, p_princ)
    c_req_id = c_res.delegation_request_id

    # Step 3: Close parent
    service.close_delegation(parent_id, principal=_make_principal(agent_b_id, session_id))

    # Step 4: Attempt to approve child
    appr_res = service.resolve_delegation_approval(c_req_id, p_princ)
    assert appr_res.decision == PolicyDecision.DENY
    assert appr_res.delegation_id is None
    assert "RULE_DELEGATION_APPROVAL_STALE_AUTHORITY" in appr_res.matched_rules


def test_stale_approval_parent_expired():
    """Verify that parent grant expiration before approval blocks child issuance."""
    service, _, _, _, session_id, root_id, agent_a_id = _setup_service()
    agent_b_id = "agent-b"
    agent_c_id = "agent-c"

    # Parent grant with short/expired TTL
    p_prop = _make_proposal(
        session_id, root_id, agent_a_id, agent_b_id, allow_subdel=True, depth=3, ttl=-10
    )
    p_princ = _make_principal(agent_a_id, session_id, is_control_plane=True)
    p_res = service.propose_delegation(p_prop, p_princ)
    p_grant_res = service.resolve_delegation_approval(p_res.delegation_request_id, p_princ)
    parent_id = p_grant_res.delegation_id

    # Propose child
    c_prop = _make_proposal(session_id, root_id, agent_b_id, agent_c_id, parent_id=parent_id)
    c_res = service.propose_delegation(c_prop, p_princ)
    c_req_id = c_res.delegation_request_id

    appr_res = service.resolve_delegation_approval(c_req_id, p_princ)
    assert appr_res.decision == PolicyDecision.DENY
    assert appr_res.delegation_id is None
    assert "RULE_DELEGATION_APPROVAL_STALE_AUTHORITY" in appr_res.matched_rules


def test_stale_approval_subdelegation_disabled():
    """Verify that if parent grant disallows subdelegation, child approval fails."""
    service, _, _, _, session_id, root_id, agent_a_id = _setup_service()
    agent_b_id = "agent-b"
    agent_c_id = "agent-c"

    p_prop = _make_proposal(session_id, root_id, agent_a_id, agent_b_id, allow_subdel=False)
    p_princ = _make_principal(agent_a_id, session_id, is_control_plane=True)
    p_res = service.propose_delegation(p_prop, p_princ)
    p_grant_res = service.resolve_delegation_approval(p_res.delegation_request_id, p_princ)
    parent_id = p_grant_res.delegation_id

    c_prop = _make_proposal(session_id, root_id, agent_b_id, agent_c_id, parent_id=parent_id)
    c_res = service.propose_delegation(c_prop, p_princ)
    if c_res.decision == PolicyDecision.REQUIRE_APPROVAL:
        appr_res = service.resolve_delegation_approval(c_res.delegation_request_id, p_princ)
        assert appr_res.decision == PolicyDecision.DENY
    else:
        assert c_res.decision == PolicyDecision.DENY


def test_stale_approval_depth_exhausted():
    """Verify that if remaining subdelegation depth is exhausted, child issuance fails."""
    service, _, _, _, session_id, root_id, agent_a_id = _setup_service()
    agent_b_id = "agent-b"
    agent_c_id = "agent-c"

    p_prop = _make_proposal(session_id, root_id, agent_a_id, agent_b_id, allow_subdel=True, depth=1)
    p_princ = _make_principal(agent_a_id, session_id, is_control_plane=True)
    p_res = service.propose_delegation(p_prop, p_princ)
    p_grant_res = service.resolve_delegation_approval(p_res.delegation_request_id, p_princ)
    parent_id = p_grant_res.delegation_id

    c_prop = _make_proposal(
        session_id, root_id, agent_b_id, agent_c_id, parent_id=parent_id, allow_subdel=True
    )
    c_res = service.propose_delegation(c_prop, p_princ)
    if c_res.decision == PolicyDecision.REQUIRE_APPROVAL:
        appr_res = service.resolve_delegation_approval(c_res.delegation_request_id, p_princ)
        assert appr_res.decision == PolicyDecision.DENY
    else:
        assert c_res.decision == PolicyDecision.DENY


def test_stale_approval_session_mismatch():
    """Verify that proposal session mismatch against checkpoint is denied."""
    service, _, _, _, session_id, root_id, agent_a_id = _setup_service()
    agent_b_id = "agent-b"

    proposal = _make_proposal(session_id, root_id, agent_a_id, agent_b_id)
    principal = _make_principal(agent_a_id, session_id, is_control_plane=True)
    c_res = service.propose_delegation(proposal, principal)
    req_id = c_res.delegation_request_id

    # Tamper checkpoint session_id
    service._pending_approvals[req_id]["session_id"] = uuid4()

    res = service.resolve_delegation_approval(req_id, principal)
    assert res.decision == PolicyDecision.DENY
    assert res.delegation_id is None
    assert "RULE_DELEGATION_APPROVAL_STALE_AUTHORITY" in res.matched_rules


def test_stale_approval_principal_mismatch():
    """Verify that an untrusted approver principal fails with identity mismatch."""
    service, _, _, _, session_id, root_id, agent_a_id = _setup_service()
    agent_b_id = "agent-b"

    proposal = _make_proposal(session_id, root_id, agent_a_id, agent_b_id)
    principal = _make_principal(agent_a_id, session_id, is_control_plane=True)
    c_res = service.propose_delegation(proposal, principal)
    req_id = c_res.delegation_request_id

    # Untrusted principal (not control plane, not user)
    rogue_principal = _make_principal("rogue-agent", session_id, is_control_plane=False)
    res = service.resolve_delegation_approval(req_id, rogue_principal)
    assert res.decision == PolicyDecision.DENY
    assert res.delegation_id is None
    assert "RULE_DELEGATION_APPROVAL_IDENTITY_MISMATCH" in res.matched_rules


def test_stale_approval_request_payload_changed():
    """Verify that mutating the proposal payload between request and approval fails."""
    service, _, _, _, session_id, root_id, agent_a_id = _setup_service()
    agent_b_id = "agent-b"

    proposal = _make_proposal(session_id, root_id, agent_a_id, agent_b_id)
    principal = _make_principal(agent_a_id, session_id, is_control_plane=True)
    c_res = service.propose_delegation(proposal, principal)
    req_id = c_res.delegation_request_id

    # Tamper proposal payload in pending map
    service._pending_approvals[req_id]["proposal"].requested_tools.append("system.execute")

    res = service.resolve_delegation_approval(req_id, principal)
    assert res.decision == PolicyDecision.DENY
    assert res.delegation_id is None
    assert "RULE_DELEGATION_APPROVAL_STALE_AUTHORITY" in res.matched_rules


def test_stale_approval_trajectory_quarantined():
    """Verify that quarantining delegator's trajectory before approval blocks issuance."""
    service, _, _, traj_store, session_id, root_id, agent_a_id = _setup_service()
    agent_b_id = "agent-b"

    proposal = _make_proposal(session_id, root_id, agent_a_id, agent_b_id)
    principal = _make_principal(agent_a_id, session_id, is_control_plane=True)
    c_res = service.propose_delegation(proposal, principal)
    req_id = c_res.delegation_request_id

    # Quarantine delegator's trajectory
    traj_id = traj_store.get_trajectory_id(str(session_id), root_id, agent_a_id)
    assert traj_id is not None
    traj_store.mark_quarantined(traj_id)

    res = service.resolve_delegation_approval(req_id, principal)
    assert res.decision == PolicyDecision.DENY
    assert res.delegation_id is None
    assert "RULE_DELEGATION_APPROVAL_STALE_AUTHORITY" in res.matched_rules


def test_stale_approval_budget_exhausted():
    """Verify that exhausting root intent budget before approval blocks issuance."""
    service, intent_service, _, _, session_id, root_id, agent_a_id = _setup_service()
    agent_b_id = "agent-b"

    proposal = _make_proposal(session_id, root_id, agent_a_id, agent_b_id)
    principal = _make_principal(agent_a_id, session_id, is_control_plane=True)
    c_res = service.propose_delegation(proposal, principal)
    req_id = c_res.delegation_request_id

    # Exhaust root intent budget
    for _ in range(10):
        intent_service.reserve_tool_execution(root_id)

    res = service.resolve_delegation_approval(req_id, principal)
    assert res.decision == PolicyDecision.DENY
    assert res.delegation_id is None
    assert "RULE_DELEGATION_APPROVAL_STALE_AUTHORITY" in res.matched_rules


def test_stale_approval_ancestor_authority_narrowed_regression():
    """Required regression: Root Intent: search + db.read; A->B: search + db.read; B->C: search + db.read.

    Pending C->D requests db.read.
    Before approval, ancestor B authority is narrowed (e.g. db.read removed).
    Approval T2 MUST fail; no grant created, no delegation_id issued.
    """
    service, _, store, _, session_id, root_id, agent_a_id = _setup_service()
    agent_b_id = "agent-b"
    agent_c_id = "agent-c"
    agent_d_id = "agent-d"

    princ_a = _make_principal(agent_a_id, session_id, is_control_plane=True)
    princ_b = _make_principal(agent_b_id, session_id, is_control_plane=False)
    princ_c = _make_principal(agent_c_id, session_id, is_control_plane=False)

    # 1. A -> B (tools: database.read, web.search)
    prop_ab = DelegationProposal(
        session_id=session_id,
        root_intent_id=root_id,
        delegator_agent_id=agent_a_id,
        delegatee_agent_id=agent_b_id,
        delegated_task_id="task-ab",
        requested_tools=["database.read", "web.search"],
        requested_resource_scope=ResourceAuthorityScopeRequest.allowlist(["customer-db"]),
        requested_environments=[TargetEnvironment.PRODUCTION],
        requested_classifications=[DataClassification.INTERNAL],
        allow_subdelegation=True,
        requested_depth=5,
    )
    res_ab = service.propose_delegation(prop_ab, princ_a)
    grant_ab_res = service.resolve_delegation_approval(res_ab.delegation_request_id, princ_a)
    assert grant_ab_res.decision == PolicyDecision.ALLOW
    grant_ab_id = grant_ab_res.delegation_id

    # 2. B -> C (tools: database.read, web.search)
    prop_bc = DelegationProposal(
        session_id=session_id,
        root_intent_id=root_id,
        parent_delegation_id=grant_ab_id,
        delegator_agent_id=agent_b_id,
        delegatee_agent_id=agent_c_id,
        delegated_task_id="task-bc",
        requested_tools=["database.read", "web.search"],
        requested_resource_scope=ResourceAuthorityScopeRequest.allowlist(["customer-db"]),
        requested_environments=[TargetEnvironment.PRODUCTION],
        requested_classifications=[DataClassification.INTERNAL],
        allow_subdelegation=True,
        requested_depth=4,
    )
    res_bc = service.propose_delegation(prop_bc, princ_b)
    grant_bc_res = service.resolve_delegation_approval(res_bc.delegation_request_id, princ_a)
    assert grant_bc_res.decision == PolicyDecision.ALLOW
    grant_bc_id = grant_bc_res.delegation_id

    # 3. C -> D (requests database.read)
    prop_cd = DelegationProposal(
        session_id=session_id,
        root_intent_id=root_id,
        parent_delegation_id=grant_bc_id,
        delegator_agent_id=agent_c_id,
        delegatee_agent_id=agent_d_id,
        delegated_task_id="task-cd",
        requested_tools=["database.read"],
        requested_resource_scope=ResourceAuthorityScopeRequest.allowlist(["customer-db"]),
        requested_environments=[TargetEnvironment.PRODUCTION],
        requested_classifications=[DataClassification.INTERNAL],
        allow_subdelegation=False,
    )
    res_cd = service.propose_delegation(prop_cd, princ_c)
    assert res_cd.decision == PolicyDecision.REQUIRE_APPROVAL
    req_cd_id = res_cd.delegation_request_id

    # Pre-condition: NO DelegationGrant exists for C->D before approval
    assert res_cd.delegation_id is None
    assert req_cd_id in service._pending_approvals

    # 4. Narrow ancestor B's authority: remove database.read from B's envelope
    grant_b = store.get_grant(grant_ab_id)
    assert grant_b is not None
    narrowed_env = grant_b.authority_envelope.model_copy(
        update={"allowed_tools": frozenset(["web.search"])}
    )
    narrowed_b = grant_b.model_copy(update={"authority_envelope": narrowed_env})
    store._grants[grant_ab_id] = narrowed_b

    # 5. Attempt to approve C -> D
    res_approve = service.resolve_delegation_approval(req_cd_id, princ_a)
    assert res_approve.decision == PolicyDecision.DENY
    assert res_approve.delegation_id is None
    assert "RULE_DELEGATION_APPROVAL_STALE_AUTHORITY" in res_approve.matched_rules
    assert any(
        "Requested tools exceed live effective parent authority" in r for r in res_approve.reasons
    )
    # Ensure no grant created
    assert req_cd_id not in service._pending_approvals


def test_stale_approval_multi_tier_ancestor_revoked():
    """Verify that revoking ancestor B (grandparent of D) blocks approval of C->D."""
    service, _, store, _, session_id, root_id, agent_a_id = _setup_service()
    agent_b_id = "agent-b"
    agent_c_id = "agent-c"
    agent_d_id = "agent-d"

    princ_a = _make_principal(agent_a_id, session_id, is_control_plane=True)
    princ_b = _make_principal(agent_b_id, session_id, is_control_plane=False)
    princ_c = _make_principal(agent_c_id, session_id, is_control_plane=False)

    # A -> B
    p_ab = _make_proposal(session_id, root_id, agent_a_id, agent_b_id, allow_subdel=True, depth=5)
    r_ab = service.propose_delegation(p_ab, princ_a)
    g_ab_id = service.resolve_delegation_approval(r_ab.delegation_request_id, princ_a).delegation_id

    # B -> C
    p_bc = _make_proposal(
        session_id, root_id, agent_b_id, agent_c_id, parent_id=g_ab_id, allow_subdel=True, depth=4
    )
    r_bc = service.propose_delegation(p_bc, princ_b)
    g_bc_id = service.resolve_delegation_approval(r_bc.delegation_request_id, princ_a).delegation_id

    # C -> D (pending)
    p_cd = _make_proposal(session_id, root_id, agent_c_id, agent_d_id, parent_id=g_bc_id)
    r_cd = service.propose_delegation(p_cd, princ_c)
    req_cd_id = r_cd.delegation_request_id

    # Revoke grandparent A->B before approval of C->D
    service.revoke_delegation(g_ab_id, principal=princ_a)

    # Approve C->D
    res = service.resolve_delegation_approval(req_cd_id, princ_a)
    assert res.decision == PolicyDecision.DENY
    assert res.delegation_id is None
    assert "RULE_DELEGATION_APPROVAL_STALE_AUTHORITY" in res.matched_rules
    assert any("revoked or closed" in r for r in res.reasons)


def test_stale_approval_multi_tier_ancestor_closed():
    """Verify that closing ancestor B blocks approval of C->D."""
    service, _, store, _, session_id, root_id, agent_a_id = _setup_service()
    agent_b_id = "agent-b"
    agent_c_id = "agent-c"
    agent_d_id = "agent-d"

    princ_a = _make_principal(agent_a_id, session_id, is_control_plane=True)
    princ_b = _make_principal(agent_b_id, session_id, is_control_plane=False)
    princ_c = _make_principal(agent_c_id, session_id, is_control_plane=False)

    p_ab = _make_proposal(session_id, root_id, agent_a_id, agent_b_id, allow_subdel=True, depth=5)
    g_ab_id = service.resolve_delegation_approval(
        service.propose_delegation(p_ab, princ_a).delegation_request_id, princ_a
    ).delegation_id

    p_bc = _make_proposal(
        session_id, root_id, agent_b_id, agent_c_id, parent_id=g_ab_id, allow_subdel=True, depth=4
    )
    g_bc_id = service.resolve_delegation_approval(
        service.propose_delegation(p_bc, princ_b).delegation_request_id, princ_a
    ).delegation_id

    p_cd = _make_proposal(session_id, root_id, agent_c_id, agent_d_id, parent_id=g_bc_id)
    req_cd_id = service.propose_delegation(p_cd, princ_c).delegation_request_id

    # Close grandparent A->B before approval
    service.close_delegation(g_ab_id, principal=_make_principal(agent_b_id, session_id))

    res = service.resolve_delegation_approval(req_cd_id, princ_a)
    assert res.decision == PolicyDecision.DENY
    assert res.delegation_id is None
    assert "RULE_DELEGATION_APPROVAL_STALE_AUTHORITY" in res.matched_rules


def test_stale_approval_multi_tier_ancestor_expired():
    """Verify that ancestor B expiration blocks approval of C->D."""
    service, _, store, _, session_id, root_id, agent_a_id = _setup_service()
    agent_b_id = "agent-b"
    agent_c_id = "agent-c"
    agent_d_id = "agent-d"

    princ_a = _make_principal(agent_a_id, session_id, is_control_plane=True)
    princ_b = _make_principal(agent_b_id, session_id, is_control_plane=False)
    princ_c = _make_principal(agent_c_id, session_id, is_control_plane=False)

    # A->B has short TTL (-10 seconds)
    p_ab = _make_proposal(
        session_id, root_id, agent_a_id, agent_b_id, allow_subdel=True, depth=5, ttl=-10
    )
    g_ab_id = service.resolve_delegation_approval(
        service.propose_delegation(p_ab, princ_a).delegation_request_id, princ_a
    ).delegation_id

    p_bc = _make_proposal(
        session_id, root_id, agent_b_id, agent_c_id, parent_id=g_ab_id, allow_subdel=True, depth=4
    )
    g_bc_id = service.resolve_delegation_approval(
        service.propose_delegation(p_bc, princ_b).delegation_request_id, princ_a
    ).delegation_id

    p_cd = _make_proposal(session_id, root_id, agent_c_id, agent_d_id, parent_id=g_bc_id)
    req_cd_id = service.propose_delegation(p_cd, princ_c).delegation_request_id

    res = service.resolve_delegation_approval(req_cd_id, princ_a)
    assert res.decision == PolicyDecision.DENY
    assert res.delegation_id is None
    assert "RULE_DELEGATION_APPROVAL_STALE_AUTHORITY" in res.matched_rules


def test_stale_approval_multi_tier_ancestor_budget_exhausted():
    """Verify that ancestor B budget exhaustion blocks approval of C->D."""
    service, _, store, _, session_id, root_id, agent_a_id = _setup_service()
    agent_b_id = "agent-b"
    agent_c_id = "agent-c"
    agent_d_id = "agent-d"

    princ_a = _make_principal(agent_a_id, session_id, is_control_plane=True)
    princ_b = _make_principal(agent_b_id, session_id, is_control_plane=False)
    princ_c = _make_principal(agent_c_id, session_id, is_control_plane=False)

    p_ab = _make_proposal(session_id, root_id, agent_a_id, agent_b_id, allow_subdel=True, depth=5)
    g_ab_id = service.resolve_delegation_approval(
        service.propose_delegation(p_ab, princ_a).delegation_request_id, princ_a
    ).delegation_id

    p_bc = _make_proposal(
        session_id, root_id, agent_b_id, agent_c_id, parent_id=g_ab_id, allow_subdel=True, depth=4
    )
    g_bc_id = service.resolve_delegation_approval(
        service.propose_delegation(p_bc, princ_b).delegation_request_id, princ_a
    ).delegation_id

    p_cd = _make_proposal(session_id, root_id, agent_c_id, agent_d_id, parent_id=g_bc_id)
    req_cd_id = service.propose_delegation(p_cd, princ_c).delegation_request_id

    # Exhaust ancestor A->B budget
    grant_ab = store.get_grant(g_ab_id)
    state_ab = store.get_runtime_state(g_ab_id)
    state_ab.actions_executed_count = grant_ab.max_actions
    store._runtime_states[g_ab_id] = state_ab

    res = service.resolve_delegation_approval(req_cd_id, princ_a)
    assert res.decision == PolicyDecision.DENY
    assert res.delegation_id is None
    assert "RULE_DELEGATION_APPROVAL_STALE_AUTHORITY" in res.matched_rules


def test_stale_approval_ancestor_session_or_root_mismatch():
    """Verify that session or root intent mismatch on an ancestor blocks approval."""
    service, _, store, _, session_id, root_id, agent_a_id = _setup_service()
    agent_b_id = "agent-b"
    agent_c_id = "agent-c"
    agent_d_id = "agent-d"

    princ_a = _make_principal(agent_a_id, session_id, is_control_plane=True)
    princ_b = _make_principal(agent_b_id, session_id, is_control_plane=False)
    princ_c = _make_principal(agent_c_id, session_id, is_control_plane=False)

    p_ab = _make_proposal(session_id, root_id, agent_a_id, agent_b_id, allow_subdel=True, depth=5)
    g_ab_id = service.resolve_delegation_approval(
        service.propose_delegation(p_ab, princ_a).delegation_request_id, princ_a
    ).delegation_id

    p_bc = _make_proposal(
        session_id, root_id, agent_b_id, agent_c_id, parent_id=g_ab_id, allow_subdel=True, depth=4
    )
    g_bc_id = service.resolve_delegation_approval(
        service.propose_delegation(p_bc, princ_b).delegation_request_id, princ_a
    ).delegation_id

    p_cd = _make_proposal(session_id, root_id, agent_c_id, agent_d_id, parent_id=g_bc_id)
    req_cd_id = service.propose_delegation(p_cd, princ_c).delegation_request_id

    # Mutate ancestor A->B root_intent_id in store
    grant_ab = store.get_grant(g_ab_id)
    store._grants[g_ab_id] = grant_ab.model_copy(update={"root_intent_id": uuid4()})

    res = service.resolve_delegation_approval(req_cd_id, princ_a)
    assert res.decision == PolicyDecision.DENY
    assert res.delegation_id is None
    assert "RULE_DELEGATION_APPROVAL_STALE_AUTHORITY" in res.matched_rules


def test_pending_record_vs_active_grant_lifecycle():
    """Verify explicit invariant: NO DelegationGrant exists before approval.

    - Before approval: store lookup returns None; delegation_id is None; pending record present.
    - After successful approval: DelegationGrant present in store; pending record resolved.
    - After stale approval failure: DelegationGrant absent in store.
    """
    service, intent_service, store, _, session_id, root_id, agent_a_id = _setup_service()
    agent_b_id = "agent-b"

    proposal = _make_proposal(session_id, root_id, agent_a_id, agent_b_id)
    principal = _make_principal(agent_a_id, session_id, is_control_plane=True)

    # 1. Proposal triggers REQUIRE_APPROVAL
    create_res = service.propose_delegation(proposal, principal)
    assert create_res.decision == PolicyDecision.REQUIRE_APPROVAL
    assert create_res.delegation_id is None
    req_id = create_res.delegation_request_id

    # Verification: Before approval
    # - Pending request/action record is present
    assert req_id in service._pending_approvals
    pending_record = service._pending_approvals[req_id]
    assert pending_record["action_id"] == req_id
    assert pending_record["proposal"] == proposal

    # - NO DelegationGrant exists in DelegationStore
    assert store.get_session_active_grant_count(session_id) == 0
    assert store.get_grant(req_id) is None
    for existing_grant in store._grants.values():
        assert existing_grant.delegated_task_id != proposal.delegated_task_id

    # 2. Successful approval creates active grant and clears pending record
    appr_res = service.resolve_delegation_approval(req_id, principal, decision="APPROVED")
    assert appr_res.decision == PolicyDecision.ALLOW
    assert appr_res.delegation_id is not None
    issued_grant_id = appr_res.delegation_id

    # - Active DelegationGrant is now present in store
    issued_grant = store.get_grant(issued_grant_id)
    assert issued_grant is not None
    assert issued_grant.delegation_id == issued_grant_id
    assert issued_grant.delegatee_agent_id == agent_b_id

    # - Pending request is resolved and cleared from pending map
    assert req_id not in service._pending_approvals
