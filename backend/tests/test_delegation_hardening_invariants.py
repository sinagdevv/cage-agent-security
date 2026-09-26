"""Comprehensive hardening tests for CAGE Phase 8 closure blockers:
- Blocker 5: Intent-rule changes did not weaken Phase 2 single-agent/multi-agent boundaries
- Blocker 6: Client-supplied delegation_id is never authority (untrusted UUID is only lookup reference)
- Blocker 7: Dual governance in causal graph (INTENT --GOVERNS--> ACTION and DELEGATION --GOVERNS--> ACTION)
- Blocker 8: Full graph is not forced into a global DAG (heterogeneous cycles allowed, typed DAGs enforced)
- Blocker 9: Shared ancestor budget atomicity and concurrency
- Blocker 10: No security-store locks held during tool execution
"""

import threading
from uuid import UUID, uuid4

import networkx as nx

from app.delegation.analyzer import DelegationAnalyzer
from app.delegation.models import DelegationProposal, ResourceAuthorityScopeRequest
from app.delegation.service import DelegationService
from app.delegation.store import DelegationStore
from app.gateway.registry import ToolRegistry, ToolSpec
from app.gateway.service import AgentGateway
from app.gateway.tools import ToolExecutor, ToolResult
from app.graph.causal_graph import CausalExecutionGraph, SessionGraphManager
from app.identity.principal import AgentPrincipal, PrincipalAuthenticationSource
from app.intent.service import IntentService
from app.policies.engine import PolicyEngine
from app.policies.rules import DeterministicPolicyEvaluator
from app.provenance.store import ProvenanceStore
from app.schemas.action import AgentActionProposal
from app.schemas.enums import (
    PolicyBackend,
    PolicyDecision,
    TargetEnvironment,
)
from app.schemas.intent import IntentContractCreate
from app.trajectory.store import TrajectoryStore


class MockLockCheckExecutor(ToolExecutor):
    """Test executor that records whether security-store locks were held during tool execution."""

    def __init__(
        self,
        delegation_store: DelegationStore,
        trajectory_store: TrajectoryStore,
        intent_service: IntentService,
        simulate_failure: bool = False,
    ) -> None:
        super().__init__()
        self.del_store = delegation_store
        self.traj_store = trajectory_store
        self.intent_svc = intent_service
        self.simulate_failure = simulate_failure
        self.lock_held_during_exec = False
        self.execution_count = 0

    def execute(self, request, decision) -> ToolResult:
        self.execution_count += 1

        # Deterministically check if any lock is held
        def _check(lk):
            if hasattr(lk, "_is_owned"):
                return bool(lk._is_owned())
            if hasattr(lk, "locked"):
                return bool(lk.locked())
            return False

        del_locked = _check(self.del_store._lock)
        traj_locked = _check(self.traj_store._lock)
        intent_locked = _check(self.intent_svc._lock)

        if del_locked or traj_locked or intent_locked:
            self.lock_held_during_exec = True

        if self.simulate_failure:
            return ToolResult(
                tool_name=request.tool_name,
                success=False,
                output="",
                error="Simulated tool execution failure",
            )
        return ToolResult(
            tool_name=request.tool_name,
            success=True,
            output="Executed successfully",
            error=None,
        )


def _build_test_gateway(
    simulate_failure: bool = False,
) -> tuple[
    AgentGateway,
    DelegationService,
    IntentService,
    TrajectoryStore,
    SessionGraphManager,
    MockLockCheckExecutor,
]:
    tool_reg = ToolRegistry()
    tool_reg.register(
        ToolSpec(
            name="web.search",
            description="Web search tool",
            resource_scoped=False,
        )
    )
    tool_reg.register(
        ToolSpec(
            name="database.read",
            description="DB read tool",
            resource_scoped=True,
            privileged=True,
        )
    )
    tool_reg.register(
        ToolSpec(
            name="file.write",
            description="File write tool",
            resource_scoped=True,
            privileged=False,
        )
    )

    intent_service = IntentService()
    graph_manager = SessionGraphManager()
    traj_store = TrajectoryStore()
    del_store = DelegationStore()
    del_analyzer = DelegationAnalyzer()

    evaluator = DeterministicPolicyEvaluator(tool_registry=tool_reg)
    policy_engine = PolicyEngine(python_evaluator=evaluator, backend=PolicyBackend.PYTHON)

    del_service = DelegationService(
        store=del_store,
        analyzer=del_analyzer,
        intent_service=intent_service,
        evaluator=evaluator,
        graph_manager=graph_manager,
        trajectory_store=traj_store,
    )

    tool_executor = MockLockCheckExecutor(
        delegation_store=del_store,
        trajectory_store=traj_store,
        intent_service=intent_service,
        simulate_failure=simulate_failure,
    )

    prov_store = ProvenanceStore()
    gateway = AgentGateway(
        graph_manager=graph_manager,
        policy_engine=policy_engine,
        intent_service=intent_service,
        tool_registry=tool_reg,
        provenance_store=prov_store,
        trajectory_store=traj_store,
        delegation_service=del_service,
        tool_executor=tool_executor,
        require_intent=True,
    )

    return gateway, del_service, intent_service, traj_store, graph_manager, tool_executor


# ==============================================================================
# BLOCKER 5 & 6: Intent-rule integrity & Client delegation_id is never authority
# ==============================================================================


def test_single_agent_path_intent_ownership_strict():
    """Verify single-agent path strictly rejects agent mismatch without delegation."""
    gateway, _, intent_service, _, _, _ = _build_test_gateway()
    session_id = uuid4()

    intent_service.create_intent(
        IntentContractCreate(
            session_id=str(session_id),
            agent_id="agent-owner",
            user_id="user-1",
            goal="Single agent test",
            allowed_tools=["web.search"],
            maximum_tool_calls=10,
        )
    )

    proposal = AgentActionProposal(
        session_id=str(session_id),
        agent_id="agent-imposter",  # Different agent, NO delegation_id
        tool_name="web.search",
    )
    action, decision = gateway.evaluate_proposal(proposal)

    assert decision.decision == PolicyDecision.DENY
    assert "RULE_INTENT_MISMATCH" in decision.matched_rules


def test_client_supplied_unknown_delegation_id_denied():
    """Verify client supplying a random unknown UUID is rejected."""
    gateway, _, intent_service, _, _, _ = _build_test_gateway()
    session_id = uuid4()

    intent_service.create_intent(
        IntentContractCreate(
            session_id=str(session_id),
            agent_id="agent-owner",
            user_id="user-1",
            goal="Single agent test",
            allowed_tools=["web.search"],
            maximum_tool_calls=10,
        )
    )

    proposal = AgentActionProposal(
        session_id=str(session_id),
        agent_id="agent-b",
        tool_name="web.search",
        delegation_id=uuid4(),  # Random unknown UUID
    )
    action, decision = gateway.evaluate_proposal(proposal)

    assert decision.decision == PolicyDecision.DENY
    assert (
        "RULE_INTENT_MISMATCH" in decision.matched_rules
        or "RULE_DELEGATION_REVOKED" in decision.matched_rules
    )


def test_client_supplied_wrong_session_grant_denied():
    """Verify grant issued in session 1 cannot authorize an action in session 2."""
    gateway, del_service, intent_service, _, _, _ = _build_test_gateway()
    session_1 = uuid4()
    session_2 = uuid4()

    intent_1 = intent_service.create_intent(
        IntentContractCreate(
            session_id=str(session_1),
            agent_id="agent-a",
            user_id="user-1",
            goal="Session 1",
            allowed_tools=["web.search"],
        )
    )
    intent_service.create_intent(
        IntentContractCreate(
            session_id=str(session_2),
            agent_id="agent-a",
            user_id="user-1",
            goal="Session 2",
            allowed_tools=["web.search"],
        )
    )

    # Issue grant in Session 1
    prop = DelegationProposal(
        session_id=session_1,
        root_intent_id=intent_1.intent_id,
        delegator_agent_id="agent-a",
        delegatee_agent_id="agent-b",
        delegated_task_id="task-1",
        requested_tools=["web.search"],
    )
    princ = AgentPrincipal(
        agent_id="agent-a",
        session_id=session_1,
        authentication_source=PrincipalAuthenticationSource.HOSTING_RUNTIME,
        is_control_plane=True,
    )
    create_res = del_service.propose_delegation(prop, princ)
    grant_id = create_res.delegation_id

    # Attempt to replay grant in Session 2
    action_prop = AgentActionProposal(
        session_id=str(session_2),
        agent_id="agent-b",
        tool_name="web.search",
        delegation_id=grant_id,
    )
    action, decision = gateway.evaluate_proposal(action_prop)

    assert decision.decision == PolicyDecision.DENY
    assert (
        "RULE_INTENT_MISMATCH" in decision.matched_rules
        or "RULE_DELEGATION_CROSS_SESSION" in decision.matched_rules
    )


def test_client_supplied_wrong_delegatee_grant_denied():
    """Verify grant issued to Agent B cannot be stolen or used by Agent C."""
    gateway, del_service, intent_service, _, _, _ = _build_test_gateway()
    session_id = uuid4()

    intent = intent_service.create_intent(
        IntentContractCreate(
            session_id=str(session_id),
            agent_id="agent-a",
            user_id="user-1",
            goal="Grant theft test",
            allowed_tools=["web.search"],
        )
    )

    prop = DelegationProposal(
        session_id=session_id,
        root_intent_id=intent.intent_id,
        delegator_agent_id="agent-a",
        delegatee_agent_id="agent-b",
        delegated_task_id="task-b",
        requested_tools=["web.search"],
    )
    princ = AgentPrincipal(
        agent_id="agent-a",
        session_id=session_id,
        authentication_source=PrincipalAuthenticationSource.HOSTING_RUNTIME,
        is_control_plane=True,
    )
    create_res = del_service.propose_delegation(prop, princ)
    grant_id = create_res.delegation_id

    # Agent C tries to use Agent B's grant
    action_prop = AgentActionProposal(
        session_id=str(session_id),
        agent_id="agent-c",
        tool_name="web.search",
        delegation_id=grant_id,
    )
    action, decision = gateway.evaluate_proposal(action_prop)

    assert decision.decision == PolicyDecision.DENY
    assert (
        "RULE_DELEGATION_PRINCIPAL_MISMATCH" in decision.matched_rules
        or "RULE_INTENT_MISMATCH" in decision.matched_rules
    )


def test_client_supplied_revoked_grant_denied():
    """Verify using a revoked delegation grant is denied."""
    gateway, del_service, intent_service, _, _, _ = _build_test_gateway()
    session_id = uuid4()

    intent = intent_service.create_intent(
        IntentContractCreate(
            session_id=str(session_id),
            agent_id="agent-a",
            user_id="user-1",
            goal="Revoke test",
            allowed_tools=["web.search"],
        )
    )

    prop = DelegationProposal(
        session_id=session_id,
        root_intent_id=intent.intent_id,
        delegator_agent_id="agent-a",
        delegatee_agent_id="agent-b",
        delegated_task_id="task-rev",
        requested_tools=["web.search"],
    )
    princ = AgentPrincipal(
        agent_id="agent-a",
        session_id=session_id,
        authentication_source=PrincipalAuthenticationSource.HOSTING_RUNTIME,
        is_control_plane=True,
    )
    create_res = del_service.propose_delegation(prop, princ)
    grant_id = create_res.delegation_id

    # Revoke grant
    del_service.revoke_delegation(grant_id, principal=princ)

    # Attempt action under revoked grant
    action_prop = AgentActionProposal(
        session_id=str(session_id),
        agent_id="agent-b",
        tool_name="web.search",
        delegation_id=grant_id,
    )
    action, decision = gateway.evaluate_proposal(action_prop)

    assert decision.decision == PolicyDecision.DENY
    assert "RULE_DELEGATION_REVOKED" in decision.matched_rules


def test_client_supplied_closed_grant_denied():
    """Verify using a closed delegation grant is denied."""
    gateway, del_service, intent_service, _, _, _ = _build_test_gateway()
    session_id = uuid4()

    intent = intent_service.create_intent(
        IntentContractCreate(
            session_id=str(session_id),
            agent_id="agent-a",
            user_id="user-1",
            goal="Close test",
            allowed_tools=["web.search"],
        )
    )

    prop = DelegationProposal(
        session_id=session_id,
        root_intent_id=intent.intent_id,
        delegator_agent_id="agent-a",
        delegatee_agent_id="agent-b",
        delegated_task_id="task-close",
        requested_tools=["web.search"],
    )
    princ = AgentPrincipal(
        agent_id="agent-a",
        session_id=session_id,
        authentication_source=PrincipalAuthenticationSource.HOSTING_RUNTIME,
        is_control_plane=True,
    )
    create_res = del_service.propose_delegation(prop, princ)
    grant_id = create_res.delegation_id

    # Close grant
    del_service.close_delegation(
        grant_id,
        principal=AgentPrincipal(
            agent_id="agent-b",
            session_id=session_id,
            authentication_source=PrincipalAuthenticationSource.HOSTING_RUNTIME,
        ),
    )

    action_prop = AgentActionProposal(
        session_id=str(session_id),
        agent_id="agent-b",
        tool_name="web.search",
        delegation_id=grant_id,
    )
    action, decision = gateway.evaluate_proposal(action_prop)

    assert decision.decision == PolicyDecision.DENY
    assert "RULE_DELEGATION_CLOSED" in decision.matched_rules


def test_client_supplied_expired_grant_denied():
    """Verify using an expired delegation grant is denied."""
    gateway, del_service, intent_service, _, _, _ = _build_test_gateway()
    session_id = uuid4()

    intent = intent_service.create_intent(
        IntentContractCreate(
            session_id=str(session_id),
            agent_id="agent-a",
            user_id="user-1",
            goal="Expired grant test",
            allowed_tools=["web.search"],
        )
    )

    prop = DelegationProposal(
        session_id=session_id,
        root_intent_id=intent.intent_id,
        delegator_agent_id="agent-a",
        delegatee_agent_id="agent-b",
        delegated_task_id="task-exp",
        requested_tools=["web.search"],
        requested_ttl_seconds=-60,  # Already expired
    )
    princ = AgentPrincipal(
        agent_id="agent-a",
        session_id=session_id,
        authentication_source=PrincipalAuthenticationSource.HOSTING_RUNTIME,
        is_control_plane=True,
    )
    create_res = del_service.propose_delegation(prop, princ)
    grant_id = create_res.delegation_id

    action_prop = AgentActionProposal(
        session_id=str(session_id),
        agent_id="agent-b",
        tool_name="web.search",
        delegation_id=grant_id,
    )
    action, decision = gateway.evaluate_proposal(action_prop)

    assert decision.decision == PolicyDecision.DENY
    assert "RULE_DELEGATION_EXPIRED" in decision.matched_rules


def test_client_supplied_root_invalid_grant_denied():
    """Verify using a grant whose root Intent Contract was revoked is denied."""
    gateway, del_service, intent_service, _, _, _ = _build_test_gateway()
    session_id = uuid4()

    intent = intent_service.create_intent(
        IntentContractCreate(
            session_id=str(session_id),
            agent_id="agent-a",
            user_id="user-1",
            goal="Root invalid test",
            allowed_tools=["web.search"],
        )
    )

    prop = DelegationProposal(
        session_id=session_id,
        root_intent_id=intent.intent_id,
        delegator_agent_id="agent-a",
        delegatee_agent_id="agent-b",
        delegated_task_id="task-root-inv",
        requested_tools=["web.search"],
    )
    princ = AgentPrincipal(
        agent_id="agent-a",
        session_id=session_id,
        authentication_source=PrincipalAuthenticationSource.HOSTING_RUNTIME,
        is_control_plane=True,
    )
    create_res = del_service.propose_delegation(prop, princ)
    grant_id = create_res.delegation_id

    # Revoke root intent
    intent_service.revoke_intent(intent.intent_id)

    action_prop = AgentActionProposal(
        session_id=str(session_id),
        agent_id="agent-b",
        tool_name="web.search",
        delegation_id=grant_id,
    )
    action, decision = gateway.evaluate_proposal(action_prop)

    assert decision.decision == PolicyDecision.DENY
    assert (
        "RULE_DELEGATION_ROOT_INTENT_INVALID" in decision.matched_rules
        or "RULE_INTENT_REVOKED" in decision.matched_rules
    )


def test_client_supplied_out_of_scope_action_denied():
    """Verify executing an action outside the grant's authority envelope is denied."""
    gateway, del_service, intent_service, _, _, _ = _build_test_gateway()
    session_id = uuid4()

    intent = intent_service.create_intent(
        IntentContractCreate(
            session_id=str(session_id),
            agent_id="agent-a",
            user_id="user-1",
            goal="Scope test",
            allowed_tools=["web.search", "file.write"],
            allowed_resources=["safe-file.txt", "other.txt"],
        )
    )

    # Grant only authorizes web.search and safe-file.txt
    prop = DelegationProposal(
        session_id=session_id,
        root_intent_id=intent.intent_id,
        delegator_agent_id="agent-a",
        delegatee_agent_id="agent-b",
        delegated_task_id="task-scope",
        requested_tools=["web.search"],
        requested_resource_scope=ResourceAuthorityScopeRequest.allowlist(["safe-file.txt"]),
    )
    princ = AgentPrincipal(
        agent_id="agent-a",
        session_id=session_id,
        authentication_source=PrincipalAuthenticationSource.HOSTING_RUNTIME,
        is_control_plane=True,
    )
    create_res = del_service.propose_delegation(prop, princ)
    grant_id = create_res.delegation_id

    # Attempt to call file.write (outside grant authority envelope)
    action_prop = AgentActionProposal(
        session_id=str(session_id),
        agent_id="agent-b",
        tool_name="file.write",
        target_resource="safe-file.txt",
        delegation_id=grant_id,
    )
    action, decision = gateway.evaluate_proposal(action_prop)

    assert decision.decision == PolicyDecision.DENY
    assert "RULE_DELEGATION_TOOL_NOT_AUTHORIZED" in decision.matched_rules


# ==============================================================================
# BLOCKER 7: Dual Governance in Causal Graph
# ==============================================================================


def test_delegation_dual_governance_graph_edges():
    """Verify that every delegated action graph entry has BOTH INTENT and DELEGATION governs edges."""
    gateway, del_service, intent_service, _, graph_manager, tool_executor = _build_test_gateway()
    session_id = uuid4()

    intent = intent_service.create_intent(
        IntentContractCreate(
            session_id=str(session_id),
            agent_id="agent-a",
            user_id="user-1",
            goal="Dual governance test",
            allowed_tools=["web.search"],
            maximum_tool_calls=10,
        )
    )

    prop = DelegationProposal(
        session_id=session_id,
        root_intent_id=intent.intent_id,
        delegator_agent_id="agent-a",
        delegatee_agent_id="agent-b",
        delegated_task_id="task-dual",
        requested_tools=["web.search"],
        requested_environments=[TargetEnvironment.DEVELOPMENT],
    )
    princ = AgentPrincipal(
        agent_id="agent-a",
        session_id=session_id,
        authentication_source=PrincipalAuthenticationSource.HOSTING_RUNTIME,
        is_control_plane=True,
    )
    create_res = del_service.propose_delegation(prop, princ)
    grant_id = create_res.delegation_id

    action_prop = AgentActionProposal(
        session_id=str(session_id),
        agent_id="agent-b",
        tool_name="web.search",
        delegation_id=grant_id,
    )
    action, decision = gateway.evaluate_proposal(action_prop)
    assert decision.decision == PolicyDecision.ALLOW

    # Execute action
    result = gateway.execute_authorized_action(action.action_id)
    assert result.success is True

    # Graph Invariant Verification: Both edges must exist
    graph = graph_manager.get(str(session_id))
    action_key = str(action.action_id)
    intent_key = str(intent.intent_id)
    grant_key = str(grant_id)

    # 1. INTENT --GOVERNS--> ACTION
    assert graph._graph.has_edge(intent_key, action_key), "Missing INTENT --GOVERNS--> ACTION edge"
    assert graph._graph.edges[intent_key, action_key].get("relation") == "governs"

    # 2. DELEGATION --GOVERNS--> ACTION
    assert graph._graph.has_edge(grant_key, action_key), (
        "Missing DELEGATION --GOVERNS--> ACTION edge"
    )
    assert graph._graph.edges[grant_key, action_key].get("relation") == "governs"


# ==============================================================================
# BLOCKER 8: Full Graph Not Forced Into a Global DAG
# ==============================================================================


def test_full_graph_not_forced_dag_typed_dags_enforced():
    """Verify that typed DAGs are enforced without forcing the full multi-relation graph into a DAG."""
    graph = CausalExecutionGraph("test-dag-session")

    # Add Action 1
    graph.add_node("act-1", node_type="action")
    # Add Artifact 1
    graph.add_node("art-1", node_type="artifact")

    # Act-1 produces Art-1
    graph.add_produces_edge("act-1", "art-1")

    # Mixed cycle: Art-1 relates back to Act-1 via another relation type (e.g. references or consumes)
    graph._graph.add_edge("art-1", "act-1", relation="references")

    # Heterogeneous full graph contains cycle
    assert nx.is_directed_acyclic_graph(graph._graph) is False

    # But typed DAGs remain strictly valid
    assert graph.is_action_causality_dag() is True
    assert graph.is_artifact_lineage_dag() is True
    assert graph.is_subdelegation_dag() is True
    assert graph.has_valid_typed_dags() is True


# ==============================================================================
# BLOCKER 9: Shared Ancestor Budget Atomicity & Concurrency
# ==============================================================================


def test_shared_ancestor_budget_exhaustion():
    """Verify parent budget = 3, Child B cap = 3, Child C cap = 3.
    B dispatches 2, C dispatches 1 -> Parent remaining = 0.
    Next dispatch by B or C must fail closed with RULE_DELEGATION_BUDGET_EXHAUSTED.
    """
    gateway, del_service, intent_service, _, _, tool_executor = _build_test_gateway()
    session_id = uuid4()

    intent = intent_service.create_intent(
        IntentContractCreate(
            session_id=str(session_id),
            agent_id="agent-a",
            user_id="user-1",
            goal="Ancestor budget test",
            allowed_tools=["web.search"],
            maximum_tool_calls=20,
        )
    )

    princ = AgentPrincipal(
        agent_id="agent-a",
        session_id=session_id,
        authentication_source=PrincipalAuthenticationSource.HOSTING_RUNTIME,
        is_control_plane=True,
    )

    # Parent Grant A with max_actions = 3
    p_prop = DelegationProposal(
        session_id=session_id,
        root_intent_id=intent.intent_id,
        delegator_agent_id="agent-a",
        delegatee_agent_id="agent-parent",
        delegated_task_id="task-parent-budget",
        requested_tools=["web.search"],
        requested_environments=[TargetEnvironment.DEVELOPMENT],
        requested_max_actions=3,
        allow_subdelegation=True,
        requested_depth=3,
    )
    p_res = del_service.propose_delegation(p_prop, princ)
    parent_id = p_res.delegation_id

    # Child Grant B with cap 3
    b_prop = DelegationProposal(
        session_id=session_id,
        root_intent_id=intent.intent_id,
        parent_delegation_id=parent_id,
        delegator_agent_id="agent-parent",
        delegatee_agent_id="agent-b",
        delegated_task_id="task-b-budget",
        requested_tools=["web.search"],
        requested_environments=[TargetEnvironment.DEVELOPMENT],
        requested_max_actions=3,
    )
    b_res = del_service.propose_delegation(b_prop, princ)
    grant_b_id = b_res.delegation_id

    # Child Grant C with cap 3
    c_prop = DelegationProposal(
        session_id=session_id,
        root_intent_id=intent.intent_id,
        parent_delegation_id=parent_id,
        delegator_agent_id="agent-parent",
        delegatee_agent_id="agent-c",
        delegated_task_id="task-c-budget",
        requested_tools=["web.search"],
        requested_environments=[TargetEnvironment.DEVELOPMENT],
        requested_max_actions=3,
    )
    c_res = del_service.propose_delegation(c_prop, princ)
    grant_c_id = c_res.delegation_id

    # Invariant: Grant creation does NOT reserve ancestor capacity
    state_parent_initial = del_service.store.get_runtime_state(parent_id)
    assert state_parent_initial.actions_executed_count == 0
    assert del_service.store.get_runtime_state(grant_b_id).actions_executed_count == 0
    assert del_service.store.get_runtime_state(grant_c_id).actions_executed_count == 0

    # B dispatches 1
    act_b1, dec_b1 = gateway.evaluate_proposal(
        AgentActionProposal(
            session_id=str(session_id),
            agent_id="agent-b",
            tool_name="web.search",
            delegation_id=grant_b_id,
            parent_action_id=None,
        )
    )
    assert dec_b1.decision == PolicyDecision.ALLOW
    gateway.execute_authorized_action(act_b1.action_id)

    # B dispatches 2 (linear continuation from act_b1)
    act_b2, dec_b2 = gateway.evaluate_proposal(
        AgentActionProposal(
            session_id=str(session_id),
            agent_id="agent-b",
            tool_name="web.search",
            delegation_id=grant_b_id,
            parent_action_id=act_b1.action_id,
        )
    )
    assert dec_b2.decision == PolicyDecision.ALLOW
    gateway.execute_authorized_action(act_b2.action_id)

    # C dispatches 1 (Parent total = 3 exhausted; C's first action has parent_action_id=None)
    act_c1, dec_c1 = gateway.evaluate_proposal(
        AgentActionProposal(
            session_id=str(session_id),
            agent_id="agent-c",
            tool_name="web.search",
            delegation_id=grant_c_id,
            parent_action_id=None,
        )
    )
    assert dec_c1.decision == PolicyDecision.ALLOW
    gateway.execute_authorized_action(act_c1.action_id)

    # Verify counts
    state_parent = del_service.store.get_runtime_state(parent_id)
    state_b = del_service.store.get_runtime_state(grant_b_id)
    state_c = del_service.store.get_runtime_state(grant_c_id)
    assert state_parent.actions_executed_count == 3
    assert state_b.actions_executed_count == 2
    assert state_c.actions_executed_count == 1

    # 4th action attempt by B must fail closed
    act_b3, dec_b3 = gateway.evaluate_proposal(
        AgentActionProposal(
            session_id=str(session_id),
            agent_id="agent-b",
            tool_name="web.search",
            delegation_id=grant_b_id,
            parent_action_id=act_b2.action_id,
        )
    )
    assert dec_b3.decision == PolicyDecision.DENY
    assert "RULE_DELEGATION_BUDGET_EXHAUSTED" in dec_b3.matched_rules

    # 4th action attempt by C must fail closed
    act_c2, dec_c2 = gateway.evaluate_proposal(
        AgentActionProposal(
            session_id=str(session_id),
            agent_id="agent-c",
            tool_name="web.search",
            delegation_id=grant_c_id,
            parent_action_id=act_c1.action_id,
        )
    )
    assert dec_c2.decision == PolicyDecision.DENY
    assert "RULE_DELEGATION_BUDGET_EXHAUSTED" in dec_c2.matched_rules


def test_shared_ancestor_budget_multithreaded_concurrency():
    """Verify that concurrent sibling dispatches cannot oversubscribe parent budget."""
    gateway, del_service, intent_service, _, _, _ = _build_test_gateway()
    session_id = uuid4()

    intent = intent_service.create_intent(
        IntentContractCreate(
            session_id=str(session_id),
            agent_id="agent-a",
            user_id="user-1",
            goal="Concurrent budget test",
            allowed_tools=["web.search"],
            maximum_tool_calls=20,
        )
    )

    princ = AgentPrincipal(
        agent_id="agent-a",
        session_id=session_id,
        authentication_source=PrincipalAuthenticationSource.HOSTING_RUNTIME,
        is_control_plane=True,
    )

    # Parent grant budget = 3
    p_prop = DelegationProposal(
        session_id=session_id,
        root_intent_id=intent.intent_id,
        delegator_agent_id="agent-a",
        delegatee_agent_id="agent-parent",
        delegated_task_id="task-concur-parent",
        requested_tools=["web.search"],
        requested_environments=[TargetEnvironment.DEVELOPMENT],
        requested_max_actions=3,
        allow_subdelegation=True,
    )
    parent_id = del_service.propose_delegation(p_prop, princ).delegation_id

    # Sibling child grants B, C, D, E under parent
    grants = []
    agents = ["agent-b", "agent-c", "agent-d", "agent-e"]
    for ag in agents:
        prop = DelegationProposal(
            session_id=session_id,
            root_intent_id=intent.intent_id,
            parent_delegation_id=parent_id,
            delegator_agent_id="agent-parent",
            delegatee_agent_id=ag,
            delegated_task_id=f"task-{ag}",
            requested_tools=["web.search"],
            requested_environments=[TargetEnvironment.DEVELOPMENT],
            requested_max_actions=3,
        )
        grants.append(del_service.propose_delegation(prop, princ).delegation_id)

    # 4 concurrent threads making 2 dispatches each (8 total attempts against budget=3)
    results = []
    results_lock = threading.Lock()

    def worker(agent_name: str, grant_id: UUID):
        last_action_id = None
        for _ in range(2):
            prop = AgentActionProposal(
                session_id=str(session_id),
                agent_id=agent_name,
                tool_name="web.search",
                delegation_id=grant_id,
                parent_action_id=last_action_id,
            )
            action, decision = gateway.evaluate_proposal(prop)
            if decision.decision == PolicyDecision.ALLOW:
                gateway.execute_authorized_action(action.action_id)
                last_action_id = action.action_id
            with results_lock:
                results.append(decision.decision)

    threads = [threading.Thread(target=worker, args=(agents[i], grants[i])) for i in range(4)]

    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Invariants: Exactly 3 ALLOW and 5 DENY
    allowed_count = sum(1 for r in results if r == PolicyDecision.ALLOW)
    denied_count = sum(1 for r in results if r == PolicyDecision.DENY)
    assert allowed_count == 3
    assert denied_count == 5

    state_parent = del_service.store.get_runtime_state(parent_id)
    assert state_parent.actions_executed_count == 3


def test_tool_failure_does_not_refund_budget():
    """Verify tool failure after actual dispatch does NOT refund action budget."""
    gateway, del_service, intent_service, _, _, tool_executor = _build_test_gateway(
        simulate_failure=True
    )
    session_id = uuid4()

    intent = intent_service.create_intent(
        IntentContractCreate(
            session_id=str(session_id),
            agent_id="agent-a",
            user_id="user-1",
            goal="Failure refund test",
            allowed_tools=["web.search"],
            maximum_tool_calls=10,
        )
    )

    princ = AgentPrincipal(
        agent_id="agent-a",
        session_id=session_id,
        authentication_source=PrincipalAuthenticationSource.HOSTING_RUNTIME,
        is_control_plane=True,
    )
    prop = DelegationProposal(
        session_id=session_id,
        root_intent_id=intent.intent_id,
        delegator_agent_id="agent-a",
        delegatee_agent_id="agent-b",
        delegated_task_id="task-fail-refund",
        requested_tools=["web.search"],
        requested_environments=[TargetEnvironment.DEVELOPMENT],
        requested_max_actions=2,
    )
    grant_id = del_service.propose_delegation(prop, princ).delegation_id

    # Action 1: Dispatches and tool execution returns failure
    action, decision = gateway.evaluate_proposal(
        AgentActionProposal(
            session_id=str(session_id),
            agent_id="agent-b",
            tool_name="web.search",
            delegation_id=grant_id,
        )
    )
    assert decision.decision == PolicyDecision.ALLOW
    res = gateway.execute_authorized_action(action.action_id)
    assert res.success is False

    # Budget MUST remain consumed exactly once
    state = del_service.store.get_runtime_state(grant_id)
    assert state.actions_executed_count == 1

    # Root intent budget also consumed exactly once
    updated_intent = intent_service.get_intent(intent.intent_id)
    assert updated_intent.tool_calls_count == 1

    # Invariant: A DENIED action consumes zero budget
    act_denied, dec_denied = gateway.evaluate_proposal(
        AgentActionProposal(
            session_id=str(session_id),
            agent_id="agent-b",
            tool_name="unauthorized.tool",
            delegation_id=grant_id,
            parent_action_id=action.action_id,
        )
    )
    assert dec_denied.decision == PolicyDecision.DENY
    assert del_service.store.get_runtime_state(grant_id).actions_executed_count == 1
    assert intent_service.get_intent(intent.intent_id).tool_calls_count == 1

    # Invariant: A REQUIRE_APPROVAL action consumes zero budget
    # Update root intent to require human approval for web.search
    curr_intent = intent_service.get_intent(intent.intent_id)
    intent_service._intents[intent.intent_id] = curr_intent.model_copy(
        update={"requires_approval": frozenset(["web.search"])}
    )

    act_appr, dec_appr = gateway.evaluate_proposal(
        AgentActionProposal(
            session_id=str(session_id),
            agent_id="agent-b",
            tool_name="web.search",
            delegation_id=grant_id,
            parent_action_id=act_denied.action_id,
        )
    )
    assert dec_appr.decision == PolicyDecision.REQUIRE_APPROVAL
    assert del_service.store.get_runtime_state(grant_id).actions_executed_count == 1
    assert intent_service.get_intent(intent.intent_id).tool_calls_count == 1


# ==============================================================================
# BLOCKER 10: No Security-Store Lock Held During Tool Execution
# ==============================================================================


def test_no_security_store_lock_held_during_tool_execution():
    """Verify DelegationStore, TrajectoryStore, and IntentService locks are released before tool execution."""
    gateway, del_service, intent_service, traj_store, _, tool_executor = _build_test_gateway()
    session_id = uuid4()

    intent_service.create_intent(
        IntentContractCreate(
            session_id=str(session_id),
            agent_id="agent-a",
            user_id="user-1",
            goal="Lock check test",
            allowed_tools=["web.search"],
            maximum_tool_calls=10,
        )
    )

    action_prop = AgentActionProposal(
        session_id=str(session_id),
        agent_id="agent-a",
        tool_name="web.search",
    )
    action, decision = gateway.evaluate_proposal(action_prop)
    assert decision.decision == PolicyDecision.ALLOW

    # Execute action
    result = gateway.execute_authorized_action(action.action_id)
    assert result.success is True

    # Assert MockLockCheckExecutor witnessed all locks free during execution
    assert tool_executor.execution_count == 1
    assert tool_executor.lock_held_during_exec is False
