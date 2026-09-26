"""Observational benchmarks for Phase 8 multi-agent delegation operations."""

import time
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from app.delegation.analyzer import DelegationAnalyzer
from app.delegation.models import DelegationGrant
from app.delegation.store import DelegationStore
from app.policies.policy_input import (
    build_delegated_action_context,
)
from app.policies.rules import DeterministicPolicyEvaluator
from app.schemas.action import AgentAction
from app.schemas.enums import (
    ActionType,
    AuthorityScopeMode,
    DataClassification,
    DelegationIssuanceSource,
    IntentStatus,
    TargetEnvironment,
)
from app.schemas.intent import IntentContract
from app.trajectory.models import AuthorityEnvelope, ResourceAuthorityScope


def _build_test_grant(
    session_id,
    delegation_id,
    root_intent_id=None,
    parent_id=None,
    depth=1,
    rem_depth=10,
    delegator="agent-root",
    delegatee="agent-sub",
):
    return DelegationGrant(
        delegation_id=delegation_id,
        session_id=session_id,
        root_intent_id=root_intent_id or uuid4(),
        parent_delegation_id=parent_id,
        issued_from_action_id=uuid4(),
        delegator_agent_id=delegator,
        delegatee_agent_id=delegatee,
        delegated_task_id="task-bench",
        authority_envelope=AuthorityEnvelope(
            allowed_tools=frozenset(["web.search", "db.read", "file.read"]),
            resource_scope=ResourceAuthorityScope(
                mode=AuthorityScopeMode.ALLOWLIST,
                allowed_resources=frozenset(["res://1", "res://2", "res://3"]),
            ),
            allowed_environments=frozenset(
                [TargetEnvironment.DEVELOPMENT, TargetEnvironment.PRODUCTION]
            ),
            allowed_data_classifications=frozenset(
                [DataClassification.PUBLIC, DataClassification.INTERNAL]
            ),
        ),
        depth=depth,
        remaining_subdelegation_depth=rem_depth,
        allow_subdelegation=True,
        max_actions=1000,
        expires_at=datetime.now(UTC) + timedelta(hours=2),
        issuance_source=DelegationIssuanceSource.AGENT_DIRECT,
    )


@pytest.mark.benchmark
@pytest.mark.parametrize("chain_depth", [1, 3, 5, 10])
def test_delegation_chain_depth_benchmarks(chain_depth: int):
    """Benchmark chain validation, authority derivation, context construction, and policy evaluation across chain depths."""
    store = DelegationStore()
    analyzer = DelegationAnalyzer(max_session_delegation_depth=15)
    session_id = uuid4()
    intent_id = uuid4()

    contract = IntentContract(
        intent_id=intent_id,
        session_id=str(session_id),
        agent_id="agent-0",
        user_id="user-bench",
        goal="Benchmark delegation",
        allowed_tools=["web.search", "db.read", "file.read"],
        allowed_environments=[TargetEnvironment.DEVELOPMENT, TargetEnvironment.PRODUCTION],
        allowed_resources=["res://1", "res://2", "res://3"],
        allowed_data_classifications=[DataClassification.PUBLIC, DataClassification.INTERNAL],
        maximum_tool_calls=10000,
        status=IntentStatus.ACTIVE,
    )

    parent_id = None
    last_grant = None
    for d in range(1, chain_depth + 1):
        del_id = uuid4()
        grant = _build_test_grant(
            session_id=session_id,
            delegation_id=del_id,
            parent_id=parent_id,
            depth=d,
            rem_depth=15 - d,
            delegator=f"agent-{d - 1}",
            delegatee=f"agent-{d}",
        )
        store.create_grant(grant)
        parent_id = del_id
        last_grant = grant

    grants, states = store.get_chain_with_states(last_grant.delegation_id)

    # 1. Chain validation & live status derivation
    t0 = time.perf_counter()
    for _ in range(100):
        _ = analyzer.compute_effective_status(
            grant=last_grant,
            runtime_state=states[-1],
            ancestors=grants[:-1],
            ancestor_states=states[:-1],
            root_intent=contract,
        )
    status_dur_us = ((time.perf_counter() - t0) / 100) * 1e6

    # 2. Live authority scope derivation
    t0 = time.perf_counter()
    for _ in range(100):
        _ = analyzer.compute_live_effective_authority(
            grant=last_grant,
            ancestors=grants[:-1],
            root_intent=contract,
        )
    scope_dur_us = ((time.perf_counter() - t0) / 100) * 1e6

    # 3. PolicyDelegationContext build
    action = AgentAction(
        session_id=str(session_id),
        agent_id=last_grant.delegatee_agent_id,
        tool_name="web.search",
        action_type=ActionType.READ,
        target_resource="res://1",
        target_environment=TargetEnvironment.DEVELOPMENT,
        data_classifications=[DataClassification.INTERNAL],
        delegation_id=last_grant.delegation_id,
    )
    from app.identity.principal import AgentPrincipal, PrincipalAuthenticationSource

    principal = AgentPrincipal(
        agent_id=last_grant.delegatee_agent_id,
        session_id=session_id,
        authentication_source=PrincipalAuthenticationSource.TEST_FIXTURE,
    )

    t0 = time.perf_counter()
    for _ in range(100):
        del_ctx = build_delegated_action_context(
            action=action,
            principal=principal,
            grant=last_grant,
            runtime_state=states[-1],
            root_intent=contract,
            ancestors=grants[:-1],
            ancestor_states=states[:-1],
            analyzer=analyzer,
        )
    ctx_dur_us = ((time.perf_counter() - t0) / 100) * 1e6

    # 4. Python rule evaluation
    py_evaluator = DeterministicPolicyEvaluator()
    t0 = time.perf_counter()
    for _ in range(100):
        _ = py_evaluator.evaluate(
            action=action,
            contract=contract,
            delegation_context=del_ctx,
        )
    py_eval_dur_us = ((time.perf_counter() - t0) / 100) * 1e6

    print(
        f"\n[BENCHMARK] Depth={chain_depth:2d} | "
        f"Status Deriv: {status_dur_us:6.2f} µs | "
        f"Scope Deriv: {scope_dur_us:6.2f} µs | "
        f"Context Build: {ctx_dur_us:6.2f} µs | "
        f"Python Eval: {py_eval_dur_us:6.2f} µs"
    )

    assert status_dur_us < 5000  # < 5ms
    assert scope_dur_us < 5000
    assert ctx_dur_us < 5000
    assert py_eval_dur_us < 5000


@pytest.mark.benchmark
@pytest.mark.parametrize("total_grants", [10, 100, 500])
def test_delegation_session_scale_benchmarks(total_grants: int):
    """Benchmark store lookups and DAG validation with 10, 100, and 500 grants in a single session."""
    store = DelegationStore()
    session_id = uuid4()
    del_ids = []

    t0 = time.perf_counter()
    for i in range(total_grants):
        del_id = uuid4()
        grant = _build_test_grant(
            session_id=session_id,
            delegation_id=del_id,
            parent_id=del_ids[-1] if (del_ids and i % 5 != 0) else None,
            depth=(i % 5) + 1,
            delegator=f"agent-{i}",
            delegatee=f"agent-{i + 1}",
        )
        store.create_grant(grant)
        del_ids.append(del_id)
    pop_dur_ms = (time.perf_counter() - t0) * 1000

    # Test retrieval of session grants
    t0 = time.perf_counter()
    for _ in range(50):
        grants = store.get_grants_by_session(session_id)
    session_fetch_us = ((time.perf_counter() - t0) / 50) * 1e6

    # Test chain fetch
    target_id = del_ids[-1]
    t0 = time.perf_counter()
    for _ in range(50):
        chain = store.get_chain(target_id)
    chain_fetch_us = ((time.perf_counter() - t0) / 50) * 1e6

    print(
        f"\n[BENCHMARK] Session Grants={total_grants:3d} | "
        f"Population: {pop_dur_ms:6.2f} ms | "
        f"Session Query: {session_fetch_us:6.2f} µs | "
        f"Chain Query: {chain_fetch_us:6.2f} µs"
    )

    assert len(grants) == total_grants
    assert len(chain) > 0
    assert session_fetch_us < 10000  # < 10ms
    assert chain_fetch_us < 5000
