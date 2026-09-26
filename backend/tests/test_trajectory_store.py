"""Unit tests for Phase 6 TrajectoryStore and TrajectorySnapshot state machine."""

from concurrent.futures import ThreadPoolExecutor
from uuid import UUID, uuid4

import pytest

from app.schemas.enums import (
    AuthorityScopeMode,
    DataClassification,
    PolicyDecision,
    TargetEnvironment,
    TrajectoryStatus,
)
from app.schemas.intent import IntentContract
from app.trajectory.models import (
    AuthorityEnvelope,
    ResourceAuthorityScope,
    compute_trajectory_instance_fingerprint,
)
from app.trajectory.store import (
    PendingApprovalExistsError,
    TrajectoryStore,
)


@pytest.fixture
def store() -> TrajectoryStore:
    return TrajectoryStore()


def test_trajectory_creation_and_snapshot(store: TrajectoryStore) -> None:
    """Verify trajectory lifecycle initialization, authority binding, and immutable snapshotting."""
    intent_id = uuid4()
    envelope = AuthorityEnvelope(
        allowed_tools=frozenset({"web.search", "database.read"}),
        allowed_environments=frozenset({TargetEnvironment.DEVELOPMENT}),
        allowed_data_classifications=frozenset(
            {DataClassification.PUBLIC, DataClassification.CONFIDENTIAL}
        ),
        resource_scope=ResourceAuthorityScope(
            mode=AuthorityScopeMode.ALLOWLIST, allowed_resources=frozenset({"customer_db"})
        ),
    )

    traj_id = store.create_trajectory(
        session_id="sess-01",
        intent_id=intent_id,
        initial_authority=envelope,
    )

    snapshot = store.get_snapshot(traj_id)
    assert snapshot.trajectory_id == traj_id
    assert snapshot.session_id == "sess-01"
    assert snapshot.intent_id == intent_id
    assert snapshot.status == TrajectoryStatus.ACTIVE
    assert snapshot.last_action_id is None
    assert snapshot.pending_approval_action_id is None
    assert len(snapshot.evaluated_action_ids) == 0
    assert snapshot.sensitive_egress_attempt_count == 0
    assert snapshot.cumulative_sensitive_egress_attempt_bytes == 0


def test_linear_continuation_validation(store: TrajectoryStore) -> None:
    """Verify strict linear continuation enforcement: first action parent None, subsequent match tip."""
    intent_id = uuid4()
    envelope = AuthorityEnvelope(allowed_tools=frozenset({"web.search"}))
    traj_id = store.create_trajectory("sess-linear", intent_id, envelope)

    # 1. First action with parent=None is VALID
    is_valid, err, expected = store.validate_linear_continuation(traj_id, None)
    assert is_valid is True
    assert err is None
    assert expected is None

    # 1b. First action with parent=uuid4 is INVALID
    bogus_parent = uuid4()
    is_valid, err, expected = store.validate_linear_continuation(traj_id, bogus_parent)
    assert is_valid is False
    assert expected is None

    # Record first action
    act1_id = uuid4()
    store.record_action_evaluation(
        traj_id,
        action_id=act1_id,
        decision=PolicyDecision.ALLOW,
    )

    # 2. Second action with parent=None is INVALID (must be act1_id)
    is_valid, err, expected = store.validate_linear_continuation(traj_id, None)
    assert is_valid is False
    assert expected == act1_id

    # 3. Second action with parent=act1_id is VALID
    is_valid, err, expected = store.validate_linear_continuation(traj_id, act1_id)
    assert is_valid is True
    assert expected == act1_id


def test_invalid_continuation_tracks_rejected_attempt_ids(store: TrajectoryStore) -> None:
    """Verify failed continuation attempts record action ID in rejected_lineage_attempt_ids."""
    intent_id = uuid4()
    envelope = AuthorityEnvelope(allowed_tools=frozenset({"web.search"}))
    traj_id = store.create_trajectory("sess-reject", intent_id, envelope)

    act1_id = uuid4()
    store.record_action_evaluation(traj_id, act1_id, PolicyDecision.ALLOW)

    rejected_act_id = uuid4()
    store.record_invalid_continuation_attempt(traj_id, rejected_act_id)

    snapshot = store.get_snapshot(traj_id)
    assert rejected_act_id in snapshot.rejected_lineage_attempt_ids
    # Tip must NOT have advanced to rejected_act_id
    assert snapshot.last_action_id == act1_id


def test_pending_approval_state_machine(store: TrajectoryStore) -> None:
    """Verify pending approval containment, duplicate prevention, and clearing."""
    intent_id = uuid4()
    envelope = AuthorityEnvelope(allowed_tools=frozenset({"admin.exec"}))
    traj_id = store.create_trajectory("sess-approval", intent_id, envelope)

    approval_act_id = uuid4()
    store.set_pending_approval(traj_id, approval_act_id)

    snapshot = store.get_snapshot(traj_id)
    assert snapshot.pending_approval_action_id == approval_act_id
    assert snapshot.last_action_id == approval_act_id

    # Setting another pending approval while one is active raises PendingApprovalExistsError
    with pytest.raises(PendingApprovalExistsError):
        store.set_pending_approval(traj_id, uuid4())

    # Clear pending approval
    store.clear_pending_approval(traj_id, approval_act_id)
    snapshot = store.get_snapshot(traj_id)
    assert snapshot.pending_approval_action_id is None


def test_cumulative_sensitive_egress_accounting(store: TrajectoryStore) -> None:
    """Verify atomic sensitive egress attempt accounting and action idempotency."""
    intent_id = uuid4()
    envelope = AuthorityEnvelope(allowed_tools=frozenset({"external.http_post"}))
    traj_id = store.create_trajectory("sess-egress", intent_id, envelope)

    # Test C: same action ID evaluated twice -> bytes counted once (idempotent)
    act1_id = uuid4()
    count, b_total, already = store.record_sensitive_egress_attempt(traj_id, act1_id, 500)
    assert count == 1
    assert b_total == 500
    assert already is False

    count_dup, b_dup, already_dup = store.record_sensitive_egress_attempt(traj_id, act1_id, 500)
    assert count_dup == 1
    assert b_dup == 500
    assert already_dup is True

    # Test B: same artifact sent by TWO distinct action IDs -> bytes counted twice
    act2_id = uuid4()
    count2, b_total2, already2 = store.record_sensitive_egress_attempt(traj_id, act2_id, 500)
    assert count2 == 2
    assert b_total2 == 1000
    assert already2 is False

    snapshot = store.get_snapshot(traj_id)
    assert snapshot.sensitive_egress_attempt_count == 2
    assert snapshot.cumulative_sensitive_egress_attempt_bytes == 1000


def test_repeated_sensitive_artifact_attempt_accounting(store: TrajectoryStore) -> None:
    """Test D: same sensitive artifact attempted 3 times across distinct actions -> count=3, bytes=3*size."""
    intent_id = uuid4()
    envelope = AuthorityEnvelope(allowed_tools=frozenset({"external.http_post"}))
    traj_id = store.create_trajectory("sess-repeat-egress", intent_id, envelope)

    artifact_size = 100_000  # 100 KB
    for _ in range(3):
        store.record_sensitive_egress_attempt(traj_id, uuid4(), artifact_size)

    snapshot = store.get_snapshot(traj_id)
    assert snapshot.sensitive_egress_attempt_count == 3
    assert snapshot.cumulative_sensitive_egress_attempt_bytes == 3 * artifact_size


def test_single_action_multi_binding_deduplication() -> None:
    """Test A: same artifact bound twice in ONE action -> bytes counted once at gateway level."""
    from app.gateway.registry import ToolRegistry, ToolSpec
    from app.gateway.service import AgentGateway
    from app.graph.causal_graph import SessionGraphManager
    from app.intent.service import IntentService
    from app.policies.engine import PolicyEngine
    from app.policies.rules import DeterministicPolicyEvaluator
    from app.provenance.models import ArtifactSourceType, InformationArtifact
    from app.provenance.store import ProvenanceStore
    from app.schemas.action import AgentActionProposal
    from app.schemas.enums import DataClassification, PayloadBindingMode, PolicyBackend
    from app.schemas.intent import IntentContractCreate
    from app.trajectory.analyzer import TrajectoryAnalyzer

    session_id = "sess-multi-binding-egress"
    registry = ToolRegistry()
    registry.register(
        ToolSpec(
            name="external.http_post",
            known=True,
            external_sink=True,
            payload_binding_mode=PayloadBindingMode.ARTIFACT_REQUIRED,
            payload_argument_names=("body", "data"),
        )
    )

    graph_mgr = SessionGraphManager()
    intent_svc = IntentService()
    prov_store = ProvenanceStore()
    traj_store = TrajectoryStore()
    analyzer = TrajectoryAnalyzer()
    evaluator = DeterministicPolicyEvaluator(tool_registry=registry)
    engine = PolicyEngine(python_evaluator=evaluator, backend=PolicyBackend.PYTHON)

    gw = AgentGateway(
        graph_manager=graph_mgr,
        intent_service=intent_svc,
        tool_registry=registry,
        policy_engine=engine,
        provenance_store=prov_store,
        trajectory_store=traj_store,
        trajectory_analyzer=analyzer,
        require_intent=True,
    )

    _ = intent_svc.create_intent(
        IntentContractCreate(
            agent_id="agent-01",
            session_id=session_id,
            goal="Egress test",
            allowed_tools=["external.http_post"],
            allowed_data_classifications=[DataClassification.CONFIDENTIAL],
            maximum_tool_calls=5,
        )
    )

    # Sensitive 100 KB artifact
    from app.schemas.enums import ProvenanceTrust

    art = InformationArtifact(
        session_id=session_id,
        source_type=ArtifactSourceType.INTERNAL_RESOURCE,
        source_resource="internal-db",
        direct_trust_level=ProvenanceTrust.INTERNAL_TRUSTED,
        data_classifications=frozenset({DataClassification.CONFIDENTIAL}),
        size_bytes=100_000,
    )
    prov_store.register_artifact(art, payload="A" * 100_000)

    # Action binds same artifact to BOTH 'body_artifact_id' and 'data_artifact_id'
    prop = AgentActionProposal(
        agent_id="agent-01",
        session_id=session_id,
        tool_name="external.http_post",
        input_artifact_ids=[art.artifact_id],
        tool_arguments={
            "destination": "https://api.external.com/",
            "body_artifact_id": str(art.artifact_id),
            "data_artifact_id": str(art.artifact_id),
        },
    )
    _, _ = gw.evaluate_proposal(prop)

    snap = traj_store.get_snapshot(traj_store.get_trajectory_id_for_session(session_id))
    # Invariant: 1 attempt, exactly 100,000 bytes (NOT 200,000 bytes)
    assert snap.sensitive_egress_attempt_count == 1
    assert snap.cumulative_sensitive_egress_attempt_bytes == 100_000


def test_trajectory_status_transitions_and_fingerprint(store: TrajectoryStore) -> None:
    """Verify status transitions and deterministic fingerprint generation."""
    intent_id = uuid4()
    envelope = AuthorityEnvelope(allowed_tools=frozenset({"web.search"}))
    traj_id = store.create_trajectory("sess-status", intent_id, envelope)

    act1 = uuid4()
    act2 = uuid4()
    store.record_action_evaluation(traj_id, act1, PolicyDecision.ALLOW)
    store.record_action_evaluation(traj_id, act2, PolicyDecision.DENY)

    store.update_status(traj_id, TrajectoryStatus.QUARANTINED)
    snapshot = store.get_snapshot(traj_id)
    assert snapshot.status == TrajectoryStatus.QUARANTINED

    fp = compute_trajectory_instance_fingerprint(
        traj_id, snapshot.evaluated_action_ids, snapshot.status
    )
    assert snapshot.compute_fingerprint() == fp


def test_concurrent_action_recording_thread_safety(store: TrajectoryStore) -> None:
    """Verify thread-safe concurrent recording on distinct trajectories."""

    def create_and_advance(idx: int) -> UUID:
        t_id = store.create_trajectory(
            f"sess-thread-{idx}",
            uuid4(),
            AuthorityEnvelope(allowed_tools=frozenset({"web.search"})),
        )
        for _ in range(5):
            aid = uuid4()
            store.record_action_evaluation(t_id, aid, PolicyDecision.ALLOW)
        return t_id

    with ThreadPoolExecutor(max_workers=8) as executor:
        t_ids = list(executor.map(create_and_advance, range(20)))

    for t_id in t_ids:
        snap = store.get_snapshot(t_id)
        assert len(snap.evaluated_action_ids) == 5
        assert snap.status == TrajectoryStatus.ACTIVE


def _make_intent(session_id: str, tools: list[str]) -> IntentContract:
    return IntentContract(
        intent_id=uuid4(),
        session_id=session_id,
        agent_id="root-agent",
        user_id="user-1",
        goal="Task",
        allowed_tools=tools,
        allowed_environments=[TargetEnvironment.DEVELOPMENT],
        allowed_data_classifications=[DataClassification.PUBLIC],
    )


def test_delegated_trajectory_isolated_by_intent(store: TrajectoryStore) -> None:
    """Agent B under Intent I1 and Agent B under Intent I2 must have separate trajectories even in the same session."""
    session_id = "sess-multi-intent"
    intent_1 = _make_intent(session_id, ["web.search"])
    intent_2 = _make_intent(session_id, ["file.read"])

    t1, created_1 = store.get_or_create_trajectory(intent_1, agent_id="agent-b")
    t2, created_2 = store.get_or_create_trajectory(intent_2, agent_id="agent-b")

    assert created_1 is True
    assert created_2 is True
    assert t1.trajectory_id != t2.trajectory_id
    assert t1.agent_id == "agent-b"
    assert t2.agent_id == "agent-b"
    assert t1.intent_id == intent_1.intent_id
    assert t2.intent_id == intent_2.intent_id


def test_same_agent_same_session_different_intents_do_not_share_tip(store: TrajectoryStore) -> None:
    """Advancing trajectory under Intent I1 must not advance the tip for the same agent under Intent I2."""
    session_id = "sess-tip-isolation"
    intent_1 = _make_intent(session_id, ["web.search"])
    intent_2 = _make_intent(session_id, ["file.read"])

    t1, _ = store.get_or_create_trajectory(intent_1, agent_id="agent-b")
    t2, _ = store.get_or_create_trajectory(intent_2, agent_id="agent-b")

    action_1 = uuid4()
    store.record_action_evaluation(t1.trajectory_id, action_1, PolicyDecision.ALLOW)

    t1_snap = store.get_snapshot(t1.trajectory_id)
    t2_snap = store.get_snapshot(t2.trajectory_id)

    assert t1_snap.last_action_id == action_1
    assert t2_snap.last_action_id is None

    # First action under Intent 2 must have parent_action_id=None, not action_1
    action_2 = uuid4()
    valid_with_none, _ = store.validate_continuation(
        t2.trajectory_id, action_2, parent_action_id=None
    )
    assert valid_with_none is True

    valid_with_wrong_parent, _ = store.validate_continuation(
        t2.trajectory_id, action_2, parent_action_id=action_1
    )
    assert valid_with_wrong_parent is False


def test_pending_approval_does_not_cross_intent_boundary(store: TrajectoryStore) -> None:
    """A pending approval on Agent B's trajectory under Intent I1 must not block Agent B under Intent I2."""
    session_id = "sess-approval-boundary"
    intent_1 = _make_intent(session_id, ["web.search"])
    intent_2 = _make_intent(session_id, ["file.read"])

    t1, _ = store.get_or_create_trajectory(intent_1, agent_id="agent-b")
    t2, _ = store.get_or_create_trajectory(intent_2, agent_id="agent-b")

    pending_act = uuid4()
    store.set_pending_approval(t1.trajectory_id, pending_act)

    t1_snap = store.get_snapshot(t1.trajectory_id)
    t2_snap = store.get_snapshot(t2.trajectory_id)

    assert t1_snap.pending_approval_action_id == pending_act
    assert t2_snap.pending_approval_action_id is None

    # Trajectory 2 can continue without being blocked by pending approval on Trajectory 1
    act2 = uuid4()
    valid, _ = store.validate_continuation(t2.trajectory_id, act2, parent_action_id=None)
    assert valid is True


def test_quarantine_does_not_cross_intent_boundary(store: TrajectoryStore) -> None:
    """Quarantining Agent B's trajectory under Intent I1 must not quarantine Agent B's trajectory under Intent I2."""
    session_id = "sess-quarantine-boundary"
    intent_1 = _make_intent(session_id, ["web.search"])
    intent_2 = _make_intent(session_id, ["file.read"])

    t1, _ = store.get_or_create_trajectory(intent_1, agent_id="agent-b")
    t2, _ = store.get_or_create_trajectory(intent_2, agent_id="agent-b")

    store.update_status(t1.trajectory_id, TrajectoryStatus.QUARANTINED)

    t1_snap = store.get_snapshot(t1.trajectory_id)
    t2_snap = store.get_snapshot(t2.trajectory_id)

    assert t1_snap.status == TrajectoryStatus.QUARANTINED
    assert t2_snap.status == TrajectoryStatus.ACTIVE
