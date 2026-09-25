"""Unit and integration tests for Phase 6 trajectory governance policy rules."""

from uuid import uuid4

import pytest

from app.gateway.registry import ToolRegistry, ToolSpec
from app.policies.rules import DeterministicPolicyEvaluator
from app.schemas.action import AgentAction
from app.schemas.enums import (
    ActionType,
    DataClassification,
    PolicyDecision,
    TargetEnvironment,
    TrajectoryAnalysisStatus,
    TrajectoryStatus,
)
from app.schemas.intent import IntentContract, IntentContractCreate
from app.schemas.policy import PolicyTrajectoryContext


@pytest.fixture
def policy_evaluator() -> DeterministicPolicyEvaluator:
    registry = ToolRegistry()
    registry.register(ToolSpec(name="web.search", known=True))
    registry.register(ToolSpec(name="agent.transform", known=True))
    registry.register(
        ToolSpec(
            name="database.read",
            known=True,
            reads_resource_data=True,
            default_classification=DataClassification.CONFIDENTIAL,
        )
    )
    registry.register(
        ToolSpec(
            name="external.http_post",
            known=True,
            external_sink=True,
        )
    )
    registry.register(ToolSpec(name="admin.exec_cmd", known=True, privileged=True))
    return DeterministicPolicyEvaluator(tool_registry=registry)


@pytest.fixture
def sample_contract() -> IntentContract:
    return IntentContract.from_create(
        IntentContractCreate(
            agent_id="agent-01",
            session_id="sess-traj-rules",
            goal="Test trajectory governance",
            allowed_tools=["web.search", "database.read", "external.http_post", "admin.exec_cmd"],
            allowed_environments=[TargetEnvironment.DEVELOPMENT],
            allowed_data_classifications=[
                DataClassification.PUBLIC,
                DataClassification.CONFIDENTIAL,
            ],
            maximum_tool_calls=10,
        )
    )


def test_rule_trajectory_quarantined_denies_all(
    policy_evaluator: DeterministicPolicyEvaluator, sample_contract: IntentContract
) -> None:
    """Verify quarantined trajectory halts all execution."""
    action = AgentAction(
        action_id=uuid4(),
        agent_id="agent-01",
        session_id="sess-traj-rules",
        tool_name="web.search",
        action_type=ActionType.TOOL_CALL,
        target_environment=TargetEnvironment.DEVELOPMENT,
        data_classifications=[DataClassification.PUBLIC],
    )
    traj_ctx = PolicyTrajectoryContext(
        trajectory_status=TrajectoryStatus.QUARANTINED,
        analysis_status=TrajectoryAnalysisStatus.SUCCESS,
        analysis_complete=True,
    )

    decision = policy_evaluator.evaluate(
        action=action,
        contract=sample_contract,
        trajectory_context=traj_ctx,
    )
    assert decision.decision == PolicyDecision.DENY
    assert "RULE_TRAJECTORY_QUARANTINED" in decision.matched_rules


def test_rule_trajectory_analysis_failed_fail_closed(
    policy_evaluator: DeterministicPolicyEvaluator, sample_contract: IntentContract
) -> None:
    """Verify analysis failure (e.g. depth limit) results in fail-closed DENY."""
    action = AgentAction(
        action_id=uuid4(),
        agent_id="agent-01",
        session_id="sess-traj-rules",
        tool_name="web.search",
        action_type=ActionType.TOOL_CALL,
        target_environment=TargetEnvironment.DEVELOPMENT,
        data_classifications=[DataClassification.PUBLIC],
    )
    traj_ctx = PolicyTrajectoryContext(
        trajectory_status=TrajectoryStatus.ACTIVE,
        analysis_status=TrajectoryAnalysisStatus.ACTION_DEPTH_LIMIT_EXCEEDED,
        analysis_complete=False,
    )

    decision = policy_evaluator.evaluate(
        action=action,
        contract=sample_contract,
        trajectory_context=traj_ctx,
    )
    assert decision.decision == PolicyDecision.DENY
    assert "RULE_TRAJECTORY_ACTION_DEPTH_LIMIT_EXCEEDED" in decision.matched_rules


def test_rule_trajectory_untrusted_to_sensitive_access_requires_approval(
    policy_evaluator: DeterministicPolicyEvaluator, sample_contract: IntentContract
) -> None:
    """Verify untrusted origin reaching sensitive resource requires human approval."""
    action = AgentAction(
        action_id=uuid4(),
        agent_id="agent-01",
        session_id="sess-traj-rules",
        tool_name="database.read",
        target_resource="customer_db",
        action_type=ActionType.READ,
        target_environment=TargetEnvironment.DEVELOPMENT,
        data_classifications=[DataClassification.CONFIDENTIAL],
    )
    traj_ctx = PolicyTrajectoryContext(
        trajectory_status=TrajectoryStatus.ACTIVE,
        analysis_status=TrajectoryAnalysisStatus.SUCCESS,
        analysis_complete=True,
        untrusted_path_to_current_action=True,
        current_action_attempts_sensitive_access=True,
        untrusted_path_to_sensitive_access=True,
        prospective_access_classifications=("CONFIDENTIAL",),
    )

    decision = policy_evaluator.evaluate(
        action=action,
        contract=sample_contract,
        trajectory_context=traj_ctx,
    )
    assert decision.decision == PolicyDecision.REQUIRE_APPROVAL
    assert "RULE_TRAJECTORY_UNTRUSTED_PATH_TO_SENSITIVE_ACCESS" in decision.matched_rules


def test_rule_trajectory_untrusted_to_sensitive_egress_denied(
    policy_evaluator: DeterministicPolicyEvaluator, sample_contract: IntentContract
) -> None:
    """Verify untrusted origin reaching external sink with sensitive payload is DENIED."""
    action = AgentAction(
        action_id=uuid4(),
        agent_id="agent-01",
        session_id="sess-traj-rules",
        tool_name="external.http_post",
        action_type=ActionType.WRITE,
        target_environment=TargetEnvironment.DEVELOPMENT,
        data_classifications=[DataClassification.CONFIDENTIAL],
    )
    traj_ctx = PolicyTrajectoryContext(
        trajectory_status=TrajectoryStatus.ACTIVE,
        analysis_status=TrajectoryAnalysisStatus.SUCCESS,
        analysis_complete=True,
        untrusted_path_to_current_action=True,
        untrusted_path_to_sensitive_egress=True,
    )

    decision = policy_evaluator.evaluate(
        action=action,
        contract=sample_contract,
        trajectory_context=traj_ctx,
    )
    assert decision.decision == PolicyDecision.DENY
    assert "RULE_TRAJECTORY_UNTRUSTED_PATH_TO_SENSITIVE_EGRESS" in decision.matched_rules


def test_rule_trajectory_split_exfiltration_quarantined(
    policy_evaluator: DeterministicPolicyEvaluator, sample_contract: IntentContract
) -> None:
    """Verify repeated egress attempts exceeding threshold trigger QUARANTINE."""
    action = AgentAction(
        action_id=uuid4(),
        agent_id="agent-01",
        session_id="sess-traj-rules",
        tool_name="external.http_post",
        action_type=ActionType.WRITE,
        target_environment=TargetEnvironment.DEVELOPMENT,
        data_classifications=[DataClassification.PUBLIC],
    )
    traj_ctx = PolicyTrajectoryContext(
        trajectory_status=TrajectoryStatus.ACTIVE,
        analysis_status=TrajectoryAnalysisStatus.SUCCESS,
        analysis_complete=True,
        sensitive_egress_attempt_count=3,
        split_exfiltration_threshold_exceeded=True,
    )

    decision = policy_evaluator.evaluate(
        action=action,
        contract=sample_contract,
        trajectory_context=traj_ctx,
    )
    assert decision.decision == PolicyDecision.QUARANTINE
    assert "RULE_TRAJECTORY_CUMULATIVE_SENSITIVE_EGRESS" in decision.matched_rules


# =============================================================================
# Benign Negative Controls
# =============================================================================


def test_benign_public_research_publication_allowed(
    policy_evaluator: DeterministicPolicyEvaluator, sample_contract: IntentContract
) -> None:
    """Negative Control 1: Public research publication -> ALLOW."""
    action = AgentAction(
        action_id=uuid4(),
        agent_id="agent-01",
        session_id="sess-traj-rules",
        tool_name="web.search",
        action_type=ActionType.TOOL_CALL,
        target_environment=TargetEnvironment.DEVELOPMENT,
        data_classifications=[DataClassification.PUBLIC],
    )
    traj_ctx = PolicyTrajectoryContext(
        trajectory_status=TrajectoryStatus.ACTIVE,
        analysis_status=TrajectoryAnalysisStatus.SUCCESS,
        analysis_complete=True,
    )

    decision = policy_evaluator.evaluate(
        action=action,
        contract=sample_contract,
        trajectory_context=traj_ctx,
    )
    assert decision.decision == PolicyDecision.ALLOW
    assert "RULE_INTENT_ALLOW" in decision.matched_rules


def test_benign_authorized_internal_pii_analysis_allowed(
    policy_evaluator: DeterministicPolicyEvaluator, sample_contract: IntentContract
) -> None:
    """Negative Control 2: Authorized internal confidential/PII analysis -> ALLOW."""
    action = AgentAction(
        action_id=uuid4(),
        agent_id="agent-01",
        session_id="sess-traj-rules",
        tool_name="database.read",
        target_resource="customer_db",
        action_type=ActionType.READ,
        target_environment=TargetEnvironment.DEVELOPMENT,
        data_classifications=[DataClassification.CONFIDENTIAL],
    )
    traj_ctx = PolicyTrajectoryContext(
        trajectory_status=TrajectoryStatus.ACTIVE,
        analysis_status=TrajectoryAnalysisStatus.SUCCESS,
        analysis_complete=True,
        untrusted_path_to_current_action=False,
        untrusted_path_to_sensitive_access=False,
    )

    decision = policy_evaluator.evaluate(
        action=action,
        contract=sample_contract,
        trajectory_context=traj_ctx,
    )
    assert decision.decision == PolicyDecision.ALLOW
    assert "RULE_INTENT_ALLOW" in decision.matched_rules


def test_benign_untrusted_public_publication_allowed(
    policy_evaluator: DeterministicPolicyEvaluator, sample_contract: IntentContract
) -> None:
    """Negative Control 3: Untrusted PUBLIC data published to external sink -> ALLOW."""
    action = AgentAction(
        action_id=uuid4(),
        agent_id="agent-01",
        session_id="sess-traj-rules",
        tool_name="external.http_post",
        action_type=ActionType.WRITE,
        target_environment=TargetEnvironment.DEVELOPMENT,
        data_classifications=[DataClassification.PUBLIC],
    )
    traj_ctx = PolicyTrajectoryContext(
        trajectory_status=TrajectoryStatus.ACTIVE,
        analysis_status=TrajectoryAnalysisStatus.SUCCESS,
        analysis_complete=True,
        untrusted_path_to_current_action=True,
        untrusted_path_to_sensitive_egress=False,
    )

    decision = policy_evaluator.evaluate(
        action=action,
        contract=sample_contract,
        trajectory_context=traj_ctx,
    )
    assert decision.decision == PolicyDecision.ALLOW
    assert "RULE_INTENT_ALLOW" in decision.matched_rules


def test_benign_stale_untrusted_history_beyond_distance_no_trigger(
    policy_evaluator: DeterministicPolicyEvaluator, sample_contract: IntentContract
) -> None:
    """Negative Control 4: Stale untrusted history beyond causal distance threshold -> ALLOW without trigger."""
    action = AgentAction(
        action_id=uuid4(),
        agent_id="agent-01",
        session_id="sess-traj-rules",
        tool_name="database.read",
        target_resource="customer_db",
        action_type=ActionType.READ,
        target_environment=TargetEnvironment.DEVELOPMENT,
        data_classifications=[DataClassification.CONFIDENTIAL],
    )
    traj_ctx = PolicyTrajectoryContext(
        trajectory_status=TrajectoryStatus.ACTIVE,
        analysis_status=TrajectoryAnalysisStatus.SUCCESS,
        analysis_complete=True,
        untrusted_path_to_current_action=True,
        nearest_untrusted_action_distance=5,  # > max_distance (3)
        current_action_attempts_sensitive_access=True,
        untrusted_path_to_sensitive_access=False,  # Not triggered because distance > 3
    )

    decision = policy_evaluator.evaluate(
        action=action,
        contract=sample_contract,
        trajectory_context=traj_ctx,
    )
    assert decision.decision == PolicyDecision.ALLOW
    assert "RULE_INTENT_ALLOW" in decision.matched_rules


def test_e2e_gateway_untrusted_path_to_sensitive_access_requires_approval() -> None:
    """Flagship End-to-End Integration Test: Full Gateway -> TrajectoryAnalyzer -> PolicyInput v4 -> PolicyEngine pipeline.

    Exercises:
    1. Agent receives untrusted artifact via web.search (direct_trust = EXTERNAL_UNTRUSTED).
    2. Gateway validates proposal, executes action, and links CONSUMES edge.
    3. Agent subsequently proposes sensitive internal database.read (target_resource = customer_db).
    4. Gateway derives PolicyTrajectoryContext with untrusted_path_to_sensitive_access = True.
    5. PolicyEngine evaluates CagePolicyInput v4 and outputs REQUIRE_APPROVAL with RULE_TRAJECTORY_UNTRUSTED_PATH_TO_SENSITIVE_ACCESS.
    """
    from app.gateway.service import AgentGateway
    from app.graph.causal_graph import SessionGraphManager
    from app.intent.service import IntentService
    from app.policies.engine import PolicyEngine
    from app.provenance.models import ArtifactSourceType, InformationArtifact
    from app.provenance.resources import ResourceSecurityProfile, ResourceSecurityProfileRegistry
    from app.provenance.store import ProvenanceStore
    from app.schemas.action import AgentActionProposal
    from app.schemas.enums import PolicyBackend, ProvenanceTrust, ToolExecutionStatus
    from app.trajectory.analyzer import TrajectoryAnalyzer
    from app.trajectory.store import TrajectoryStore

    session_id = "sess-e2e-untrusted-to-sensitive"
    registry = ToolRegistry()
    registry.register(ToolSpec(name="web.search", known=True))
    registry.register(
        ToolSpec(
            name="database.read",
            known=True,
            reads_resource_data=True,
            default_classification=DataClassification.CONFIDENTIAL,
        )
    )

    res_registry = ResourceSecurityProfileRegistry()
    res_registry.register(
        ResourceSecurityProfile(
            resource_id="customer_db",
            source_type=ArtifactSourceType.INTERNAL_RESOURCE,
            trust_level=ProvenanceTrust.INTERNAL_TRUSTED,
            data_classifications=frozenset(
                {DataClassification.PII, DataClassification.CONFIDENTIAL}
            ),
        )
    )

    graph_mgr = SessionGraphManager()
    intent_svc = IntentService()
    prov_store = ProvenanceStore()
    traj_store = TrajectoryStore()
    analyzer = TrajectoryAnalyzer()
    evaluator = DeterministicPolicyEvaluator(tool_registry=registry)
    engine = PolicyEngine(python_evaluator=evaluator, backend=PolicyBackend.PYTHON)

    gateway = AgentGateway(
        graph_manager=graph_mgr,
        intent_service=intent_svc,
        tool_registry=registry,
        policy_engine=engine,
        provenance_store=prov_store,
        trajectory_store=traj_store,
        trajectory_analyzer=analyzer,
        resource_registry=res_registry,
        require_intent=True,
    )

    contract = intent_svc.create_intent(
        IntentContractCreate(
            agent_id="agent-01",
            session_id=session_id,
            goal="Process web queries and customer data",
            allowed_tools=["web.search", "database.read"],
            allowed_resources=["customer_db"],
            allowed_data_classifications=[
                DataClassification.PUBLIC,
                DataClassification.PII,
                DataClassification.CONFIDENTIAL,
            ],
            maximum_tool_calls=10,
        )
    )
    assert contract is not None

    # Step 1: External untrusted artifact is ingested and consumed by web.search
    untrusted_art = InformationArtifact(
        session_id=session_id,
        source_type=ArtifactSourceType.EXTERNAL_CONTENT,
        source_resource="untrusted-web-feed",
        direct_trust_level=ProvenanceTrust.EXTERNAL_UNTRUSTED,
        data_classifications=frozenset({DataClassification.PUBLIC}),
    )
    prov_store.register_artifact(untrusted_art, payload="Untrusted search payload")

    prop1 = AgentActionProposal(
        agent_id="agent-01",
        session_id=session_id,
        tool_name="web.search",
        input_artifact_ids=[untrusted_art.artifact_id],
    )
    act1, dec1 = gateway.evaluate_proposal(prop1)
    assert dec1.decision == PolicyDecision.ALLOW
    # Execute action to materialize execution and graph CONSUMES relationship
    gateway.execute_authorized_action(act1.action_id)

    # Step 2: Agent attempts sensitive database.read chained directly on act1
    prop2 = AgentActionProposal(
        agent_id="agent-01",
        session_id=session_id,
        tool_name="database.read",
        target_resource="customer_db",
        target_environment=TargetEnvironment.DEVELOPMENT,
        parent_action_id=act1.action_id,
    )
    act2, dec2 = gateway.evaluate_proposal(prop2)

    # Invariant: Flagship trajectory policy evaluates to REQUIRE_APPROVAL
    assert dec2.decision == PolicyDecision.REQUIRE_APPROVAL
    assert "RULE_TRAJECTORY_UNTRUSTED_PATH_TO_SENSITIVE_ACCESS" in dec2.matched_rules
    assert act2.execution_status == ToolExecutionStatus.PENDING_APPROVAL
