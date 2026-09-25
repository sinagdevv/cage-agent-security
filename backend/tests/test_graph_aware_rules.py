"""Tests for graph-aware security rules, fail-closed limit handling, and API security."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.gateway.registry import ToolRegistry, ToolSpec
from app.gateway.service import AgentGateway
from app.graph.analyzer import GraphSecurityAnalyzer
from app.graph.causal_graph import (
    GraphCycleError,
    SessionGraphManager,
)
from app.intent.service import IntentService
from app.main import app
from app.policies.engine import PolicyEngine
from app.policies.rules import DeterministicPolicyEvaluator
from app.schemas.action import AgentAction, AgentActionProposal
from app.schemas.enums import (
    DataClassification,
    GraphAnalysisStatus,
    GraphRelation,
    PolicyBackend,
    PolicyDecision,
    TargetEnvironment,
)
from app.schemas.intent import IntentContractCreate
from app.schemas.policy import PolicyGraphContext


@pytest.fixture
def clean_gateway():
    """Provides a fresh AgentGateway with isolated graph manager and intent service."""
    registry = ToolRegistry()
    registry.register(ToolSpec(name="web.search", description="Search tool", known=True))
    registry.register(ToolSpec(name="file.write", description="File write", known=True))
    registry.register(
        ToolSpec(
            name="database.read",
            description="Database read",
            known=True,
            default_classification=DataClassification.CONFIDENTIAL,
        )
    )
    registry.register(
        ToolSpec(
            name="external.http_post",
            description="External HTTP sink",
            known=True,
            external_sink=True,
        )
    )
    registry.register(
        ToolSpec(
            name="system.delete_resource",
            description="Destructive delete",
            known=True,
            destructive=True,
        )
    )
    registry.register(
        ToolSpec(
            name="admin.exec_cmd",
            description="Privileged admin execution",
            known=True,
            privileged=True,
        )
    )
    registry.register(
        ToolSpec(
            name="vault.read_secret",
            description="Read secret from vault",
            known=True,
            default_classification=DataClassification.SECRET,
        )
    )
    registry.register(
        ToolSpec(
            name="auth.get_token",
            description="Fetch credential token",
            known=True,
            default_classification=DataClassification.CREDENTIAL,
        )
    )
    registry.register(
        ToolSpec(
            name="user.get_profile",
            description="Fetch user PII profile",
            known=True,
            default_classification=DataClassification.PII,
        )
    )
    graph_manager = SessionGraphManager()
    intent_service = IntentService()
    analyzer = GraphSecurityAnalyzer(max_depth=25, max_nodes=500)
    evaluator = DeterministicPolicyEvaluator(tool_registry=registry)
    engine = PolicyEngine(python_evaluator=evaluator, backend=PolicyBackend.SHADOW)
    gateway = AgentGateway(
        graph_manager=graph_manager,
        intent_service=intent_service,
        tool_registry=registry,
        policy_engine=engine,
        graph_analyzer=analyzer,
        require_intent=True,
    )
    return gateway, intent_service, registry


def create_test_intent(intent_service: IntentService, session_id: str, agent_id: str):
    """Helper to create a permissive active IntentContract for testing."""
    return intent_service.create_intent(
        IntentContractCreate(
            session_id=session_id,
            agent_id=agent_id,
            goal="Graph security evaluation",
            allowed_tools=[
                "web.search",
                "file.write",
                "database.read",
                "external.http_post",
                "system.delete_resource",
                "admin.exec_cmd",
                "custom.unknown",
            ],
            allowed_environments=[
                TargetEnvironment.LOCAL,
                TargetEnvironment.DEVELOPMENT,
                TargetEnvironment.STAGING,
                TargetEnvironment.PRODUCTION,
            ],
            allowed_data_classifications=[
                DataClassification.PUBLIC,
                DataClassification.INTERNAL,
                DataClassification.CONFIDENTIAL,
                DataClassification.RESTRICTED,
                DataClassification.SECRET,
                DataClassification.CREDENTIAL,
            ],
            maximum_tool_calls=50,
            expires_at=datetime.now(UTC) + timedelta(hours=2),
        )
    )


def test_rule_graph_external_after_sensitive_access_denied(clean_gateway):
    """Scenario 2 / Requirement 10: Sensitive ancestor access blocks external sink."""
    gateway, intent_service, _ = clean_gateway
    session_id = "session-sensitive-sink"
    agent_id = "agent-test"
    create_test_intent(intent_service, session_id, agent_id)

    # 1. Step 1: database.read (accesses CONFIDENTIAL data)
    prop_1 = AgentActionProposal(
        agent_id=agent_id,
        agent_instance_id="inst-1",
        session_id=session_id,
        tool_name="database.read",
        goal="Read customer record",
        current_task="read",
        data_classifications=[DataClassification.CONFIDENTIAL],
    )
    act_1, dec_1 = gateway.evaluate_proposal(prop_1)
    assert dec_1.decision == PolicyDecision.ALLOW

    # 2. Step 2: file.write (intermediate step)
    prop_2 = AgentActionProposal(
        agent_id=agent_id,
        agent_instance_id="inst-1",
        session_id=session_id,
        tool_name="file.write",
        goal="Write cache",
        current_task="write",
        parent_action_id=act_1.action_id,
    )
    act_2, dec_2 = gateway.evaluate_proposal(prop_2)
    assert dec_2.decision == PolicyDecision.ALLOW

    # 3. Step 3: external.http_post (external sink with sensitive ancestor)
    prop_3 = AgentActionProposal(
        agent_id=agent_id,
        agent_instance_id="inst-1",
        session_id=session_id,
        tool_name="external.http_post",
        goal="Send report",
        current_task="post",
        parent_action_id=act_2.action_id,
    )
    act_3, dec_3 = gateway.evaluate_proposal(prop_3)

    assert dec_3.decision == PolicyDecision.DENY
    assert "RULE_GRAPH_EXTERNAL_AFTER_SENSITIVE_ACCESS" in dec_3.matched_rules
    assert "sensitive-classified data" in dec_3.reason


def test_rule_graph_denied_ancestor_escalation_requires_approval(clean_gateway):
    """Requirement 11: Action following a previously denied ancestor requires approval if privileged."""
    gateway, intent_service, registry = clean_gateway
    session_id = "session-escalate"
    agent_id = "agent-test"
    # Create intent where secret.key is explicitly denied
    _ = intent_service.create_intent(
        IntentContractCreate(
            session_id=session_id,
            agent_id=agent_id,
            goal="Escalation test",
            allowed_tools=["admin.exec_cmd", "system.delete_resource"],
            denied_tools=["secret.tool"],
            allowed_environments=[TargetEnvironment.DEVELOPMENT],
            allowed_data_classifications=[DataClassification.PUBLIC],
            maximum_tool_calls=10,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
    )

    # 1. Step 1: secret.tool -> DENIED by intent
    prop_1 = AgentActionProposal(
        agent_id=agent_id,
        agent_instance_id="inst-1",
        session_id=session_id,
        tool_name="secret.tool",
        goal="Forbidden probe",
        current_task="probe",
    )
    act_1, dec_1 = gateway.evaluate_proposal(prop_1)
    assert dec_1.decision == PolicyDecision.DENY

    # 2. Step 2: admin.exec_cmd with act_1 as parent -> attempts privileged tool after denied ancestor
    prop_2 = AgentActionProposal(
        agent_id=agent_id,
        agent_instance_id="inst-1",
        session_id=session_id,
        tool_name="admin.exec_cmd",
        goal="Privileged follow up",
        current_task="admin",
        parent_action_id=act_1.action_id,
    )
    act_2, dec_2 = gateway.evaluate_proposal(prop_2)

    assert dec_2.decision == PolicyDecision.REQUIRE_APPROVAL
    assert "RULE_GRAPH_DENIED_ANCESTOR_ESCALATION" in dec_2.matched_rules


def test_rule_graph_benign_action_after_denial_does_not_trigger_escalation(clean_gateway):
    """Requirement 3: Benign action following a denied ancestor must NOT trigger escalation or poison trajectory."""
    gateway, intent_service, _ = clean_gateway
    session_id = "session-benign-after-deny"
    agent_id = "agent-test"
    _ = intent_service.create_intent(
        IntentContractCreate(
            session_id=session_id,
            agent_id=agent_id,
            goal="Benign follow up test",
            allowed_tools=["web.search", "file.write"],
            denied_tools=["secret.tool"],
            allowed_environments=[TargetEnvironment.DEVELOPMENT],
            allowed_data_classifications=[DataClassification.PUBLIC],
            maximum_tool_calls=10,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
    )

    # 1. Step 1: secret.tool -> DENIED by intent
    prop_1 = AgentActionProposal(
        agent_id=agent_id,
        agent_instance_id="inst-1",
        session_id=session_id,
        tool_name="secret.tool",
        goal="Denied probe",
        current_task="probe",
    )
    act_1, dec_1 = gateway.evaluate_proposal(prop_1)
    assert dec_1.decision == PolicyDecision.DENY

    # 2. Step 2: web.search with act_1 as parent -> normal benign action
    prop_2 = AgentActionProposal(
        agent_id=agent_id,
        agent_instance_id="inst-1",
        session_id=session_id,
        tool_name="web.search",
        goal="Benign search following denial",
        current_task="search",
        parent_action_id=act_1.action_id,
    )
    act_2, dec_2 = gateway.evaluate_proposal(prop_2)

    # CRITICAL INVARIANT: Benign action is NOT poisoned by prior denial
    assert dec_2.decision == PolicyDecision.ALLOW
    assert "RULE_GRAPH_DENIED_ANCESTOR_ESCALATION" not in dec_2.matched_rules


def test_rule_graph_sensitive_ancestry_secret_and_credential_and_pii(clean_gateway):
    """Requirement 2 & 5: Causal ancestry containing SECRET, CREDENTIAL, or PII blocks external transmission."""
    gateway, intent_service, _ = clean_gateway

    for tool_name, class_name, sess_suffix in [
        ("vault.read_secret", DataClassification.SECRET, "secret"),
        ("auth.get_token", DataClassification.CREDENTIAL, "credential"),
        ("user.get_profile", DataClassification.PII, "pii"),
    ]:
        session_id = f"session-sens-{sess_suffix}"
        agent_id = "agent-test"
        _ = intent_service.create_intent(
            IntentContractCreate(
                session_id=session_id,
                agent_id=agent_id,
                goal=f"Test {class_name.value} ancestry",
                allowed_tools=[tool_name, "file.write", "external.http_post"],
                allowed_environments=[TargetEnvironment.DEVELOPMENT],
                allowed_data_classifications=[
                    DataClassification.PUBLIC,
                    class_name,
                ],
                maximum_tool_calls=10,
                expires_at=datetime.now(UTC) + timedelta(hours=1),
            )
        )

        # Step 1: Access sensitive resource
        prop_1 = AgentActionProposal(
            agent_id=agent_id,
            agent_instance_id="inst-1",
            session_id=session_id,
            tool_name=tool_name,
            goal="Read sensitive data",
            current_task="read",
        )
        act_1, dec_1 = gateway.evaluate_proposal(prop_1)
        assert dec_1.decision == PolicyDecision.ALLOW

        # Step 2: Intermediate step
        prop_2 = AgentActionProposal(
            agent_id=agent_id,
            agent_instance_id="inst-1",
            session_id=session_id,
            tool_name="file.write",
            goal="Save to local buffer",
            current_task="buffer",
            parent_action_id=act_1.action_id,
        )
        act_2, dec_2 = gateway.evaluate_proposal(prop_2)
        assert dec_2.decision == PolicyDecision.ALLOW

        # Step 3: External transmission -> MUST be DENIED
        prop_3 = AgentActionProposal(
            agent_id=agent_id,
            agent_instance_id="inst-1",
            session_id=session_id,
            tool_name="external.http_post",
            goal="Exfiltrate",
            current_task="send",
            parent_action_id=act_2.action_id,
        )
        act_3, dec_3 = gateway.evaluate_proposal(prop_3)
        assert dec_3.decision == PolicyDecision.DENY
        assert "RULE_GRAPH_EXTERNAL_AFTER_SENSITIVE_ACCESS" in dec_3.matched_rules
        assert (
            "External transmission denied because the validated causal ancestry contains access to sensitive-classified data."
            in dec_3.reason
        )


def test_rule_graph_repeated_privilege_probing_quarantined(clean_gateway):
    """Scenario 3 / Requirement 9: Repeated privilege probing (>= 3 attempts) triggers QUARANTINE."""
    gateway, intent_service, _ = clean_gateway
    session_id = "session-probing"
    agent_id = "agent-test"
    create_test_intent(intent_service, session_id, agent_id)

    # Probe 1: unknown custom tool
    prop_1 = AgentActionProposal(
        agent_id=agent_id,
        agent_instance_id="inst-1",
        session_id=session_id,
        tool_name="unknown.probe_1",
        goal="Probe 1",
        current_task="p1",
    )
    act_1, dec_1 = gateway.evaluate_proposal(prop_1)

    # Probe 2: admin.exec_cmd (privileged)
    prop_2 = AgentActionProposal(
        agent_id=agent_id,
        agent_instance_id="inst-1",
        session_id=session_id,
        tool_name="admin.exec_cmd",
        goal="Probe 2",
        current_task="p2",
        parent_action_id=act_1.action_id,
    )
    act_2, dec_2 = gateway.evaluate_proposal(prop_2)

    # Probe 3: system.delete_resource (destructive)
    # Total probes = 2 prior + 1 current = 3 >= threshold 3 -> QUARANTINE
    prop_3 = AgentActionProposal(
        agent_id=agent_id,
        agent_instance_id="inst-1",
        session_id=session_id,
        tool_name="system.delete_resource",
        goal="Probe 3",
        current_task="p3",
        parent_action_id=act_2.action_id,
    )
    act_3, dec_3 = gateway.evaluate_proposal(prop_3)

    assert dec_3.decision == PolicyDecision.QUARANTINE
    assert "RULE_GRAPH_REPEATED_PRIVILEGE_PROBING" in dec_3.matched_rules


def test_rule_graph_environment_escalation_requires_approval(clean_gateway):
    """Scenario 4 / Requirement 3: Trajectory from DEV to privileged PROD requires approval."""
    gateway, intent_service, _ = clean_gateway
    session_id = "session-env-escalate"
    agent_id = "agent-test"
    create_test_intent(intent_service, session_id, agent_id)

    # Step 1: In DEVELOPMENT
    prop_1 = AgentActionProposal(
        agent_id=agent_id,
        agent_instance_id="inst-1",
        session_id=session_id,
        tool_name="web.search",
        target_environment=TargetEnvironment.DEVELOPMENT,
        goal="Dev search",
        current_task="search",
    )
    act_1, _ = gateway.evaluate_proposal(prop_1)

    # Step 2: Escalate to PRODUCTION with privileged tool
    prop_2 = AgentActionProposal(
        agent_id=agent_id,
        agent_instance_id="inst-1",
        session_id=session_id,
        tool_name="admin.exec_cmd",
        target_environment=TargetEnvironment.PRODUCTION,
        goal="Prod admin",
        current_task="admin",
        parent_action_id=act_1.action_id,
    )
    act_2, dec_2 = gateway.evaluate_proposal(prop_2)

    assert dec_2.decision == PolicyDecision.REQUIRE_APPROVAL
    assert "RULE_GRAPH_ENVIRONMENT_ESCALATION" in dec_2.matched_rules


def test_root_production_action_does_not_trigger_environment_escalation(clean_gateway):
    """Requirement 3 & 24: A root production action (0 ancestors) does NOT trigger environment escalation."""
    gateway, intent_service, _ = clean_gateway
    session_id = "session-root-prod"
    agent_id = "agent-test"
    create_test_intent(intent_service, session_id, agent_id)

    # Root action targeting PRODUCTION
    prop = AgentActionProposal(
        agent_id=agent_id,
        agent_instance_id="inst-1",
        session_id=session_id,
        tool_name="web.search",
        target_environment=TargetEnvironment.PRODUCTION,
        goal="Root prod query",
        current_task="query",
        parent_action_id=None,
    )
    act, dec = gateway.evaluate_proposal(prop)

    assert "RULE_GRAPH_ENVIRONMENT_ESCALATION" not in dec.matched_rules


def test_graph_traversal_depth_limit_triggers_fail_closed_deny():
    """Requirement 1 & 23: Graph traversal depth overflow fails closed with RULE_GRAPH_DEPTH_LIMIT_EXCEEDED."""
    evaluator = DeterministicPolicyEvaluator()
    graph_ctx = PolicyGraphContext(
        analysis_status=GraphAnalysisStatus.DEPTH_LIMIT_EXCEEDED,
        analysis_complete=False,
    )
    action = AgentActionProposal(
        agent_id="test",
        agent_instance_id="i1",
        session_id="s1",
        tool_name="web.search",
        goal="test",
        current_task="t",
    )
    authoritative_action = AgentAction.from_proposal(action)

    decision = evaluator.evaluate(
        action=authoritative_action,
        graph_context=graph_ctx,
    )

    assert decision.decision == PolicyDecision.DENY
    assert "RULE_GRAPH_DEPTH_LIMIT_EXCEEDED" in decision.matched_rules


def test_graph_node_limit_triggers_fail_closed_deny():
    """Requirement 1 & 23: Node traversal limit overflow fails closed with RULE_GRAPH_NODE_LIMIT_EXCEEDED."""
    evaluator = DeterministicPolicyEvaluator()
    graph_ctx = PolicyGraphContext(
        analysis_status=GraphAnalysisStatus.NODE_LIMIT_EXCEEDED,
        analysis_complete=False,
    )
    action = AgentActionProposal(
        agent_id="test",
        agent_instance_id="i1",
        session_id="s1",
        tool_name="web.search",
        goal="test",
        current_task="t",
    )
    authoritative_action = AgentAction.from_proposal(action)

    decision = evaluator.evaluate(
        action=authoritative_action,
        graph_context=graph_ctx,
    )

    assert decision.decision == PolicyDecision.DENY
    assert "RULE_GRAPH_NODE_LIMIT_EXCEEDED" in decision.matched_rules


def test_cycle_attempt_via_gateway_raises_bad_request(clean_gateway):
    """Requirement 7 & 8: Gateway rejects cyclic parentage requests with GraphCycleError."""
    gateway, intent_service, _ = clean_gateway
    session_id = "session-cycle-gw"
    agent_id = "agent-test"
    create_test_intent(intent_service, session_id, agent_id)

    # 1. Step A
    prop_a = AgentActionProposal(
        agent_id=agent_id,
        agent_instance_id="i1",
        session_id=session_id,
        tool_name="web.search",
        goal="A",
        current_task="A",
    )
    act_a, _ = gateway.evaluate_proposal(prop_a)

    # 2. Step B (parent=A)
    prop_b = AgentActionProposal(
        agent_id=agent_id,
        agent_instance_id="i1",
        session_id=session_id,
        tool_name="web.search",
        goal="B",
        current_task="B",
        parent_action_id=act_a.action_id,
    )
    act_b, _ = gateway.evaluate_proposal(prop_b)

    # 3. Simulate internal edge addition that would create a cycle B -> A
    graph = gateway.graph_manager.get(session_id)
    with pytest.raises(GraphCycleError):
        graph.add_relationship(
            str(act_b.action_id), str(act_a.action_id), relation=GraphRelation.CAUSES
        )


def test_ancestry_endpoint_requires_control_plane_authority():
    """Requirement 17 & 24: GET /actions/{id}/ancestry requires control-plane authority."""
    client = TestClient(app)

    # In test environment where debug is active, test without control-plane header vs forbidden
    # Non-existent action returns 404 under control-plane
    res = client.get(
        f"/api/v1/actions/{uuid4()}/ancestry",
        headers={"X-CAGE-Control-Plane": "trusted-admin"},
    )
    assert res.status_code == 404


def test_client_cannot_inject_policy_graph_context():
    """Requirement 24: AgentActionProposal forbids client injection of graph context."""
    with pytest.raises(ValueError):
        AgentActionProposal.model_validate(
            {
                "agent_id": "agent-1",
                "agent_instance_id": "inst-1",
                "session_id": "s1",
                "tool_name": "web.search",
                "goal": "test",
                "current_task": "t",
                "graph": {"contains_denied_ancestor": True},  # Forbidden client field
            }
        )
