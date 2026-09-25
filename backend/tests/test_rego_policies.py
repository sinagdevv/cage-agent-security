"""Integration tests evaluating Rego policies against a live running OPA container.

Marked with @pytest.mark.opa so standard local unit tests run with mocked/offline adapters.
Run via: pytest -m opa
"""

from uuid import uuid4

import pytest

from app.gateway.registry import ToolRegistry, ToolSpec
from app.policies.opa_client import OpaClient
from app.policies.policy_input import build_cage_policy_input
from app.policies.rules import DeterministicPolicyEvaluator
from app.schemas.action import AgentAction
from app.schemas.enums import (
    ActionType,
    DataClassification,
    GraphAnalysisStatus,
    OpaStatus,
    PolicyDecision,
    ProvenanceAnalysisStatus,
    ProvenanceTrust,
    TargetEnvironment,
    TrustLevel,
)
from app.schemas.intent import IntentContract, IntentContractCreate
from app.schemas.policy import PolicyGraphContext, PolicyProvenanceContext


@pytest.fixture
def live_opa_client():
    client = OpaClient()
    if not client.check_health():
        pytest.skip(f"Live OPA container not reachable at {client.opa_url}")
    return client


@pytest.mark.opa
def test_live_rego_intent_allow(live_opa_client: OpaClient) -> None:
    """Verify live OPA evaluates conforming action to RULE_INTENT_ALLOW."""
    action = AgentAction(
        action_id=uuid4(),
        agent_id="agent-01",
        session_id="session-live-1",
        tool_name="web.search",
        action_type=ActionType.TOOL_CALL,
        target_environment=TargetEnvironment.DEVELOPMENT,
        data_classifications=[DataClassification.PUBLIC],
        input_trust_level=TrustLevel.MEDIUM,
    )
    contract = IntentContract.from_create(
        IntentContractCreate(
            agent_id="agent-01",
            session_id="session-live-1",
            goal="Research",
            allowed_tools=["web.search"],
            allowed_environments=[TargetEnvironment.DEVELOPMENT],
            allowed_data_classifications=[DataClassification.PUBLIC],
        )
    )
    policy_input = build_cage_policy_input(action, contract=contract)
    res = live_opa_client.evaluate(policy_input)

    assert res.status == OpaStatus.SUCCESS
    rule_ids = [f.rule_id for f in res.findings]
    assert "RULE_INTENT_ALLOW" in rule_ids
    assert all(f.decision == PolicyDecision.ALLOW for f in res.findings)


@pytest.mark.opa
def test_live_rego_tool_outside_intent(live_opa_client: OpaClient) -> None:
    """Verify live OPA produces RULE_TOOL_OUTSIDE_INTENT for unauthorized tool."""
    action = AgentAction(
        action_id=uuid4(),
        agent_id="agent-01",
        session_id="session-live-2",
        tool_name="database.read",
        action_type=ActionType.TOOL_CALL,
        target_environment=TargetEnvironment.DEVELOPMENT,
        input_trust_level=TrustLevel.MEDIUM,
    )
    contract = IntentContract.from_create(
        IntentContractCreate(
            agent_id="agent-01",
            session_id="session-live-2",
            goal="Research",
            allowed_tools=["web.search"],
        )
    )
    policy_input = build_cage_policy_input(action, contract=contract)
    res = live_opa_client.evaluate(policy_input)

    assert res.status == OpaStatus.SUCCESS
    rule_ids = [f.rule_id for f in res.findings]
    assert "RULE_TOOL_OUTSIDE_INTENT" in rule_ids


@pytest.mark.opa
def test_live_rego_approval_tool(live_opa_client: OpaClient) -> None:
    """Verify live OPA produces RULE_APPROVAL_TOOL."""
    action = AgentAction(
        action_id=uuid4(),
        agent_id="agent-01",
        session_id="session-live-3",
        tool_name="external.http_post",
        action_type=ActionType.TOOL_CALL,
        target_environment=TargetEnvironment.DEVELOPMENT,
        input_trust_level=TrustLevel.MEDIUM,
    )
    contract = IntentContract.from_create(
        IntentContractCreate(
            agent_id="agent-01",
            session_id="session-live-3",
            goal="Dispatch webhook",
            allowed_tools=["external.http_post"],
            requires_approval=["external.http_post"],
        )
    )
    policy_input = build_cage_policy_input(action, contract=contract)
    res = live_opa_client.evaluate(policy_input)

    assert res.status == OpaStatus.SUCCESS
    rule_ids = [f.rule_id for f in res.findings]
    assert "RULE_APPROVAL_TOOL" in rule_ids
    approval_finding = next(f for f in res.findings if f.rule_id == "RULE_APPROVAL_TOOL")
    assert approval_finding.decision == PolicyDecision.REQUIRE_APPROVAL


@pytest.mark.opa
def test_live_rego_credential_external_exfiltration(live_opa_client: OpaClient) -> None:
    """Verify live OPA produces RULE_B_CREDENTIAL_EXTERNAL_EXFILTRATION."""
    registry = ToolRegistry()
    registry.register(
        ToolSpec(
            name="external.http_post",
            description="External HTTP sink",
            external_sink=True,
        )
    )
    action = AgentAction(
        action_id=uuid4(),
        agent_id="agent-01",
        session_id="session-live-4",
        tool_name="external.http_post",
        action_type=ActionType.TOOL_CALL,
        target_environment=TargetEnvironment.DEVELOPMENT,
        data_classifications=[DataClassification.CREDENTIAL],
        input_trust_level=TrustLevel.MEDIUM,
    )
    contract = IntentContract.from_create(
        IntentContractCreate(
            agent_id="agent-01",
            session_id="session-live-4",
            goal="Data transfer",
            allowed_tools=["external.http_post"],
            allowed_data_classifications=[DataClassification.CREDENTIAL],
        )
    )
    policy_input = build_cage_policy_input(action, contract=contract, tool_registry=registry)
    res = live_opa_client.evaluate(policy_input)

    assert res.status == OpaStatus.SUCCESS
    rule_ids = [f.rule_id for f in res.findings]
    assert "RULE_B_CREDENTIAL_EXTERNAL_EXFILTRATION" in rule_ids


@pytest.mark.opa
def test_live_rego_production_destructive(live_opa_client: OpaClient) -> None:
    """Verify live OPA produces RULE_A_PRODUCTION_DESTRUCTIVE."""
    registry = ToolRegistry()
    registry.register(
        ToolSpec(
            name="system.delete_resource",
            description="Destructive deletion",
            destructive=True,
        )
    )
    action = AgentAction(
        action_id=uuid4(),
        agent_id="agent-01",
        session_id="session-live-5",
        tool_name="system.delete_resource",
        action_type=ActionType.DESTRUCTIVE,
        target_environment=TargetEnvironment.PRODUCTION,
        input_trust_level=TrustLevel.MEDIUM,
    )
    contract = IntentContract.from_create(
        IntentContractCreate(
            agent_id="agent-01",
            session_id="session-live-5",
            goal="System cleanup",
            allowed_tools=["system.delete_resource"],
            allowed_environments=[TargetEnvironment.PRODUCTION],
        )
    )
    policy_input = build_cage_policy_input(action, contract=contract, tool_registry=registry)
    res = live_opa_client.evaluate(policy_input)

    assert res.status == OpaStatus.SUCCESS
    rule_ids = [f.rule_id for f in res.findings]
    assert "RULE_A_PRODUCTION_DESTRUCTIVE" in rule_ids


@pytest.mark.opa
def test_live_rego_graph_sensitive_ancestry_confidential_and_pii(
    live_opa_client: OpaClient,
) -> None:
    """Requirement 2 & 7: Verify live OPA denies external transmission following CONFIDENTIAL/PII access."""
    registry = ToolRegistry()
    registry.register(
        ToolSpec(
            name="external.http_post",
            description="External HTTP sink",
            external_sink=True,
        )
    )
    action = AgentAction(
        action_id=uuid4(),
        agent_id="agent-01",
        session_id="session-live-g1",
        tool_name="external.http_post",
        action_type=ActionType.TOOL_CALL,
        target_environment=TargetEnvironment.DEVELOPMENT,
        data_classifications=[DataClassification.PUBLIC],
        input_trust_level=TrustLevel.MEDIUM,
    )
    contract = IntentContract.from_create(
        IntentContractCreate(
            agent_id="agent-01",
            session_id="session-live-g1",
            goal="Data transmit",
            allowed_tools=["external.http_post"],
            allowed_data_classifications=[DataClassification.PUBLIC],
        )
    )
    graph_ctx = PolicyGraphContext(
        analysis_status=GraphAnalysisStatus.SUCCESS,
        analysis_complete=True,
        causal_depth=2,
        ancestor_count=2,
        ancestor_action_ids=["id-1", "id-2"],
        ancestor_tool_sequence=["database.read", "file.write"],
        ancestor_environments=["DEVELOPMENT", "DEVELOPMENT"],
        ancestor_data_classifications=["CONFIDENTIAL", "PII"],
    )
    policy_input = build_cage_policy_input(
        action, contract=contract, tool_registry=registry, graph_context=graph_ctx
    )
    res = live_opa_client.evaluate(policy_input)

    assert res.status == OpaStatus.SUCCESS
    rule_ids = [f.rule_id for f in res.findings]
    assert "RULE_GRAPH_EXTERNAL_AFTER_SENSITIVE_ACCESS" in rule_ids
    assert any(f.decision == PolicyDecision.DENY for f in res.findings)


@pytest.mark.opa
def test_live_rego_graph_sensitive_ancestry_secret_and_credential(
    live_opa_client: OpaClient,
) -> None:
    """Requirement 5 & 7: Verify live OPA denies external sink for SECRET and CREDENTIAL ancestry."""
    registry = ToolRegistry()
    registry.register(
        ToolSpec(
            name="external.http_post",
            description="External HTTP sink",
            external_sink=True,
        )
    )

    for sensitive_class in ["SECRET", "CREDENTIAL"]:
        action = AgentAction(
            action_id=uuid4(),
            agent_id="agent-01",
            session_id=f"session-live-sens-{sensitive_class.lower()}",
            tool_name="external.http_post",
            action_type=ActionType.TOOL_CALL,
            target_environment=TargetEnvironment.DEVELOPMENT,
            data_classifications=[DataClassification.PUBLIC],
            input_trust_level=TrustLevel.MEDIUM,
        )
        contract = IntentContract.from_create(
            IntentContractCreate(
                agent_id="agent-01",
                session_id=f"session-live-sens-{sensitive_class.lower()}",
                goal="Data transfer",
                allowed_tools=["external.http_post"],
            )
        )
        graph_ctx = PolicyGraphContext(
            analysis_status=GraphAnalysisStatus.SUCCESS,
            analysis_complete=True,
            causal_depth=1,
            ancestor_count=1,
            ancestor_action_ids=["sens-id-1"],
            ancestor_tool_sequence=["vault.fetch"],
            ancestor_environments=["DEVELOPMENT"],
            ancestor_data_classifications=[sensitive_class],
        )
        policy_input = build_cage_policy_input(
            action, contract=contract, tool_registry=registry, graph_context=graph_ctx
        )
        res = live_opa_client.evaluate(policy_input)

        assert res.status == OpaStatus.SUCCESS
        rule_ids = [f.rule_id for f in res.findings]
        assert "RULE_GRAPH_EXTERNAL_AFTER_SENSITIVE_ACCESS" in rule_ids
        assert any(f.decision == PolicyDecision.DENY for f in res.findings)


@pytest.mark.opa
def test_live_rego_graph_repeated_privilege_probing(live_opa_client: OpaClient) -> None:
    """Requirement 7 & 8: Verify live OPA yields QUARANTINE on repeated probing threshold (3 attempts)."""
    registry = ToolRegistry()
    registry.register(
        ToolSpec(
            name="admin.exec_cmd",
            description="Privileged admin execution",
            known=True,
            privileged=True,
        )
    )
    action = AgentAction(
        action_id=uuid4(),
        agent_id="agent-01",
        session_id="session-live-probing",
        tool_name="admin.exec_cmd",
        action_type=ActionType.TOOL_CALL,
        target_environment=TargetEnvironment.DEVELOPMENT,
        input_trust_level=TrustLevel.MEDIUM,
    )
    contract = IntentContract.from_create(
        IntentContractCreate(
            agent_id="agent-01",
            session_id="session-live-probing",
            goal="Maintenance",
            allowed_tools=["admin.exec_cmd"],
        )
    )
    graph_ctx = PolicyGraphContext(
        analysis_status=GraphAnalysisStatus.SUCCESS,
        analysis_complete=True,
        causal_depth=2,
        ancestor_count=2,
        ancestor_action_ids=["probe-1", "probe-2"],
        ancestor_tool_sequence=["probe.unknown1", "probe.unknown2"],
        ancestor_environments=["DEVELOPMENT", "DEVELOPMENT"],
        privileged_probe_count=2,  # 2 prior probes + 1 current probe = 3 -> threshold reached!
    )
    policy_input = build_cage_policy_input(
        action, contract=contract, tool_registry=registry, graph_context=graph_ctx
    )
    res = live_opa_client.evaluate(policy_input)

    assert res.status == OpaStatus.SUCCESS
    rule_ids = [f.rule_id for f in res.findings]
    assert "RULE_GRAPH_REPEATED_PRIVILEGE_PROBING" in rule_ids
    quarantine_finding = next(
        f for f in res.findings if f.rule_id == "RULE_GRAPH_REPEATED_PRIVILEGE_PROBING"
    )
    assert quarantine_finding.decision == PolicyDecision.QUARANTINE


@pytest.mark.opa
def test_live_rego_graph_environment_escalation(live_opa_client: OpaClient) -> None:
    """Requirement 7 & 8: Verify live OPA yields REQUIRE_APPROVAL on environment escalation."""
    registry = ToolRegistry()
    registry.register(
        ToolSpec(
            name="admin.exec_cmd",
            description="Privileged admin execution",
            known=True,
            privileged=True,
        )
    )
    action = AgentAction(
        action_id=uuid4(),
        agent_id="agent-01",
        session_id="session-live-env",
        tool_name="admin.exec_cmd",
        action_type=ActionType.TOOL_CALL,
        target_environment=TargetEnvironment.PRODUCTION,
        input_trust_level=TrustLevel.MEDIUM,
    )
    contract = IntentContract.from_create(
        IntentContractCreate(
            agent_id="agent-01",
            session_id="session-live-env",
            goal="Prod deployment",
            allowed_tools=["admin.exec_cmd"],
            allowed_environments=[TargetEnvironment.PRODUCTION],
        )
    )
    graph_ctx = PolicyGraphContext(
        analysis_status=GraphAnalysisStatus.SUCCESS,
        analysis_complete=True,
        causal_depth=2,
        ancestor_count=2,
        ancestor_action_ids=["id-dev-1", "id-dev-2"],
        ancestor_tool_sequence=["web.search", "file.write"],
        ancestor_environments=["DEVELOPMENT", "DEVELOPMENT"],
        has_lower_environment_ancestor=True,
        has_high_environment_ancestor=False,
    )
    policy_input = build_cage_policy_input(
        action, contract=contract, tool_registry=registry, graph_context=graph_ctx
    )
    res = live_opa_client.evaluate(policy_input)

    assert res.status == OpaStatus.SUCCESS
    rule_ids = [f.rule_id for f in res.findings]
    assert "RULE_GRAPH_ENVIRONMENT_ESCALATION" in rule_ids
    escalation_finding = next(
        f for f in res.findings if f.rule_id == "RULE_GRAPH_ENVIRONMENT_ESCALATION"
    )
    assert escalation_finding.decision == PolicyDecision.REQUIRE_APPROVAL


@pytest.mark.opa
def test_live_rego_graph_denied_ancestor_privileged_escalation(live_opa_client: OpaClient) -> None:
    """Requirement 1 & 7: Verify live OPA yields REQUIRE_APPROVAL for privileged action after denial."""
    registry = ToolRegistry()
    registry.register(
        ToolSpec(
            name="admin.exec_cmd",
            description="Privileged admin execution",
            known=True,
            privileged=True,
        )
    )
    action = AgentAction(
        action_id=uuid4(),
        agent_id="agent-01",
        session_id="session-live-denied-priv",
        tool_name="admin.exec_cmd",
        action_type=ActionType.TOOL_CALL,
        target_environment=TargetEnvironment.DEVELOPMENT,
        input_trust_level=TrustLevel.MEDIUM,
    )
    contract = IntentContract.from_create(
        IntentContractCreate(
            agent_id="agent-01",
            session_id="session-live-denied-priv",
            goal="Follow up execution",
            allowed_tools=["admin.exec_cmd"],
        )
    )
    graph_ctx = PolicyGraphContext(
        analysis_status=GraphAnalysisStatus.SUCCESS,
        analysis_complete=True,
        causal_depth=1,
        ancestor_count=1,
        ancestor_action_ids=["denied-1"],
        ancestor_tool_sequence=["forbidden.tool"],
        ancestor_environments=["DEVELOPMENT"],
        contains_denied_ancestor=True,
    )
    policy_input = build_cage_policy_input(
        action, contract=contract, tool_registry=registry, graph_context=graph_ctx
    )
    res = live_opa_client.evaluate(policy_input)

    assert res.status == OpaStatus.SUCCESS
    rule_ids = [f.rule_id for f in res.findings]
    assert "RULE_GRAPH_DENIED_ANCESTOR_ESCALATION" in rule_ids
    finding = next(f for f in res.findings if f.rule_id == "RULE_GRAPH_DENIED_ANCESTOR_ESCALATION")
    assert finding.decision == PolicyDecision.REQUIRE_APPROVAL


@pytest.mark.opa
def test_live_rego_graph_denied_ancestor_benign_action_allowed(live_opa_client: OpaClient) -> None:
    """Requirement 1 & 3: Benign action after denial must NOT trigger RULE_GRAPH_DENIED_ANCESTOR_ESCALATION in live OPA."""
    registry = ToolRegistry()
    registry.register(
        ToolSpec(
            name="web.search",
            description="Search tool",
            known=True,
            privileged=False,
            destructive=False,
        )
    )
    action = AgentAction(
        action_id=uuid4(),
        agent_id="agent-01",
        session_id="session-live-denied-benign",
        tool_name="web.search",
        action_type=ActionType.TOOL_CALL,
        target_environment=TargetEnvironment.DEVELOPMENT,
        data_classifications=[DataClassification.PUBLIC],
        input_trust_level=TrustLevel.MEDIUM,
    )
    contract = IntentContract.from_create(
        IntentContractCreate(
            agent_id="agent-01",
            session_id="session-live-denied-benign",
            goal="Research following denial",
            allowed_tools=["web.search"],
        )
    )
    graph_ctx = PolicyGraphContext(
        analysis_status=GraphAnalysisStatus.SUCCESS,
        analysis_complete=True,
        causal_depth=1,
        ancestor_count=1,
        ancestor_action_ids=["denied-1"],
        ancestor_tool_sequence=["forbidden.tool"],
        ancestor_environments=["DEVELOPMENT"],
        contains_denied_ancestor=True,
    )
    policy_input = build_cage_policy_input(
        action, contract=contract, tool_registry=registry, graph_context=graph_ctx
    )
    res = live_opa_client.evaluate(policy_input)

    assert res.status == OpaStatus.SUCCESS
    rule_ids = [f.rule_id for f in res.findings]
    # CRITICAL: Benign action does NOT trigger denied-ancestor escalation
    assert "RULE_GRAPH_DENIED_ANCESTOR_ESCALATION" not in rule_ids
    assert "RULE_INTENT_ALLOW" in rule_ids
    assert all(f.decision == PolicyDecision.ALLOW for f in res.findings)


@pytest.mark.opa
def test_live_rego_graph_depth_limit_failure(live_opa_client: OpaClient) -> None:
    """Requirement 7 & 8: Verify live OPA evaluates DEPTH_LIMIT_EXCEEDED to DENY fail-closed."""
    action = AgentAction(
        action_id=uuid4(),
        agent_id="agent-01",
        session_id="session-live-limit",
        tool_name="web.search",
        action_type=ActionType.TOOL_CALL,
        target_environment=TargetEnvironment.DEVELOPMENT,
        input_trust_level=TrustLevel.MEDIUM,
    )
    contract = IntentContract.from_create(
        IntentContractCreate(
            agent_id="agent-01",
            session_id="session-live-limit",
            goal="Traversal test",
            allowed_tools=["web.search"],
        )
    )
    graph_ctx = PolicyGraphContext(
        analysis_status=GraphAnalysisStatus.DEPTH_LIMIT_EXCEEDED,
        analysis_complete=False,
        causal_depth=26,
        ancestor_count=26,
    )
    policy_input = build_cage_policy_input(action, contract=contract, graph_context=graph_ctx)
    res = live_opa_client.evaluate(policy_input)

    assert res.status == OpaStatus.SUCCESS
    rule_ids = [f.rule_id for f in res.findings]
    assert "RULE_GRAPH_DEPTH_LIMIT_EXCEEDED" in rule_ids
    depth_finding = next(f for f in res.findings if f.rule_id == "RULE_GRAPH_DEPTH_LIMIT_EXCEEDED")
    assert depth_finding.decision == PolicyDecision.DENY


@pytest.mark.opa
def test_live_rego_graph_python_parity(live_opa_client: OpaClient) -> None:
    """Requirement 7: Verify live OPA and Python evaluator produce identical decisions for graph policies."""
    registry = ToolRegistry()
    registry.register(
        ToolSpec(
            name="admin.exec_cmd",
            description="Privileged admin execution",
            known=True,
            privileged=True,
        )
    )
    action = AgentAction(
        action_id=uuid4(),
        agent_id="agent-01",
        session_id="session-live-parity",
        tool_name="admin.exec_cmd",
        action_type=ActionType.TOOL_CALL,
        target_environment=TargetEnvironment.DEVELOPMENT,
        input_trust_level=TrustLevel.MEDIUM,
    )
    contract = IntentContract.from_create(
        IntentContractCreate(
            agent_id="agent-01",
            session_id="session-live-parity",
            goal="Maintenance",
            allowed_tools=["admin.exec_cmd"],
        )
    )
    graph_ctx = PolicyGraphContext(
        analysis_status=GraphAnalysisStatus.SUCCESS,
        analysis_complete=True,
        causal_depth=2,
        ancestor_count=2,
        ancestor_action_ids=["id-1", "id-2"],
        ancestor_tool_sequence=["t1", "t2"],
        ancestor_environments=["DEVELOPMENT", "DEVELOPMENT"],
        privileged_probe_count=2,
    )
    policy_input = build_cage_policy_input(
        action, contract=contract, tool_registry=registry, graph_context=graph_ctx
    )

    # 1. Live OPA evaluation
    opa_res = live_opa_client.evaluate(policy_input)
    assert opa_res.status == OpaStatus.SUCCESS
    opa_rules = {f.rule_id for f in opa_res.findings}

    # 2. Python evaluation
    python_evaluator = DeterministicPolicyEvaluator(tool_registry=registry)
    python_decision = python_evaluator.evaluate(
        action=action,
        contract=contract,
        require_intent=True,
        graph_context=graph_ctx,
    )

    # 3. Assert parity
    assert "RULE_GRAPH_REPEATED_PRIVILEGE_PROBING" in opa_rules
    assert "RULE_GRAPH_REPEATED_PRIVILEGE_PROBING" in python_decision.matched_rules
    assert python_decision.decision == PolicyDecision.QUARANTINE
    assert any(f.decision == PolicyDecision.QUARANTINE for f in opa_res.findings)


@pytest.mark.opa
def test_live_rego_provenance_sensitive_to_external(live_opa_client: OpaClient) -> None:
    """Verify live OPA evaluates RULE_PROVENANCE_SENSITIVE_TO_EXTERNAL as DENY."""
    registry = ToolRegistry()
    registry.register(
        ToolSpec(
            name="external.http_post",
            description="External HTTP sink",
            external_sink=True,
        )
    )
    action = AgentAction(
        action_id=uuid4(),
        agent_id="agent-01",
        session_id="session-live-prov-sens",
        tool_name="external.http_post",
        action_type=ActionType.TOOL_CALL,
        target_environment=TargetEnvironment.DEVELOPMENT,
        data_classifications=[DataClassification.PUBLIC],
        input_trust_level=TrustLevel.MEDIUM,
    )
    contract = IntentContract.from_create(
        IntentContractCreate(
            agent_id="agent-01",
            session_id="session-live-prov-sens",
            goal="Data export",
            allowed_tools=["external.http_post"],
        )
    )
    prov_ctx = PolicyProvenanceContext(
        contains_sensitive_input=True,
        input_classifications=["CONFIDENTIAL", "PII"],
    )
    policy_input = build_cage_policy_input(
        action, contract=contract, tool_registry=registry, provenance_context=prov_ctx
    )

    res = live_opa_client.evaluate(policy_input)
    assert res.status == OpaStatus.SUCCESS
    rule_ids = [f.rule_id for f in res.findings]
    assert "RULE_PROVENANCE_SENSITIVE_TO_EXTERNAL" in rule_ids
    assert any(
        f.decision == PolicyDecision.DENY and f.rule_id == "RULE_PROVENANCE_SENSITIVE_TO_EXTERNAL"
        for f in res.findings
    )


@pytest.mark.opa
def test_live_rego_provenance_untracked_egress(live_opa_client: OpaClient) -> None:
    """Verify live OPA evaluates RULE_PROVENANCE_UNTRACKED_EGRESS as DENY."""
    from app.schemas.enums import PayloadBindingMode

    registry = ToolRegistry()
    registry.register(
        ToolSpec(
            name="external.http_post",
            description="External HTTP sink",
            external_sink=True,
            requires_tracked_inputs=True,
            payload_binding_mode=PayloadBindingMode.ARTIFACT_REQUIRED,
        )
    )
    action = AgentAction(
        action_id=uuid4(),
        agent_id="agent-01",
        session_id="session-live-prov-untracked",
        tool_name="external.http_post",
        action_type=ActionType.TOOL_CALL,
        target_environment=TargetEnvironment.DEVELOPMENT,
        data_classifications=[DataClassification.PUBLIC],
        input_trust_level=TrustLevel.MEDIUM,
    )
    contract = IntentContract.from_create(
        IntentContractCreate(
            agent_id="agent-01",
            session_id="session-live-prov-untracked",
            goal="Data export",
            allowed_tools=["external.http_post"],
        )
    )
    prov_ctx = PolicyProvenanceContext(
        payload_binding_required=True,
        payload_binding_satisfied=False,
    )
    policy_input = build_cage_policy_input(
        action, contract=contract, tool_registry=registry, provenance_context=prov_ctx
    )

    res = live_opa_client.evaluate(policy_input)
    assert res.status == OpaStatus.SUCCESS
    rule_ids = [f.rule_id for f in res.findings]
    assert "RULE_PROVENANCE_UNTRACKED_EGRESS" in rule_ids
    assert any(
        f.decision == PolicyDecision.DENY and f.rule_id == "RULE_PROVENANCE_UNTRACKED_EGRESS"
        for f in res.findings
    )


@pytest.mark.opa
def test_live_rego_provenance_untrusted_to_privileged(live_opa_client: OpaClient) -> None:
    """Verify live OPA evaluates RULE_PROVENANCE_UNTRUSTED_TO_PRIVILEGED as REQUIRE_APPROVAL."""
    registry = ToolRegistry()
    registry.register(
        ToolSpec(
            name="system.delete_resource",
            description="System delete tool",
            privileged=True,
            destructive=True,
        )
    )
    action = AgentAction(
        action_id=uuid4(),
        agent_id="agent-01",
        session_id="session-live-prov-untrusted",
        tool_name="system.delete_resource",
        action_type=ActionType.TOOL_CALL,
        target_environment=TargetEnvironment.DEVELOPMENT,
        data_classifications=[DataClassification.PUBLIC],
        input_trust_level=TrustLevel.EXTERNAL_UNTRUSTED,
    )
    contract = IntentContract.from_create(
        IntentContractCreate(
            agent_id="agent-01",
            session_id="session-live-prov-untrusted",
            goal="Admin cleanup",
            allowed_tools=["system.delete_resource"],
        )
    )
    prov_ctx = PolicyProvenanceContext(
        contains_untrusted_input=True,
        input_direct_trust_levels=["EXTERNAL_UNTRUSTED"],
    )
    policy_input = build_cage_policy_input(
        action, contract=contract, tool_registry=registry, provenance_context=prov_ctx
    )

    res = live_opa_client.evaluate(policy_input)
    assert res.status == OpaStatus.SUCCESS
    rule_ids = [f.rule_id for f in res.findings]
    assert "RULE_PROVENANCE_UNTRUSTED_TO_PRIVILEGED" in rule_ids
    assert any(
        f.decision == PolicyDecision.REQUIRE_APPROVAL
        and f.rule_id == "RULE_PROVENANCE_UNTRUSTED_TO_PRIVILEGED"
        for f in res.findings
    )


@pytest.mark.opa
def test_live_rego_provenance_python_parity(live_opa_client: OpaClient) -> None:
    """Verify Python and live OPA parity across provenance rules."""
    from app.schemas.enums import PayloadBindingMode

    registry = ToolRegistry()
    registry.register(
        ToolSpec(
            name="external.http_post",
            description="External HTTP sink",
            external_sink=True,
            requires_tracked_inputs=True,
            payload_binding_mode=PayloadBindingMode.ARTIFACT_REQUIRED,
        )
    )
    action = AgentAction(
        action_id=uuid4(),
        agent_id="agent-01",
        session_id="session-live-prov-parity",
        tool_name="external.http_post",
        action_type=ActionType.TOOL_CALL,
        target_environment=TargetEnvironment.DEVELOPMENT,
        data_classifications=[DataClassification.PUBLIC],
        input_trust_level=TrustLevel.MEDIUM,
    )
    contract = IntentContract.from_create(
        IntentContractCreate(
            agent_id="agent-01",
            session_id="session-live-prov-parity",
            goal="Export",
            allowed_tools=["external.http_post"],
        )
    )
    prov_ctx = PolicyProvenanceContext(
        contains_credential_input=True,
        input_classifications=["CREDENTIAL"],
        payload_binding_required=True,
        payload_binding_satisfied=True,
    )
    policy_input = build_cage_policy_input(
        action, contract=contract, tool_registry=registry, provenance_context=prov_ctx
    )

    # 1. Live OPA evaluation
    opa_res = live_opa_client.evaluate(policy_input)
    assert opa_res.status == OpaStatus.SUCCESS
    opa_rules = {f.rule_id for f in opa_res.findings}

    # 2. Python evaluation
    python_evaluator = DeterministicPolicyEvaluator(tool_registry=registry)
    python_decision = python_evaluator.evaluate(
        action=action,
        contract=contract,
        require_intent=True,
        provenance_context=prov_ctx,
    )

    # 3. Assert parity
    assert "RULE_PROVENANCE_CREDENTIAL_TO_EXTERNAL" in opa_rules
    assert "RULE_PROVENANCE_CREDENTIAL_TO_EXTERNAL" in python_decision.matched_rules
    assert python_decision.decision == PolicyDecision.DENY
    assert any(
        f.decision == PolicyDecision.DENY and f.rule_id == "RULE_PROVENANCE_CREDENTIAL_TO_EXTERNAL"
        for f in opa_res.findings
    )


@pytest.mark.opa
def test_live_rego_provenance_credential_to_external(live_opa_client: OpaClient) -> None:
    """Verify live OPA evaluates RULE_PROVENANCE_CREDENTIAL_TO_EXTERNAL as DENY and partitions disjointly."""
    registry = ToolRegistry()
    registry.register(
        ToolSpec(
            name="external.http_post",
            description="External HTTP sink",
            external_sink=True,
        )
    )
    action = AgentAction(
        action_id=uuid4(),
        agent_id="agent-01",
        session_id="session-live-prov-cred",
        tool_name="external.http_post",
        action_type=ActionType.TOOL_CALL,
        target_environment=TargetEnvironment.DEVELOPMENT,
        data_classifications=[DataClassification.PUBLIC],
        input_trust_level=TrustLevel.MEDIUM,
    )
    contract = IntentContract.from_create(
        IntentContractCreate(
            agent_id="agent-01",
            session_id="session-live-prov-cred",
            goal="Data export",
            allowed_tools=["external.http_post"],
        )
    )
    # CREDENTIAL input alone: contains_credential_input is True, contains_sensitive_input is False
    prov_ctx = PolicyProvenanceContext(
        contains_credential_input=True,
        contains_sensitive_input=False,
        input_classifications=["CREDENTIAL", "SECRET"],
    )
    policy_input = build_cage_policy_input(
        action, contract=contract, tool_registry=registry, provenance_context=prov_ctx
    )

    res = live_opa_client.evaluate(policy_input)
    assert res.status == OpaStatus.SUCCESS
    rule_ids = [f.rule_id for f in res.findings]
    assert "RULE_PROVENANCE_CREDENTIAL_TO_EXTERNAL" in rule_ids
    # Crucial partition check: GENERAL_SENSITIVE rule is NOT emitted for purely CREDENTIAL/SECRET input
    assert "RULE_PROVENANCE_SENSITIVE_TO_EXTERNAL" not in rule_ids
    assert any(
        f.decision == PolicyDecision.DENY and f.rule_id == "RULE_PROVENANCE_CREDENTIAL_TO_EXTERNAL"
        for f in res.findings
    )


@pytest.mark.opa
def test_live_rego_provenance_missing_artifact(live_opa_client: OpaClient) -> None:
    """Verify live OPA evaluates RULE_PROVENANCE_MISSING_ARTIFACT as DENY fail-closed on analysis failure."""
    registry = ToolRegistry()
    registry.register(
        ToolSpec(
            name="file.write",
            description="Write file",
        )
    )
    action = AgentAction(
        action_id=uuid4(),
        agent_id="agent-01",
        session_id="session-live-prov-missing",
        tool_name="file.write",
        action_type=ActionType.TOOL_CALL,
        target_environment=TargetEnvironment.DEVELOPMENT,
        data_classifications=[DataClassification.PUBLIC],
        input_trust_level=TrustLevel.MEDIUM,
    )
    contract = IntentContract.from_create(
        IntentContractCreate(
            agent_id="agent-01",
            session_id="session-live-prov-missing",
            goal="File output",
            allowed_tools=["file.write"],
        )
    )
    prov_ctx = PolicyProvenanceContext(
        analysis_status=ProvenanceAnalysisStatus.MISSING_ARTIFACT,
        analysis_complete=False,
    )
    policy_input = build_cage_policy_input(
        action, contract=contract, tool_registry=registry, provenance_context=prov_ctx
    )

    res = live_opa_client.evaluate(policy_input)
    assert res.status == OpaStatus.SUCCESS
    rule_ids = [f.rule_id for f in res.findings]
    assert "RULE_PROVENANCE_MISSING_ARTIFACT" in rule_ids
    finding = next(f for f in res.findings if f.rule_id == "RULE_PROVENANCE_MISSING_ARTIFACT")
    assert finding.decision == PolicyDecision.DENY


@pytest.mark.opa
def test_live_rego_provenance_unknown_to_privileged(live_opa_client: OpaClient) -> None:
    """Verify live OPA evaluates RULE_PROVENANCE_UNKNOWN_TO_PRIVILEGED as REQUIRE_APPROVAL."""
    registry = ToolRegistry()
    registry.register(
        ToolSpec(
            name="system.reboot",
            description="Privileged reboot tool",
            privileged=True,
        )
    )
    action = AgentAction(
        action_id=uuid4(),
        agent_id="agent-01",
        session_id="session-live-prov-unknown",
        tool_name="system.reboot",
        action_type=ActionType.TOOL_CALL,
        target_environment=TargetEnvironment.DEVELOPMENT,
        data_classifications=[DataClassification.PUBLIC],
        input_trust_level=ProvenanceTrust.UNKNOWN,
    )
    contract = IntentContract.from_create(
        IntentContractCreate(
            agent_id="agent-01",
            session_id="session-live-prov-unknown",
            goal="System reboot",
            allowed_tools=["system.reboot"],
        )
    )
    prov_ctx = PolicyProvenanceContext(
        analysis_complete=True,
        contains_unknown_input=True,
        input_direct_trust_levels=["UNKNOWN"],
    )
    policy_input = build_cage_policy_input(
        action, contract=contract, tool_registry=registry, provenance_context=prov_ctx
    )

    res = live_opa_client.evaluate(policy_input)
    assert res.status == OpaStatus.SUCCESS
    rule_ids = [f.rule_id for f in res.findings]
    assert "RULE_PROVENANCE_UNKNOWN_TO_PRIVILEGED" in rule_ids
    finding = next(f for f in res.findings if f.rule_id == "RULE_PROVENANCE_UNKNOWN_TO_PRIVILEGED")
    assert finding.decision == PolicyDecision.REQUIRE_APPROVAL
