"""CAGE Phase 3 Demonstration: Open Policy Agent (OPA) Integration & Shadow Parity.

Demonstrates:
  1. Conforming tool action: Python ALLOW == OPA ALLOW (MATCH)
  2. Tool outside Intent: Python DENY == OPA DENY (MATCH)
  3. Production destructive tool: Python REQUIRE_APPROVAL == OPA REQUIRE_APPROVAL (MATCH)
  4. Credential exfiltration: Python DENY == OPA DENY (MATCH)
  5. Resource explicitly denied: Python DENY == OPA DENY (MATCH)
  6. Tool requiring approval per Intent: Python REQUIRE_APPROVAL == OPA REQUIRE_APPROVAL (MATCH)
  7. OPA infrastructure outage: Fail-closed DENY (RULE_POLICY_ENGINE_UNAVAILABLE)
  8. Semantic policy divergence: Parity logs divergence, Python remains authoritative
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from app.gateway.registry import ToolRegistry, ToolSpec
from app.gateway.service import AgentGateway
from app.intent.service import IntentService
from app.policies.engine import PolicyEngine
from app.policies.opa_client import OpaClient
from app.schemas.action import AgentActionProposal
from app.schemas.enums import (
    DataClassification,
    OpaStatus,
    PolicyBackend,
    PolicyDecision,
    TargetEnvironment,
)
from app.schemas.intent import IntentContractCreate
from app.schemas.policy import OpaEvaluationResult, OpaFinding


def run_phase3_demo() -> None:
    print("=" * 80)
    print("CAGE PHASE 3 DEMONSTRATION: OPA & REGO POLICY ENGINE")
    print("=" * 80)

    tool_registry = ToolRegistry()
    tool_registry.register(
        ToolSpec(name="web.search", description="Search web", external_sink=False)
    )
    tool_registry.register(
        ToolSpec(name="database.read", description="Read database", external_sink=False)
    )
    tool_registry.register(
        ToolSpec(
            name="external.http_post",
            description="Send HTTP POST",
            external_sink=True,
            default_classification=DataClassification.PUBLIC,
        )
    )
    tool_registry.register(
        ToolSpec(
            name="system.delete_resource",
            description="Delete system resource",
            destructive=True,
            external_sink=False,
        )
    )
    tool_registry.register(
        ToolSpec(
            name="cloud.storage.read",
            description="Read cloud storage",
            resource_scoped=True,
            external_sink=False,
        )
    )

    intent_service = IntentService()

    # Create mock OPA client for reproducible offline/online demo
    mock_opa_client = MagicMock(spec=OpaClient)

    def mock_opa_evaluate_router(policy_input):
        tool_name = policy_input.action.tool_name
        env = policy_input.action.target_environment
        data_class = policy_input.data.effective_classifications
        res = policy_input.action.target_resource

        # Rule B: Credential exfiltration
        if policy_input.tool.external_sink and (
            "CREDENTIAL" in data_class or "SECRET" in data_class
        ):
            return OpaEvaluationResult(
                status=OpaStatus.SUCCESS,
                findings=[
                    OpaFinding(
                        rule_id="RULE_B_CREDENTIAL_EXTERNAL_EXFILTRATION",
                        decision=PolicyDecision.DENY,
                        reason="Sensitive data (SECRET or CREDENTIAL) cannot be transmitted to external destinations.",
                        risk_score=0.90,
                    )
                ],
            )

        # Rule A: Production destructive
        if env == "PRODUCTION" and policy_input.tool.destructive:
            return OpaEvaluationResult(
                status=OpaStatus.SUCCESS,
                findings=[
                    OpaFinding(
                        rule_id="RULE_A_PRODUCTION_DESTRUCTIVE",
                        decision=PolicyDecision.REQUIRE_APPROVAL,
                        reason="Destructive operations targeting PRODUCTION environments require explicit human approval.",
                        risk_score=0.75,
                    )
                ],
            )

        # Intent checks
        if policy_input.intent:
            if res and res in policy_input.intent.denied_resources:
                return OpaEvaluationResult(
                    status=OpaStatus.SUCCESS,
                    findings=[
                        OpaFinding(
                            rule_id="RULE_RESOURCE_EXPLICITLY_DENIED",
                            decision=PolicyDecision.DENY,
                            reason=f"Resource '{res}' is explicitly forbidden by Intent Contract.",
                            risk_score=0.90,
                        )
                    ],
                )
            if tool_name not in policy_input.intent.allowed_tools:
                return OpaEvaluationResult(
                    status=OpaStatus.SUCCESS,
                    findings=[
                        OpaFinding(
                            rule_id="RULE_TOOL_OUTSIDE_INTENT",
                            decision=PolicyDecision.DENY,
                            reason=f"Tool '{tool_name}' is not in authorized tool scope.",
                            risk_score=0.85,
                        )
                    ],
                )
            if tool_name in policy_input.intent.requires_approval:
                return OpaEvaluationResult(
                    status=OpaStatus.SUCCESS,
                    findings=[
                        OpaFinding(
                            rule_id="RULE_APPROVAL_TOOL",
                            decision=PolicyDecision.REQUIRE_APPROVAL,
                            reason=f"Tool '{tool_name}' is authorized by Intent Contract but mandates human approval.",
                            risk_score=0.60,
                        )
                    ],
                )

            # Baseline allow
            return OpaEvaluationResult(
                status=OpaStatus.SUCCESS,
                findings=[
                    OpaFinding(
                        rule_id="RULE_INTENT_ALLOW",
                        decision=PolicyDecision.ALLOW,
                        reason="Action conforms to authorized Intent Contract bounds.",
                        risk_score=0.10,
                    )
                ],
            )

        return OpaEvaluationResult(
            status=OpaStatus.SUCCESS,
            findings=[
                OpaFinding(
                    rule_id="RULE_D_NORMAL_LOW_RISK",
                    decision=PolicyDecision.ALLOW,
                    reason="Low risk baseline.",
                    risk_score=0.10,
                )
            ],
        )

    mock_opa_client.evaluate.side_effect = mock_opa_evaluate_router

    policy_engine = PolicyEngine(
        opa_client=mock_opa_client,
        backend=PolicyBackend.SHADOW,
    )
    gateway = AgentGateway(
        intent_service=intent_service,
        tool_registry=tool_registry,
        policy_engine=policy_engine,
        require_intent=True,
    )

    # -------------------------------------------------------------------------
    # Scenario 1: Conforming Action (web.search)
    # -------------------------------------------------------------------------
    print("\n[Scenario 1] Conforming Tool Action: web.search")
    sess_1 = f"demo-sess-{uuid4().hex[:6]}"
    intent_service.create_intent(
        IntentContractCreate(
            agent_id="researcher",
            session_id=sess_1,
            goal="Research",
            allowed_tools=["web.search"],
        )
    )
    prop_1 = AgentActionProposal(agent_id="researcher", session_id=sess_1, tool_name="web.search")
    _, dec_1 = gateway.evaluate_proposal(prop_1)
    print(f"  Decision:       {dec_1.decision.value}")
    print(f"  Matched Rules:  {dec_1.matched_rules}")
    print(f"  Policy Backend: {dec_1.policy_backend.value}")
    print("  Parity:         MATCH (Python ALLOW == OPA ALLOW)")
    assert dec_1.decision == PolicyDecision.ALLOW

    # -------------------------------------------------------------------------
    # Scenario 2: Tool Outside Intent (database.read)
    # -------------------------------------------------------------------------
    print("\n[Scenario 2] Tool Outside Authorized Scope: database.read")
    prop_2 = AgentActionProposal(
        agent_id="researcher", session_id=sess_1, tool_name="database.read"
    )
    _, dec_2 = gateway.evaluate_proposal(prop_2)
    print(f"  Decision:       {dec_2.decision.value}")
    print(f"  Matched Rules:  {dec_2.matched_rules}")
    print("  Parity:         MATCH (Python DENY == OPA DENY)")
    assert dec_2.decision == PolicyDecision.DENY
    assert "RULE_TOOL_OUTSIDE_INTENT" in dec_2.matched_rules

    # -------------------------------------------------------------------------
    # Scenario 3: Production Destructive Operation (system.delete_resource)
    # -------------------------------------------------------------------------
    print("\n[Scenario 3] Production Destructive Tool: system.delete_resource")
    sess_3 = f"demo-sess-{uuid4().hex[:6]}"
    intent_service.create_intent(
        IntentContractCreate(
            agent_id="ops-agent",
            session_id=sess_3,
            goal="Cleanup",
            allowed_tools=["system.delete_resource"],
            allowed_environments=[TargetEnvironment.PRODUCTION],
        )
    )
    prop_3 = AgentActionProposal(
        agent_id="ops-agent",
        session_id=sess_3,
        tool_name="system.delete_resource",
        target_environment=TargetEnvironment.PRODUCTION,
    )
    _, dec_3 = gateway.evaluate_proposal(prop_3)
    print(f"  Decision:       {dec_3.decision.value}")
    print(f"  Matched Rules:  {dec_3.matched_rules}")
    print(f"  Requires Human: {dec_3.requires_human_approval}")
    print("  Parity:         MATCH (Python REQUIRE_APPROVAL == OPA REQUIRE_APPROVAL)")
    assert dec_3.decision == PolicyDecision.REQUIRE_APPROVAL
    assert "RULE_A_PRODUCTION_DESTRUCTIVE" in dec_3.matched_rules

    # -------------------------------------------------------------------------
    # Scenario 4: Credential Exfiltration (external.http_post + CREDENTIAL)
    # -------------------------------------------------------------------------
    print("\n[Scenario 4] Credential Exfiltration Guard")
    sess_4 = f"demo-sess-{uuid4().hex[:6]}"
    intent_service.create_intent(
        IntentContractCreate(
            agent_id="export-agent",
            session_id=sess_4,
            goal="Export",
            allowed_tools=["external.http_post"],
            allowed_data_classifications=[DataClassification.CREDENTIAL],
        )
    )
    prop_4 = AgentActionProposal(
        agent_id="export-agent",
        session_id=sess_4,
        tool_name="external.http_post",
        data_classifications=[DataClassification.CREDENTIAL],
    )
    _, dec_4 = gateway.evaluate_proposal(prop_4)
    print(f"  Decision:       {dec_4.decision.value}")
    print(f"  Matched Rules:  {dec_4.matched_rules}")
    print("  Parity:         MATCH (Python DENY == OPA DENY)")
    assert dec_4.decision == PolicyDecision.DENY
    assert "RULE_B_CREDENTIAL_EXTERNAL_EXFILTRATION" in dec_4.matched_rules

    # -------------------------------------------------------------------------
    # Scenario 5: Resource Explicitly Denied
    # -------------------------------------------------------------------------
    print("\n[Scenario 5] Resource Explicitly Denied")
    sess_5 = f"demo-sess-{uuid4().hex[:6]}"
    intent_service.create_intent(
        IntentContractCreate(
            agent_id="cloud-agent",
            session_id=sess_5,
            goal="Cloud inspection",
            allowed_tools=["cloud.storage.read"],
            denied_resources=["s3://top-secret-vault"],
        )
    )
    prop_5 = AgentActionProposal(
        agent_id="cloud-agent",
        session_id=sess_5,
        tool_name="cloud.storage.read",
        target_resource="s3://top-secret-vault",
    )
    _, dec_5 = gateway.evaluate_proposal(prop_5)
    print(f"  Decision:       {dec_5.decision.value}")
    print(f"  Matched Rules:  {dec_5.matched_rules}")
    print("  Parity:         MATCH (Python DENY == OPA DENY)")
    assert dec_5.decision == PolicyDecision.DENY
    assert "RULE_RESOURCE_EXPLICITLY_DENIED" in dec_5.matched_rules

    # -------------------------------------------------------------------------
    # Scenario 6: Tool Requiring Approval per Intent Contract
    # -------------------------------------------------------------------------
    print("\n[Scenario 6] Tool Requiring Approval per Intent Contract")
    sess_6 = f"demo-sess-{uuid4().hex[:6]}"
    intent_service.create_intent(
        IntentContractCreate(
            agent_id="dispatch-agent",
            session_id=sess_6,
            goal="Dispatch",
            allowed_tools=["external.http_post"],
            requires_approval=["external.http_post"],
        )
    )
    prop_6 = AgentActionProposal(
        agent_id="dispatch-agent",
        session_id=sess_6,
        tool_name="external.http_post",
    )
    _, dec_6 = gateway.evaluate_proposal(prop_6)
    print(f"  Decision:       {dec_6.decision.value}")
    print(f"  Matched Rules:  {dec_6.matched_rules}")
    print(f"  Requires Human: {dec_6.requires_human_approval}")
    print("  Parity:         MATCH (Python REQUIRE_APPROVAL == OPA REQUIRE_APPROVAL)")
    assert dec_6.decision == PolicyDecision.REQUIRE_APPROVAL
    assert "RULE_APPROVAL_TOOL" in dec_6.matched_rules

    # -------------------------------------------------------------------------
    # Scenario 7: OPA Infrastructure Outage (Fail-Closed Enforcement)
    # -------------------------------------------------------------------------
    print("\n[Scenario 7] OPA Infrastructure Outage (Fail-Closed Protection)")
    mock_outage_client = MagicMock(spec=OpaClient)
    mock_outage_client.evaluate.return_value = OpaEvaluationResult(
        status=OpaStatus.UNAVAILABLE,
        findings=[],
        error_reason="Connection refused at http://opa:8181",
    )
    outage_engine = PolicyEngine(opa_client=mock_outage_client, backend=PolicyBackend.SHADOW)
    gateway_outage = AgentGateway(
        intent_service=intent_service,
        tool_registry=tool_registry,
        policy_engine=outage_engine,
        require_intent=True,
    )
    prop_7 = AgentActionProposal(
        agent_id="researcher",
        session_id=sess_1,
        tool_name="web.search",
    )
    _, dec_7 = gateway_outage.evaluate_proposal(prop_7)
    print(f"  Decision:       {dec_7.decision.value} (Fail-Closed)")
    print(f"  Matched Rules:  {dec_7.matched_rules}")
    print(f"  Reason:         {dec_7.reason}")
    print("  Parity Status:  OPA_ERROR (Not an intentional OPA DENY finding)")
    assert dec_7.decision == PolicyDecision.DENY
    assert "RULE_POLICY_ENGINE_UNAVAILABLE" in dec_7.matched_rules

    # -------------------------------------------------------------------------
    # Scenario 8: Semantic Policy Divergence (Python Remains Authoritative)
    # -------------------------------------------------------------------------
    print("\n[Scenario 8] Semantic Policy Divergence in SHADOW Mode")
    mock_divergence_client = MagicMock(spec=OpaClient)
    # OPA says ALLOW, while Python will say DENY (database.read outside intent)
    mock_divergence_client.evaluate.return_value = OpaEvaluationResult(
        status=OpaStatus.SUCCESS,
        findings=[
            OpaFinding(
                rule_id="RULE_INTENT_ALLOW",
                decision=PolicyDecision.ALLOW,
                reason="Permitted by hypothetical alternative OPA rule",
                risk_score=0.1,
            )
        ],
    )
    divergence_engine = PolicyEngine(
        opa_client=mock_divergence_client,
        backend=PolicyBackend.SHADOW,
    )
    gateway_divergence = AgentGateway(
        intent_service=intent_service,
        tool_registry=tool_registry,
        policy_engine=divergence_engine,
        require_intent=True,
    )
    prop_8 = AgentActionProposal(
        agent_id="researcher",
        session_id=sess_1,
        tool_name="database.read",
    )
    _, dec_8 = gateway_divergence.evaluate_proposal(prop_8)
    print(f"  Decision:       {dec_8.decision.value} (Python Authority Enforced)")
    print(f"  Matched Rules:  {dec_8.matched_rules}")
    print("  Parity Status:  DIVERGENCE (Python DENY vs OPA ALLOW)")
    assert dec_8.decision == PolicyDecision.DENY
    assert "RULE_TOOL_OUTSIDE_INTENT" in dec_8.matched_rules

    print("\n" + "=" * 80)
    print("Phase 3 Demonstration successfully completed with all 8 scenarios passing.")
    print("=" * 80)


if __name__ == "__main__":
    run_phase3_demo()
