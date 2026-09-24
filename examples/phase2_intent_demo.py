"""Phase 2 Demonstration: Task-Scoped Intent Contracts and Authority Boundaries.

Demonstrates:
Scenario 1: Benign action within intent scope -> ALLOW
Scenario 2: Tool outside authorized intent scope -> DENY (RULE_TOOL_OUTSIDE_INTENT)
Scenario 3: Tool requires human approval per intent contract -> REQUIRE_APPROVAL (RULE_APPROVAL_TOOL)
Scenario 4: Expired Intent Contract -> DENY (RULE_INTENT_EXPIRED)
Scenario 5: Revoked Intent Contract -> DENY (RULE_INTENT_REVOKED)
Scenario 6: Tool execution budget quota exhaustion -> DENY (RULE_TOOL_BUDGET_EXCEEDED)
Scenario 7: Intent allows tool, but action contains CREDENTIAL data -> DENY (Runtime Security Overrides Intent)
"""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from app.gateway.service import AgentGateway
from app.graph.causal_graph import SessionGraphManager
from app.intent.service import IntentService
from app.schemas.action import AgentActionProposal
from app.schemas.enums import (
    DataClassification,
    PolicyDecision,
    TargetEnvironment,
)
from app.schemas.intent import IntentContractCreate


def run_demo() -> None:
    session_id = f"phase2-demo-{uuid4().hex[:8]}"
    intent_service = IntentService()
    graph_manager = SessionGraphManager()
    gateway = AgentGateway(
        intent_service=intent_service,
        graph_manager=graph_manager,
        require_intent=True,
    )

    print("=" * 80)
    print(f"CAGE PHASE 2 DEMONSTRATION: INTENT CONTRACTS (Session: {session_id})")
    print("=" * 80)

    # -------------------------------------------------------------------------
    # Scenario 1: Action Conforming to Intent Contract
    # -------------------------------------------------------------------------
    print("\n[Scenario 1] Action Conforming to Intent Contract")
    contract_create = IntentContractCreate(
        user_id="alice@example.com",
        agent_id="researcher-01",
        session_id=session_id,
        goal="Research public information about Company A",
        allowed_tools=["web.search", "file.write"],
        denied_tools=["system.delete_resource"],
        allowed_environments=[TargetEnvironment.LOCAL, TargetEnvironment.DEVELOPMENT],
        allowed_data_classifications=[DataClassification.PUBLIC],
        maximum_tool_calls=10,
    )
    contract_1 = intent_service.create_intent(contract_create)
    print(f"  Created Intent Contract: {contract_1.intent_id}")
    print(f"  Allowed Tools: {sorted(contract_1.allowed_tools)}")

    proposal_1 = AgentActionProposal(
        agent_id="researcher-01",
        session_id=session_id,
        tool_name="web.search",
        tool_arguments={"query": "Company A products"},
        target_environment=TargetEnvironment.LOCAL,
        data_classifications=[DataClassification.PUBLIC],
    )
    action_1, decision_1 = gateway.evaluate_proposal(proposal_1)
    print(f"  Decision: {decision_1.decision.value}")
    print(f"  Reason:   {decision_1.reason}")
    print(f"  Matched:  {decision_1.matched_rules}")
    assert decision_1.decision == PolicyDecision.ALLOW, "Scenario 1 must be ALLOWed"

    # -------------------------------------------------------------------------
    # Scenario 2: Tool Outside Authorized Intent Scope
    # -------------------------------------------------------------------------
    print("\n[Scenario 2] Tool Outside Authorized Intent Scope")
    print("Agent requests: database.read (not in allowed_tools)")
    proposal_2 = AgentActionProposal(
        agent_id="researcher-01",
        session_id=session_id,
        tool_name="database.read",
        tool_arguments={"table": "internal_records"},
        target_environment=TargetEnvironment.DEVELOPMENT,
    )
    action_2, decision_2 = gateway.evaluate_proposal(proposal_2)
    print(f"  Decision: {decision_2.decision.value}")
    print(f"  Reason:   {decision_2.reason}")
    print(f"  Matched:  {decision_2.matched_rules}")
    assert decision_2.decision == PolicyDecision.DENY, "Scenario 2 must be DENIED"
    assert "RULE_TOOL_OUTSIDE_INTENT" in decision_2.matched_rules

    # -------------------------------------------------------------------------
    # Scenario 3: Tool Permitted but Requiring Approval per Intent Contract
    # -------------------------------------------------------------------------
    print("\n[Scenario 3] Tool Requiring Approval per Intent Contract")
    sess_approval = f"approval-sess-{uuid4().hex[:6]}"
    _ = intent_service.create_intent(
        IntentContractCreate(
            agent_id="dispatch-agent",
            session_id=sess_approval,
            goal="Notify external partner",
            allowed_tools=["web.search", "external.http_post"],
            requires_approval=["external.http_post"],
            allowed_data_classifications=[DataClassification.PUBLIC],
        )
    )
    proposal_3 = AgentActionProposal(
        agent_id="dispatch-agent",
        session_id=sess_approval,
        tool_name="external.http_post",
        tool_arguments={"url": "https://partner.example/webhook"},
        data_classifications=[DataClassification.PUBLIC],
    )
    _, decision_3 = gateway.evaluate_proposal(proposal_3)
    print(f"  Decision: {decision_3.decision.value}")
    print(f"  Reason:   {decision_3.reason}")
    print(f"  Matched:  {decision_3.matched_rules}")
    print(f"  Requires Human Approval: {decision_3.requires_human_approval}")
    assert decision_3.decision == PolicyDecision.REQUIRE_APPROVAL
    assert "RULE_APPROVAL_TOOL" in decision_3.matched_rules

    # -------------------------------------------------------------------------
    # Scenario 4: Expired Intent Contract
    # -------------------------------------------------------------------------
    print("\n[Scenario 4] Expired Intent Contract")
    sess_expired = f"expired-sess-{uuid4().hex[:6]}"
    past_time = datetime.now(UTC) - timedelta(minutes=10)
    intent_service.create_intent(
        IntentContractCreate(
            agent_id="timed-agent",
            session_id=sess_expired,
            goal="Short-lived research task",
            allowed_tools=["web.search"],
            expires_at=past_time,
        )
    )
    proposal_4 = AgentActionProposal(
        agent_id="timed-agent",
        session_id=sess_expired,
        tool_name="web.search",
        tool_arguments={"query": "test query"},
    )
    _, decision_4 = gateway.evaluate_proposal(proposal_4)
    print(f"  Decision: {decision_4.decision.value}")
    print(f"  Reason:   {decision_4.reason}")
    print(f"  Matched:  {decision_4.matched_rules}")
    assert decision_4.decision == PolicyDecision.DENY
    assert "RULE_INTENT_EXPIRED" in decision_4.matched_rules

    # -------------------------------------------------------------------------
    # Scenario 5: Revoked Intent Contract
    # -------------------------------------------------------------------------
    print("\n[Scenario 5] Revoked Intent Contract")
    sess_revoked = f"revoked-sess-{uuid4().hex[:6]}"
    contract_revoked = intent_service.create_intent(
        IntentContractCreate(
            agent_id="revoked-agent",
            session_id=sess_revoked,
            goal="Aborted investigation",
            allowed_tools=["web.search"],
        )
    )
    # Revoke contract through control plane
    intent_service.revoke_intent(
        contract_revoked.intent_id, reason="Security incident initiated revocation"
    )
    print(f"  Contract {contract_revoked.intent_id} revoked by control plane.")

    proposal_5 = AgentActionProposal(
        agent_id="revoked-agent",
        session_id=sess_revoked,
        tool_name="web.search",
        tool_arguments={"query": "investigate"},
    )
    _, decision_5 = gateway.evaluate_proposal(proposal_5)
    print(f"  Decision: {decision_5.decision.value}")
    print(f"  Reason:   {decision_5.reason}")
    print(f"  Matched:  {decision_5.matched_rules}")
    assert decision_5.decision == PolicyDecision.DENY
    assert "RULE_INTENT_REVOKED" in decision_5.matched_rules

    # -------------------------------------------------------------------------
    # Scenario 6: Tool Execution Budget Quota Exhaustion
    # -------------------------------------------------------------------------
    print("\n[Scenario 6] Tool Execution Budget Quota Enforcement")
    sess_budget = f"budget-sess-{uuid4().hex[:6]}"
    contract_budget = intent_service.create_intent(
        IntentContractCreate(
            agent_id="budget-agent",
            session_id=sess_budget,
            goal="Rate limited batch search",
            allowed_tools=["web.search"],
            maximum_tool_calls=3,
        )
    )
    print(f"  Contract maximum_tool_calls: {contract_budget.maximum_tool_calls}")

    # Execute 3 calls within quota
    for i in range(1, 4):
        p = AgentActionProposal(
            agent_id="budget-agent",
            session_id=sess_budget,
            tool_name="web.search",
            tool_arguments={"query": f"search item {i}"},
        )
        _, dec = gateway.evaluate_proposal(p)
        print(f"  Call {i}: Decision = {dec.decision.value} (Quota reserved)")
        assert dec.decision == PolicyDecision.ALLOW

    # 4th call exceeds quota
    p_exceed = AgentActionProposal(
        agent_id="budget-agent",
        session_id=sess_budget,
        tool_name="web.search",
        tool_arguments={"query": "search item 4 (overflow)"},
    )
    _, dec_exceed = gateway.evaluate_proposal(p_exceed)
    print(f"  Call 4: Decision = {dec_exceed.decision.value}")
    print(f"  Reason: {dec_exceed.reason}")
    print(f"  Matched: {dec_exceed.matched_rules}")
    assert dec_exceed.decision == PolicyDecision.DENY
    assert "RULE_TOOL_BUDGET_EXCEEDED" in dec_exceed.matched_rules

    # -------------------------------------------------------------------------
    # Scenario 7: Intent Allows Tool, but Runtime Policy Denies Credential Exfiltration
    # -------------------------------------------------------------------------
    print("\n[Scenario 7] Intent Allows Tool, but Runtime Policy Denies Exfiltration")
    sess_runtime = f"runtime-sess-{uuid4().hex[:6]}"
    intent_service.create_intent(
        IntentContractCreate(
            agent_id="exfil-test-agent",
            session_id=sess_runtime,
            goal="Data export task",
            allowed_tools=["external.http_post"],
            allowed_data_classifications=[DataClassification.PUBLIC, DataClassification.CREDENTIAL],
        )
    )
    # The intent contract author erroneously whitelisted CREDENTIAL data, but
    # CAGE runtime security policy RULE_B unconditionally forbids CREDENTIAL data to external sinks!
    proposal_7 = AgentActionProposal(
        agent_id="exfil-test-agent",
        session_id=sess_runtime,
        tool_name="external.http_post",
        tool_arguments={"url": "https://external.sink.example/dump"},
        data_classifications=[DataClassification.CREDENTIAL],
    )
    _, decision_7 = gateway.evaluate_proposal(proposal_7)
    print(f"  Decision: {decision_7.decision.value}")
    print(f"  Reason:   {decision_7.reason}")
    print(f"  Matched:  {decision_7.matched_rules}")
    # Runtime security overrides intent allowance!
    assert decision_7.decision == PolicyDecision.DENY
    assert "RULE_B_CREDENTIAL_EXTERNAL_EXFILTRATION" in decision_7.matched_rules

    # -------------------------------------------------------------------------
    # Causal Graph Inspection
    # -------------------------------------------------------------------------
    print("\n" + "=" * 80)
    print("SESSION CAUSAL EXECUTION GRAPH STATE (Session 1)")
    print("=" * 80)
    graph = graph_manager.get(session_id)
    assert graph is not None
    graph_data = graph.get_session_graph()
    print(f"Nodes recorded: {graph_data['node_count']}")
    print(f"Causal edges:   {graph_data['edge_count']}")
    print(f"Is valid DAG:   {graph_data['is_dag']}")
    print("\nNodes in Graph:")
    for n in graph_data["nodes"]:
        if n["node_type"] == "intent":
            print(f"  - [INTENT] ID: {n['id'][:8]}... Goal: '{n.get('goal')}'")
        else:
            print(
                f"  - [ACTION] ID: {n['id'][:8]}... Tool: {n.get('tool_name'):<18} "
                f"Verdict: {str(n.get('policy_result')):<16} Status: {n.get('execution_status')}"
            )

    print("\nCausal Edges (Governance & Causes):")
    for edge in graph_data["edges"]:
        print(f"  - {edge['source'][:8]}... --[{edge['relation']}]--> {edge['target'][:8]}...")

    print("\nPhase 2 Demonstration successfully completed with all 7 scenarios passing.")


if __name__ == "__main__":
    run_demo()
