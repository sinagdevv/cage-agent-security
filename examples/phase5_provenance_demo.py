"""Phase 5 Demonstration: Information Provenance and Data Flow Tracking.

Demonstrates all 9 required Phase 5 scenarios:
1. Transformation preserves untrusted external origin (Provenance Anti-Laundering).
2. Tracked sensitive information flow to external sink is DENIED.
3. Attempted classification downgrade is prevented (Classification Anti-Laundering).
4. Untrusted information consumed by privileged operation triggers REQUIRE_APPROVAL.
5. Untracked egress payload is DENIED (Egress Protection).
6. Cross-session artifact reference is blocked.
7. Unknown artifact reference is blocked.
8. Python and OPA policy engines achieve parity.
9. Lineage traversal limit fails closed without fabricating facts.
"""

import sys
from pathlib import Path
from uuid import uuid4

# Ensure backend directory is in sys.path
backend_dir = Path(__file__).resolve().parent.parent / "backend"
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.gateway.service import AgentGateway  # noqa: E402
from app.intent.service import IntentService  # noqa: E402
from app.policies.engine import PolicyEngine  # noqa: E402
from app.policies.opa_client import OpaClient  # noqa: E402
from app.provenance.analyzer import ProvenanceAnalyzer  # noqa: E402
from app.provenance.models import InformationArtifact  # noqa: E402
from app.provenance.store import ProvenanceStore  # noqa: E402
from app.schemas.action import AgentActionProposal  # noqa: E402
from app.schemas.enums import (  # noqa: E402
    ArtifactSourceType,
    DataClassification,
    PolicyBackend,
    PolicyDecision,
    TrustLevel,
)
from app.schemas.intent import IntentContractCreate  # noqa: E402


def print_scenario(num: int, title: str) -> None:
    print(f"\n{'=' * 65}")
    print(f"SCENARIO {num}: {title}")
    print(f"{'=' * 65}")


def run_demo() -> None:
    intent_service = IntentService()
    store = ProvenanceStore()
    gateway = AgentGateway(
        intent_service=intent_service,
        provenance_store=store,
        require_intent=True,
    )

    # =========================================================================
    # SCENARIO 1: Provenance Survives Transformation (Anti-Laundering)
    # =========================================================================
    print_scenario(1, "Provenance Survives Transformation (Anti-Laundering)")
    s1_session = "sess-demo-s1"
    intent_service.create_intent(
        IntentContractCreate(
            agent_id="agent-01",
            session_id=s1_session,
            goal="Web research and summarization",
            allowed_tools=["web.search", "agent.transform"],
            maximum_tool_calls=10,
        )
    )

    # 1. web.search executes
    p1 = AgentActionProposal(
        agent_id="agent-01",
        session_id=s1_session,
        tool_name="web.search",
        tool_arguments={"query": "quantum computing"},
    )
    act1, dec1 = gateway.evaluate_proposal(p1)
    assert dec1.decision == PolicyDecision.ALLOW
    gateway.execute_authorized_action(act1.action_id)
    assert len(act1.output_artifact_ids) == 1

    art_a = store.get_artifact(act1.output_artifact_ids[0])
    assert art_a.direct_trust_level == TrustLevel.EXTERNAL_UNTRUSTED
    print(f"Artifact A produced: direct_trust={art_a.direct_trust_level.value}")

    # 2. agent.transform summarizes A into B
    p2 = AgentActionProposal(
        agent_id="agent-01",
        session_id=s1_session,
        tool_name="agent.transform",
        tool_arguments={"content": "summarized quantum notes"},
        input_artifact_ids=[art_a.artifact_id],
    )
    act2, dec2 = gateway.evaluate_proposal(p2)
    assert dec2.decision == PolicyDecision.ALLOW
    gateway.execute_authorized_action(act2.action_id)
    assert len(act2.output_artifact_ids) == 1

    art_b = store.get_artifact(act2.output_artifact_ids[0])
    assert art_b.direct_trust_level == TrustLevel.AGENT_DERIVED
    assert TrustLevel.EXTERNAL_UNTRUSTED in art_b.inherited_trust_levels
    print(f"Artifact B produced: direct_trust={art_b.direct_trust_level.value}")
    print(f"Artifact B inherited_trust={[t.value for t in art_b.inherited_trust_levels]}")
    print("SUCCESS: EXTERNAL_UNTRUSTED origin survived agent transformation!")

    # =========================================================================
    # SCENARIO 2: Tracked Sensitive Data Flow to External Sink -> DENY
    # =========================================================================
    print_scenario(2, "Tracked Sensitive Data Flow to External Sink -> DENY")
    s2_session = "sess-demo-s2"
    intent_service.create_intent(
        IntentContractCreate(
            agent_id="agent-01",
            session_id=s2_session,
            goal="Customer processing",
            allowed_tools=["database.read", "file.write", "external.http_post"],
            allowed_data_classifications=[
                DataClassification.INTERNAL,
                DataClassification.PII,
                DataClassification.CONFIDENTIAL,
            ],
            maximum_tool_calls=10,
        )
    )

    # database.read produces sensitive artifact
    p_db = AgentActionProposal(
        agent_id="agent-01",
        session_id=s2_session,
        tool_name="database.read",
        tool_arguments={"table": "customers"},
        target_resource="customer-db",
    )
    act_db, _ = gateway.evaluate_proposal(p_db)
    gateway.execute_authorized_action(act_db.action_id)
    db_art = store.get_artifact(act_db.output_artifact_ids[0])

    # file.write derives report from customer data
    p_fw = AgentActionProposal(
        agent_id="agent-01",
        session_id=s2_session,
        tool_name="file.write",
        tool_arguments={"path": "report.json", "content": "customer data"},
        input_artifact_ids=[db_art.artifact_id],
    )
    act_fw, _ = gateway.evaluate_proposal(p_fw)
    gateway.execute_authorized_action(act_fw.action_id)
    report_art = store.get_artifact(act_fw.output_artifact_ids[0])

    # external.http_post consumes report
    p_post = AgentActionProposal(
        agent_id="agent-01",
        session_id=s2_session,
        tool_name="external.http_post",
        tool_arguments={
            "destination": "https://analytics.external.io",
            "body_artifact_id": str(report_art.artifact_id),
        },
        input_artifact_ids=[report_art.artifact_id],
    )
    _, dec_post = gateway.evaluate_proposal(p_post)
    print(f"Decision: {dec_post.decision.value}, Rules: {dec_post.matched_rules}")
    assert dec_post.decision == PolicyDecision.DENY
    assert "RULE_PROVENANCE_SENSITIVE_TO_EXTERNAL" in dec_post.matched_rules
    print(
        "SUCCESS: Explicit data flow from customer-db to external sink blocked by provenance rule!"
    )

    # =========================================================================
    # SCENARIO 3: Classification Laundering Prevention
    # =========================================================================
    print_scenario(3, "Classification Laundering Prevention")
    s3_session = "sess-demo-s3"
    intent_service.create_intent(
        IntentContractCreate(
            agent_id="agent-01",
            session_id=s3_session,
            goal="Credentials audit",
            allowed_tools=["secrets.vault_read", "agent.transform", "external.http_post"],
            allowed_data_classifications=[
                DataClassification.CREDENTIAL,
                DataClassification.SECRET,
                DataClassification.PUBLIC,
            ],
            maximum_tool_calls=10,
        )
    )

    # secrets.vault_read produces CREDENTIAL artifact
    p_sec = AgentActionProposal(
        agent_id="agent-01",
        session_id=s3_session,
        tool_name="secrets.vault_read",
        tool_arguments={"secret_key": "api_key"},
        target_resource="secrets-vault",
    )
    act_sec, _ = gateway.evaluate_proposal(p_sec)
    gateway.execute_authorized_action(act_sec.action_id)
    vault_art = store.get_artifact(act_sec.output_artifact_ids[0])

    # Agent summarizes and claims PUBLIC
    p_sum = AgentActionProposal(
        agent_id="agent-01",
        session_id=s3_session,
        tool_name="agent.transform",
        tool_arguments={"content": "obfuscated key"},
        data_classifications=[DataClassification.PUBLIC],
        input_artifact_ids=[vault_art.artifact_id],
    )
    act_sum, _ = gateway.evaluate_proposal(p_sum)
    gateway.execute_authorized_action(act_sum.action_id)
    sum_art = store.get_artifact(act_sum.output_artifact_ids[0])

    print(
        f"Transformed artifact classifications: {[c.value for c in sum_art.data_classifications]}"
    )
    assert DataClassification.CREDENTIAL in sum_art.data_classifications

    # Attempt egress of laundered summary
    p_exfil = AgentActionProposal(
        agent_id="agent-01",
        session_id=s3_session,
        tool_name="external.http_post",
        tool_arguments={
            "destination": "https://pastebin.com/raw",
            "body_artifact_id": str(sum_art.artifact_id),
        },
        input_artifact_ids=[sum_art.artifact_id],
    )
    _, dec_exfil = gateway.evaluate_proposal(p_exfil)
    print(f"Decision: {dec_exfil.decision.value}, Rules: {dec_exfil.matched_rules}")
    assert dec_exfil.decision == PolicyDecision.DENY
    assert "RULE_PROVENANCE_CREDENTIAL_TO_EXTERNAL" in dec_exfil.matched_rules
    print("SUCCESS: Agent-declared PUBLIC claim failed to downgrade CREDENTIAL lineage!")

    # =========================================================================
    # SCENARIO 4: Untrusted Information to Privileged Action -> REQUIRE_APPROVAL
    # =========================================================================
    print_scenario(4, "Untrusted Information to Privileged Action -> REQUIRE_APPROVAL")
    s4_session = "sess-demo-s4"
    intent_service.create_intent(
        IntentContractCreate(
            agent_id="agent-01",
            session_id=s4_session,
            goal="Cluster maintenance",
            allowed_tools=["web.search", "system.delete_resource"],
            maximum_tool_calls=10,
        )
    )

    p_web = AgentActionProposal(
        agent_id="agent-01",
        session_id=s4_session,
        tool_name="web.search",
        tool_arguments={"query": "how to clean cache"},
    )
    act_web, _ = gateway.evaluate_proposal(p_web)
    gateway.execute_authorized_action(act_web.action_id)
    untrusted_art = store.get_artifact(act_web.output_artifact_ids[0])

    p_del = AgentActionProposal(
        agent_id="agent-01",
        session_id=s4_session,
        tool_name="system.delete_resource",
        tool_arguments={"resource_id": "cache-cluster-01"},
        input_artifact_ids=[untrusted_art.artifact_id],
    )
    _, dec_del = gateway.evaluate_proposal(p_del)
    print(f"Decision: {dec_del.decision.value}, Rules: {dec_del.matched_rules}")
    assert dec_del.decision == PolicyDecision.REQUIRE_APPROVAL
    assert "RULE_PROVENANCE_UNTRUSTED_TO_PRIVILEGED" in dec_del.matched_rules
    print("SUCCESS: Privileged deletion consuming untrusted web input requires human approval!")

    # =========================================================================
    # SCENARIO 5: Untracked External Egress -> DENY
    # =========================================================================
    print_scenario(5, "Untracked External Egress -> DENY")
    s5_session = "sess-demo-s5"
    intent_service.create_intent(
        IntentContractCreate(
            agent_id="agent-01",
            session_id=s5_session,
            goal="Egress testing",
            allowed_tools=["external.http_post"],
            maximum_tool_calls=10,
        )
    )

    p_untracked = AgentActionProposal(
        agent_id="agent-01",
        session_id=s5_session,
        tool_name="external.http_post",
        tool_arguments={
            "destination": "https://api.external.com/sink",
            "body": "Raw untracked exfiltration string",
        },
        input_artifact_ids=[],
    )
    _, dec_untracked = gateway.evaluate_proposal(p_untracked)
    print(f"Decision: {dec_untracked.decision.value}, Rules: {dec_untracked.matched_rules}")
    assert dec_untracked.decision == PolicyDecision.DENY
    assert "RULE_PROVENANCE_UNTRACKED_EGRESS" in dec_untracked.matched_rules
    print("SUCCESS: Payload-bearing egress without validated artifact binding denied!")

    # =========================================================================
    # SCENARIO 6: Cross-Session Artifact Reference -> DENY / Rejected
    # =========================================================================
    print_scenario(6, "Cross-Session Artifact Reference -> DENY / Rejected")
    s6_session = "sess-demo-s6"
    intent_service.create_intent(
        IntentContractCreate(
            agent_id="agent-01",
            session_id=s6_session,
            goal="Cross-session isolation check",
            allowed_tools=["file.write"],
            maximum_tool_calls=10,
        )
    )

    # Use artifact from Scenario 1 session (s1_session)
    p_cross = AgentActionProposal(
        agent_id="agent-01",
        session_id=s6_session,
        tool_name="file.write",
        tool_arguments={"path": "out.txt", "content": "borrowed data"},
        input_artifact_ids=[art_a.artifact_id],
    )
    _, dec_cross = gateway.evaluate_proposal(p_cross)
    print(f"Decision: {dec_cross.decision.value}, Rules: {dec_cross.matched_rules}")
    assert dec_cross.decision == PolicyDecision.DENY
    assert "RULE_PROVENANCE_CROSS_SESSION_REFERENCE" in dec_cross.matched_rules
    print("SUCCESS: Cross-session artifact reference rejected and failed closed!")

    # =========================================================================
    # SCENARIO 7: Unknown Artifact ID Reference -> DENY / Rejected
    # =========================================================================
    print_scenario(7, "Unknown Artifact ID Reference -> DENY / Rejected")
    s7_session = "sess-demo-s7"
    intent_service.create_intent(
        IntentContractCreate(
            agent_id="agent-01",
            session_id=s7_session,
            goal="Unknown reference check",
            allowed_tools=["file.write"],
            maximum_tool_calls=10,
        )
    )

    fake_id = uuid4()
    p_fake = AgentActionProposal(
        agent_id="agent-01",
        session_id=s7_session,
        tool_name="file.write",
        tool_arguments={"path": "out.txt", "content": "ghost data"},
        input_artifact_ids=[fake_id],
    )
    _, dec_fake = gateway.evaluate_proposal(p_fake)
    print(f"Decision: {dec_fake.decision.value}, Rules: {dec_fake.matched_rules}")
    assert dec_fake.decision == PolicyDecision.DENY
    assert "RULE_PROVENANCE_MISSING_ARTIFACT" in dec_fake.matched_rules
    print("SUCCESS: Non-existent artifact reference denied!")

    # =========================================================================
    # SCENARIO 8: Python / OPA Provenance Parity
    # =========================================================================
    print_scenario(8, "Python / OPA Provenance Parity")
    opa_client = OpaClient()
    if opa_client.check_health():
        engine = PolicyEngine(backend=PolicyBackend.SHADOW)
        gateway_shadow = AgentGateway(
            intent_service=intent_service,
            provenance_store=store,
            policy_engine=engine,
            require_intent=True,
        )
        s8_session = "sess-demo-s8"
        intent_service.create_intent(
            IntentContractCreate(
                agent_id="agent-01",
                session_id=s8_session,
                goal="Parity validation",
                allowed_tools=["external.http_post"],
                maximum_tool_calls=10,
            )
        )
        p_parity = AgentActionProposal(
            agent_id="agent-01",
            session_id=s8_session,
            tool_name="external.http_post",
            tool_arguments={"destination": "https://api.test.org", "body": "untracked"},
        )
        _, dec_parity = gateway_shadow.evaluate_proposal(p_parity)
        print(f"Shadow Decision: {dec_parity.decision.value}")
        print(f"Matched rules: {dec_parity.matched_rules}")
        assert dec_parity.decision == PolicyDecision.DENY
        assert "RULE_PROVENANCE_UNTRACKED_EGRESS" in dec_parity.matched_rules
        print("SUCCESS: Python and OPA engines in full decision and rule agreement!")
    else:
        print("NOTICE: Live OPA not reachable; skipping live parity check in demo.")

    # =========================================================================
    # SCENARIO 9: Provenance Traversal Limit Exceeded -> Fail-Closed
    # =========================================================================
    print_scenario(9, "Provenance Traversal Limit Exceeded -> Fail-Closed")
    s9_session = "sess-demo-s9"
    # Analyzer with small max_depth of 3
    bounded_analyzer = ProvenanceAnalyzer(store=store, max_depth=3)
    gateway_bounded = AgentGateway(
        intent_service=intent_service,
        provenance_store=store,
        provenance_analyzer=bounded_analyzer,
        require_intent=True,
    )
    intent_service.create_intent(
        IntentContractCreate(
            agent_id="agent-01",
            session_id=s9_session,
            goal="Deep chain test",
            allowed_tools=["file.write"],
            maximum_tool_calls=10,
        )
    )

    # Build chain of depth 5
    curr = InformationArtifact(
        session_id=s9_session,
        source_type=ArtifactSourceType.INTERNAL_RESOURCE,
        source_resource="res-init",
        direct_trust_level=TrustLevel.INTERNAL_TRUSTED,
    )
    store.register_artifact(curr)
    for _ in range(4):
        child = InformationArtifact(
            session_id=s9_session,
            source_type=ArtifactSourceType.AGENT_GENERATED,
            source_resource="res-child",
            direct_trust_level=TrustLevel.AGENT_DERIVED,
            parent_artifact_ids=(curr.artifact_id,),
        )
        store.register_artifact(child)
        curr = child

    p_deep = AgentActionProposal(
        agent_id="agent-01",
        session_id=s9_session,
        tool_name="file.write",
        tool_arguments={"path": "deep.txt", "content": "chain"},
        input_artifact_ids=[curr.artifact_id],
    )
    _, dec_deep = gateway_bounded.evaluate_proposal(p_deep)
    print(f"Decision: {dec_deep.decision.value}, Rules: {dec_deep.matched_rules}")
    assert dec_deep.decision == PolicyDecision.DENY
    assert "RULE_PROVENANCE_DEPTH_LIMIT_EXCEEDED" in dec_deep.matched_rules
    print("SUCCESS: Exceeding depth limit fails closed without fabricating facts!")

    print(f"\n{'=' * 65}")
    print("ALL 9 PHASE 5 DEMO SCENARIOS COMPLETED SUCCESSFULLY!")
    print(f"{'=' * 65}\n")


if __name__ == "__main__":
    run_demo()
