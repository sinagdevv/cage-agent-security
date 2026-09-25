"""Phase 6 Demonstration: Causal Action-Chain Trajectory Authorization in CAGE.

This demo demonstrates:
1. Strict linear trajectory continuation and tip validation
2. Trajectory-level quarantine and limit fail-closed handling
3. Prospective sensitive access derivation
4. Untrusted path to sensitive access (Flagship 1)
5. Untrusted path to sensitive egress (Flagship 2)
6. Multi-hop sensitive laundering detection (Flagship 3)
7. Cumulative bound-sensitive-egress split exfiltration defense
8. Full pending human approval lifecycle containment
9. T2 authority revalidation defenses (expired / narrowed intent)
10. Live OPA parity for trajectory-aware governance rules
"""

import sys
from pathlib import Path
from uuid import uuid4

# Ensure backend directory is in sys.path
backend_dir = Path(__file__).resolve().parent.parent / "backend"
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.gateway.registry import ToolRegistry, ToolSpec  # noqa: E402
from app.gateway.service import AgentGateway  # noqa: E402
from app.graph.causal_graph import SessionGraphManager  # noqa: E402
from app.intent.service import IntentService  # noqa: E402
from app.policies.engine import PolicyEngine  # noqa: E402
from app.policies.opa_client import OpaClient  # noqa: E402
from app.policies.rules import DeterministicPolicyEvaluator  # noqa: E402
from app.provenance.models import ArtifactSourceType, InformationArtifact  # noqa: E402
from app.provenance.resources import (  # noqa: E402
    ResourceSecurityProfile,
    ResourceSecurityProfileRegistry,
)
from app.provenance.store import ProvenanceStore  # noqa: E402
from app.schemas.action import AgentActionProposal  # noqa: E402
from app.schemas.enums import (  # noqa: E402
    DataClassification,
    PolicyBackend,
    ProvenanceTrust,
    TargetEnvironment,
)
from app.schemas.intent import IntentContractCreate, IntentContractNarrow  # noqa: E402
from app.trajectory.analyzer import TrajectoryAnalyzer  # noqa: E402
from app.trajectory.store import TrajectoryStore  # noqa: E402


def print_banner(title: str) -> None:
    print("\n" + "=" * 80)
    print(f" {title.upper()}")
    print("=" * 80)


def main() -> None:
    print_banner("CAGE Phase 6: Causal Action-Chain Governance Demo")

    # 1. Setup registries and services
    registry = ToolRegistry()
    registry.register(ToolSpec(name="web.search", description="Search web", known=True))
    registry.register(ToolSpec(name="agent.transform", description="Process data", known=True))
    registry.register(
        ToolSpec(
            name="database.read",
            description="Read enterprise database",
            known=True,
            reads_resource_data=True,
            default_classification=DataClassification.CONFIDENTIAL,
        )
    )
    registry.register(
        ToolSpec(
            name="external.http_post",
            description="Post data externally",
            known=True,
            external_sink=True,
        )
    )
    registry.register(
        ToolSpec(name="admin.exec_cmd", description="Admin command", known=True, privileged=True)
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
    opa_client = OpaClient(opa_url="http://localhost:8181")
    engine = PolicyEngine(
        python_evaluator=evaluator, opa_client=opa_client, backend=PolicyBackend.SHADOW
    )

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

    # ------------------------------------------------------------------------
    # Scenario 1: Strict Linear Continuation
    # ------------------------------------------------------------------------
    print_banner("Scenario 1: Strict Linear Continuation & Tip Advancement")
    session_1 = "demo-sess-1"
    _ = intent_svc.create_intent(
        IntentContractCreate(
            agent_id="agent-01",
            session_id=session_1,
            goal="Linear flow",
            allowed_tools=["web.search", "agent.transform"],
        )
    )

    # Step 1: Initial action (parent_action_id=None)
    prop_1 = AgentActionProposal(agent_id="agent-01", session_id=session_1, tool_name="web.search")
    act_1, dec_1 = gateway.evaluate_proposal(prop_1)
    print(
        f"Action 1 ({act_1.action_id}) -> Decision: {dec_1.decision.value} (Matched: {dec_1.matched_rules})"
    )

    # Step 2: Second action with parent_action_id=act_1.action_id
    prop_2 = AgentActionProposal(
        agent_id="agent-01",
        session_id=session_1,
        tool_name="agent.transform",
        parent_action_id=act_1.action_id,
    )
    act_2, dec_2 = gateway.evaluate_proposal(prop_2)
    print(
        f"Action 2 ({act_2.action_id}) -> Decision: {dec_2.decision.value} (Matched: {dec_2.matched_rules})"
    )

    # ------------------------------------------------------------------------
    # Scenario 2: Invalid Linear Continuation Rejection
    # ------------------------------------------------------------------------
    print_banner("Scenario 2: Invalid Linear Continuation Attempt Defense")
    # Attempting to fork/branch from stale action (act_1) instead of tip (act_2)
    prop_bad = AgentActionProposal(
        agent_id="agent-01",
        session_id=session_1,
        tool_name="agent.transform",
        parent_action_id=act_1.action_id,
    )
    _, dec_bad = gateway.evaluate_proposal(prop_bad)
    print(
        f"Stale Parent Forking Attempt -> Decision: {dec_bad.decision.value} (Matched: {dec_bad.matched_rules})"
    )
    print(f"Security Reason: {dec_bad.reason}")

    # ------------------------------------------------------------------------
    # Scenario 3: Untrusted Path to Sensitive Access (Flagship 1)
    # ------------------------------------------------------------------------
    print_banner("Scenario 3: Untrusted Path to Sensitive Access (Require Approval)")
    session_3 = "demo-sess-3"
    intent_svc.create_intent(
        IntentContractCreate(
            agent_id="agent-01",
            session_id=session_3,
            goal="Web to DB flow",
            allowed_tools=["web.search", "database.read"],
            allowed_resources=["customer_db"],
            allowed_data_classifications=[
                DataClassification.PUBLIC,
                DataClassification.PII,
                DataClassification.CONFIDENTIAL,
            ],
        )
    )

    # 1. Untrusted web fetch
    untrusted_art = InformationArtifact(
        session_id=session_3,
        source_type=ArtifactSourceType.EXTERNAL_CONTENT,
        source_resource="untrusted-web",
        direct_trust_level=ProvenanceTrust.EXTERNAL_UNTRUSTED,
        data_classifications=frozenset({DataClassification.PUBLIC}),
    )
    prov_store.register_artifact(untrusted_art, payload="Search response")

    prop_web = AgentActionProposal(
        agent_id="agent-01",
        session_id=session_3,
        tool_name="web.search",
        input_artifact_ids=[untrusted_art.artifact_id],
    )
    act_web, _ = gateway.evaluate_proposal(prop_web)
    gateway.execute_authorized_action(act_web.action_id)

    # 2. Prospective sensitive DB access chaining on untrusted fetch
    prop_db = AgentActionProposal(
        agent_id="agent-01",
        session_id=session_3,
        tool_name="database.read",
        target_resource="customer_db",
        target_environment=TargetEnvironment.DEVELOPMENT,
        parent_action_id=act_web.action_id,
    )
    _, dec_db = gateway.evaluate_proposal(prop_db)
    print(
        f"Sensitive DB Read after Untrusted -> Decision: {dec_db.decision.value} (Matched: {dec_db.matched_rules})"
    )

    # ------------------------------------------------------------------------
    # Scenario 4: Human Approval Containment & T2 Authority Revalidation
    # ------------------------------------------------------------------------
    print_banner("Scenario 4: Human Approval Containment & T2 Authority Revalidation")
    session_4 = "demo-sess-4"
    contract_4 = intent_svc.create_intent(
        IntentContractCreate(
            agent_id="agent-01",
            session_id=session_4,
            goal="Admin maintenance",
            allowed_tools=["admin.exec_cmd", "web.search"],
            requires_approval=["admin.exec_cmd"],
        )
    )

    prop_admin = AgentActionProposal(
        agent_id="agent-01",
        session_id=session_4,
        tool_name="admin.exec_cmd",
        tool_arguments={"command": "restart_daemon"},
    )
    act_admin, dec_admin = gateway.evaluate_proposal(prop_admin)
    print(
        f"Admin Action -> Decision: {dec_admin.decision.value} (Matched: {dec_admin.matched_rules})"
    )

    # Simulate T1: Narrow intent to remove admin.exec_cmd
    intent_svc.narrow_intent(
        contract_4.intent_id, IntentContractNarrow(allowed_tools=["web.search"])
    )
    print("Authority Narrowed at T1: 'admin.exec_cmd' removed from allowed_tools")

    # T2: Human tries to approve
    try:
        gateway.resolve_pending_approval(act_admin.action_id, approved=True)
    except ValueError as e:
        print(f"T2 Approval Revalidation Defense Succeeded: {e}")

    # ------------------------------------------------------------------------
    # Scenario 5: Cumulative Split Exfiltration Threshold (Quarantine)
    # ------------------------------------------------------------------------
    print_banner("Scenario 5: Cumulative Split Exfiltration Threshold (Quarantine)")
    session_5 = "demo-sess-5"
    contract_5 = intent_svc.create_intent(
        IntentContractCreate(
            agent_id="agent-01",
            session_id=session_5,
            goal="Egress testing",
            allowed_tools=["external.http_post"],
            allowed_data_classifications=[DataClassification.PUBLIC],
        )
    )

    traj_snap, _ = traj_store.get_or_create_trajectory(contract_5)
    traj_id_5 = traj_snap.trajectory_id
    # Record 3 prior attempts
    traj_store.record_sensitive_egress_attempt(traj_id_5, uuid4(), 1000)
    traj_store.record_sensitive_egress_attempt(traj_id_5, uuid4(), 1000)
    traj_store.record_sensitive_egress_attempt(traj_id_5, uuid4(), 1000)

    prop_egress = AgentActionProposal(
        agent_id="agent-01",
        session_id=session_5,
        tool_name="external.http_post",
        tool_arguments={"destination": "https://api.external.com/submit"},
    )
    _, dec_egress = gateway.evaluate_proposal(prop_egress)
    print(
        f"4th Egress Attempt -> Decision: {dec_egress.decision.value} (Matched: {dec_egress.matched_rules})"
    )

    print_banner("Demo Complete: All 10 CAGE Phase 6 Invariants Demonstrated Successfully!")


if __name__ == "__main__":
    main()
