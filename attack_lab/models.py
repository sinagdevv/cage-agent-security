"""Declarative data models and result schemas for the CAGE Attack Simulation Lab."""

from enum import StrEnum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.enums import (
    ActionType,
    ArtifactSourceType,
    DataClassification,
    PayloadBindingMode,
    PolicyDecision,
    TargetEnvironment,
    TrajectoryStatus,
    TrustLevel,
)


class ScenarioOutcome(StrEnum):
    """Authoritative outcome classification for an executed attack scenario or step."""

    BLOCKED_AS_EXPECTED = "BLOCKED_AS_EXPECTED"
    REQUIRE_APPROVAL_AS_EXPECTED = "REQUIRE_APPROVAL_AS_EXPECTED"
    APPROVED_EXECUTION_AS_EXPECTED = "APPROVED_EXECUTION_AS_EXPECTED"
    APPROVAL_REJECTED_AS_EXPECTED = "APPROVAL_REJECTED_AS_EXPECTED"
    QUARANTINED_AS_EXPECTED = "QUARANTINED_AS_EXPECTED"
    ALLOWED_AS_EXPECTED = "ALLOWED_AS_EXPECTED"
    UNEXPECTED_ALLOW_SECURITY_FAILURE = "UNEXPECTED_ALLOW_SECURITY_FAILURE"
    UNEXPECTED_APPROVAL_SECURITY_FAILURE = "UNEXPECTED_APPROVAL_SECURITY_FAILURE"
    UNEXPECTED_BLOCK_FALSE_POSITIVE = "UNEXPECTED_BLOCK_FALSE_POSITIVE"
    UNEXPECTED_QUARANTINE_FALSE_POSITIVE = "UNEXPECTED_QUARANTINE_FALSE_POSITIVE"
    CONTAINMENT_STATE_FAILURE = "CONTAINMENT_STATE_FAILURE"
    POLICY_PARITY_MISMATCH = "POLICY_PARITY_MISMATCH"
    SCENARIO_CONFIGURATION_ERROR = "SCENARIO_CONFIGURATION_ERROR"
    ANALYSIS_FAILURE = "ANALYSIS_FAILURE"


class AttackCategory(StrEnum):
    """Canonical Phase 7 taxonomy categories (A through T)."""

    INDIRECT_INJECTION = "INDIRECT_INJECTION"  # Cat A
    ACTION_CHAIN_BYPASS = "ACTION_CHAIN_BYPASS"  # Cat B
    PROVENANCE_LAUNDERING = "PROVENANCE_LAUNDERING"  # Cat C
    SENSITIVE_DATA_LAUNDERING = "SENSITIVE_DATA_LAUNDERING"  # Cat D
    SPLIT_EXFILTRATION = "SPLIT_EXFILTRATION"  # Cat E
    UNUSED_SENSITIVE_INPUT_CONTROL = "UNUSED_SENSITIVE_INPUT_CONTROL"  # Cat F
    LINEAGE_RESET = "LINEAGE_RESET"  # Cat G
    APPROVAL_BYPASS = "APPROVAL_BYPASS"  # Cat H
    STALE_APPROVAL_TOCTOU = "STALE_APPROVAL_TOCTOU"  # Cat I
    AUTHORITY_LAUNDERING = "AUTHORITY_LAUNDERING"  # Cat J
    CAUSAL_DISTANCE_EVASION = "CAUSAL_DISTANCE_EVASION"  # Cat K
    GRAPH_RELATION_CONFUSION = "GRAPH_RELATION_CONFUSION"  # Cat L
    ANALYSIS_LIMIT_ATTACKS = "ANALYSIS_LIMIT_ATTACKS"  # Cat M
    POLICY_PARITY = "POLICY_PARITY"  # Cat N
    UNKNOWN_TOOL_RESOURCE = "UNKNOWN_TOOL_RESOURCE"  # Cat O
    EXTERNAL_DESTINATION_BINDING = "EXTERNAL_DESTINATION_BINDING"  # Cat P
    CREDENTIAL_EXFILTRATION = "CREDENTIAL_EXFILTRATION"  # Cat Q
    RETRY_REPLAY_ATTACKS = "RETRY_REPLAY_ATTACKS"  # Cat R
    TRUST_SPOOFING = "TRUST_SPOOFING"  # Cat S
    BENIGN_CONTROL = "BENIGN_CONTROL"  # Cat T
    MALICIOUS_MCP = "MALICIOUS_MCP"  # MCP Simulation
    DELEGATION_ATTACKS = "DELEGATION_ATTACKS"  # Phase 8 Multi-Agent Attacks


class InitialArtifactFixture(BaseModel):
    """Seeded artifact fixture placed into ProvenanceStore before scenario execution."""

    key: str
    classification: DataClassification = DataClassification.INTERNAL
    classifications: list[DataClassification] = Field(default_factory=list)
    source_type: ArtifactSourceType = ArtifactSourceType.INTERNAL_RESOURCE
    trust_level: TrustLevel = TrustLevel.INTERNAL_TRUSTED
    source_resource: str | None = None
    byte_count: int = 100
    content: Any = "simulated-artifact-payload"
    is_sensitive: bool = False
    parent_artifact_keys: list[str] = Field(default_factory=list)


class ScenarioStep(BaseModel):
    """Declarative definition of a single step within an attack scenario."""

    step_id: str
    description: str
    tool_name: str
    action_type: ActionType = ActionType.TOOL_CALL
    resource_id: str = "default-resource"
    resource_type: str = "resource"
    environment: TargetEnvironment = TargetEnvironment.PRODUCTION

    # Multi-agent attributes (Phase 8)
    agent_id: str | None = None
    delegation_key: str | None = None
    is_delegation_creation: bool = False
    delegation_proposal: dict[str, Any] | None = None

    # Lineage and binding specifications
    parent_step_id: str | None = None  # Resolved to actual UUID during execution
    explicit_parent_action_id: UUID | None = None  # For testing invalid/stale parent injections
    omit_parent: bool = False  # For testing lineage reset (submitting None when parent exists)

    input_artifact_keys: list[str] = Field(default_factory=list)
    payload_binding_mode: PayloadBindingMode = PayloadBindingMode.NONE
    payload_bindings: dict[str, Any] = Field(default_factory=dict)
    tool_arguments: dict[str, Any] = Field(default_factory=dict)

    # Metadata and spoofing tests
    metadata: dict[str, Any] = Field(default_factory=dict)
    client_action_id: UUID | None = None

    # Intermediate actions
    request_approval: bool = False  # Execute human approval flow if REQUIRE_APPROVAL
    expected_approval_result: bool | None = (
        None  # True if approval execution is expected to succeed
    )
    mutate_intent_before_approval: dict[str, Any] | None = None  # For TOCTOU tests

    # Security Expectations (Used ONLY for assertions, never for runtime policy evaluation)
    expected_decision: PolicyDecision = PolicyDecision.ALLOW
    expected_rule_ids: list[str] = Field(default_factory=list)
    expect_dispatch: bool = False
    expect_quarantine: bool = False
    expect_error: str | None = None  # e.g., "INVALID_TRAJECTORY_CONTINUATION"


class AttackScenario(BaseModel):
    """Declarative specification of an end-to-end attack simulation scenario."""

    scenario_id: str
    category: AttackCategory
    name: str
    description: str
    threat_actor: str
    attack_intent: str
    security_invariant: str

    # Intent Contract configuration fixture
    intent_tools: list[str] = Field(default_factory=list)
    intent_resources: list[str] = Field(default_factory=list)
    intent_environments: list[TargetEnvironment] = Field(default_factory=list)
    intent_classifications: list[DataClassification] = Field(default_factory=list)
    intent_max_actions: int = 50
    intent_ttl_seconds: int = 3600

    # Limit parameter overrides for analysis limit testing
    max_action_depth: int | None = None
    max_provenance_depth: int | None = None
    max_nodes: int | None = None

    # Initial Fixtures & Step Sequence
    initial_artifacts: list[InitialArtifactFixture] = Field(default_factory=list)
    steps: list[ScenarioStep]

    # Global expectations
    expected_final_trajectory_status: TrajectoryStatus = TrajectoryStatus.ACTIVE
    expected_overall_outcome: ScenarioOutcome | None = None
    expect_agent_manipulation_success: bool = True
    expect_cage_bypass: bool = False


class StepResult(BaseModel):
    """Execution telemetry and security verdict comparison for a single step."""

    step_id: str
    action_id: UUID | None = None
    expected_decision: PolicyDecision
    actual_decision: PolicyDecision | None = None
    outcome: ScenarioOutcome
    decision_matches: bool
    expected_rule_ids: list[str] = Field(default_factory=list)
    actual_rule_ids: list[str] = Field(default_factory=list)
    rules_match: bool
    tool_dispatched: bool = False
    side_effect_occurred: bool = False
    policy_parity_passed: bool = True
    error_raised: str | None = None
    approval_attempted: bool = False
    approval_succeeded: bool | None = None
    duration_ms: float = 0.0


class AttackScenarioResult(BaseModel):
    """Canonical result schema produced by the AttackScenarioRunner."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scenario_id: str
    scenario_name: str
    category: AttackCategory

    # High-level outcome assertions
    agent_manipulation_succeeded: bool
    attack_goal_reached: bool = False
    cage_bypass_succeeded: bool
    scenario_passed: bool
    overall_outcome: ScenarioOutcome

    # Security-critical facts & decisions
    expected_final_decision: PolicyDecision | str | None = None
    actual_final_decision: PolicyDecision | str | None = None
    expected_rule_ids: list[str] = Field(default_factory=list)
    actual_rule_ids: list[str] = Field(default_factory=list)
    tool_dispatched: bool = False
    simulated_side_effect_occurred: bool = False

    # Detailed telemetry
    step_results: list[StepResult]
    final_trajectory_status: TrajectoryStatus
    initial_gate_decision: PolicyDecision | str | None = None
    approval_resolution: str | None = None
    quarantine_triggered: bool = False

    # Security weakening and containment telemetry
    authorization_weaker_than_expected: bool = False
    containment_state_failed: bool = False
    security_expectation_failed: bool = False

    # Security metrics
    false_positive: bool = False
    false_negative: bool = False
    policy_parity_passed: bool = True
    policy_parity_failures: list[str] = Field(default_factory=list)

    evidence_action_ids: list[UUID] = Field(default_factory=list)
    evidence_artifact_ids: list[UUID] = Field(default_factory=list)

    notes: list[str] = Field(default_factory=list)
    execution_duration_ms: float = 0.0
    total_duration_ms: float = 0.0
