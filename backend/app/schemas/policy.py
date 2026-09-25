"""Canonical schemas for CAGE policy input, OPA evaluation, and parity comparison."""

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.schemas.enums import (
    GraphAnalysisStatus,
    OpaStatus,
    PolicyBackend,
    PolicyDecision,
    PolicyParityStatus,
)

# Global schema identifier for policy input
POLICY_INPUT_SCHEMA_VERSION = "cage-policy-input-v2"
POLICY_VERSION = "phase4-v1"


class PolicyActionContext(BaseModel):
    """Normalized action attributes for policy evaluation."""

    model_config = ConfigDict(extra="forbid")

    action_id: str
    action_type: str
    tool_name: str
    target_resource: str | None = None
    target_environment: str


class PolicyAgentContext(BaseModel):
    """Normalized agent and session identities."""

    model_config = ConfigDict(extra="forbid")

    agent_id: str
    session_id: str
    user_id: str | None = None


class PolicyIntentContext(BaseModel):
    """Normalized intent bounds for policy evaluation."""

    model_config = ConfigDict(extra="forbid")

    intent_id: str
    status: str
    allowed_tools: list[str]
    denied_tools: list[str]
    allowed_environments: list[str]
    allowed_resources: list[str]
    denied_resources: list[str]
    allowed_data_classifications: list[str]
    requires_approval: list[str]
    maximum_tool_calls: int
    tool_calls_count: int


class PolicyToolContext(BaseModel):
    """Authoritative tool specifications derived from trusted registry."""

    model_config = ConfigDict(extra="forbid")

    known: bool
    privileged: bool
    destructive: bool
    external_sink: bool
    resource_scoped: bool
    server_known_classifications: list[str]


class PolicyDataContext(BaseModel):
    """Effective classifications combining server-known and client-declared."""

    model_config = ConfigDict(extra="forbid")

    effective_classifications: list[str]


class PolicyRuntimeContext(BaseModel):
    """CAGE operational flags and causal context."""

    model_config = ConfigDict(extra="forbid")

    require_intent: bool
    intent_mismatch: bool = False
    parent_action_id: str | None = None
    delegation_depth: int = 0


class PolicyGraphContext(BaseModel):
    """Authoritative, server-derived causal graph facts for runtime policy evaluation.

    Client runtimes cannot supply or alter these fields.
    """

    model_config = ConfigDict(extra="forbid")

    analysis_status: GraphAnalysisStatus = GraphAnalysisStatus.SUCCESS
    analysis_complete: bool = True
    causal_depth: int = Field(default=0, ge=0)
    ancestor_count: int = Field(default=0, ge=0)
    ancestor_action_ids: list[str] = Field(default_factory=list)
    ancestor_tool_sequence: list[str] = Field(default_factory=list)
    ancestor_environments: list[str] = Field(default_factory=list)
    ancestor_data_classifications: list[str] = Field(default_factory=list)

    contains_denied_ancestor: bool = False
    contains_approval_ancestor: bool = False
    contains_external_sink_ancestor: bool = False
    contains_privileged_ancestor: bool = False
    contains_destructive_ancestor: bool = False

    privileged_probe_count: int = Field(default=0, ge=0)
    has_lower_environment_ancestor: bool = False
    has_high_environment_ancestor: bool = False


class CagePolicyInput(BaseModel):
    """Canonical, server-derived policy input document sent to policy evaluators.

    Raw client proposals are NEVER sent directly to OPA.
    All attributes are authoritative, sanitized, and normalized by CAGE.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: str = Field(
        default=POLICY_INPUT_SCHEMA_VERSION,
        description="Version identifier for input document structure",
    )
    action: PolicyActionContext
    agent: PolicyAgentContext
    intent: PolicyIntentContext | None = None
    tool: PolicyToolContext
    data: PolicyDataContext
    context: PolicyRuntimeContext
    graph: PolicyGraphContext = Field(default_factory=PolicyGraphContext)


class OpaFinding(BaseModel):
    """Single declarative policy rule finding returned by OPA."""

    model_config = ConfigDict(extra="forbid")

    rule_id: str
    decision: PolicyDecision
    reason: str
    risk_score: float = Field(default=0.5, ge=0.0, le=1.0)

    @field_validator("risk_score")
    @classmethod
    def validate_risk_bounds(cls, v: float) -> float:
        if not (0.0 <= v <= 1.0):
            raise ValueError("risk_score must be between 0.0 and 1.0 inclusive")
        return round(v, 2)


class OpaEvaluationResult(BaseModel):
    """Result of an OPA HTTP policy evaluation request."""

    model_config = ConfigDict(extra="forbid")

    status: OpaStatus
    findings: list[OpaFinding] = Field(default_factory=list)
    error_reason: str | None = None


class PolicyParityResult(BaseModel):
    """Comparison result between Python and OPA policy evaluations."""

    model_config = ConfigDict(extra="forbid")

    status: PolicyParityStatus
    python_decision: PolicyDecision | None = None
    opa_decision: PolicyDecision | None = None
    decision_match: bool = False
    rule_match: bool = False
    python_rules: list[str] = Field(default_factory=list)
    opa_rules: list[str] = Field(default_factory=list)
    missing_in_opa: list[str] = Field(default_factory=list)
    extra_in_opa: list[str] = Field(default_factory=list)
    error_reason: str | None = None


class PolicyEngineHealth(BaseModel):
    """Status details for policy engine in health check."""

    backend: PolicyBackend
    status: str
    opa_reachable: bool
    opa_required: bool
    policy_version: str
    schema_version: str = POLICY_INPUT_SCHEMA_VERSION
    error: str | None = None
