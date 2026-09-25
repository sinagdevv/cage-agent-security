"""Agent action proposal and authoritative normalized action models."""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.enums import (
    ActionType,
    DataClassification,
    PolicyDecision,
    TargetEnvironment,
    ToolExecutionStatus,
    TrustLevel,
)


class AgentActionProposal(BaseModel):
    """Untrusted client proposal representing a tool action requested by an AI agent.

    Authoritative CAGE security attributes (action_id, policy_result, risk_score,
    execution_status) are excluded from this model and forbidden to prevent tampering.
    """

    model_config = ConfigDict(extra="forbid")

    client_action_id: str | None = Field(
        default=None,
        description="Optional client-provided correlation ID (not authoritative)",
    )
    agent_id: str = Field(..., description="Unique identifier of the agent")
    agent_instance_id: str | None = Field(default=None, description="Ephemeral runtime instance ID")
    session_id: str = Field(..., description="Causal execution session identifier")
    user_id: str | None = Field(default=None, description="Initiating human user identifier")
    intent_contract_id: UUID | str | None = Field(
        default=None, description="Reference to root intent agreement"
    )

    # Intent Context
    goal: str | None = Field(default=None, description="High-level agent objective")
    current_task: str | None = Field(default=None, description="Immediate task being executed")

    # Proposed Operation
    action_type: ActionType = Field(
        default=ActionType.TOOL_CALL, description="Type of proposed action"
    )
    tool_name: str = Field(..., description="Identifier of the target tool (e.g. 'web.search')")
    tool_arguments: dict[str, Any] = Field(
        default_factory=dict, description="Parameters passed to tool"
    )
    target_resource: str | None = Field(
        default=None, description="Target URI, path, or resource identifier"
    )
    target_environment: TargetEnvironment = Field(default=TargetEnvironment.DEVELOPMENT)

    # Trajectory Lineage References (Validated against session history)
    parent_action_id: UUID | None = Field(
        default=None, description="Immediate causal parent action ID"
    )
    previous_action_ids: list[UUID] = Field(
        default_factory=list, description="Preceding action IDs"
    )
    input_sources: list[str] = Field(
        default_factory=list, description="Origins of input data consumed"
    )
    influenced_by: list[str] = Field(
        default_factory=list, description="IDs of actions influencing this call"
    )

    # Provenance & Trust Classification
    input_trust_level: TrustLevel = Field(default=TrustLevel.MEDIUM)
    data_classifications: list[DataClassification] = Field(default_factory=list)
    delegation_chain: list[str] = Field(
        default_factory=list, description="Chain of delegating agent IDs"
    )
    capability_id: str | None = Field(default=None, description="Target capability identifier")
    expected_effect: str | None = Field(
        default=None, description="Agent's declared intended effect"
    )
    input_artifact_ids: list[UUID] = Field(
        default_factory=list, description="Untrusted client references to input artifacts"
    )
    client_correlation_id: str | None = Field(
        default=None, description="Optional client-provided correlation ID (no auth meaning)"
    )


class AgentAction(BaseModel):
    """Authoritative normalized CAGE event stored in execution history and causal graph.

    Contains server-controlled identifiers, computed risk scores, policy verdicts,
    and actual execution status.
    """

    model_config = ConfigDict(extra="ignore")

    # Authoritative Server Identifier
    action_id: UUID = Field(
        default_factory=uuid4, description="Server-generated unique action UUID"
    )
    client_action_id: str | None = Field(default=None, description="Correlated client proposal ID")
    trajectory_id: UUID | None = Field(
        default=None, description="Server-authoritative execution trajectory identifier (Phase 6)"
    )

    # Context & Proposal Information
    agent_id: str
    agent_instance_id: str | None = None
    session_id: str
    user_id: str | None = None
    intent_contract_id: UUID | str | None = None

    goal: str | None = None
    current_task: str | None = None

    action_type: ActionType = Field(default=ActionType.TOOL_CALL)
    tool_name: str
    tool_arguments: dict[str, Any] = Field(default_factory=dict)
    target_resource: str | None = None
    target_environment: TargetEnvironment = Field(default=TargetEnvironment.DEVELOPMENT)

    # Validated Lineage
    parent_action_id: UUID | None = None
    previous_action_ids: list[UUID] = Field(default_factory=list)
    input_sources: list[str] = Field(default_factory=list)
    influenced_by: list[str] = Field(default_factory=list)

    input_trust_level: TrustLevel = Field(default=TrustLevel.MEDIUM)
    data_classifications: list[DataClassification] = Field(default_factory=list)
    delegation_chain: list[str] = Field(default_factory=list)
    capability_id: str | None = None
    expected_effect: str | None = None

    # Phase 5 Information Provenance
    attempted_input_artifact_ids: list[UUID] = Field(
        default_factory=list, description="Client-submitted input artifact IDs before validation"
    )
    validated_input_artifact_ids: list[UUID] = Field(
        default_factory=list, description="Server-validated authoritative input artifact IDs"
    )
    output_artifact_ids: list[UUID] = Field(
        default_factory=list,
        description="Authoritative output artifact IDs produced by execution",
    )

    # Server-Authoritative Governance Fields
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    policy_result: PolicyDecision | None = None
    security_reason: str | None = None
    matched_rules: list[str] = Field(default_factory=list)
    execution_status: ToolExecutionStatus = Field(default=ToolExecutionStatus.PROPOSED)
    execution_result: dict[str, Any] | None = None

    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @classmethod
    def from_proposal(
        cls,
        proposal: AgentActionProposal,
        action_id: UUID | None = None,
        trajectory_id: UUID | None = None,
    ) -> "AgentAction":
        """Instantiate an authoritative AgentAction from a client proposal."""
        return cls(
            action_id=action_id or uuid4(),
            client_action_id=proposal.client_action_id or proposal.client_correlation_id,
            trajectory_id=trajectory_id,
            agent_id=proposal.agent_id,
            agent_instance_id=proposal.agent_instance_id,
            session_id=proposal.session_id,
            user_id=proposal.user_id,
            intent_contract_id=proposal.intent_contract_id,
            goal=proposal.goal,
            current_task=proposal.current_task,
            action_type=proposal.action_type,
            tool_name=proposal.tool_name,
            tool_arguments=proposal.tool_arguments,
            target_resource=proposal.target_resource,
            target_environment=proposal.target_environment,
            parent_action_id=proposal.parent_action_id,
            previous_action_ids=proposal.previous_action_ids,
            input_sources=proposal.input_sources,
            influenced_by=proposal.influenced_by,
            input_trust_level=proposal.input_trust_level,
            data_classifications=proposal.data_classifications,
            delegation_chain=proposal.delegation_chain,
            capability_id=proposal.capability_id,
            expected_effect=proposal.expected_effect,
            attempted_input_artifact_ids=list(proposal.input_artifact_ids),
            validated_input_artifact_ids=[],
            output_artifact_ids=[],
            execution_status=ToolExecutionStatus.PROPOSED,
        )
