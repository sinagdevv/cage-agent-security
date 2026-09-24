"""Intent Contract schemas for task-scoped agent authorization."""

from datetime import UTC, datetime
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.enums import DataClassification, IntentStatus, TargetEnvironment


class IntentContractCreate(BaseModel):
    """Trusted control-plane request to create an authoritative Intent Contract.

    Intent Contracts establish the task-scoped authority granted by a human
    or authorized application to an AI agent.
    """

    model_config = ConfigDict(extra="forbid")

    user_id: str | None = Field(default=None, description="Human principal authorizing the task")
    agent_id: str = Field(..., description="Target agent authorized by this contract")
    session_id: str = Field(..., description="Execution session bound to this contract")
    goal: str = Field(..., description="Authorized human objective")
    description: str | None = Field(default=None, description="Detailed task scope description")

    allowed_tools: list[str] = Field(
        ..., min_length=1, description="Explicit whitelist of allowed tools (default deny)"
    )
    denied_tools: list[str] = Field(
        default_factory=list, description="Explicit blacklist of forbidden tools"
    )
    allowed_resources: list[str] = Field(
        default_factory=list, description="Allowed target resource identifiers (exact match)"
    )
    denied_resources: list[str] = Field(
        default_factory=list, description="Explicitly forbidden target resource identifiers"
    )
    allowed_environments: list[TargetEnvironment] = Field(
        default_factory=lambda: [TargetEnvironment.LOCAL, TargetEnvironment.DEVELOPMENT],
        description="Deployment environments authorized for this task",
    )
    allowed_data_classifications: list[DataClassification] = Field(
        default_factory=lambda: [DataClassification.PUBLIC],
        description="Data sensitivity tiers the agent is permitted to process",
    )
    requires_approval: list[str] = Field(
        default_factory=list,
        description="Permitted tools that nonetheless mandate human approval",
    )
    maximum_tool_calls: int = Field(
        default=20, ge=1, description="Hard quota on cumulative tool executions"
    )
    delegation_allowed: bool = Field(
        default=False, description="Whether agent may delegate subtasks"
    )
    maximum_delegation_depth: int = Field(default=0, ge=0)
    expires_at: datetime | None = Field(default=None, description="UTC expiration deadline")


class IntentContractNarrow(BaseModel):
    """Authority reduction request adhering to: authority_next <= authority_original.

    Authority expansion is strictly prohibited.
    """

    model_config = ConfigDict(extra="forbid")

    allowed_tools: list[str] | None = Field(
        default=None, description="Subset of currently allowed tools (removal only)"
    )
    denied_tools: list[str] | None = Field(
        default=None, description="Additional tools to explicitly deny (superset)"
    )
    allowed_resources: list[str] | None = Field(
        default=None, description="Subset of currently allowed resources"
    )
    denied_resources: list[str] | None = Field(
        default=None, description="Additional resources to explicitly deny"
    )
    allowed_environments: list[TargetEnvironment] | None = Field(
        default=None, description="Subset of currently allowed environments"
    )
    allowed_data_classifications: list[DataClassification] | None = Field(
        default=None, description="Subset of currently allowed data classifications"
    )
    requires_approval: list[str] | None = Field(
        default=None, description="Superset of approval requirements (stricter only)"
    )
    maximum_tool_calls: int | None = Field(
        default=None, description="Reduced tool call quota (must be >= current usage)"
    )
    delegation_allowed: bool | None = Field(
        default=None, description="Can only transition from True to False"
    )
    maximum_delegation_depth: int | None = Field(default=None, description="Can only decrease")
    expires_at: datetime | None = Field(
        default=None, description="Can only be earlier than current expiration"
    )


class IntentContract(BaseModel):
    """Authoritative, immutable Intent Contract stored by CAGE.

    Internal permission collections use frozensets to prevent silent in-place mutation.
    """

    model_config = ConfigDict(extra="ignore", frozen=True)

    intent_id: UUID = Field(
        default_factory=uuid4, description="Server-generated unique intent UUID"
    )
    user_id: str | None = None
    agent_id: str
    session_id: str
    goal: str
    description: str | None = None

    allowed_tools: frozenset[str]
    denied_tools: frozenset[str] = frozenset()
    allowed_resources: frozenset[str] = frozenset()
    denied_resources: frozenset[str] = frozenset()
    allowed_environments: frozenset[TargetEnvironment]
    allowed_data_classifications: frozenset[DataClassification]
    requires_approval: frozenset[str] = frozenset()

    maximum_tool_calls: int = 20
    tool_calls_count: int = 0  # Authoritative executions consumed

    delegation_allowed: bool = False
    maximum_delegation_depth: int = 0

    expires_at: datetime | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    status: IntentStatus = IntentStatus.ACTIVE
    revoked_reason: str | None = None

    def is_active(self, now: datetime | None = None) -> bool:
        """Check if contract is active and not expired."""
        current_time = now or datetime.now(UTC)
        if self.status != IntentStatus.ACTIVE:
            return False
        if self.expires_at is not None and current_time >= self.expires_at:
            return False
        return True

    @classmethod
    def from_create(
        cls, req: IntentContractCreate, intent_id: UUID | None = None
    ) -> "IntentContract":
        """Instantiate an authoritative IntentContract from a trusted creation request."""
        return cls(
            intent_id=intent_id or uuid4(),
            user_id=req.user_id,
            agent_id=req.agent_id,
            session_id=req.session_id,
            goal=req.goal,
            description=req.description,
            allowed_tools=frozenset(req.allowed_tools),
            denied_tools=frozenset(req.denied_tools),
            allowed_resources=frozenset(req.allowed_resources),
            denied_resources=frozenset(req.denied_resources),
            allowed_environments=frozenset(req.allowed_environments),
            allowed_data_classifications=frozenset(req.allowed_data_classifications),
            requires_approval=frozenset(req.requires_approval),
            maximum_tool_calls=req.maximum_tool_calls,
            tool_calls_count=0,
            delegation_allowed=req.delegation_allowed,
            maximum_delegation_depth=req.maximum_delegation_depth,
            expires_at=req.expires_at,
            status=IntentStatus.ACTIVE,
        )
