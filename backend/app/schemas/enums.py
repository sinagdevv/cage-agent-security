"""Core enums for CAGE agent action governance and security decisions."""

from enum import StrEnum


class ActionType(StrEnum):
    """Categorization of proposed agent actions."""

    TOOL_CALL = "TOOL_CALL"
    DELEGATION = "DELEGATION"
    READ = "READ"
    WRITE = "WRITE"
    EXECUTE = "EXECUTE"
    NETWORK_REQUEST = "NETWORK_REQUEST"
    DESTRUCTIVE = "DESTRUCTIVE"


class ToolExecutionStatus(StrEnum):
    """State lifecycle of a tool invocation."""

    PROPOSED = "PROPOSED"
    AUTHORIZED = "AUTHORIZED"
    EXECUTING = "EXECUTING"
    COMPLETED = "COMPLETED"
    DENIED = "DENIED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    FAILED = "FAILED"
    ABORTED = "ABORTED"


class PolicyDecision(StrEnum):
    """Authoritative CAGE policy verdict.

    Precedence order (highest to lowest severity):
    DENY > QUARANTINE > SANDBOX > REQUIRE_APPROVAL > ALLOW_WITH_LIMITS > ALLOW
    """

    DENY = "DENY"
    QUARANTINE = "QUARANTINE"
    SANDBOX = "SANDBOX"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    ALLOW_WITH_LIMITS = "ALLOW_WITH_LIMITS"
    ALLOW = "ALLOW"

    @property
    def severity_rank(self) -> int:
        """Numeric rank for deterministic precedence resolution (higher is more restrictive)."""
        ranks = {
            PolicyDecision.DENY: 6,
            PolicyDecision.QUARANTINE: 5,
            PolicyDecision.SANDBOX: 4,
            PolicyDecision.REQUIRE_APPROVAL: 3,
            PolicyDecision.ALLOW_WITH_LIMITS: 2,
            PolicyDecision.ALLOW: 1,
        }
        return ranks[self]


class TrustLevel(StrEnum):
    """Trust tier of an input or execution origin."""

    UNTRUSTED = "UNTRUSTED"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    VERIFIED_HUMAN = "VERIFIED_HUMAN"


class DataClassification(StrEnum):
    """Sensitivity classification of information processed by agents."""

    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"
    SECRET = "SECRET"
    CREDENTIAL = "CREDENTIAL"


class TargetEnvironment(StrEnum):
    """Target deployment environment of an action."""

    LOCAL = "LOCAL"
    DEVELOPMENT = "DEVELOPMENT"
    STAGING = "STAGING"
    PRODUCTION = "PRODUCTION"


class IntentStatus(StrEnum):
    """Lifecycle state of an Intent Contract."""

    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    COMPLETED = "COMPLETED"


class PolicyBackend(StrEnum):
    """Operational mode for CAGE deterministic policy enforcement."""

    PYTHON = "PYTHON"
    SHADOW = "SHADOW"
    OPA = "OPA"


class PolicyParityStatus(StrEnum):
    """Classification of parity comparison between Python and OPA engines."""

    MATCH = "MATCH"
    DIVERGENCE = "DIVERGENCE"
    OPA_ERROR = "OPA_ERROR"
    NOT_EVALUATED = "NOT_EVALUATED"


class OpaStatus(StrEnum):
    """Outcome of OPA HTTP client evaluation attempt."""

    SUCCESS = "SUCCESS"
    TIMEOUT = "TIMEOUT"
    UNAVAILABLE = "UNAVAILABLE"
    INVALID_RESPONSE = "INVALID_RESPONSE"
    EVALUATION_ERROR = "EVALUATION_ERROR"
