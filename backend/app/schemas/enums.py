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


class ProvenanceTrust(StrEnum):
    """Authoritative information provenance and origin trust taxonomy (Phase 5)."""

    TRUSTED_HUMAN = "TRUSTED_HUMAN"
    TRUSTED_SYSTEM = "TRUSTED_SYSTEM"
    INTERNAL_TRUSTED = "INTERNAL_TRUSTED"
    EXTERNAL_UNTRUSTED = "EXTERNAL_UNTRUSTED"
    AGENT_DERIVED = "AGENT_DERIVED"
    UNKNOWN = "UNKNOWN"


class LegacyTrustLevel(StrEnum):
    """Legacy action-level input trust score (Phase 1)."""

    UNTRUSTED = "UNTRUSTED"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    VERIFIED_HUMAN = "VERIFIED_HUMAN"


class TrustLevel(StrEnum):
    """Unified trust enum maintaining backward compatibility for legacy action tests."""

    # Legacy action-level confidence tiers (Phase 1)
    UNTRUSTED = "UNTRUSTED"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    VERIFIED_HUMAN = "VERIFIED_HUMAN"

    # Canonical Phase 5 provenance trust taxonomy
    TRUSTED_HUMAN = "TRUSTED_HUMAN"
    TRUSTED_SYSTEM = "TRUSTED_SYSTEM"
    INTERNAL_TRUSTED = "INTERNAL_TRUSTED"
    EXTERNAL_UNTRUSTED = "EXTERNAL_UNTRUSTED"
    AGENT_DERIVED = "AGENT_DERIVED"
    UNKNOWN = "UNKNOWN"


def normalize_to_provenance_trust(
    trust: object,
    source_type: object = None,
    is_trusted_human_origin: bool = False,
) -> ProvenanceTrust:
    """Normalize an input trust score or origin indicator into a canonical ProvenanceTrust.

    CRITICAL INVARIANT (Phase 5):
    Legacy confidence/risk scores (LOW, MEDIUM, HIGH, VERIFIED_HUMAN, UNTRUSTED)
    must NEVER manufacture factual provenance origin. If only a legacy trust score
    is provided without authoritative provenance metadata, it normalizes to UNKNOWN.
    """
    raw_val = trust.value if hasattr(trust, "value") else str(trust)
    src_val = (
        source_type.value
        if hasattr(source_type, "value")
        else (str(source_type) if source_type else None)
    )

    # 1. Authoritative human ingestion path
    if is_trusted_human_origin or src_val == "HUMAN_INPUT":
        return ProvenanceTrust.TRUSTED_HUMAN

    # 2. Authoritative external content ingestion
    if src_val == "EXTERNAL_CONTENT":
        return ProvenanceTrust.EXTERNAL_UNTRUSTED

    # 3. Explicit legacy confidence/risk levels without authoritative provenance metadata -> UNKNOWN
    if raw_val in (
        LegacyTrustLevel.LOW.value,
        LegacyTrustLevel.MEDIUM.value,
        LegacyTrustLevel.HIGH.value,
    ):
        return ProvenanceTrust.UNKNOWN

    if raw_val == LegacyTrustLevel.VERIFIED_HUMAN.value:
        return ProvenanceTrust.TRUSTED_HUMAN if is_trusted_human_origin else ProvenanceTrust.UNKNOWN

    if raw_val == LegacyTrustLevel.UNTRUSTED.value:
        return (
            ProvenanceTrust.EXTERNAL_UNTRUSTED
            if src_val == "EXTERNAL_CONTENT"
            else ProvenanceTrust.UNKNOWN
        )

    # 4. Canonical ProvenanceTrust origins
    try:
        return ProvenanceTrust(raw_val)
    except ValueError:
        return ProvenanceTrust.UNKNOWN


class ArtifactSourceType(StrEnum):
    """Origin category of an information artifact."""

    HUMAN_INPUT = "HUMAN_INPUT"
    TOOL_RESULT = "TOOL_RESULT"
    EXTERNAL_CONTENT = "EXTERNAL_CONTENT"
    INTERNAL_RESOURCE = "INTERNAL_RESOURCE"
    AGENT_GENERATED = "AGENT_GENERATED"
    FILE = "FILE"
    DATABASE = "DATABASE"
    SYSTEM = "SYSTEM"
    UNKNOWN = "UNKNOWN"


class PayloadBindingMode(StrEnum):
    """Enforcement mode for binding tool payload parameters to validated artifacts."""

    NONE = "NONE"
    ARTIFACT_REQUIRED = "ARTIFACT_REQUIRED"


class ProvenanceAnalysisStatus(StrEnum):
    """Outcome status of provenance analysis and artifact lineage traversal."""

    SUCCESS = "SUCCESS"
    DEPTH_LIMIT_EXCEEDED = "DEPTH_LIMIT_EXCEEDED"
    ARTIFACT_LIMIT_EXCEEDED = "ARTIFACT_LIMIT_EXCEEDED"
    INVALID_LINEAGE = "INVALID_LINEAGE"
    MISSING_ARTIFACT = "MISSING_ARTIFACT"
    CROSS_SESSION_REFERENCE = "CROSS_SESSION_REFERENCE"
    CYCLE_DETECTED = "CYCLE_DETECTED"
    UNTRACKED_PAYLOAD = "UNTRACKED_PAYLOAD"


class DataClassification(StrEnum):
    """Sensitivity classification of information processed by agents."""

    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"
    PII = "PII"
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


class GraphNodeType(StrEnum):
    """Standardized node types within the CAGE causal execution graph."""

    INTENT = "intent"
    ACTION = "action"
    ARTIFACT = "artifact"
    AGENT = "agent"
    DELEGATION = "delegation"


class GraphRelation(StrEnum):
    """Standardized directed edge relations within the CAGE causal execution graph."""

    GOVERNS = "governs"
    CAUSES = "causes"
    PRODUCES = "produces"
    CONSUMES = "consumes"
    DERIVED_FROM = "derived_from"
    ISSUES_DELEGATION = "issues_delegation"
    GRANTS_TO = "grants_to"
    SUBDELEGATES = "subdelegates"
    CREATES_DELEGATION = "creates_delegation"


class GraphAnalysisStatus(StrEnum):
    """Outcome status of graph security analysis and traversal."""

    SUCCESS = "SUCCESS"
    DEPTH_LIMIT_EXCEEDED = "DEPTH_LIMIT_EXCEEDED"
    NODE_LIMIT_EXCEEDED = "NODE_LIMIT_EXCEEDED"
    INVALID_GRAPH = "INVALID_GRAPH"
    CYCLE_DETECTED = "CYCLE_DETECTED"


class TrajectoryStatus(StrEnum):
    """Authoritative lifecycle status of a CAGE execution trajectory."""

    ACTIVE = "ACTIVE"
    QUARANTINED = "QUARANTINED"
    CLOSED = "CLOSED"
    ABORTED = "ABORTED"


class TrajectoryAnalysisStatus(StrEnum):
    """Outcome status of trajectory security analysis and causal traversal."""

    SUCCESS = "SUCCESS"
    ACTION_DEPTH_LIMIT_EXCEEDED = "ACTION_DEPTH_LIMIT_EXCEEDED"
    ARTIFACT_DEPTH_LIMIT_EXCEEDED = "ARTIFACT_DEPTH_LIMIT_EXCEEDED"
    NODE_LIMIT_EXCEEDED = "NODE_LIMIT_EXCEEDED"
    INVALID_TYPED_PATH = "INVALID_TYPED_PATH"
    MISSING_GRAPH_EVIDENCE = "MISSING_GRAPH_EVIDENCE"
    INCONSISTENT_PROVENANCE = "INCONSISTENT_PROVENANCE"


class AuthorityScopeMode(StrEnum):
    """Scope mode for authority capability constraints."""

    UNCONSTRAINED = "UNCONSTRAINED"
    ALLOWLIST = "ALLOWLIST"


class AuthorityViolationType(StrEnum):
    """Specific category of unauthorized authority expansion attempt."""

    TOOL = "TOOL"
    RESOURCE = "RESOURCE"
    ENVIRONMENT = "ENVIRONMENT"
    DATA_CLASSIFICATION = "DATA_CLASSIFICATION"


class DelegationStatus(StrEnum):
    """Stored lifecycle state of a DelegationGrant."""

    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"
    CLOSED = "CLOSED"


class EffectiveDelegationStatus(StrEnum):
    """Derived live authorization state of a DelegationGrant."""

    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"
    CLOSED = "CLOSED"
    EXPIRED = "EXPIRED"
    CONSUMED = "CONSUMED"
    ROOT_INVALID = "ROOT_INVALID"
    ANCESTOR_INVALID = "ANCESTOR_INVALID"


class DelegationIssuanceSource(StrEnum):
    """Source of delegation issuance."""

    AGENT_DIRECT = "AGENT_DIRECT"
    CONTROL_PLANE_MEDIATED = "CONTROL_PLANE_MEDIATED"


class DelegationOperation(StrEnum):
    """Specific operational context for delegation policy evaluation."""

    NONE = "NONE"
    CREATE_GRANT = "CREATE_GRANT"
    EXECUTE_ACTION = "EXECUTE_ACTION"
    RESOLVE_APPROVAL = "RESOLVE_APPROVAL"
    REVOKE_GRANT = "REVOKE_GRANT"


class DelegationAnalysisStatus(StrEnum):
    """Execution status of delegation security analysis."""

    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
