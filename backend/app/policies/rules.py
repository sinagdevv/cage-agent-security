"""Deterministic security rules and precedence-based policy evaluation.

Integrates task-scoped Intent Contract authorization with runtime security policies:
Intent Authorization AND Runtime Security Policy = Final Decision

Precedence resolution:
DENY > QUARANTINE > SANDBOX > REQUIRE_APPROVAL > ALLOW_WITH_LIMITS > ALLOW.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from app.schemas.action import AgentAction
from app.schemas.decision import SecurityDecision
from app.schemas.enums import (
    ActionType,
    DataClassification,
    PolicyDecision,
    TargetEnvironment,
)

if TYPE_CHECKING:
    from app.gateway.registry import ToolRegistry
    from app.schemas.intent import IntentContract
    from app.schemas.policy import (
        PolicyDelegationContext,
        PolicyGraphContext,
        PolicyProvenanceContext,
        PolicyTrajectoryContext,
    )


@dataclass(frozen=True)
class MatchedRule:
    """Individual rule matched during evaluation."""

    rule_id: str
    decision: PolicyDecision
    reason: str
    risk_score: float


class DeterministicPolicyEvaluator:
    """Deterministic policy evaluator for CAGE governance."""

    def __init__(self, tool_registry: ToolRegistry | None = None) -> None:
        from app.gateway.registry import default_tool_registry
        from app.policies.intent_rules import IntentRulesEvaluator

        self.tool_registry = tool_registry if tool_registry is not None else default_tool_registry
        self.intent_evaluator = IntentRulesEvaluator(tool_registry=self.tool_registry)

    def evaluate(
        self,
        action: AgentAction,
        contract: IntentContract | None = None,
        require_intent: bool = False,
        intent_mismatch: bool = False,
        graph_context: PolicyGraphContext | None = None,
        provenance_context: PolicyProvenanceContext | None = None,
        trajectory_context: PolicyTrajectoryContext | None = None,
        delegation_context: PolicyDelegationContext | None = None,
    ) -> SecurityDecision:
        """Evaluate an authoritative AgentAction against Intent rules and runtime policies.

        Evaluates ALL applicable rules first, then resolves the final verdict deterministically
        according to the severity rank hierarchy:
        DENY > QUARANTINE > SANDBOX > REQUIRE_APPROVAL > ALLOW_WITH_LIMITS > ALLOW.
        """

        tool_spec = self.tool_registry.get(action.tool_name)
        matched_rules: list[MatchedRule] = []

        # =============================================================
        # 1. Intent Scope Evaluation (Task Authority)
        # =============================================================
        intent_matched = self.intent_evaluator.evaluate_intent(
            action=action,
            contract=contract,
            require_intent=require_intent,
            intent_mismatch=intent_mismatch,
            delegation_context=delegation_context,
        )
        matched_rules.extend(intent_matched)

        # =============================================================
        # 2. Runtime Security Policies (Phase 1 Rules)
        # =============================================================

        # -------------------------------------------------------------
        # Rule B: Credential / Secret Exfiltration Prevention
        # Effective classifications combine server_known UNION client_declared
        # -------------------------------------------------------------
        sensitive_classifications = {
            DataClassification.SECRET,
            DataClassification.CREDENTIAL,
        }
        effective_classifications = self.tool_registry.get_effective_classifications(
            action.tool_name, action.data_classifications
        )
        has_sensitive_data = any(c in sensitive_classifications for c in effective_classifications)
        is_external_sink = tool_spec.external_sink

        if has_sensitive_data and is_external_sink:
            matched_rules.append(
                MatchedRule(
                    rule_id="RULE_B_CREDENTIAL_EXTERNAL_EXFILTRATION",
                    decision=PolicyDecision.DENY,
                    reason="Sensitive data (SECRET or CREDENTIAL) cannot be transmitted to external destinations.",
                    risk_score=0.9,
                )
            )

        # -------------------------------------------------------------
        # Rule A: Production Destructive Operation Guard
        # If target_environment == PRODUCTION and tool or action is destructive
        # -------------------------------------------------------------
        is_destructive = tool_spec.destructive or action.action_type == ActionType.DESTRUCTIVE
        if action.target_environment == TargetEnvironment.PRODUCTION and is_destructive:
            matched_rules.append(
                MatchedRule(
                    rule_id="RULE_A_PRODUCTION_DESTRUCTIVE",
                    decision=PolicyDecision.REQUIRE_APPROVAL,
                    reason="Destructive operations targeting PRODUCTION environments require explicit human approval.",
                    risk_score=0.75,
                )
            )

        # -------------------------------------------------------------
        # Rule C: Unknown Tool Privileged Access Guard
        # -------------------------------------------------------------
        if action.action_type != ActionType.DELEGATION and not tool_spec.known:
            if tool_spec.privileged or is_destructive or action.action_type == ActionType.EXECUTE:
                matched_rules.append(
                    MatchedRule(
                        rule_id="RULE_C_UNKNOWN_TOOL_PRIVILEGED",
                        decision=PolicyDecision.REQUIRE_APPROVAL,
                        reason=f"Unknown tool '{action.tool_name}' requesting privileged access requires human approval.",
                        risk_score=0.6,
                    )
                )

        # =============================================================
        # 3. Causal Graph Security Policies (Phase 4 Rules)
        # =============================================================
        if graph_context is not None:
            from app.schemas.enums import GraphAnalysisStatus

            # ---------------------------------------------------------
            # Graph Infrastructure / Traversal Limits (Fail-Closed)
            # ---------------------------------------------------------
            if graph_context.analysis_status == GraphAnalysisStatus.DEPTH_LIMIT_EXCEEDED:
                matched_rules.append(
                    MatchedRule(
                        rule_id="RULE_GRAPH_DEPTH_LIMIT_EXCEEDED",
                        decision=PolicyDecision.DENY,
                        reason="Causal graph traversal depth limit exceeded during analysis. Fail-closed enforced.",
                        risk_score=0.95,
                    )
                )
            elif graph_context.analysis_status == GraphAnalysisStatus.NODE_LIMIT_EXCEEDED:
                matched_rules.append(
                    MatchedRule(
                        rule_id="RULE_GRAPH_NODE_LIMIT_EXCEEDED",
                        decision=PolicyDecision.DENY,
                        reason="Causal graph traversal node limit exceeded during analysis. Fail-closed enforced.",
                        risk_score=0.95,
                    )
                )
            elif graph_context.analysis_status in (
                GraphAnalysisStatus.INVALID_GRAPH,
                GraphAnalysisStatus.CYCLE_DETECTED,
            ):
                matched_rules.append(
                    MatchedRule(
                        rule_id="RULE_GRAPH_INVALID_DAG",
                        decision=PolicyDecision.DENY,
                        reason=f"Causal graph integrity failure ({graph_context.analysis_status.value}). Fail-closed enforced.",
                        risk_score=0.99,
                    )
                )

            # ---------------------------------------------------------
            # Rule: External Transmission After Sensitive Access
            # ---------------------------------------------------------
            sensitive_ancestor_classes = {
                "CONFIDENTIAL",
                "RESTRICTED",
                "PII",
                "SECRET",
                "CREDENTIAL",
            }
            has_sensitive_ancestor = any(
                c in sensitive_ancestor_classes for c in graph_context.ancestor_data_classifications
            )
            if graph_context.analysis_complete and is_external_sink and has_sensitive_ancestor:
                matched_rules.append(
                    MatchedRule(
                        rule_id="RULE_GRAPH_EXTERNAL_AFTER_SENSITIVE_ACCESS",
                        decision=PolicyDecision.DENY,
                        reason="External transmission denied because the validated causal ancestry contains access to sensitive-classified data.",
                        risk_score=0.90,
                    )
                )

            # ---------------------------------------------------------
            # Rule: Denied Ancestor Escalation Guard
            # ---------------------------------------------------------
            is_privileged_or_destructive = (
                tool_spec.privileged
                or tool_spec.destructive
                or action.action_type in (ActionType.DESTRUCTIVE, ActionType.EXECUTE)
            )
            if (
                graph_context.analysis_complete
                and graph_context.contains_denied_ancestor
                and is_privileged_or_destructive
            ):
                matched_rules.append(
                    MatchedRule(
                        rule_id="RULE_GRAPH_DENIED_ANCESTOR_ESCALATION",
                        decision=PolicyDecision.REQUIRE_APPROVAL,
                        reason="Privileged or destructive operation attempted following a previously denied action in the causal trajectory.",
                        risk_score=0.80,
                    )
                )

            # ---------------------------------------------------------
            # Rule: Repeated Privilege Probing Guard
            # ---------------------------------------------------------
            is_current_probe = (
                not tool_spec.known
                or tool_spec.privileged
                or is_destructive
                or action.action_type == ActionType.EXECUTE
            )
            total_probe_count = graph_context.privileged_probe_count + (
                1 if is_current_probe else 0
            )
            if is_current_probe and total_probe_count >= 3:
                matched_rules.append(
                    MatchedRule(
                        rule_id="RULE_GRAPH_REPEATED_PRIVILEGE_PROBING",
                        decision=PolicyDecision.QUARANTINE,
                        reason=f"Repeated privileged or destructive probing detected in causal trajectory ({total_probe_count} attempts >= 3). Action quarantined.",
                        risk_score=0.95,
                    )
                )

            # ---------------------------------------------------------
            # Rule: Environment Escalation Guard
            # ---------------------------------------------------------
            is_high_env = action.target_environment in (
                TargetEnvironment.PRODUCTION,
                TargetEnvironment.STAGING,
            )
            if (
                graph_context.ancestor_count > 0
                and graph_context.has_lower_environment_ancestor
                and not graph_context.has_high_environment_ancestor
                and is_high_env
                and is_privileged_or_destructive
            ):
                matched_rules.append(
                    MatchedRule(
                        rule_id="RULE_GRAPH_ENVIRONMENT_ESCALATION",
                        decision=PolicyDecision.REQUIRE_APPROVAL,
                        reason="Causal trajectory escalated from development to production without prior production lineage.",
                        risk_score=0.75,
                    )
                )

        # =============================================================
        # 3. Provenance & Data Flow Security Policies (Phase 5 Rules)
        # =============================================================
        if provenance_context is not None:
            # ---------------------------------------------------------
            # Provenance Analysis Failure Guard (Fail-Closed)
            # ---------------------------------------------------------
            if (
                not provenance_context.analysis_complete
                or provenance_context.analysis_status != "SUCCESS"
            ):
                status_str = (
                    provenance_context.analysis_status.value
                    if hasattr(provenance_context.analysis_status, "value")
                    else str(provenance_context.analysis_status)
                )
                rule_id_map = {
                    "DEPTH_LIMIT_EXCEEDED": "RULE_PROVENANCE_DEPTH_LIMIT_EXCEEDED",
                    "ARTIFACT_LIMIT_EXCEEDED": "RULE_PROVENANCE_ARTIFACT_LIMIT_EXCEEDED",
                    "MISSING_ARTIFACT": "RULE_PROVENANCE_MISSING_ARTIFACT",
                    "CROSS_SESSION_REFERENCE": "RULE_PROVENANCE_CROSS_SESSION_REFERENCE",
                    "INVALID_LINEAGE": "RULE_PROVENANCE_INVALID_LINEAGE",
                    "CYCLE_DETECTED": "RULE_PROVENANCE_CYCLE_DETECTED",
                    "UNTRACKED_PAYLOAD": "RULE_PROVENANCE_UNTRACKED_EGRESS",
                }
                fail_rule_id = rule_id_map.get(status_str, "RULE_PROVENANCE_ANALYSIS_FAILED")
                matched_rules.append(
                    MatchedRule(
                        rule_id=fail_rule_id,
                        decision=PolicyDecision.DENY,
                        reason=f"Provenance analysis failed ({status_str}). Fail-closed enforced.",
                        risk_score=0.99 if "CYCLE" in status_str else 0.95,
                    )
                )

            # ---------------------------------------------------------
            # Rule: Untracked External Egress Guard
            # ---------------------------------------------------------
            if (
                tool_spec.external_sink
                and tool_spec.requires_tracked_inputs
                and provenance_context.payload_binding_required
                and not provenance_context.payload_binding_satisfied
            ):
                matched_rules.append(
                    MatchedRule(
                        rule_id="RULE_PROVENANCE_UNTRACKED_EGRESS",
                        decision=PolicyDecision.DENY,
                        reason="External egress denied: tool requires tracked input payload binding, but no valid artifact-backed payload was satisfied.",
                        risk_score=0.95,
                    )
                )

            # ---------------------------------------------------------
            # Rule: Credential to External Sink Guard
            # ---------------------------------------------------------
            if tool_spec.external_sink and provenance_context.contains_credential_input:
                matched_rules.append(
                    MatchedRule(
                        rule_id="RULE_PROVENANCE_CREDENTIAL_TO_EXTERNAL",
                        decision=PolicyDecision.DENY,
                        reason="External transmission denied: consumed input artifacts contain CREDENTIAL classified information.",
                        risk_score=0.95,
                    )
                )

            # ---------------------------------------------------------
            # Rule: Sensitive Data to External Sink Guard
            # ---------------------------------------------------------
            if tool_spec.external_sink and provenance_context.contains_sensitive_input:
                matched_rules.append(
                    MatchedRule(
                        rule_id="RULE_PROVENANCE_SENSITIVE_TO_EXTERNAL",
                        decision=PolicyDecision.DENY,
                        reason="External transmission denied: consumed input artifacts contain sensitive data classifications.",
                        risk_score=0.90,
                    )
                )

            # ---------------------------------------------------------
            # Rule: Untrusted Origin to Privileged Action Guard
            # ---------------------------------------------------------
            if provenance_context.contains_untrusted_input and is_privileged_or_destructive:
                matched_rules.append(
                    MatchedRule(
                        rule_id="RULE_PROVENANCE_UNTRUSTED_TO_PRIVILEGED",
                        decision=PolicyDecision.REQUIRE_APPROVAL,
                        reason="Privileged or destructive action consumes information with untrusted external provenance.",
                        risk_score=0.80,
                    )
                )

            # ---------------------------------------------------------
            # Rule: Unknown Origin to Privileged Action Guard
            # ---------------------------------------------------------
            if provenance_context.contains_unknown_input and is_privileged_or_destructive:
                matched_rules.append(
                    MatchedRule(
                        rule_id="RULE_PROVENANCE_UNKNOWN_TO_PRIVILEGED",
                        decision=PolicyDecision.REQUIRE_APPROVAL,
                        reason="Privileged or destructive action consumes information with unknown provenance origin.",
                        risk_score=0.75,
                    )
                )

        # =============================================================
        # Phase 6: Trajectory Governance & Action-Chain Policies
        # =============================================================
        if trajectory_context is not None:
            # 1. Trajectory Lifecycle Enforcement Rules
            if trajectory_context.trajectory_status == "QUARANTINED":
                matched_rules.append(
                    MatchedRule(
                        rule_id="RULE_TRAJECTORY_QUARANTINED",
                        decision=PolicyDecision.DENY,
                        reason="Action rejected because trajectory is in QUARANTINED containment state.",
                        risk_score=1.0,
                    )
                )

            if trajectory_context.trajectory_status == "ABORTED":
                matched_rules.append(
                    MatchedRule(
                        rule_id="RULE_TRAJECTORY_ABORTED",
                        decision=PolicyDecision.DENY,
                        reason="Action rejected because trajectory has been permanently ABORTED.",
                        risk_score=1.0,
                    )
                )

            # 2. Trajectory Traversal Limits & Fail-Closed Errors
            if not trajectory_context.analysis_complete:
                status_str = (
                    trajectory_context.analysis_status.value
                    if hasattr(trajectory_context.analysis_status, "value")
                    else str(trajectory_context.analysis_status)
                )
                rule_map = {
                    "ACTION_DEPTH_LIMIT_EXCEEDED": (
                        "RULE_TRAJECTORY_ACTION_DEPTH_LIMIT_EXCEEDED",
                        "Trajectory action traversal depth exceeded safety limits.",
                    ),
                    "ARTIFACT_DEPTH_LIMIT_EXCEEDED": (
                        "RULE_TRAJECTORY_ARTIFACT_DEPTH_LIMIT_EXCEEDED",
                        "Trajectory artifact derivation depth exceeded safety limits.",
                    ),
                    "NODE_LIMIT_EXCEEDED": (
                        "RULE_TRAJECTORY_NODE_LIMIT_EXCEEDED",
                        "Trajectory graph traversal node limit exceeded safety limits.",
                    ),
                    "INVALID_TYPED_PATH": (
                        "RULE_TRAJECTORY_INVALID_TYPED_PATH",
                        "Trajectory contains invalid or broken typed edge relations.",
                    ),
                    "MISSING_GRAPH_EVIDENCE": (
                        "RULE_TRAJECTORY_MISSING_GRAPH_EVIDENCE",
                        "Trajectory causal history contains missing or corrupted graph nodes.",
                    ),
                    "INCONSISTENT_PROVENANCE": (
                        "RULE_TRAJECTORY_INCONSISTENT_PROVENANCE",
                        "Trajectory references inconsistent or missing provenance artifacts.",
                    ),
                }
                rule_id, reason = rule_map.get(
                    status_str,
                    ("RULE_TRAJECTORY_ANALYSIS_FAILED", "Trajectory security analysis failed."),
                )
                matched_rules.append(
                    MatchedRule(
                        rule_id=rule_id,
                        decision=PolicyDecision.DENY,
                        reason=reason,
                        risk_score=0.95,
                    )
                )

            # 3. Flagship Trajectory Security Policies
            if trajectory_context.analysis_complete:
                # Flagship 1: Untrusted causal path leading to sensitive internal access
                if trajectory_context.untrusted_path_to_sensitive_access:
                    matched_rules.append(
                        MatchedRule(
                            rule_id="RULE_TRAJECTORY_UNTRUSTED_PATH_TO_SENSITIVE_ACCESS",
                            decision=PolicyDecision.REQUIRE_APPROVAL,
                            reason="Externally untrusted information participated in the validated causal trajectory leading to sensitive access.",
                            risk_score=0.85,
                        )
                    )

                # Flagship 2: Untrusted causal path leading to sensitive external egress
                if trajectory_context.untrusted_path_to_sensitive_egress:
                    matched_rules.append(
                        MatchedRule(
                            rule_id="RULE_TRAJECTORY_UNTRUSTED_PATH_TO_SENSITIVE_EGRESS",
                            decision=PolicyDecision.DENY,
                            reason="Validated causal trajectory connects externally untrusted origin to sensitive external egress sink.",
                            risk_score=0.95,
                        )
                    )

                # Flagship 3: Information cannot expand authority
                if (
                    trajectory_context.unauthorized_authority_expansion_attempted
                    and trajectory_context.untrusted_path_to_current_action
                ):
                    matched_rules.append(
                        MatchedRule(
                            rule_id="RULE_TRAJECTORY_INFORMATION_CANNOT_EXPAND_AUTHORITY",
                            decision=PolicyDecision.DENY,
                            reason="Untrusted information on causal trajectory attempted unauthorized authority expansion.",
                            risk_score=0.90,
                        )
                    )

                # Flagship 4: Cumulative sensitive egress attempts threshold exceeded
                if trajectory_context.split_exfiltration_threshold_exceeded:
                    matched_rules.append(
                        MatchedRule(
                            rule_id="RULE_TRAJECTORY_CUMULATIVE_SENSITIVE_EGRESS",
                            decision=PolicyDecision.QUARANTINE,
                            reason="Cumulative sensitive egress attempts or volume exceeded safety thresholds; quarantining trajectory.",
                            risk_score=0.95,
                        )
                    )

                # Flagship 5: Sensitive hop laundering
                if trajectory_context.sensitive_hop_laundering_detected:
                    matched_rules.append(
                        MatchedRule(
                            rule_id="RULE_TRAJECTORY_SENSITIVE_HOP_LAUNDERING",
                            decision=PolicyDecision.DENY,
                            reason="Sensitive information traversed multi-hop transformation sequence before exiting to external sink.",
                            risk_score=0.90,
                        )
                    )

        # =============================================================
        # 5. Multi-Agent Delegation Rules (Phase 8 Rules)
        # =============================================================
        if delegation_context is not None and delegation_context.is_delegated:
            op = delegation_context.operation

            if op == "CREATE_GRANT":
                if not delegation_context.caller_is_authorized_issuer:
                    matched_rules.append(
                        MatchedRule(
                            rule_id="RULE_DELEGATION_CALLER_NOT_AUTHORIZED",
                            decision=PolicyDecision.DENY,
                            reason="Caller principal is not authorized to issue this delegation grant.",
                            risk_score=1.0,
                        )
                    )
                if (
                    delegation_context.parent_delegation_id is not None
                    and not delegation_context.parent_grant_valid
                ):
                    matched_rules.append(
                        MatchedRule(
                            rule_id="RULE_DELEGATION_INVALID_PARENT",
                            decision=PolicyDecision.DENY,
                            reason="Referenced parent delegation grant does not exist or is invalid.",
                            risk_score=1.0,
                        )
                    )
                if not delegation_context.cross_session_match:
                    matched_rules.append(
                        MatchedRule(
                            rule_id="RULE_DELEGATION_CROSS_SESSION",
                            decision=PolicyDecision.DENY,
                            reason="Delegation proposal references an intent or parent from a different session.",
                            risk_score=1.0,
                        )
                    )
                if (
                    delegation_context.parent_delegation_id is not None
                    and not delegation_context.subdelegation_allowed
                ):
                    matched_rules.append(
                        MatchedRule(
                            rule_id="RULE_DELEGATION_SUBDELEGATION_NOT_ALLOWED",
                            decision=PolicyDecision.DENY,
                            reason="Parent delegation grant explicitly prohibits creating child subdelegations.",
                            risk_score=0.95,
                        )
                    )
                if not delegation_context.depth_within_limits:
                    matched_rules.append(
                        MatchedRule(
                            rule_id="RULE_DELEGATION_DEPTH_EXCEEDED",
                            decision=PolicyDecision.DENY,
                            reason="Requested delegation depth exceeds maximum allowed session depth.",
                            risk_score=0.95,
                        )
                    )
                if not delegation_context.scope_within_parent:
                    matched_rules.append(
                        MatchedRule(
                            rule_id="RULE_DELEGATION_SCOPE_EXCEEDS_PARENT",
                            decision=PolicyDecision.DENY,
                            reason="Requested delegation authority exceeds parent grant envelope.",
                            risk_score=1.0,
                        )
                    )
                if not delegation_context.scope_within_root:
                    matched_rules.append(
                        MatchedRule(
                            rule_id="RULE_DELEGATION_SCOPE_EXCEEDS_ROOT",
                            decision=PolicyDecision.DENY,
                            reason="Requested delegation authority exceeds root Intent Contract scope.",
                            risk_score=1.0,
                        )
                    )
                if (
                    delegation_context.is_high_risk_delegation
                    and delegation_context.caller_is_authorized_issuer
                    and delegation_context.scope_within_root
                    and delegation_context.scope_within_parent
                    and delegation_context.depth_within_limits
                    and delegation_context.cross_session_match
                ):
                    matched_rules.append(
                        MatchedRule(
                            rule_id="RULE_DELEGATION_REQUIRE_APPROVAL",
                            decision=PolicyDecision.REQUIRE_APPROVAL,
                            reason="Delegation grants high-risk or approval-required capabilities.",
                            risk_score=0.7,
                        )
                    )

            elif op == "EXECUTE_ACTION":
                if not delegation_context.principal_matches_delegatee:
                    matched_rules.append(
                        MatchedRule(
                            rule_id="RULE_DELEGATION_PRINCIPAL_MISMATCH",
                            decision=PolicyDecision.DENY,
                            reason="Authenticated caller principal does not match grant delegatee.",
                            risk_score=1.0,
                        )
                    )
                if delegation_context.effective_status == "REVOKED":
                    matched_rules.append(
                        MatchedRule(
                            rule_id="RULE_DELEGATION_REVOKED",
                            decision=PolicyDecision.DENY,
                            reason="Delegation grant or an ancestor in its chain has been REVOKED.",
                            risk_score=1.0,
                        )
                    )
                elif delegation_context.effective_status == "CLOSED":
                    matched_rules.append(
                        MatchedRule(
                            rule_id="RULE_DELEGATION_CLOSED",
                            decision=PolicyDecision.DENY,
                            reason="Delegation grant has been CLOSED upon completed task.",
                            risk_score=0.95,
                        )
                    )
                elif delegation_context.effective_status == "EXPIRED":
                    matched_rules.append(
                        MatchedRule(
                            rule_id="RULE_DELEGATION_EXPIRED",
                            decision=PolicyDecision.DENY,
                            reason="Delegation grant TTL has expired.",
                            risk_score=0.95,
                        )
                    )
                elif delegation_context.effective_status == "CONSUMED":
                    matched_rules.append(
                        MatchedRule(
                            rule_id="RULE_DELEGATION_BUDGET_EXHAUSTED",
                            decision=PolicyDecision.DENY,
                            reason="Delegation grant action execution budget has been exhausted.",
                            risk_score=0.95,
                        )
                    )
                elif delegation_context.effective_status == "ROOT_INVALID":
                    matched_rules.append(
                        MatchedRule(
                            rule_id="RULE_DELEGATION_ROOT_INTENT_INVALID",
                            decision=PolicyDecision.DENY,
                            reason="Root Intent Contract is inactive, expired, or revoked.",
                            risk_score=1.0,
                        )
                    )
                elif delegation_context.effective_status == "ANCESTOR_INVALID":
                    matched_rules.append(
                        MatchedRule(
                            rule_id="RULE_DELEGATION_INVALID_PARENT",
                            decision=PolicyDecision.DENY,
                            reason="An ancestor grant in the delegation hierarchy is expired, consumed, or invalid.",
                            risk_score=1.0,
                        )
                    )

                if not delegation_context.budget_available:
                    matched_rules.append(
                        MatchedRule(
                            rule_id="RULE_DELEGATION_BUDGET_EXHAUSTED",
                            decision=PolicyDecision.DENY,
                            reason="Action budget on root intent or ancestor grant has been exhausted.",
                            risk_score=0.95,
                        )
                    )
                if not delegation_context.current_tool_within_effective_authority:
                    matched_rules.append(
                        MatchedRule(
                            rule_id="RULE_DELEGATION_TOOL_NOT_AUTHORIZED",
                            decision=PolicyDecision.DENY,
                            reason="Requested tool is not authorized under live effective delegation authority.",
                            risk_score=1.0,
                        )
                    )
                if not delegation_context.current_resource_within_effective_authority:
                    matched_rules.append(
                        MatchedRule(
                            rule_id="RULE_DELEGATION_RESOURCE_NOT_AUTHORIZED",
                            decision=PolicyDecision.DENY,
                            reason="Target resource is not authorized under live effective delegation scope.",
                            risk_score=1.0,
                        )
                    )
                if not delegation_context.current_environment_within_effective_authority:
                    matched_rules.append(
                        MatchedRule(
                            rule_id="RULE_DELEGATION_ENVIRONMENT_NOT_AUTHORIZED",
                            decision=PolicyDecision.DENY,
                            reason="Target environment is not authorized under live effective delegation scope.",
                            risk_score=1.0,
                        )
                    )
                if not delegation_context.current_classification_within_effective_authority:
                    matched_rules.append(
                        MatchedRule(
                            rule_id="RULE_DELEGATION_CLASSIFICATION_NOT_AUTHORIZED",
                            decision=PolicyDecision.DENY,
                            reason="Data classification exceeds live effective delegation limits.",
                            risk_score=1.0,
                        )
                    )

            elif op == "RESOLVE_APPROVAL":
                appr = delegation_context.approval
                if appr.approval_context_present:
                    if not appr.approval_identity_match:
                        matched_rules.append(
                            MatchedRule(
                                rule_id="RULE_DELEGATION_APPROVAL_IDENTITY_MISMATCH",
                                decision=PolicyDecision.DENY,
                                reason="Approver identity does not match designated approver for delegation checkpoint.",
                                risk_score=1.0,
                            )
                        )
                    if not appr.approval_revalidation_passed:
                        matched_rules.append(
                            MatchedRule(
                                rule_id="RULE_DELEGATION_APPROVAL_STALE_AUTHORITY",
                                decision=PolicyDecision.DENY,
                                reason="Pre-execution revalidation failed; root intent or parent authority was modified or revoked.",
                                risk_score=1.0,
                            )
                        )

            elif op == "REVOKE_GRANT":
                if not delegation_context.caller_is_authorized_to_revoke:
                    matched_rules.append(
                        MatchedRule(
                            rule_id="RULE_DELEGATION_REVOCATION_NOT_AUTHORIZED",
                            decision=PolicyDecision.DENY,
                            reason="Caller is not authorized to revoke this delegation grant.",
                            risk_score=1.0,
                        )
                    )

            if delegation_context.analysis_status == "FAILED":
                matched_rules.append(
                    MatchedRule(
                        rule_id="RULE_DELEGATION_ANALYSIS_FAILED",
                        decision=PolicyDecision.DENY,
                        reason="Delegation analysis failed or delegation invariants could not be verified.",
                        risk_score=1.0,
                    )
                )

        # -------------------------------------------------------------
        # Rule D: Normal Low-Risk Baseline
        # Applies only if no restrictive rules triggered and intent didn't already match
        # -------------------------------------------------------------
        if not matched_rules:
            matched_rules.append(
                MatchedRule(
                    rule_id="RULE_D_NORMAL_LOW_RISK",
                    decision=PolicyDecision.ALLOW,
                    reason="Action conforms to standard low-risk policy baselines.",
                    risk_score=0.1,
                )
            )

        # =============================================================
        # 3. Precedence Resolution
        # Precedence order: DENY > QUARANTINE > SANDBOX > REQUIRE_APPROVAL > ALLOW_WITH_LIMITS > ALLOW
        # =============================================================
        primary_match = max(matched_rules, key=lambda r: r.decision.severity_rank)
        resolved_decision = primary_match.decision
        resolved_reason = primary_match.reason
        max_risk = max(r.risk_score for r in matched_rules)
        rule_ids = [r.rule_id for r in matched_rules]
        requires_approval = resolved_decision == PolicyDecision.REQUIRE_APPROVAL

        return SecurityDecision(
            action_id=action.action_id,
            session_id=action.session_id,
            intent_contract_id=contract.intent_id if contract else None,
            decision=resolved_decision,
            reason=resolved_reason,
            matched_rules=rule_ids,
            risk_score=round(max_risk, 2),
            requires_human_approval=requires_approval,
        )


# Global default instance
default_policy_evaluator = DeterministicPolicyEvaluator()
