"""Agent Gateway service coordinating action ingestion, graph recording, intent validation, and policy evaluation."""

import logging
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

from app.gateway.registry import ToolRegistry, default_tool_registry
from app.gateway.tools import ToolExecutor, ToolRequest, ToolResult, default_tool_executor
from app.graph.analyzer import GraphSecurityAnalyzer, default_graph_security_analyzer
from app.graph.causal_graph import (
    CrossSessionParentError,
    ParentActionNotFoundError,
    SessionGraphManager,
    default_session_graph_manager,
)
from app.intent.service import IntentService, default_intent_service
from app.policies.engine import PolicyEngine, default_policy_engine

if TYPE_CHECKING:
    from app.delegation.service import DelegationService
from app.identity.principal import AgentPrincipal, PrincipalAuthenticationSource
from app.policies.policy_input import build_cage_policy_input, build_delegated_action_context
from app.policies.rules import DeterministicPolicyEvaluator
from app.provenance.analyzer import ProvenanceAnalyzer, default_provenance_analyzer
from app.provenance.factory import ArtifactFactory, default_artifact_factory
from app.provenance.resources import (
    ResourceSecurityProfileRegistry,
    default_resource_registry,
)
from app.provenance.store import ProvenanceStore, default_provenance_store
from app.schemas.action import AgentAction, AgentActionProposal
from app.schemas.decision import SecurityDecision
from app.schemas.enums import (
    DataClassification,
    GraphRelation,
    PayloadBindingMode,
    PolicyBackend,
    PolicyDecision,
    ToolExecutionStatus,
    TrajectoryStatus,
)
from app.schemas.policy import PolicyDelegationContext
from app.trajectory.analyzer import TrajectoryAnalyzer, default_trajectory_analyzer
from app.trajectory.models import ControlPlaneAuthContext
from app.trajectory.store import TrajectoryStore, default_trajectory_store

logger = logging.getLogger("cage.gateway")


class AgentGateway:
    """Core gateway mediating agent actions, recording causal graphs, and evaluating policies.

    STRICT BY DEFAULT:
    By default, require_intent=True mandates that actions must be authorized by an active Intent Contract.
    """

    def __init__(
        self,
        graph_manager: SessionGraphManager | None = None,
        policy_evaluator: DeterministicPolicyEvaluator | None = None,
        policy_engine: PolicyEngine | None = None,
        intent_service: IntentService | None = None,
        tool_registry: ToolRegistry | None = None,
        tool_executor: ToolExecutor | None = None,
        graph_analyzer: GraphSecurityAnalyzer | None = None,
        provenance_store: ProvenanceStore | None = None,
        provenance_analyzer: ProvenanceAnalyzer | None = None,
        artifact_factory: ArtifactFactory | None = None,
        resource_registry: ResourceSecurityProfileRegistry | None = None,
        trajectory_store: TrajectoryStore | None = None,
        trajectory_analyzer: TrajectoryAnalyzer | None = None,
        delegation_service: DelegationService | None = None,
        require_intent: bool = True,
    ) -> None:
        self.graph_manager = graph_manager or default_session_graph_manager
        self.intent_service = intent_service or default_intent_service
        self.tool_registry = tool_registry or default_tool_registry
        self.tool_executor = tool_executor or default_tool_executor
        self.graph_analyzer = graph_analyzer or default_graph_security_analyzer
        self.provenance_store = provenance_store or default_provenance_store
        self.provenance_analyzer = (
            provenance_analyzer
            if provenance_analyzer is not None
            else (
                ProvenanceAnalyzer(store=self.provenance_store)
                if provenance_store is not None
                else default_provenance_analyzer
            )
        )
        self.artifact_factory = artifact_factory or default_artifact_factory
        self.resource_registry = resource_registry or default_resource_registry
        self.trajectory_store = trajectory_store or (
            TrajectoryStore()
            if intent_service is not None or graph_manager is not None
            else default_trajectory_store
        )
        self.trajectory_analyzer = trajectory_analyzer or default_trajectory_analyzer
        if delegation_service is not None:
            self.delegation_service = delegation_service
        else:
            from app.delegation.service import default_delegation_service

            self.delegation_service = default_delegation_service
        self.require_intent = require_intent

        if policy_engine is not None:
            self.policy_engine = policy_engine
            self.policy_evaluator = policy_engine.python_evaluator
        elif policy_evaluator is not None:
            self.policy_evaluator = policy_evaluator
            self.policy_engine = PolicyEngine(
                python_evaluator=policy_evaluator, backend=PolicyBackend.PYTHON
            )
        else:
            self.policy_engine = default_policy_engine
            self.policy_evaluator = default_policy_engine.python_evaluator

    def evaluate_proposal(
        self,
        proposal: AgentActionProposal,
        principal: AgentPrincipal | None = None,
    ) -> tuple[AgentAction, SecurityDecision]:
        """Ingest, validate, record in causal graph, and evaluate an AgentActionProposal.

        Lifecycle:
        1. Look up authoritative Intent Contract bound to the session.
        2. Validate parent and previous references in causal graph.
        3. Validate trajectory continuation and sovereign binding.
        4. Create authoritative AgentAction with server-generated UUID.
        5. Record proposed action and Intent node in causal graph.
        6. Link causal edges (Intent -> Action and Parent Action -> Current Action).
        7. Evaluate unified Intent rules and runtime policies with precedence.
        8. If ALLOWed, atomically reserve a tool execution budget slot.
        9. Update action node in graph with final verdict and execution status.
        10. Return authoritative action and SecurityDecision.
        """
        session_id = proposal.session_id
        graph = self.graph_manager.get_or_create(session_id)

        # 1. Authoritative server-side Intent Contract lookup
        contract = self.intent_service.get_intent_for_session(session_id)

        # Verify client correlation if client supplied an intent_contract_id
        intent_mismatch = False
        if proposal.intent_contract_id is not None:
            try:
                proposal_cid = (
                    UUID(str(proposal.intent_contract_id))
                    if not isinstance(proposal.intent_contract_id, UUID)
                    else proposal.intent_contract_id
                )
            except (ValueError, TypeError):
                proposal_cid = None

            if contract is None or contract.intent_id != proposal_cid:
                intent_mismatch = True

        # 2. Parent relationship validation in causal execution graph
        if proposal.parent_action_id is not None:
            parent_key = str(proposal.parent_action_id)
            if not graph.graph.has_node(parent_key):
                if self.graph_manager.get_action_globally(parent_key) is not None:
                    raise CrossSessionParentError(
                        f"Parent action '{parent_key}' belongs to a different session. "
                        f"Cross-session parentage is prohibited."
                    )
                raise ParentActionNotFoundError(
                    f"Parent action '{parent_key}' not found in session '{session_id}'."
                )

        for prev_id in proposal.previous_action_ids:
            prev_key = str(prev_id)
            if not graph.graph.has_node(prev_key):
                if self.graph_manager.get_action_globally(prev_key) is not None:
                    raise CrossSessionParentError(
                        f"Previous action '{prev_key}' belongs to another session."
                    )
                raise ParentActionNotFoundError(
                    f"Referenced previous action '{prev_key}' not found in session '{session_id}'."
                )

        # 3. Phase 6 Trajectory Continuation Check & Sovereign Binding
        trajectory_snapshot = None
        action_id = uuid4()
        trajectory_id: UUID | None = None

        if contract is not None:
            trajectory_snapshot, _ = self.trajectory_store.get_or_create_trajectory(
                contract, agent_id=proposal.agent_id
            )
            trajectory_id = trajectory_snapshot.trajectory_id

            # Check if pending approval is blocking the trajectory
            if trajectory_snapshot.pending_approval_action_id is not None:
                action = AgentAction.from_proposal(
                    proposal, action_id=action_id, trajectory_id=trajectory_id
                )
                action.policy_result = PolicyDecision.DENY
                action.execution_status = ToolExecutionStatus.DENIED
                action.matched_rules = ["RULE_TRAJECTORY_APPROVAL_PENDING"]
                action.security_reason = (
                    "Action rejected: Trajectory has an unresolved pending approval checkpoint."
                )
                decision = SecurityDecision(
                    action_id=action.action_id,
                    session_id=action.session_id,
                    intent_contract_id=contract.intent_id,
                    decision=PolicyDecision.DENY,
                    reason=action.security_reason,
                    matched_rules=action.matched_rules,
                    risk_score=0.90,
                    requires_human_approval=False,
                    policy_backend=self.policy_engine.backend,
                    policy_version=self.policy_engine.policy_version,
                    policy_input_schema_version=self.policy_engine.schema_version,
                )
                return action, decision

            # Enforce strict linear continuation
            valid_cont, cont_reason = self.trajectory_store.validate_continuation(
                trajectory_id=trajectory_snapshot.trajectory_id,
                action_id=action_id,
                parent_action_id=proposal.parent_action_id,
            )
            if not valid_cont:
                action = AgentAction.from_proposal(
                    proposal, action_id=action_id, trajectory_id=trajectory_id
                )
                action.policy_result = PolicyDecision.DENY
                action.execution_status = ToolExecutionStatus.DENIED
                action.matched_rules = ["RULE_TRAJECTORY_INVALID_CONTINUATION"]
                action.security_reason = cont_reason or "Invalid trajectory continuation."
                decision = SecurityDecision(
                    action_id=action.action_id,
                    session_id=action.session_id,
                    intent_contract_id=contract.intent_id,
                    decision=PolicyDecision.DENY,
                    reason=action.security_reason,
                    matched_rules=action.matched_rules,
                    risk_score=0.95,
                    requires_human_approval=False,
                    policy_backend=self.policy_engine.backend,
                    policy_version=self.policy_engine.policy_version,
                    policy_input_schema_version=self.policy_engine.schema_version,
                )
                return action, decision

        # 4. Create server-authoritative AgentAction
        action = AgentAction.from_proposal(
            proposal, action_id=action_id, trajectory_id=trajectory_id
        )
        if (
            contract is not None
            and contract.session_id == session_id
            and (contract.agent_id == proposal.agent_id or proposal.delegation_id is not None)
            and not intent_mismatch
        ):
            action.intent_contract_id = contract.intent_id
        else:
            action.intent_contract_id = None

        action_key = str(action.action_id)

        # 5. Record Intent node and Action node in graph BEFORE evaluation (forensic visibility)
        if contract is not None:
            graph.add_intent_node(
                intent_id=str(contract.intent_id),
                goal=contract.goal,
                agent_id=contract.agent_id,
                user_id=contract.user_id,
                created_at=contract.created_at.isoformat(),
            )

        # Look up tool spec and effective classifications for snapshotted metadata
        tool_spec = self.tool_registry.get(action.tool_name)
        effective_classifications = [
            c.value
            for c in self.tool_registry.get_effective_classifications(
                action.tool_name, action.data_classifications
            )
        ]

        graph.add_action(
            action,
            tool_spec=tool_spec,
            effective_data_classifications=effective_classifications,
            policy_version=self.policy_engine.policy_version,
            policy_input_schema_version=self.policy_engine.schema_version,
        )
        self.graph_manager.register_action_session(action_key, session_id)

        if contract is not None:
            graph.add_governs_edge(str(contract.intent_id), action_key)

        if proposal.parent_action_id is not None:
            graph.add_relationship(
                str(proposal.parent_action_id), action_key, relation=GraphRelation.CAUSES
            )

        for prev_id in proposal.previous_action_ids:
            graph.add_relationship(str(prev_id), action_key, relation="precedes")

        # 6. Derive authoritative graph security context
        graph_context = self.graph_analyzer.analyze_action_causality(
            graph=graph,
            parent_action_id=str(proposal.parent_action_id)
            if proposal.parent_action_id is not None
            else None,
        )

        # 7. Derive authoritative provenance security context
        provenance_context, validated_artifacts = self.provenance_analyzer.analyze_provenance(
            proposal=proposal,
            tool_spec=tool_spec,
        )
        action.validated_input_artifact_ids = [a.artifact_id for a in validated_artifacts]

        # 8. Cumulative Bound Sensitive Egress Accounting (Phase 6)
        bound_sensitive_artifacts = []
        if trajectory_snapshot is not None:
            outbound_aids: set[UUID] = set()
            for field_name, aid_str in provenance_context.resolved_payload_bindings.items():
                if field_name in tool_spec.payload_argument_names:
                    try:
                        outbound_aids.add(
                            UUID(aid_str) if not isinstance(aid_str, UUID) else aid_str
                        )
                    except (ValueError, TypeError):
                        pass

            sensitive_tiers = {
                DataClassification.CONFIDENTIAL,
                DataClassification.RESTRICTED,
                DataClassification.PII,
                DataClassification.SECRET,
                DataClassification.CREDENTIAL,
            }
            total_egress_bytes = 0
            for aid in outbound_aids:
                art = self.provenance_store.get_artifact(aid)
                if art is not None:
                    if art.data_classifications & sensitive_tiers:
                        bound_sensitive_artifacts.append(art)
                        total_egress_bytes += art.size_bytes or 0

            if tool_spec.external_sink and bound_sensitive_artifacts:
                self.trajectory_store.record_sensitive_egress_attempt(
                    trajectory_id=trajectory_snapshot.trajectory_id,
                    action_id=action.action_id,
                    payload_bytes=total_egress_bytes,
                )
                # Refresh snapshot with updated counters
                trajectory_snapshot = self.trajectory_store.get_snapshot(
                    trajectory_snapshot.trajectory_id
                )

        # 9. Derive authoritative trajectory security context
        trajectory_context = None
        if trajectory_snapshot is not None:
            trajectory_context = self.trajectory_analyzer.analyze(
                action=action,
                trajectory=trajectory_snapshot,
                tool_spec=tool_spec,
                causal_graph=graph,
                provenance_store=self.provenance_store,
                resource_registry=self.resource_registry,
                validated_input_artifacts=validated_artifacts,
                bound_outbound_artifacts=bound_sensitive_artifacts,
            )

        # 9b. Derive authoritative delegation security context (Phase 8)
        delegation_context = PolicyDelegationContext(operation="NONE", is_delegated=False)
        resolved_delegation_id = None
        if proposal.delegation_id is not None:
            grant = self.delegation_service.get_delegation_grant(proposal.delegation_id)
            if (
                grant is not None
                and str(grant.session_id) == str(session_id)
                and contract is not None
                and grant.root_intent_id == contract.intent_id
            ):
                grants, states = self.delegation_service.store.get_chain_with_states(
                    proposal.delegation_id
                )
                target_grant = grants[-1]
                target_state = states[-1]
                ancestor_grants = grants[:-1]
                ancestor_states = states[:-1]
                effective_principal = principal
                if effective_principal is None:
                    effective_principal = AgentPrincipal(
                        agent_id=proposal.agent_id,
                        session_id=UUID(str(session_id)),
                        authentication_source=PrincipalAuthenticationSource.HOSTING_RUNTIME,
                    )
                delegation_context = build_delegated_action_context(
                    action=action,
                    principal=effective_principal,
                    grant=target_grant,
                    runtime_state=target_state,
                    root_intent=contract,
                    ancestors=ancestor_grants,
                    ancestor_states=ancestor_states,
                    analyzer=self.delegation_service.analyzer,
                )
                resolved_delegation_id = target_grant.delegation_id
                graph.add_delegation_governs_edge(str(target_grant.delegation_id), action_key)
            else:
                delegation_context = PolicyDelegationContext(
                    operation="EXECUTE_ACTION",
                    is_delegated=True,
                    effective_status="REVOKED",
                    principal_matches_delegatee=False,
                )
                if contract is not None and proposal.agent_id != contract.agent_id:
                    intent_mismatch = True
        elif contract is not None and proposal.agent_id != contract.agent_id:
            intent_mismatch = True

        action.delegation_id = resolved_delegation_id

        # 10. Build single canonical CagePolicyInput document
        policy_input = build_cage_policy_input(
            action=action,
            contract=contract,
            tool_registry=self.tool_registry,
            require_intent=self.require_intent,
            intent_mismatch=intent_mismatch,
            graph_context=graph_context,
            provenance_context=provenance_context,
            trajectory_context=trajectory_context,
            delegation_context=delegation_context,
        )

        # 11. Policy evaluation (Unified Python / OPA via PolicyEngine)
        decision, parity_result = self.policy_engine.evaluate(
            policy_input=policy_input,
            action=action,
            contract=contract,
        )

        # 12. Trajectory Post-Evaluation Updates
        if trajectory_snapshot is not None:
            self.trajectory_store.record_action_evaluation(
                trajectory_id=trajectory_snapshot.trajectory_id,
                action_id=action.action_id,
            )
            if decision.decision == PolicyDecision.REQUIRE_APPROVAL:
                self.trajectory_store.set_pending_approval(
                    trajectory_id=trajectory_snapshot.trajectory_id,
                    action_id=action.action_id,
                )
            # If cumulative sensitive egress rule matched, quarantine the trajectory
            if (
                "RULE_TRAJECTORY_CUMULATIVE_SENSITIVE_EGRESS" in decision.matched_rules
                or decision.decision == PolicyDecision.QUARANTINE
            ):
                self.trajectory_store.mark_quarantined(trajectory_snapshot.trajectory_id)

        # 13. Atomic Tool Execution Budget Reservation
        if decision.decision == PolicyDecision.ALLOW:
            if action.delegation_id is not None:
                delegation_reserved = self.delegation_service.store.reserve_action_dispatch(
                    action.delegation_id
                )
                if not delegation_reserved:
                    decision = SecurityDecision(
                        action_id=action.action_id,
                        session_id=action.session_id,
                        intent_contract_id=contract.intent_id if contract else None,
                        decision=PolicyDecision.DENY,
                        reason="Action budget on root intent or ancestor grant has been exhausted.",
                        matched_rules=decision.matched_rules + ["RULE_DELEGATION_BUDGET_EXHAUSTED"],
                        risk_score=0.95,
                        requires_human_approval=False,
                        policy_backend=decision.policy_backend,
                        policy_version=decision.policy_version,
                        policy_input_schema_version=decision.policy_input_schema_version,
                    )
            if decision.decision == PolicyDecision.ALLOW and contract is not None:
                reserved = self.intent_service.reserve_tool_execution(contract.intent_id)
                if not reserved:
                    decision = SecurityDecision(
                        action_id=action.action_id,
                        session_id=action.session_id,
                        intent_contract_id=contract.intent_id,
                        decision=PolicyDecision.DENY,
                        reason=f"Tool call budget exceeded: {contract.tool_calls_count}/{contract.maximum_tool_calls} executions consumed.",
                        matched_rules=decision.matched_rules + ["RULE_TOOL_BUDGET_EXCEEDED"],
                        risk_score=0.85,
                        requires_human_approval=False,
                        policy_backend=decision.policy_backend,
                        policy_version=decision.policy_version,
                        policy_input_schema_version=decision.policy_input_schema_version,
                    )

        # 14. Map verdict to execution status
        if decision.decision == PolicyDecision.ALLOW:
            execution_status = ToolExecutionStatus.AUTHORIZED
        elif decision.decision == PolicyDecision.REQUIRE_APPROVAL:
            execution_status = ToolExecutionStatus.PENDING_APPROVAL
        else:
            execution_status = ToolExecutionStatus.DENIED

        # 15. Update action state in graph and internal storage
        graph.update_action_state(
            action_id=action_key,
            execution_status=execution_status,
            policy_result=decision.decision,
            security_reason=decision.reason,
            matched_rules=decision.matched_rules,
            risk_score=decision.risk_score,
            policy_version=decision.policy_version,
            policy_input_schema_version=decision.policy_input_schema_version,
        )

        logger.info(
            "Action evaluated: action_id=%s tool=%s decision=%s rules=%s intent=%s backend=%s version=%s",
            action.action_id,
            action.tool_name,
            decision.decision.value,
            decision.matched_rules,
            decision.intent_contract_id,
            decision.policy_backend.value if decision.policy_backend else "UNKNOWN",
            decision.policy_version or "UNKNOWN",
        )

        return action, decision

    def resolve_pending_approval(
        self,
        action_id: UUID,
        approved: bool,
        trajectory_id: UUID | None = None,
        control_plane_context: ControlPlaneAuthContext | None = None,
    ) -> tuple[AgentAction, dict | None]:
        """Resolve a pending approval checkpoint from trusted control plane with full authority revalidation."""
        action_key = str(action_id)
        action = self.graph_manager.get_action_globally(action_key)
        if action is None:
            raise KeyError(f"Action '{action_key}' not found.")

        graph = self.graph_manager.get(action.session_id)
        if graph is None:
            raise KeyError(f"Session '{action.session_id}' not found.")

        resolved_traj_id = (
            trajectory_id
            or action.trajectory_id
            or self.trajectory_store.get_trajectory_id_for_session(action.session_id)
        )
        if resolved_traj_id is None:
            raise KeyError(f"Trajectory not found for action '{action_key}'.")

        snapshot = self.trajectory_store.get_snapshot(resolved_traj_id)
        if snapshot is None:
            raise KeyError(f"Trajectory '{resolved_traj_id}' not found.")

        if snapshot.pending_approval_action_id != action_id:
            raise PermissionError(
                f"Action '{action_id}' is not the pending approval action on trajectory '{resolved_traj_id}'."
            )

        if not approved:
            # Rejection: clear pending approval checkpoint, mark action DENIED
            self.trajectory_store.clear_pending_approval(resolved_traj_id, action_id)
            graph.update_action_state(
                action_id=action_key,
                execution_status=ToolExecutionStatus.DENIED,
                policy_result=PolicyDecision.DENY,
                security_reason="Human approval was explicitly rejected by control plane.",
            )
            action.execution_status = ToolExecutionStatus.DENIED
            action.policy_result = PolicyDecision.DENY
            action.security_reason = "Human approval was explicitly rejected by control plane."
            return action, None

        # -------------------------------------------------------------
        # Revalidation checks at T2 approval execution
        # -------------------------------------------------------------
        # A & B: Trajectory exists and is ACTIVE
        if snapshot.status != TrajectoryStatus.ACTIVE:
            self.trajectory_store.clear_pending_approval(resolved_traj_id, action_id)
            action.execution_status = ToolExecutionStatus.DENIED
            action.policy_result = PolicyDecision.DENY
            action.security_reason = (
                f"Approval execution rejected: Trajectory is {snapshot.status.value}."
            )
            graph.update_action_state(
                action_id=action_key,
                execution_status=action.execution_status,
                policy_result=action.policy_result,
                security_reason=action.security_reason,
            )
            raise ValueError(action.security_reason)

        # E, F, G, H: Associated Intent Contract active, not expired, not revoked
        contract = self.intent_service.get_intent_for_session(action.session_id)
        if contract is None or not contract.is_active():
            self.trajectory_store.clear_pending_approval(resolved_traj_id, action_id)
            action.execution_status = ToolExecutionStatus.DENIED
            action.policy_result = PolicyDecision.DENY
            action.security_reason = "Approval execution rejected: no active Intent Contract (expired, revoked, or inactive)."
            graph.update_action_state(
                action_id=action_key,
                execution_status=action.execution_status,
                policy_result=action.policy_result,
                security_reason=action.security_reason,
            )
            raise ValueError(action.security_reason)

        # I: Current live Intent authority revalidation (after any narrowing at T1)
        is_tool_allowed = (
            action.tool_name in contract.allowed_tools
            and action.tool_name not in contract.denied_tools
        )
        is_env_allowed = (
            not contract.allowed_environments
            or action.target_environment in contract.allowed_environments
        )
        is_res_allowed = (
            not contract.allowed_resources
            or action.target_resource is None
            or action.target_resource in contract.allowed_resources
        )
        is_class_allowed = not contract.allowed_data_classifications or all(
            c in contract.allowed_data_classifications for c in action.data_classifications
        )
        if not is_tool_allowed or not is_env_allowed or not is_res_allowed or not is_class_allowed:
            self.trajectory_store.clear_pending_approval(resolved_traj_id, action_id)
            action.execution_status = ToolExecutionStatus.DENIED
            action.policy_result = PolicyDecision.DENY
            action.security_reason = f"Approval execution rejected: tool '{action.tool_name}' is not authorized under narrowed authority."
            graph.update_action_state(
                action_id=action_key,
                execution_status=action.execution_status,
                policy_result=action.policy_result,
                security_reason=action.security_reason,
            )
            raise ValueError(action.security_reason)

        # C: Ownership binding revalidation
        if snapshot.session_id != action.session_id or snapshot.agent_id != action.agent_id:
            self.trajectory_store.clear_pending_approval(resolved_traj_id, action_id)
            action.execution_status = ToolExecutionStatus.DENIED
            action.policy_result = PolicyDecision.DENY
            action.security_reason = (
                "Approval execution rejected: Session/Agent ownership mismatch."
            )
            graph.update_action_state(
                action_id=action_key,
                execution_status=action.execution_status,
                policy_result=action.policy_result,
                security_reason=action.security_reason,
            )
            raise ValueError(action.security_reason)

        effective_scope = snapshot.effective_authority
        all_classifications = list(action.data_classifications)
        violations = effective_scope.compute_violations(
            tool_name=action.tool_name,
            target_resource=action.target_resource,
            target_environment=action.target_environment,
            classifications=all_classifications,
        )
        if violations:
            self.trajectory_store.clear_pending_approval(resolved_traj_id, action_id)
            action.execution_status = ToolExecutionStatus.DENIED
            action.policy_result = PolicyDecision.DENY
            action.security_reason = f"Approval execution rejected: tool '{action.tool_name}' is not authorized under narrowed authority ({[v.value for v in violations]})."
            graph.update_action_state(
                action_id=action_key,
                execution_status=action.execution_status,
                policy_result=action.policy_result,
                security_reason=action.security_reason,
            )
            raise ValueError(action.security_reason)

        # K: Execution budget check: reserve execution budget slot atomically
        reserved = self.intent_service.reserve_tool_execution(contract.intent_id)
        if not reserved:
            self.trajectory_store.clear_pending_approval(resolved_traj_id, action_id)
            action.execution_status = ToolExecutionStatus.DENIED
            action.policy_result = PolicyDecision.DENY
            action.security_reason = "Approval execution rejected: Tool execution budget exhausted."
            graph.update_action_state(
                action_id=action_key,
                execution_status=action.execution_status,
                policy_result=action.policy_result,
                security_reason=action.security_reason,
            )
            raise ValueError(action.security_reason)

        # L: Verify required artifact metadata & payloads are still present
        for aid in action.validated_input_artifact_ids:
            art = self.provenance_store.get_artifact(aid)
            if art is None:
                self.trajectory_store.clear_pending_approval(resolved_traj_id, action_id)
                action.execution_status = ToolExecutionStatus.DENIED
                action.policy_result = PolicyDecision.DENY
                action.security_reason = (
                    f"Approval execution rejected: Required artifact metadata '{aid}' is missing."
                )
                graph.update_action_state(
                    action_id=action_key,
                    execution_status=action.execution_status,
                    policy_result=action.policy_result,
                    security_reason=action.security_reason,
                )
                raise ValueError(action.security_reason)
            if not self.provenance_store.payload_store.has_payload(aid):
                self.trajectory_store.clear_pending_approval(resolved_traj_id, action_id)
                action.execution_status = ToolExecutionStatus.DENIED
                action.policy_result = PolicyDecision.DENY
                action.security_reason = f"Approval execution rejected: Required artifact payload for '{aid}' is missing."
                graph.update_action_state(
                    action_id=action_key,
                    execution_status=action.execution_status,
                    policy_result=action.policy_result,
                    security_reason=action.security_reason,
                )
                raise ValueError(action.security_reason)

        # Approval revalidation passed! Clear pending checkpoint and execute exact action
        self.trajectory_store.clear_pending_approval(resolved_traj_id, action_id)
        action.policy_result = PolicyDecision.ALLOW
        action.execution_status = ToolExecutionStatus.AUTHORIZED
        graph.update_action_state(
            action_id=action_key,
            execution_status=action.execution_status,
            policy_result=action.policy_result,
            security_reason="Approved by trusted control plane.",
        )

        # Execute through authorized path
        exec_res = self.execute_authorized_action(action_id)
        updated_action = self.graph_manager.get_action_globally(action_key)
        res_dict = {
            "success": exec_res.success,
            "output": exec_res.output,
            "error": exec_res.error,
        }
        return (updated_action or action), res_dict

    def execute_authorized_action(self, action_id: UUID) -> ToolResult:
        """Execute a tool for an action that has been previously evaluated and ALLOWed."""
        action_key = str(action_id)
        action = self.graph_manager.get_action_globally(action_key)
        if action is None:
            raise KeyError(f"Action '{action_key}' not found.")

        graph = self.graph_manager.get(action.session_id)
        if graph is None:
            raise KeyError(f"Session '{action.session_id}' not found.")

        if action.policy_result != PolicyDecision.ALLOW:
            raise PermissionError(
                f"Action '{action_key}' is not authorized for execution. "
                f"Status: {action.execution_status.value}, Decision: {action.policy_result}"
            )

        graph.update_action_state(
            action_id=action_key,
            execution_status=ToolExecutionStatus.EXECUTING,
        )

        tool_spec = self.tool_registry.get(action.tool_name)

        # Artifact-backed payload binding for security-sensitive sinks
        exec_arguments = dict(action.tool_arguments)
        if tool_spec.payload_binding_mode == PayloadBindingMode.ARTIFACT_REQUIRED:
            bound_id_raw = action.tool_arguments.get(
                "body_artifact_id"
            ) or action.tool_arguments.get("payload_artifact_id")
            if bound_id_raw:
                try:
                    bound_id = (
                        UUID(str(bound_id_raw))
                        if not isinstance(bound_id_raw, UUID)
                        else bound_id_raw
                    )
                    resolved_payload = self.provenance_store.payload_store.get_payload_str(bound_id)
                    if resolved_payload is not None:
                        exec_arguments["body"] = resolved_payload
                except (ValueError, TypeError):
                    pass

        # Link CONSUMES edges at actual execution boundary for validated input artifacts
        for art_id in action.validated_input_artifact_ids:
            try:
                if not graph._graph.has_node(str(art_id)):
                    art_obj = self.provenance_store.get_artifact(art_id)
                    if art_obj is not None:
                        graph.add_artifact_node(art_obj)
                graph.add_consumes_edge(str(art_id), action_key)
            except Exception as e:
                logger.warning("Could not add CONSUMES edge for %s: %s", art_id, e)

        tool_req = ToolRequest(
            tool_name=action.tool_name,
            arguments=exec_arguments,
            action_id=action.action_id,
            session_id=action.session_id,
        )

        decision = SecurityDecision(
            action_id=action.action_id,
            session_id=action.session_id,
            intent_contract_id=action.intent_contract_id,
            decision=action.policy_result,
            reason=action.security_reason or "Authorized",
            matched_rules=action.matched_rules,
            risk_score=action.risk_score,
            requires_human_approval=False,
        )

        # Blocker 10: Deterministic assertion that no security-store lock is held during tool execution
        def _is_locked_or_owned(lk: Any) -> bool:
            if hasattr(lk, "_is_owned"):
                return bool(lk._is_owned())
            if hasattr(lk, "locked"):
                return bool(lk.locked())
            return False

        assert not _is_locked_or_owned(self.delegation_service.store._lock), (
            "DelegationStore lock held during tool execution"
        )
        assert not _is_locked_or_owned(self.trajectory_store._lock), (
            "TrajectoryStore lock held during tool execution"
        )
        assert not _is_locked_or_owned(self.intent_service._lock), (
            "IntentService lock held during tool execution"
        )

        try:
            result = self.tool_executor.execute(tool_req, decision)

            # Phase 5 Output Artifact Creation (only on success and if tool produces artifact)
            if result.success and tool_spec.produces_artifact:
                source_res_name = result.source_resource or action.target_resource or tool_spec.name
                res_profile = self.resource_registry.get_profile(source_res_name)
                parent_arts = [
                    self.provenance_store.get_artifact(aid)
                    for aid in action.validated_input_artifact_ids
                    if self.provenance_store.get_artifact(aid) is not None
                ]
                out_artifact = self.artifact_factory.create_output_artifact(
                    action=action,
                    tool_spec=tool_spec,
                    result=result,
                    parent_artifacts=parent_arts,
                    resource_profile=res_profile,
                )
                registered_art = self.provenance_store.register_artifact(
                    artifact=out_artifact,
                    payload=result.output,
                    graph=graph,
                )
                graph.add_action_output_artifact(action_key, registered_art.artifact_id)
                action.output_artifact_ids.append(registered_art.artifact_id)

            if action.trajectory_id is not None and result.success:
                self.trajectory_store.record_action_execution(
                    action.trajectory_id, action.action_id
                )

            graph.update_action_state(
                action_id=action_key,
                execution_status=ToolExecutionStatus.COMPLETED
                if result.success
                else ToolExecutionStatus.FAILED,
                execution_result={"output": result.output, "error": result.error},
            )
            return result
        except Exception as exc:
            graph.update_action_state(
                action_id=action_key,
                execution_status=ToolExecutionStatus.FAILED,
                execution_result={"error": str(exc)},
            )
            raise


# Global default gateway instance (Strict by default)
default_agent_gateway = AgentGateway(require_intent=True)
