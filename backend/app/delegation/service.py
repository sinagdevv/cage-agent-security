"""Orchestration service for multi-agent delegation lifecycle, policy evaluation, and graph synchronization."""

import hashlib
import json
from datetime import UTC, datetime, timedelta
from threading import RLock
from typing import Any
from uuid import UUID, uuid4

from app.delegation.analyzer import DelegationAnalyzer
from app.delegation.models import (
    DelegationCreateResponse,
    DelegationGrant,
    DelegationProposal,
    DelegationSnapshot,
)
from app.delegation.store import DelegationStore
from app.graph.causal_graph import SessionGraphManager, default_session_graph_manager
from app.identity.principal import AgentPrincipal
from app.intent.service import IntentService, default_intent_service
from app.policies.policy_input import (
    build_delegation_create_context,
)
from app.policies.rules import DeterministicPolicyEvaluator, default_policy_evaluator
from app.schemas.action import AgentAction
from app.schemas.enums import (
    ActionType,
    DelegationIssuanceSource,
    DelegationStatus,
    EffectiveDelegationStatus,
    PolicyDecision,
    TargetEnvironment,
    ToolExecutionStatus,
    TrajectoryStatus,
)
from app.trajectory.models import AuthorityEnvelope
from app.trajectory.store import TrajectoryStore, default_trajectory_store


def compute_delegation_payload_hash(proposal: DelegationProposal) -> str:
    """Compute deterministic SHA-256 hash of candidate delegation proposal payload."""
    data = {
        "session_id": str(proposal.session_id),
        "root_intent_id": str(proposal.root_intent_id) if proposal.root_intent_id else None,
        "parent_delegation_id": str(proposal.parent_delegation_id)
        if proposal.parent_delegation_id
        else None,
        "delegator_agent_id": proposal.delegator_agent_id,
        "delegatee_agent_id": proposal.delegatee_agent_id,
        "delegated_task_id": proposal.delegated_task_id,
        "requested_tools": sorted(list(proposal.requested_tools)),
        "requested_resource_scope": {
            "mode": proposal.requested_resource_scope.mode.value
            if hasattr(proposal.requested_resource_scope.mode, "value")
            else str(proposal.requested_resource_scope.mode),
            "allowed_resources": sorted(list(proposal.requested_resource_scope.allowed_resources)),
        },
        "requested_environments": sorted(
            [e.value if hasattr(e, "value") else str(e) for e in proposal.requested_environments]
        ),
        "requested_classifications": sorted(
            [c.value if hasattr(c, "value") else str(c) for c in proposal.requested_classifications]
        ),
        "requested_max_actions": proposal.requested_max_actions,
        "requested_ttl_seconds": proposal.requested_ttl_seconds,
        "allow_subdelegation": proposal.allow_subdelegation,
        "requested_depth": proposal.requested_depth,
    }
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class DelegationService:
    """Canonical orchestration service for Phase 8 delegation workflows."""

    def __init__(
        self,
        store: DelegationStore | None = None,
        analyzer: DelegationAnalyzer | None = None,
        intent_service: IntentService | None = None,
        evaluator: DeterministicPolicyEvaluator | None = None,
        graph_manager: SessionGraphManager | None = None,
        trajectory_store: TrajectoryStore | None = None,
    ) -> None:
        self.store = store or DelegationStore()
        self.analyzer = analyzer or DelegationAnalyzer()
        self.intent_service = intent_service or default_intent_service
        self.evaluator = evaluator or default_policy_evaluator
        self.graph_manager = graph_manager or default_session_graph_manager
        self.trajectory_store = trajectory_store or default_trajectory_store

        self._lock = RLock()
        self._pending_approvals: dict[UUID, dict[str, Any]] = {}

    def propose_delegation(
        self,
        proposal: DelegationProposal,
        principal: AgentPrincipal,
    ) -> DelegationCreateResponse:
        """Evaluate a candidate delegation proposal and issue a grant or register pending approval."""
        with self._lock:
            # 1. Resolve root Intent Contract
            session_str = str(proposal.session_id)
            root_intent = None
            if proposal.root_intent_id:
                root_intent = self.intent_service.get_intent(proposal.root_intent_id)
            else:
                root_intent = self.intent_service.get_active_intent_for_session(session_str)

            if root_intent is None:
                # Fail closed: no active root Intent Contract
                action_id = uuid4()
                return DelegationCreateResponse(
                    decision=PolicyDecision.DENY,
                    delegation_id=None,
                    delegation_request_id=action_id,
                    status="DENIED",
                    matched_rules=["RULE_DELEGATION_CALLER_NOT_AUTHORIZED"],
                    reasons=["No active Intent Contract found for session."],
                )

            # 2. Resolve parent grant if subdelegating
            parent_grant: DelegationGrant | None = None
            if proposal.parent_delegation_id:
                parent_grant = self.store.get_grant(proposal.parent_delegation_id)

            # 3. Normalize into authoritative DELEGATION AgentAction
            action_id = uuid4()
            normalized_action = AgentAction(
                action_id=action_id,
                client_action_id=proposal.delegated_task_id,
                agent_id=proposal.delegator_agent_id,
                session_id=session_str,
                intent_contract_id=root_intent.intent_id,
                action_type=ActionType.DELEGATION,
                tool_name="delegation.create",
                tool_arguments={
                    "delegatee_agent_id": proposal.delegatee_agent_id,
                    "delegated_task_id": proposal.delegated_task_id,
                    "requested_tools": proposal.requested_tools,
                    "parent_delegation_id": str(proposal.parent_delegation_id)
                    if proposal.parent_delegation_id
                    else None,
                },
                target_environment=TargetEnvironment.DEVELOPMENT,
                execution_status=ToolExecutionStatus.PROPOSED,
            )

            # 4. Construct PolicyDelegationContext and CagePolicyInput
            ancestors = (
                self.store.get_chain(proposal.parent_delegation_id)
                if proposal.parent_delegation_id
                else []
            )
            delegation_ctx = build_delegation_create_context(
                proposal=proposal,
                principal=principal,
                root_intent=root_intent,
                parent_grant=parent_grant,
                analyzer=self.analyzer,
                ancestors=ancestors,
            )

            # 5. Evaluate policy
            decision = self.evaluator.evaluate(
                action=normalized_action,
                contract=root_intent,
                delegation_context=delegation_ctx,
            )

            # 6. Branch on policy verdict
            if decision.decision in (PolicyDecision.ALLOW, PolicyDecision.ALLOW_WITH_LIMITS):
                # Issue DelegationGrant
                authority_envelope = AuthorityEnvelope(
                    allowed_tools=frozenset(proposal.requested_tools),
                    resource_scope=proposal.requested_resource_scope.to_authoritative(),
                    allowed_environments=frozenset(proposal.requested_environments),
                    allowed_data_classifications=frozenset(proposal.requested_classifications),
                )

                depth = (parent_grant.depth + 1) if parent_grant else 1
                remaining_depth = 0
                if proposal.allow_subdelegation:
                    if parent_grant:
                        remaining_depth = max(0, parent_grant.remaining_subdelegation_depth - 1)
                    else:
                        requested_d = (
                            proposal.requested_depth
                            if proposal.requested_depth is not None
                            else self.analyzer.max_session_delegation_depth
                        )
                        remaining_depth = max(0, requested_d)

                expires_at = datetime.now(UTC) + timedelta(seconds=proposal.requested_ttl_seconds)

                issuance_source = (
                    DelegationIssuanceSource.CONTROL_PLANE_MEDIATED
                    if principal.is_control_plane
                    else DelegationIssuanceSource.AGENT_DIRECT
                )

                max_actions = proposal.requested_max_actions
                if parent_grant is not None:
                    max_actions = min(max_actions, parent_grant.max_actions)
                max_actions = min(max_actions, root_intent.maximum_tool_calls)

                grant = DelegationGrant(
                    delegation_id=uuid4(),
                    parent_delegation_id=proposal.parent_delegation_id,
                    root_intent_id=root_intent.intent_id,
                    session_id=proposal.session_id,
                    issued_from_action_id=action_id,
                    delegator_agent_id=proposal.delegator_agent_id,
                    delegatee_agent_id=proposal.delegatee_agent_id,
                    mediating_principal_id=principal.agent_id
                    if principal.is_control_plane
                    else None,
                    issuance_source=issuance_source,
                    delegated_task_id=proposal.delegated_task_id,
                    authority_envelope=authority_envelope,
                    depth=depth,
                    remaining_subdelegation_depth=remaining_depth,
                    allow_subdelegation=proposal.allow_subdelegation,
                    max_actions=max_actions,
                    expires_at=expires_at,
                )

                self.store.create_grant(grant)

                # Sync to causal graph
                graph = self.graph_manager.get_or_create(session_str)
                if not graph.has_node(str(grant.root_intent_id)):
                    graph.add_intent_node(
                        intent_id=str(root_intent.intent_id),
                        goal=root_intent.goal,
                        agent_id=str(root_intent.agent_id),
                        user_id=str(root_intent.user_id),
                        created_at=root_intent.created_at.isoformat()
                        if hasattr(root_intent.created_at, "isoformat")
                        else str(root_intent.created_at),
                    )
                graph.add_agent_node(grant.delegator_agent_id)
                graph.add_agent_node(grant.delegatee_agent_id)
                graph.add_delegation_node(grant)
                graph.add_issues_delegation_edge(grant.delegator_agent_id, str(grant.delegation_id))
                graph.add_grants_to_edge(str(grant.delegation_id), grant.delegatee_agent_id)
                graph.add_intent_delegation_governs_edge(
                    str(grant.root_intent_id), str(grant.delegation_id)
                )

                if grant.parent_delegation_id:
                    graph.add_subdelegates_edge(
                        str(grant.parent_delegation_id), str(grant.delegation_id)
                    )

                return DelegationCreateResponse(
                    decision=decision.decision,
                    delegation_id=grant.delegation_id,
                    delegation_request_id=action_id,
                    status="ACTIVE",
                    matched_rules=decision.matched_rules,
                    reasons=[decision.reason],
                )

            elif decision.decision == PolicyDecision.REQUIRE_APPROVAL:
                # Save pending approval checkpoint with authoritative hash, DO NOT create grant
                payload_hash = compute_delegation_payload_hash(proposal)
                self._pending_approvals[action_id] = {
                    "action_id": action_id,
                    "proposal": proposal,
                    "principal": principal,
                    "root_intent_id": root_intent.intent_id,
                    "session_id": proposal.session_id,
                    "delegator_agent_id": proposal.delegator_agent_id,
                    "delegatee_agent_id": proposal.delegatee_agent_id,
                    "parent_delegation_id": proposal.parent_delegation_id,
                    "payload_hash": payload_hash,
                    "created_at": datetime.now(UTC),
                }

                return DelegationCreateResponse(
                    decision=PolicyDecision.REQUIRE_APPROVAL,
                    delegation_id=None,
                    delegation_request_id=action_id,
                    status="PENDING_APPROVAL",
                    matched_rules=decision.matched_rules,
                    reasons=[decision.reason],
                )

            else:
                return DelegationCreateResponse(
                    decision=PolicyDecision.DENY,
                    delegation_id=None,
                    delegation_request_id=action_id,
                    status="DENIED",
                    matched_rules=decision.matched_rules,
                    reasons=[decision.reason],
                )

    def resolve_delegation_approval(
        self,
        request_id: UUID,
        approver_principal: AgentPrincipal,
        decision: str = "APPROVED",
    ) -> DelegationCreateResponse:
        """Resolve a pending delegation approval checkpoint with atomic live revalidation."""
        with self._lock:
            pending = self._pending_approvals.get(request_id)
            if pending is None:
                return DelegationCreateResponse(
                    decision=PolicyDecision.DENY,
                    delegation_id=None,
                    delegation_request_id=request_id,
                    status="REJECTED",
                    matched_rules=["RULE_DELEGATION_APPROVAL_STALE_AUTHORITY"],
                    reasons=["Pending delegation approval checkpoint not found."],
                )

            if decision != "APPROVED":
                del self._pending_approvals[request_id]
                return DelegationCreateResponse(
                    decision=PolicyDecision.DENY,
                    delegation_id=None,
                    delegation_request_id=request_id,
                    status="REJECTED",
                    matched_rules=["RULE_DELEGATION_APPROVAL_REJECTED"],
                    reasons=["Delegation proposal was rejected by reviewer."],
                )

            proposal: DelegationProposal = pending["proposal"]
            root_intent_id: UUID = pending["root_intent_id"]
            root_intent = self.intent_service.get_intent(root_intent_id)

            # 1. Verify approver principal identity and authority context
            is_authorized_approver = (
                approver_principal.is_control_plane
                or (root_intent is not None and approver_principal.agent_id == root_intent.user_id)
                or approver_principal.agent_id == "security-officer"
            )
            if not is_authorized_approver:
                del self._pending_approvals[request_id]
                return DelegationCreateResponse(
                    decision=PolicyDecision.DENY,
                    delegation_id=None,
                    delegation_request_id=request_id,
                    status="DENIED",
                    matched_rules=["RULE_DELEGATION_APPROVAL_IDENTITY_MISMATCH"],
                    reasons=["Approver principal is not authorized to approve this delegation."],
                )

            # 2. Revalidate exact normalized request hash / payload hash (no argument/scope mutation)
            expected_payload_hash = pending.get("payload_hash")
            current_payload_hash = compute_delegation_payload_hash(proposal)
            if expected_payload_hash and current_payload_hash != expected_payload_hash:
                del self._pending_approvals[request_id]
                return DelegationCreateResponse(
                    decision=PolicyDecision.DENY,
                    delegation_id=None,
                    delegation_request_id=request_id,
                    status="STALE_AUTHORITY",
                    matched_rules=["RULE_DELEGATION_APPROVAL_STALE_AUTHORITY"],
                    reasons=[
                        "Proposal payload or requested scope was mutated between submission and approval."
                    ],
                )

            # 3. Verify session, intent, delegator, delegatee, parent_delegation_id exact match
            if (
                str(proposal.session_id) != str(pending.get("session_id", proposal.session_id))
                or proposal.delegator_agent_id
                != pending.get("delegator_agent_id", proposal.delegator_agent_id)
                or proposal.delegatee_agent_id
                != pending.get("delegatee_agent_id", proposal.delegatee_agent_id)
                or proposal.parent_delegation_id
                != pending.get("parent_delegation_id", proposal.parent_delegation_id)
            ):
                del self._pending_approvals[request_id]
                return DelegationCreateResponse(
                    decision=PolicyDecision.DENY,
                    delegation_id=None,
                    delegation_request_id=request_id,
                    status="STALE_AUTHORITY",
                    matched_rules=["RULE_DELEGATION_APPROVAL_STALE_AUTHORITY"],
                    reasons=["Proposal bindings do not match stored approval checkpoint."],
                )

            # 4. Revalidate root Intent Contract: exists, ACTIVE, not expired, matching session
            now = datetime.now(UTC)
            if (
                root_intent is None
                or not root_intent.is_active()
                or (root_intent.expires_at is not None and now >= root_intent.expires_at)
                or str(root_intent.session_id) != str(proposal.session_id)
            ):
                del self._pending_approvals[request_id]
                return DelegationCreateResponse(
                    decision=PolicyDecision.DENY,
                    delegation_id=None,
                    delegation_request_id=request_id,
                    status="STALE_AUTHORITY",
                    matched_rules=["RULE_DELEGATION_APPROVAL_STALE_AUTHORITY"],
                    reasons=[
                        "Root Intent Contract is inactive, expired, revoked, or session-mismatched."
                    ],
                )

            # 5. Revalidate root Intent action budget
            if root_intent.tool_calls_count >= root_intent.maximum_tool_calls:
                del self._pending_approvals[request_id]
                return DelegationCreateResponse(
                    decision=PolicyDecision.DENY,
                    delegation_id=None,
                    delegation_request_id=request_id,
                    status="STALE_AUTHORITY",
                    matched_rules=["RULE_DELEGATION_APPROVAL_STALE_AUTHORITY"],
                    reasons=["Root Intent Contract tool execution budget is exhausted."],
                )

            # 6. Revalidate scope against live root intent
            if not self.analyzer.check_scope_subset_root(proposal, root_intent):
                del self._pending_approvals[request_id]
                return DelegationCreateResponse(
                    decision=PolicyDecision.DENY,
                    delegation_id=None,
                    delegation_request_id=request_id,
                    status="STALE_AUTHORITY",
                    matched_rules=["RULE_DELEGATION_APPROVAL_STALE_AUTHORITY"],
                    reasons=[
                        "Root Intent Contract authority narrowed; proposal exceeds live root."
                    ],
                )

            # 7. Full live delegation ancestry revalidation
            parent_grant = None
            if proposal.parent_delegation_id:
                try:
                    grants, states = self.store.get_chain_with_states(proposal.parent_delegation_id)
                except ValueError as exc:
                    del self._pending_approvals[request_id]
                    return DelegationCreateResponse(
                        decision=PolicyDecision.DENY,
                        delegation_id=None,
                        delegation_request_id=request_id,
                        status="STALE_AUTHORITY",
                        matched_rules=["RULE_DELEGATION_APPROVAL_STALE_AUTHORITY"],
                        reasons=[f"Delegation ancestry validation error: {exc}"],
                    )

                if not grants or not states:
                    del self._pending_approvals[request_id]
                    return DelegationCreateResponse(
                        decision=PolicyDecision.DENY,
                        delegation_id=None,
                        delegation_request_id=request_id,
                        status="STALE_AUTHORITY",
                        matched_rules=["RULE_DELEGATION_APPROVAL_STALE_AUTHORITY"],
                        reasons=["Parent delegation grant hierarchy not found."],
                    )

                # Structural linkage checks:
                # 1. Chain root must have no parent
                if grants[0].parent_delegation_id is not None:
                    del self._pending_approvals[request_id]
                    return DelegationCreateResponse(
                        decision=PolicyDecision.DENY,
                        delegation_id=None,
                        delegation_request_id=request_id,
                        status="STALE_AUTHORITY",
                        matched_rules=["RULE_DELEGATION_APPROVAL_STALE_AUTHORITY"],
                        reasons=[
                            "Ancestor delegation chain is structurally disconnected from root."
                        ],
                    )

                # 2. Sequential structural linking
                for idx in range(1, len(grants)):
                    if grants[idx].parent_delegation_id != grants[idx - 1].delegation_id:
                        del self._pending_approvals[request_id]
                        return DelegationCreateResponse(
                            decision=PolicyDecision.DENY,
                            delegation_id=None,
                            delegation_request_id=request_id,
                            status="STALE_AUTHORITY",
                            matched_rules=["RULE_DELEGATION_APPROVAL_STALE_AUTHORITY"],
                            reasons=["Ancestor delegation chain has a broken structural link."],
                        )

                # 3. Terminal grant must match proposal.parent_delegation_id
                if grants[-1].delegation_id != proposal.parent_delegation_id:
                    del self._pending_approvals[request_id]
                    return DelegationCreateResponse(
                        decision=PolicyDecision.DENY,
                        delegation_id=None,
                        delegation_request_id=request_id,
                        status="STALE_AUTHORITY",
                        matched_rules=["RULE_DELEGATION_APPROVAL_STALE_AUTHORITY"],
                        reasons=["Parent delegation ID does not match terminal chain grant."],
                    )

                parent_grant = grants[-1]

                # Verify every ancestor: exists, same session, same root, active status, not expired, not budget-exhausted
                for g, s in zip(grants, states, strict=False):
                    if (
                        str(g.session_id) != str(proposal.session_id)
                        or g.root_intent_id != root_intent.intent_id
                    ):
                        del self._pending_approvals[request_id]
                        return DelegationCreateResponse(
                            decision=PolicyDecision.DENY,
                            delegation_id=None,
                            delegation_request_id=request_id,
                            status="STALE_AUTHORITY",
                            matched_rules=["RULE_DELEGATION_APPROVAL_STALE_AUTHORITY"],
                            reasons=[
                                "Ancestor delegation belongs to different session or root Intent."
                            ],
                        )
                    if s.status != DelegationStatus.ACTIVE:
                        del self._pending_approvals[request_id]
                        return DelegationCreateResponse(
                            decision=PolicyDecision.DENY,
                            delegation_id=None,
                            delegation_request_id=request_id,
                            status="STALE_AUTHORITY",
                            matched_rules=["RULE_DELEGATION_APPROVAL_STALE_AUTHORITY"],
                            reasons=[
                                f"Ancestor delegation grant {g.delegation_id} is revoked or closed."
                            ],
                        )
                    if g.expires_at is not None and now >= g.expires_at:
                        del self._pending_approvals[request_id]
                        return DelegationCreateResponse(
                            decision=PolicyDecision.DENY,
                            delegation_id=None,
                            delegation_request_id=request_id,
                            status="STALE_AUTHORITY",
                            matched_rules=["RULE_DELEGATION_APPROVAL_STALE_AUTHORITY"],
                            reasons=[f"Ancestor delegation grant {g.delegation_id} has expired."],
                        )
                    if s.actions_executed_count >= g.max_actions:
                        del self._pending_approvals[request_id]
                        return DelegationCreateResponse(
                            decision=PolicyDecision.DENY,
                            delegation_id=None,
                            delegation_request_id=request_id,
                            status="STALE_AUTHORITY",
                            matched_rules=["RULE_DELEGATION_APPROVAL_STALE_AUTHORITY"],
                            reasons=[
                                f"Ancestor delegation grant {g.delegation_id} action budget is exhausted."
                            ],
                        )

                # Check subdelegation permission across ancestry:
                # Every intermediate ancestor that has a subdelegation must have allow_subdelegation
                for anc in grants[:-1]:
                    if not anc.allow_subdelegation:
                        del self._pending_approvals[request_id]
                        return DelegationCreateResponse(
                            decision=PolicyDecision.DENY,
                            delegation_id=None,
                            delegation_request_id=request_id,
                            status="STALE_AUTHORITY",
                            matched_rules=["RULE_DELEGATION_APPROVAL_STALE_AUTHORITY"],
                            reasons=[
                                f"Ancestor grant {anc.delegation_id} prohibits subdelegation."
                            ],
                        )

                # Immediate parent subdelegation right and depth
                if (
                    not parent_grant.allow_subdelegation
                    or parent_grant.remaining_subdelegation_depth <= 0
                ):
                    del self._pending_approvals[request_id]
                    return DelegationCreateResponse(
                        decision=PolicyDecision.DENY,
                        delegation_id=None,
                        delegation_request_id=request_id,
                        status="STALE_AUTHORITY",
                        matched_rules=["RULE_DELEGATION_APPROVAL_STALE_AUTHORITY"],
                        reasons=[
                            "Parent delegation grant explicitly prohibits subdelegation or depth is exhausted."
                        ],
                    )

                if parent_grant.depth + 1 > self.analyzer.max_session_delegation_depth:
                    del self._pending_approvals[request_id]
                    return DelegationCreateResponse(
                        decision=PolicyDecision.DENY,
                        delegation_id=None,
                        delegation_request_id=request_id,
                        status="STALE_AUTHORITY",
                        matched_rules=["RULE_DELEGATION_APPROVAL_STALE_AUTHORITY"],
                        reasons=[
                            "Requested delegation depth exceeds session delegation depth limit."
                        ],
                    )

                # LIVE EFFECTIVE PARENT AUTHORITY:
                # current root Intent ∩ every active ancestor grant ∩ immediate parent grant
                parent_effective_env = self.analyzer.compute_live_effective_authority(
                    grant=parent_grant,
                    ancestors=grants[:-1],
                    root_intent=root_intent,
                )

                # 1. Tools dimension
                req_tools = set(proposal.requested_tools)
                if not req_tools.issubset(parent_effective_env.allowed_tools):
                    del self._pending_approvals[request_id]
                    return DelegationCreateResponse(
                        decision=PolicyDecision.DENY,
                        delegation_id=None,
                        delegation_request_id=request_id,
                        status="STALE_AUTHORITY",
                        matched_rules=["RULE_DELEGATION_APPROVAL_STALE_AUTHORITY"],
                        reasons=[
                            "Requested tools exceed live effective parent authority across ancestor chain."
                        ],
                    )

                # 2. ResourceAuthorityScope dimension
                if not self.analyzer.is_resource_scope_subset(
                    proposal.requested_resource_scope, parent_effective_env.resource_scope
                ):
                    del self._pending_approvals[request_id]
                    return DelegationCreateResponse(
                        decision=PolicyDecision.DENY,
                        delegation_id=None,
                        delegation_request_id=request_id,
                        status="STALE_AUTHORITY",
                        matched_rules=["RULE_DELEGATION_APPROVAL_STALE_AUTHORITY"],
                        reasons=[
                            "Requested resource scope exceeds live effective parent authority across ancestor chain."
                        ],
                    )

                # 3. Environments dimension
                req_envs = {
                    e.value if hasattr(e, "value") else str(e)
                    for e in proposal.requested_environments
                }
                parent_envs = {
                    e.value if hasattr(e, "value") else str(e)
                    for e in parent_effective_env.allowed_environments
                }
                if not req_envs.issubset(parent_envs):
                    del self._pending_approvals[request_id]
                    return DelegationCreateResponse(
                        decision=PolicyDecision.DENY,
                        delegation_id=None,
                        delegation_request_id=request_id,
                        status="STALE_AUTHORITY",
                        matched_rules=["RULE_DELEGATION_APPROVAL_STALE_AUTHORITY"],
                        reasons=[
                            "Requested environments exceed live effective parent authority across ancestor chain."
                        ],
                    )

                # 4. Data classifications dimension
                req_classes = {
                    c.value if hasattr(c, "value") else str(c)
                    for c in proposal.requested_classifications
                }
                parent_classes = {
                    c.value if hasattr(c, "value") else str(c)
                    for c in parent_effective_env.allowed_data_classifications
                }
                if not req_classes.issubset(parent_classes):
                    del self._pending_approvals[request_id]
                    return DelegationCreateResponse(
                        decision=PolicyDecision.DENY,
                        delegation_id=None,
                        delegation_request_id=request_id,
                        status="STALE_AUTHORITY",
                        matched_rules=["RULE_DELEGATION_APPROVAL_STALE_AUTHORITY"],
                        reasons=[
                            "Requested data classifications exceed live effective parent authority across ancestor chain."
                        ],
                    )

                # 5. Max actions dimension
                if proposal.requested_max_actions > parent_grant.max_actions:
                    del self._pending_approvals[request_id]
                    return DelegationCreateResponse(
                        decision=PolicyDecision.DENY,
                        delegation_id=None,
                        delegation_request_id=request_id,
                        status="STALE_AUTHORITY",
                        matched_rules=["RULE_DELEGATION_APPROVAL_STALE_AUTHORITY"],
                        reasons=[
                            "Parent grant authority narrowed; proposal exceeds parent max actions."
                        ],
                    )

                # 6. Expiration dimension: must not exceed earliest ancestor or root expiration
                chain_expirations = [g.expires_at for g in grants if g.expires_at is not None]
                if root_intent.expires_at is not None:
                    chain_expirations.append(root_intent.expires_at)
                effective_expiry = min(chain_expirations) if chain_expirations else None
                req_expires = now + timedelta(seconds=proposal.requested_ttl_seconds)
                if effective_expiry is not None and req_expires > effective_expiry + timedelta(
                    seconds=1
                ):
                    del self._pending_approvals[request_id]
                    return DelegationCreateResponse(
                        decision=PolicyDecision.DENY,
                        delegation_id=None,
                        delegation_request_id=request_id,
                        status="STALE_AUTHORITY",
                        matched_rules=["RULE_DELEGATION_APPROVAL_STALE_AUTHORITY"],
                        reasons=[
                            "Requested delegation expiration exceeds ancestor chain expiration."
                        ],
                    )
            else:
                depth_req = proposal.requested_depth or 1
                if depth_req > self.analyzer.max_session_delegation_depth:
                    del self._pending_approvals[request_id]
                    return DelegationCreateResponse(
                        decision=PolicyDecision.DENY,
                        delegation_id=None,
                        delegation_request_id=request_id,
                        status="STALE_AUTHORITY",
                        matched_rules=["RULE_DELEGATION_APPROVAL_STALE_AUTHORITY"],
                        reasons=[
                            "Requested delegation depth exceeds maximum allowed session depth."
                        ],
                    )
                req_expires = now + timedelta(seconds=proposal.requested_ttl_seconds)
                if (
                    root_intent.expires_at is not None
                    and req_expires > root_intent.expires_at + timedelta(seconds=1)
                ):
                    del self._pending_approvals[request_id]
                    return DelegationCreateResponse(
                        decision=PolicyDecision.DENY,
                        delegation_id=None,
                        delegation_request_id=request_id,
                        status="STALE_AUTHORITY",
                        matched_rules=["RULE_DELEGATION_APPROVAL_STALE_AUTHORITY"],
                        reasons=[
                            "Requested delegation expiration exceeds root Intent Contract expiration."
                        ],
                    )

            # 8. Revalidate delegator trajectory status (must be ACTIVE)
            if self.trajectory_store is not None:
                traj_id = self.trajectory_store.get_trajectory_id(
                    str(proposal.session_id), root_intent.intent_id, proposal.delegator_agent_id
                )
                if traj_id is not None:
                    traj_snap = self.trajectory_store.get_snapshot(traj_id)
                    if traj_snap is not None and traj_snap.status != TrajectoryStatus.ACTIVE:
                        del self._pending_approvals[request_id]
                        return DelegationCreateResponse(
                            decision=PolicyDecision.DENY,
                            delegation_id=None,
                            delegation_request_id=request_id,
                            status="STALE_AUTHORITY",
                            matched_rules=["RULE_DELEGATION_APPROVAL_STALE_AUTHORITY"],
                            reasons=[
                                f"Delegator trajectory is {traj_snap.status.value}, not ACTIVE."
                            ],
                        )

            # 9. Session active grant limit check
            if (
                self.store.get_session_active_grant_count(proposal.session_id)
                >= self.analyzer.max_session_active_grants
            ):
                del self._pending_approvals[request_id]
                return DelegationCreateResponse(
                    decision=PolicyDecision.DENY,
                    delegation_id=None,
                    delegation_request_id=request_id,
                    status="STALE_AUTHORITY",
                    matched_rules=["RULE_DELEGATION_APPROVAL_STALE_AUTHORITY"],
                    reasons=["Session active delegation grant count limit exceeded."],
                )

            # Issue the grant
            del self._pending_approvals[request_id]

            authority_envelope = AuthorityEnvelope(
                allowed_tools=frozenset(proposal.requested_tools),
                resource_scope=proposal.requested_resource_scope.to_authoritative(),
                allowed_environments=frozenset(proposal.requested_environments),
                allowed_data_classifications=frozenset(proposal.requested_classifications),
            )

            depth = (parent_grant.depth + 1) if parent_grant else 1
            remaining_depth = 0
            if proposal.allow_subdelegation:
                if parent_grant:
                    remaining_depth = max(0, parent_grant.remaining_subdelegation_depth - 1)
                else:
                    requested_d = (
                        proposal.requested_depth or self.analyzer.max_session_delegation_depth
                    )
                    remaining_depth = max(0, requested_d - 1)

            expires_at = datetime.now(UTC) + timedelta(seconds=proposal.requested_ttl_seconds)

            max_actions = proposal.requested_max_actions
            if parent_grant is not None:
                max_actions = min(max_actions, parent_grant.max_actions)
            max_actions = min(max_actions, root_intent.maximum_tool_calls)

            grant = DelegationGrant(
                delegation_id=uuid4(),
                parent_delegation_id=proposal.parent_delegation_id,
                root_intent_id=root_intent.intent_id,
                session_id=proposal.session_id,
                issued_from_action_id=request_id,
                delegator_agent_id=proposal.delegator_agent_id,
                delegatee_agent_id=proposal.delegatee_agent_id,
                mediating_principal_id=approver_principal.agent_id
                if approver_principal.is_control_plane
                else None,
                issuance_source=DelegationIssuanceSource.AGENT_DIRECT,
                delegated_task_id=proposal.delegated_task_id,
                authority_envelope=authority_envelope,
                depth=depth,
                remaining_subdelegation_depth=remaining_depth,
                allow_subdelegation=proposal.allow_subdelegation,
                max_actions=max_actions,
                expires_at=expires_at,
            )

            self.store.create_grant(grant)

            # Sync to causal graph
            session_str = str(proposal.session_id)
            graph = self.graph_manager.get_or_create(session_str)
            if not graph.has_node(str(grant.root_intent_id)):
                graph.add_intent_node(
                    intent_id=str(root_intent.intent_id),
                    goal=root_intent.goal,
                    agent_id=str(root_intent.agent_id),
                    user_id=str(root_intent.user_id),
                    created_at=root_intent.created_at.isoformat()
                    if hasattr(root_intent.created_at, "isoformat")
                    else str(root_intent.created_at),
                )
            graph.add_agent_node(grant.delegator_agent_id)
            graph.add_agent_node(grant.delegatee_agent_id)
            graph.add_delegation_node(grant)
            graph.add_issues_delegation_edge(grant.delegator_agent_id, str(grant.delegation_id))
            graph.add_grants_to_edge(str(grant.delegation_id), grant.delegatee_agent_id)
            graph.add_intent_delegation_governs_edge(
                str(grant.root_intent_id), str(grant.delegation_id)
            )

            if grant.parent_delegation_id:
                graph.add_subdelegates_edge(
                    str(grant.parent_delegation_id), str(grant.delegation_id)
                )

            return DelegationCreateResponse(
                decision=PolicyDecision.ALLOW,
                delegation_id=grant.delegation_id,
                delegation_request_id=request_id,
                status="ACTIVE",
                matched_rules=["RULE_DELEGATION_APPROVAL_RESOLVED"],
                reasons=["Delegation approved and successfully revalidated."],
            )

    def resolve_pending_approval(
        self,
        delegation_request_id: UUID | None = None,
        request_id: UUID | None = None,
        principal: AgentPrincipal | None = None,
        approver_principal: AgentPrincipal | None = None,
        decision: Any = "APPROVED",
        approver_id: str | None = None,
    ) -> DelegationCreateResponse:
        """Alias for resolve_delegation_approval supporting flexible keyword arguments."""
        target_id = delegation_request_id or request_id
        if target_id is None:
            raise ValueError("delegation_request_id is required")
        target_principal = principal or approver_principal
        if target_principal is None:
            raise ValueError("principal is required")
        decision_str = (
            "APPROVED" if (decision in ("APPROVED", PolicyDecision.ALLOW, True)) else "REJECTED"
        )
        return self.resolve_delegation_approval(
            request_id=target_id,
            approver_principal=target_principal,
            decision=decision_str,
        )

    def revoke_delegation(
        self,
        delegation_id: UUID,
        principal: AgentPrincipal,
        reason: str | None = None,
    ) -> bool:
        """Revoke an active delegation grant with authorization check."""
        with self._lock:
            grant = self.store.get_grant(delegation_id)
            if grant is None:
                return False

            root_intent = self.intent_service.get_intent(grant.root_intent_id)
            if root_intent is None:
                return False

            if not self.analyzer.is_authorized_to_revoke(grant, principal, root_intent):
                return False

            return self.store.revoke(
                delegation_id=delegation_id,
                revoked_by_principal_id=principal.agent_id,
                reason=reason,
            )

    def close_delegation(
        self,
        delegation_id: UUID,
        principal: AgentPrincipal,
        reason: str | None = None,
    ) -> bool:
        """Close an active delegation grant upon task completion with authorization check."""
        with self._lock:
            grant = self.store.get_grant(delegation_id)
            if grant is None:
                return False

            if not self.analyzer.is_authorized_to_close(grant, principal):
                return False

            return self.store.close(
                delegation_id=delegation_id,
                closed_by_agent_id=principal.agent_id,
                reason=reason,
            )

    def get_delegation_grant(self, delegation_id: UUID) -> DelegationGrant | None:
        """Retrieve an immutable grant by ID."""
        return self.store.get_grant(delegation_id)

    def get_delegation_snapshot(self, delegation_id: UUID) -> DelegationSnapshot | None:
        """Retrieve an immutable snapshot containing grant, runtime state, and live authority."""
        with self._lock:
            grant = self.store.get_grant(delegation_id)
            state = self.store.get_runtime_state(delegation_id)
            if grant is None or state is None:
                return None

            root_intent = self.intent_service.get_intent(grant.root_intent_id)
            if root_intent is None:
                return None

            grants, states = self.store.get_chain_with_states(delegation_id)
            ancestor_grants = grants[:-1]
            ancestor_states = states[:-1]

            effective_status = self.analyzer.compute_effective_status(
                grant=grant,
                runtime_state=state,
                ancestors=ancestor_grants,
                ancestor_states=ancestor_states,
                root_intent=root_intent,
            )

            live_effective_authority = self.analyzer.compute_live_effective_authority(
                grant=grant,
                ancestors=ancestor_grants,
                root_intent=root_intent,
            )

            return DelegationSnapshot(
                grant=grant,
                runtime_status=state.status,
                effective_status=effective_status,
                actions_executed_count=state.actions_executed_count,
                remaining_actions_count=max(0, grant.max_actions - state.actions_executed_count),
                is_active=(effective_status == EffectiveDelegationStatus.ACTIVE),
                live_effective_authority=live_effective_authority,
            )

    def get_chain(self, delegation_id: UUID) -> list[DelegationGrant]:
        """Retrieve ancestor chain from root grant to target grant."""
        return self.store.get_chain(delegation_id)

    def clear(self) -> None:
        """Clear store and pending approvals (for test isolation)."""
        with self._lock:
            self.store.clear()
            self._pending_approvals.clear()


# Default singleton instance
default_delegation_service = DelegationService()
