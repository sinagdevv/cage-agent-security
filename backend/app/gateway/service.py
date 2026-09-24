"""Agent Gateway service coordinating action ingestion, graph recording, intent validation, and policy evaluation."""

import logging
from uuid import UUID

from app.gateway.registry import ToolRegistry, default_tool_registry
from app.gateway.tools import ToolExecutor, ToolRequest, ToolResult, default_tool_executor
from app.graph.causal_graph import (
    CrossSessionParentError,
    ParentActionNotFoundError,
    SessionGraphManager,
    default_session_graph_manager,
)
from app.intent.service import IntentService, default_intent_service
from app.policies.rules import DeterministicPolicyEvaluator, default_policy_evaluator
from app.schemas.action import AgentAction, AgentActionProposal
from app.schemas.decision import SecurityDecision
from app.schemas.enums import PolicyDecision, ToolExecutionStatus

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
        intent_service: IntentService | None = None,
        tool_registry: ToolRegistry | None = None,
        tool_executor: ToolExecutor | None = None,
        require_intent: bool = True,
    ) -> None:
        self.graph_manager = graph_manager or default_session_graph_manager
        self.policy_evaluator = policy_evaluator or default_policy_evaluator
        self.intent_service = intent_service or default_intent_service
        self.tool_registry = tool_registry or default_tool_registry
        self.tool_executor = tool_executor or default_tool_executor
        self.require_intent = require_intent

    def evaluate_proposal(
        self, proposal: AgentActionProposal
    ) -> tuple[AgentAction, SecurityDecision]:
        """Ingest, validate, record in causal graph, and evaluate an AgentActionProposal.

        Lifecycle:
        1. Look up authoritative Intent Contract bound to the session.
        2. Validate causal parentage (reject missing or cross-session parent references).
        3. Create authoritative AgentAction with server-generated UUID.
        4. Record proposed action and Intent node in causal graph.
        5. Link causal edges (Intent -> Action and Parent Action -> Current Action).
        6. Evaluate unified Intent rules and runtime policies with precedence.
        7. If ALLOWed, atomically reserve a tool execution budget slot.
        8. Update action node in graph with final verdict and execution status.
        9. Return authoritative action and SecurityDecision.
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

        # 2. Parent relationship validation
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

        # 3. Previous actions validation (if supplied)
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

        # 4. Create server-authoritative AgentAction
        action = AgentAction.from_proposal(proposal)
        if (
            contract is not None
            and contract.session_id == session_id
            and contract.agent_id == proposal.agent_id
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

        graph.add_action(action)
        self.graph_manager.register_action_session(action_key, session_id)

        if contract is not None:
            graph.add_governs_edge(str(contract.intent_id), action_key)

        if proposal.parent_action_id is not None:
            graph.add_relationship(str(proposal.parent_action_id), action_key, relation="causes")

        for prev_id in proposal.previous_action_ids:
            graph.add_relationship(str(prev_id), action_key, relation="precedes")

        # 6. Policy evaluation (Unified Intent + Runtime Policies)
        decision = self.policy_evaluator.evaluate(
            action=action,
            contract=contract,
            require_intent=self.require_intent,
            intent_mismatch=intent_mismatch,
        )

        # 7. Atomic Tool Execution Budget Reservation
        # Only ALLOWed actions consume from the execution budget.
        if decision.decision == PolicyDecision.ALLOW and contract is not None:
            reserved = self.intent_service.reserve_tool_execution(contract.intent_id)
            if not reserved:
                # Quota exhausted by concurrent request or hit limit
                decision = SecurityDecision(
                    action_id=action.action_id,
                    session_id=action.session_id,
                    intent_contract_id=contract.intent_id,
                    decision=PolicyDecision.DENY,
                    reason=f"Tool call budget exceeded: {contract.tool_calls_count}/{contract.maximum_tool_calls} executions consumed.",
                    matched_rules=decision.matched_rules + ["RULE_TOOL_BUDGET_EXCEEDED"],
                    risk_score=0.85,
                    requires_human_approval=False,
                )

        # 8. Map verdict to execution status
        if decision.decision == PolicyDecision.ALLOW:
            execution_status = ToolExecutionStatus.AUTHORIZED
        elif decision.decision == PolicyDecision.REQUIRE_APPROVAL:
            execution_status = ToolExecutionStatus.PENDING_APPROVAL
        else:
            execution_status = ToolExecutionStatus.DENIED

        # 9. Update action state in graph and internal storage
        graph.update_action_state(
            action_id=action_key,
            execution_status=execution_status,
            policy_result=decision.decision,
            security_reason=decision.reason,
            matched_rules=decision.matched_rules,
            risk_score=decision.risk_score,
        )

        logger.info(
            "Action evaluated: action_id=%s tool=%s decision=%s rules=%s intent=%s",
            action.action_id,
            action.tool_name,
            decision.decision.value,
            decision.matched_rules,
            decision.intent_contract_id,
        )

        return action, decision

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

        tool_req = ToolRequest(
            tool_name=action.tool_name,
            arguments=action.tool_arguments,
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

        try:
            result = self.tool_executor.execute(tool_req, decision)
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
