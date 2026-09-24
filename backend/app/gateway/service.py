"""Agent Gateway service coordinating action ingestion, graph recording, and policy evaluation."""

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
from app.policies.rules import DeterministicPolicyEvaluator, default_policy_evaluator
from app.schemas.action import AgentAction, AgentActionProposal
from app.schemas.decision import SecurityDecision
from app.schemas.enums import PolicyDecision, ToolExecutionStatus

logger = logging.getLogger("cage.gateway")


class AgentGateway:
    """Core gateway mediating agent actions, recording causal graphs, and evaluating policies."""

    def __init__(
        self,
        graph_manager: SessionGraphManager | None = None,
        policy_evaluator: DeterministicPolicyEvaluator | None = None,
        tool_registry: ToolRegistry | None = None,
        tool_executor: ToolExecutor | None = None,
    ) -> None:
        self.graph_manager = graph_manager or default_session_graph_manager
        self.policy_evaluator = policy_evaluator or default_policy_evaluator
        self.tool_registry = tool_registry or default_tool_registry
        self.tool_executor = tool_executor or default_tool_executor

    def evaluate_proposal(
        self, proposal: AgentActionProposal
    ) -> tuple[AgentAction, SecurityDecision]:
        """Ingest, validate, record in causal graph, and evaluate an AgentActionProposal.

        Lifecycle:
        1. Validate parentage (reject missing or cross-session parent references).
        2. Create authoritative AgentAction with server-generated UUID.
        3. Record proposed action in graph (forensic trace preserved even if denied).
        4. Link causal edge from parent action if present.
        5. Evaluate deterministic policies using trusted ToolRegistry and precedence.
        6. Update authoritative action and graph node with verdict and risk score.
        7. Return authoritative action and SecurityDecision.
        """
        session_id = proposal.session_id
        graph = self.graph_manager.get_or_create(session_id)

        # 1. Parent relationship validation
        if proposal.parent_action_id is not None:
            parent_key = str(proposal.parent_action_id)
            if not graph.graph.has_node(parent_key):
                # Check if parent exists in a different session
                if self.graph_manager.get_action_globally(parent_key) is not None:
                    raise CrossSessionParentError(
                        f"Parent action '{parent_key}' belongs to a different session. "
                        f"Cross-session parentage is prohibited."
                    )
                raise ParentActionNotFoundError(
                    f"Parent action '{parent_key}' not found in session '{session_id}'."
                )

        # 2. Previous actions validation (if supplied)
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

        # 3. Create server-authoritative AgentAction
        action = AgentAction.from_proposal(proposal)
        action_key = str(action.action_id)

        # 4. Record proposed action in graph BEFORE evaluation (forensic visibility)
        graph.add_action(action)
        self.graph_manager.register_action_session(action_key, session_id)

        if proposal.parent_action_id is not None:
            graph.add_relationship(str(proposal.parent_action_id), action_key, relation="causes")

        for prev_id in proposal.previous_action_ids:
            graph.add_relationship(str(prev_id), action_key, relation="precedes")

        # 5. Deterministic policy evaluation
        decision = self.policy_evaluator.evaluate(action)

        # 6. Map verdict to execution status
        if decision.decision == PolicyDecision.ALLOW:
            execution_status = ToolExecutionStatus.AUTHORIZED
        elif decision.decision == PolicyDecision.REQUIRE_APPROVAL:
            execution_status = ToolExecutionStatus.PENDING_APPROVAL
        else:
            execution_status = ToolExecutionStatus.DENIED

        # 7. Update action state in graph and internal storage
        graph.update_action_state(
            action_id=action_key,
            execution_status=execution_status,
            policy_result=decision.decision,
            security_reason=decision.reason,
            matched_rules=decision.matched_rules,
            risk_score=decision.risk_score,
        )

        logger.info(
            "Action evaluated: action_id=%s tool=%s decision=%s rules=%s",
            action.action_id,
            action.tool_name,
            decision.decision.value,
            decision.matched_rules,
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

        # Synthesize a decision check for the tool executor
        decision = SecurityDecision(
            action_id=action.action_id,
            session_id=action.session_id,
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


# Global default gateway instance
default_agent_gateway = AgentGateway()
