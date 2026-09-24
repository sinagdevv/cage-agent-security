"""Concurrency tests for atomic tool budget consumption."""

from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

from app.gateway.service import AgentGateway
from app.graph.causal_graph import SessionGraphManager
from app.intent.service import IntentService
from app.schemas.action import AgentActionProposal
from app.schemas.enums import PolicyDecision
from app.schemas.intent import IntentContractCreate


def test_concurrent_budget_consumption_cannot_exceed_maximum() -> None:
    """Verify that concurrent actions cannot exceed maximum_tool_calls."""
    intent_service = IntentService()
    graph_manager = SessionGraphManager()
    gateway = AgentGateway(
        intent_service=intent_service,
        graph_manager=graph_manager,
        require_intent=True,
    )

    session_id = f"concurrency-sess-{uuid4().hex[:6]}"
    max_budget = 5
    contract = intent_service.create_intent(
        IntentContractCreate(
            agent_id="concurrency-agent",
            session_id=session_id,
            goal="Concurrent load test",
            allowed_tools=["web.search"],
            maximum_tool_calls=max_budget,
        )
    )

    num_concurrent_requests = 25

    def submit_action(call_idx: int) -> PolicyDecision:
        proposal = AgentActionProposal(
            agent_id="concurrency-agent",
            session_id=session_id,
            tool_name="web.search",
            tool_arguments={"query": f"thread-{call_idx}"},
        )
        _, decision = gateway.evaluate_proposal(proposal)
        return decision.decision

    with ThreadPoolExecutor(max_workers=10) as executor:
        decisions = list(executor.map(submit_action, range(num_concurrent_requests)))

    allowed_count = sum(1 for d in decisions if d == PolicyDecision.ALLOW)
    denied_count = sum(1 for d in decisions if d == PolicyDecision.DENY)

    # Invariant: exactly max_budget executions are ALLOWed, rest DENIED
    assert allowed_count == max_budget
    assert denied_count == num_concurrent_requests - max_budget

    final_contract = intent_service.get_intent(contract.intent_id)
    assert final_contract is not None
    assert final_contract.tool_calls_count == max_budget
