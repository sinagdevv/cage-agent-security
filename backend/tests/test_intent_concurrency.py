from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

from app.intent.service import IntentService
from app.schemas.intent import IntentContractCreate


def test_concurrent_budget_consumption_cannot_exceed_maximum() -> None:
    """Verify that concurrent actions cannot exceed maximum_tool_calls."""
    intent_service = IntentService()

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

    def submit_action(call_idx: int) -> bool:
        return intent_service.reserve_tool_execution(contract.intent_id)

    with ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(submit_action, range(num_concurrent_requests)))

    allowed_count = sum(1 for r in results if r is True)
    denied_count = sum(1 for r in results if r is False)

    # Invariant: exactly max_budget executions are ALLOWed, rest DENIED
    assert allowed_count == max_budget
    assert denied_count == num_concurrent_requests - max_budget

    final_contract = intent_service.get_intent(contract.intent_id)
    assert final_contract is not None
    assert final_contract.tool_calls_count == max_budget
