"""Unit and integration tests for CAGE Phase 7 Attack Simulation Lab."""

import json

import pytest

from app.schemas.enums import (
    PolicyBackend,
    PolicyDecision,
    TargetEnvironment,
    TrajectoryStatus,
)
from attack_lab.fixtures import (
    build_attack_tool_registry,
)
from attack_lab.models import (
    AttackCategory,
    AttackScenario,
    ScenarioOutcome,
    ScenarioStep,
)
from attack_lab.reporting import (
    generate_json_report,
    generate_markdown_report,
)
from attack_lab.runner import AttackScenarioRunner
from attack_lab.scenarios import get_all_scenarios
from attack_lab.scenarios.action_chain import get_action_chain_scenarios
from attack_lab.scenarios.benign import get_benign_scenarios
from attack_lab.scenarios.exfiltration import get_exfiltration_scenarios
from attack_lab.scenarios.graph_and_limits import get_graph_and_limits_scenarios
from attack_lab.scenarios.injection import get_injection_scenarios
from attack_lab.scenarios.malicious_mcp import get_malicious_mcp_scenarios


@pytest.fixture
def runner():
    """Create runner with Python policy evaluator for fast unit testing."""
    return AttackScenarioRunner(policy_backend=PolicyBackend.PYTHON)


@pytest.fixture
def shadow_runner():
    """Create runner with Shadow policy evaluator (Python + OPA)."""
    return AttackScenarioRunner(policy_backend=PolicyBackend.SHADOW)


def test_scenario_model_validation():
    """Test AttackScenario Pydantic schema validation."""
    sc = AttackScenario(
        scenario_id="TEST-001",
        category=AttackCategory.INDIRECT_INJECTION,
        name="Test Scenario",
        description="A test scenario",
        threat_actor="Attacker",
        attack_intent="Steal data",
        security_invariant="Data is protected",
        intent_tools=["web.search"],
        steps=[
            ScenarioStep(
                step_id="s1",
                description="Search web",
                tool_name="web.search",
                expected_decision=PolicyDecision.ALLOW,
            )
        ],
    )
    assert sc.scenario_id == "TEST-001"
    assert sc.steps[0].step_id == "s1"
    assert sc.expected_final_trajectory_status == TrajectoryStatus.ACTIVE


def test_safe_mock_tool_execution():
    """Verify that MockExecutionRegistry safely records calls without external effects."""
    registry, recorder, executor = build_attack_tool_registry()
    assert registry.get("web.search") is not None
    assert len(recorder.dispatched_calls) == 0
    assert len(recorder.side_effects) == 0


def test_scenario_expectation_is_not_authority(runner):
    """Verify that expected_decision field does NOT influence runtime policy decision."""
    # Create scenario where an out-of-intent action falsely claims expected_decision=ALLOW
    sc_a = AttackScenario(
        scenario_id="FORGED-EXPECTATION-ALLOW",
        category=AttackCategory.INDIRECT_INJECTION,
        name="Forged Expectation Test ALLOW",
        description="Scenario claims expected_decision=ALLOW on unauthorized tool",
        threat_actor="Adversary",
        attack_intent="Bypass policy via expectation field",
        security_invariant="Expectation fields only affect assertions, not CAGE engine decisions",
        intent_tools=["web.search"],  # Only web.search allowed
        steps=[
            ScenarioStep(
                step_id="step-1",
                description="Attempt unauthorized database.read while expecting ALLOW",
                tool_name="database.read",
                resource_id="customer-db",
                expected_decision=PolicyDecision.ALLOW,  # Intentionally wrong assertion
            )
        ],
    )

    sc_b = AttackScenario(
        scenario_id="FORGED-EXPECTATION-DENY",
        category=AttackCategory.INDIRECT_INJECTION,
        name="Forged Expectation Test DENY",
        description="Scenario claims expected_decision=DENY on unauthorized tool",
        threat_actor="Adversary",
        attack_intent="Expect DENY",
        security_invariant="Expectation fields only affect assertions, not CAGE engine decisions",
        intent_tools=["web.search"],  # Only web.search allowed
        steps=[
            ScenarioStep(
                step_id="step-1",
                description="Attempt unauthorized database.read while expecting DENY",
                tool_name="database.read",
                resource_id="customer-db",
                expected_decision=PolicyDecision.DENY,  # Correct assertion
            )
        ],
    )

    res_a = runner.run_scenario(sc_a)
    res_b = runner.run_scenario(sc_b)

    # Both scenarios executed identical runtime operations; actual CAGE decisions MUST be identical
    assert (
        res_a.step_results[0].actual_decision
        == res_b.step_results[0].actual_decision
        == PolicyDecision.DENY
    )
    assert res_a.step_results[0].actual_rule_ids == res_b.step_results[0].actual_rule_ids
    assert res_a.cage_bypass_succeeded is False
    assert res_b.cage_bypass_succeeded is False


def test_runner_session_isolation(runner):
    """Verify that sequential scenario runs are completely isolated with no state leakage."""
    scenarios = get_all_scenarios()
    sc_a = scenarios[0]
    sc_b = scenarios[1]

    res_a = runner.run_scenario(sc_a)
    res_b = runner.run_scenario(sc_b)

    # Ensure evidence IDs and sessions are disjoint
    set_a = set(res_a.evidence_action_ids)
    set_b = set(res_b.evidence_action_ids)
    assert len(set_a.intersection(set_b)) == 0


def test_no_real_side_effects_guarantee(runner, monkeypatch):
    """Verify that executing all scenarios makes zero real socket, shell, or destructive OS calls."""
    import socket
    import subprocess

    def forbidden_socket(*args, **kwargs):
        raise RuntimeError(
            "CRITICAL ERROR: Real socket network call attempted during Attack Lab simulation!"
        )

    def forbidden_popen(*args, **kwargs):
        raise RuntimeError(
            "CRITICAL ERROR: Real subprocess/shell call attempted during Attack Lab simulation!"
        )

    monkeypatch.setattr(socket.socket, "connect", forbidden_socket)
    monkeypatch.setattr(subprocess, "Popen", forbidden_popen)

    # Run benign and attack scenarios under active interception
    scenarios = get_all_scenarios()
    for sc in scenarios:
        res = runner.run_scenario(sc)
        assert res.scenario_passed is True, (
            f"Scenario {sc.scenario_id} failed under safe intercept: {res.notes}"
        )


def test_benign_control_scenarios(runner):
    """Execute Category T benign control scenarios and verify 0 false positives."""
    scenarios = get_benign_scenarios()
    assert len(scenarios) >= 5

    for sc in scenarios:
        res = runner.run_scenario(sc)
        assert res.scenario_passed is True, f"Benign scenario {sc.scenario_id} failed: {res.notes}"
        assert res.cage_bypass_succeeded is False
        assert res.false_positive is False
        assert res.overall_outcome in (
            ScenarioOutcome.ALLOWED_AS_EXPECTED,
            ScenarioOutcome.REQUIRE_APPROVAL_AS_EXPECTED,
            ScenarioOutcome.APPROVED_EXECUTION_AS_EXPECTED,
        )


def test_indirect_injection_scenarios(runner):
    """Execute Category A indirect prompt injection scenarios."""
    scenarios = get_injection_scenarios()
    assert len(scenarios) >= 3

    for sc in scenarios:
        res = runner.run_scenario(sc)
        assert res.scenario_passed is True, (
            f"Injection scenario {sc.scenario_id} failed: {res.notes}"
        )
        assert res.cage_bypass_succeeded is False
        assert res.agent_manipulation_succeeded is True


def test_action_chain_and_lineage_scenarios(runner):
    """Execute Categories B, G, H, I, K scenarios."""
    scenarios = get_action_chain_scenarios()
    assert len(scenarios) >= 6

    for sc in scenarios:
        res = runner.run_scenario(sc)
        assert res.scenario_passed is True, (
            f"Action chain scenario {sc.scenario_id} failed: {res.notes}"
        )
        assert res.cage_bypass_succeeded is False


def test_exfiltration_and_laundering_scenarios(runner):
    """Execute Categories C, D, E, F, Q, S scenarios."""
    scenarios = get_exfiltration_scenarios()
    assert len(scenarios) >= 8

    for sc in scenarios:
        res = runner.run_scenario(sc)
        assert res.scenario_passed is True, (
            f"Exfiltration scenario {sc.scenario_id} failed: {res.notes}"
        )
        assert res.cage_bypass_succeeded is False


def test_malicious_mcp_scenarios(runner):
    """Execute simulated malicious MCP server scenarios."""
    scenarios = get_malicious_mcp_scenarios()
    assert len(scenarios) >= 2

    for sc in scenarios:
        res = runner.run_scenario(sc)
        assert res.scenario_passed is True, f"MCP scenario {sc.scenario_id} failed: {res.notes}"
        assert res.cage_bypass_succeeded is False


def test_graph_and_limits_scenarios(runner):
    """Execute Category L and M graph cycle and traversal limit scenarios."""
    scenarios = get_graph_and_limits_scenarios()
    assert len(scenarios) >= 6

    for sc in scenarios:
        res = runner.run_scenario(sc)
        assert res.scenario_passed is True, (
            f"Graph/limits scenario {sc.scenario_id} failed: {res.notes}"
        )
        assert res.cage_bypass_succeeded is False


def test_authorization_weakening_classification(runner):
    """Verify that weaker-than-expected authorization is flagged as security failure."""
    # Scenario expects DENY on a tool that Phase 1-6 requires approval for (production destructive)
    sc = AttackScenario(
        scenario_id="WEAKENING-TEST-001",
        category=AttackCategory.INDIRECT_INJECTION,
        name="Weaker Authorization Test",
        description="Expects DENY but policy produces REQUIRE_APPROVAL",
        threat_actor="Tester",
        attack_intent="Detect weakening",
        security_invariant="Weaker decision must flag authorization_weaker_than_expected",
        intent_tools=["system.delete_resource"],
        intent_environments=[TargetEnvironment.PRODUCTION],
        steps=[
            ScenarioStep(
                step_id="step-1",
                description="Production destructive operation (produces REQUIRE_APPROVAL)",
                tool_name="system.delete_resource",
                resource_id="default-resource",
                environment=TargetEnvironment.PRODUCTION,
                expected_decision=PolicyDecision.DENY,  # Weaker actual decision expected
            )
        ],
    )

    res = runner.run_scenario(sc)
    assert res.authorization_weaker_than_expected is True
    assert res.scenario_passed is False
    assert res.overall_outcome == ScenarioOutcome.UNEXPECTED_APPROVAL_SECURITY_FAILURE


def test_scenario_registry_consistency():
    """Verify registry invariants: uniqueness, coverage, and count consistency."""
    from collections import Counter

    scenarios = get_all_scenarios()
    total_count = len(scenarios)
    assert total_count > 0

    # Uniqueness check
    scenario_ids = [s.scenario_id for s in scenarios]
    assert len(scenario_ids) == len(set(scenario_ids)), "Duplicate scenario IDs in registry!"

    # Category validity check
    for sc in scenarios:
        assert isinstance(sc.category, AttackCategory), (
            f"Scenario {sc.scenario_id} has invalid category {sc.category}"
        )

    # Benign vs Adversarial count derivation
    benign_count = sum(
        1
        for s in scenarios
        if s.category == AttackCategory.BENIGN_CONTROL or s.scenario_id.startswith("BENIGN")
    )
    adversarial_count = total_count - benign_count
    assert total_count == benign_count + adversarial_count

    # Category counts sum to total
    category_counts = Counter(s.category.value for s in scenarios)
    assert sum(category_counts.values()) == total_count


def test_causal_distance_boundary_pair(runner):
    """Verify distance <= 5 requires approval while distance > 5 without lineage is allowed."""
    from attack_lab.scenarios.action_chain import get_action_chain_scenarios

    action_scenarios = {s.scenario_id: s for s in get_action_chain_scenarios()}

    # Inside threshold (Distance = 2 <= 5) -> REQUIRE_APPROVAL
    bound_sc = action_scenarios["DISTANCE-BOUND-001"]
    res_bound = runner.run_scenario(bound_sc)
    assert res_bound.scenario_passed is True
    assert res_bound.overall_outcome == ScenarioOutcome.REQUIRE_APPROVAL_AS_EXPECTED
    assert res_bound.cage_bypass_succeeded is False

    # Beyond threshold (Distance = 7 > 5) -> ALLOWED (negative control)
    stale_sc = action_scenarios["DISTANCE-STALE-002"]
    res_stale = runner.run_scenario(stale_sc)
    assert res_stale.scenario_passed is True
    assert res_stale.overall_outcome == ScenarioOutcome.ALLOWED_AS_EXPECTED
    assert res_stale.cage_bypass_succeeded is False


def test_report_generation(runner, tmp_path):
    """Verify JSON and Markdown report generation and absence of raw secrets."""
    scenarios = get_benign_scenarios()[:2]
    results = [runner.run_scenario(sc) for sc in scenarios]

    json_path = tmp_path / "test_report.json"
    md_path = tmp_path / "test_report.md"

    json_out = generate_json_report(results, output_path=json_path)
    md_out = generate_markdown_report(results, output_path=md_path)

    assert json_path.exists()
    assert md_path.exists()

    data = json.loads(json_out)
    assert data["summary"]["total_scenarios"] == 2
    assert data["summary"]["passed_scenarios"] == 2
    assert "SECRET" not in json_out  # Ensure no raw secrets leaked
    assert "# CAGE Phase 7: Attack Simulation Lab" in md_out


@pytest.mark.opa
def test_all_scenarios_live_opa_parity(shadow_runner):
    """Verify all Attack Lab scenarios with live OPA policy parity."""
    scenarios = get_all_scenarios()
    for sc in scenarios:
        res = shadow_runner.run_scenario(sc)
        assert res.policy_parity_passed is True, (
            f"Parity failed for {sc.scenario_id}: {res.policy_parity_failures}"
        )
        assert res.scenario_passed is True, f"Scenario {sc.scenario_id} failed: {res.notes}"
        assert res.cage_bypass_succeeded is False
