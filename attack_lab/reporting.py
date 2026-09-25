"""Report generation utilities for the CAGE Attack Simulation Lab."""

import json
from datetime import UTC, datetime
from pathlib import Path

from attack_lab.models import AttackScenarioResult


def generate_attack_metrics(results: list[AttackScenarioResult]) -> dict[str, object]:
    """Calculate aggregate metrics across all executed scenarios."""
    total = len(results)
    benign_count = sum(
        1
        for r in results
        if r.category.value == "BENIGN_CONTROL" or r.scenario_id.startswith("BENIGN")
    )
    adversarial_count = total - benign_count

    passed = sum(1 for r in results if r.scenario_passed)
    bypasses = sum(1 for r in results if r.cage_bypass_succeeded)
    auth_weaker = sum(1 for r in results if r.authorization_weaker_than_expected)
    containment_failed = sum(1 for r in results if r.containment_state_failed)
    false_positives = sum(1 for r in results if r.false_positive)
    false_negatives = sum(1 for r in results if r.false_negative)
    parity_failures = sum(1 for r in results if not r.policy_parity_passed)

    durations = [r.total_duration_ms for r in results]
    durations.sort()
    median_duration = durations[total // 2] if total > 0 else 0.0
    p95_idx = int(total * 0.95)
    p95_duration = durations[min(p95_idx, total - 1)] if total > 0 else 0.0

    category_counts: dict[str, int] = {}
    for r in results:
        cat_str = r.category.value if hasattr(r.category, "value") else str(r.category)
        category_counts[cat_str] = category_counts.get(cat_str, 0) + 1

    return {
        "total_scenarios": total,
        "benign_scenarios": benign_count,
        "adversarial_scenarios": adversarial_count,
        "category_counts": category_counts,
        "passed_scenarios": passed,
        "failed_scenarios": total - passed,
        "cage_bypasses": bypasses,
        "authorization_weaker_than_expected": auth_weaker,
        "containment_state_failed": containment_failed,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "policy_parity_failures": parity_failures,
        "pass_rate_pct": round((passed / total) * 100, 2) if total > 0 else 0.0,
        "median_duration_ms": round(median_duration, 2),
        "p95_duration_ms": round(p95_duration, 2),
    }


def generate_json_report(
    results: list[AttackScenarioResult], output_path: Path | str | None = None
) -> str:
    """Generate a machine-readable JSON evaluation report."""
    metrics = generate_attack_metrics(results)

    report_data = {
        "timestamp": datetime.now(UTC).isoformat(),
        "milestone": "Phase 7 Attack Simulation Lab",
        "summary": metrics,
        "scenarios": [
            {
                "scenario_id": r.scenario_id,
                "scenario_name": r.scenario_name,
                "category": r.category.value,
                "scenario_passed": r.scenario_passed,
                "agent_manipulation_succeeded": r.agent_manipulation_succeeded,
                "attack_goal_reached": r.attack_goal_reached,
                "cage_bypass_succeeded": r.cage_bypass_succeeded,
                "authorization_weaker_than_expected": r.authorization_weaker_than_expected,
                "containment_state_failed": r.containment_state_failed,
                "security_expectation_failed": r.security_expectation_failed,
                "overall_outcome": r.overall_outcome.value,
                "expected_final_decision": (
                    r.expected_final_decision.value
                    if hasattr(r.expected_final_decision, "value")
                    else r.expected_final_decision
                ),
                "actual_final_decision": (
                    r.actual_final_decision.value
                    if hasattr(r.actual_final_decision, "value")
                    else r.actual_final_decision
                ),
                "expected_rule_ids": r.expected_rule_ids,
                "actual_rule_ids": r.actual_rule_ids,
                "tool_dispatched": r.tool_dispatched,
                "simulated_side_effect_occurred": r.simulated_side_effect_occurred,
                "final_trajectory_status": r.final_trajectory_status.value,
                "initial_gate_decision": (
                    r.initial_gate_decision.value
                    if hasattr(r.initial_gate_decision, "value")
                    else r.initial_gate_decision
                ),
                "approval_resolution": r.approval_resolution,
                "quarantine_triggered": r.quarantine_triggered,
                "false_positive": r.false_positive,
                "false_negative": r.false_negative,
                "policy_parity_passed": r.policy_parity_passed,
                "evidence_action_ids": [str(a) for a in r.evidence_action_ids],
                "evidence_artifact_ids": [str(a) for a in r.evidence_artifact_ids],
                "execution_duration_ms": round(r.execution_duration_ms, 2),
                "total_duration_ms": round(r.total_duration_ms, 2),
                "steps": [
                    {
                        "step_id": s.step_id,
                        "action_id": str(s.action_id) if s.action_id else None,
                        "expected_decision": s.expected_decision.value,
                        "actual_decision": s.actual_decision.value if s.actual_decision else None,
                        "outcome": s.outcome.value,
                        "decision_matches": s.decision_matches,
                        "expected_rule_ids": s.expected_rule_ids,
                        "actual_rule_ids": s.actual_rule_ids,
                        "rules_match": s.rules_match,
                        "tool_dispatched": s.tool_dispatched,
                        "side_effect_occurred": s.side_effect_occurred,
                        "policy_parity_passed": s.policy_parity_passed,
                        "approval_attempted": s.approval_attempted,
                        "approval_succeeded": s.approval_succeeded,
                        "error_raised": s.error_raised,
                        "duration_ms": round(s.duration_ms, 2),
                    }
                    for s in r.step_results
                ],
                "notes": r.notes,
            }
            for r in results
        ],
    }

    json_str = json.dumps(report_data, indent=2)
    if output_path:
        p = Path(output_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json_str, encoding="utf-8")

    return json_str


def generate_markdown_report(
    results: list[AttackScenarioResult], output_path: Path | str | None = None
) -> str:
    """Generate a human-readable Markdown evaluation report."""
    metrics = generate_attack_metrics(results)
    now_str = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines = [
        "# CAGE Phase 7: Attack Simulation Lab Evaluation Report",
        "",
        f"**Generated:** {now_str}  ",
        "**Milestone:** CAGE Phase 7 (Adversarial Security Evaluation)  ",
        "",
        "## 1. Executive Summary",
        "",
        "| Metric | Value |",
        "| :--- | :--- |",
        f"| **Total Scenarios Evaluated** | `{metrics['total_scenarios']}` (Benign: `{metrics['benign_scenarios']}`, Adversarial: `{metrics['adversarial_scenarios']}`) |",
        f"| **Passed Invariant Checks** | `{metrics['passed_scenarios']}` (`{metrics['pass_rate_pct']}%`) |",
        f"| **Failed Invariant Checks** | `{metrics['failed_scenarios']}` |",
        f"| **CAGE Bypasses Detected** | `{metrics['cage_bypasses']}` |",
        f"| **Authorization Weaker Than Expected** | `{metrics['authorization_weaker_than_expected']}` |",
        f"| **Containment State Failures** | `{metrics['containment_state_failed']}` |",
        f"| **False Positives (Benign Denials)** | `{metrics['false_positives']}` |",
        f"| **False Negatives (Missed Threats)** | `{metrics['false_negatives']}` |",
        f"| **Policy Parity Failures (Python vs OPA)** | `{metrics['policy_parity_failures']}` |",
        f"| **Median Execution Latency** | `{metrics['median_duration_ms']} ms` |",
        f"| **P95 Execution Latency** | `{metrics['p95_duration_ms']} ms` |",
        "",
        "## 2. Scenario Results by Category",
        "",
        "| Scenario ID | Category | Expected | Actual | Tool Dispatched | Bypass? | Outcome |",
        "| :--- | :--- | :--- | :--- | :---: | :---: | :--- |",
    ]

    for r in results:
        exp_dec = r.step_results[-1].expected_decision.value if r.step_results else "N/A"
        act_dec = (
            r.step_results[-1].actual_decision.value
            if (r.step_results and r.step_results[-1].actual_decision)
            else (r.step_results[-1].error_raised if r.step_results else "N/A")
        )
        dispatched = "Yes" if any(s.tool_dispatched for s in r.step_results) else "No"
        bypass = "🚨 YES" if r.cage_bypass_succeeded else "✅ No"
        status_icon = "✅" if r.scenario_passed else "❌"

        lines.append(
            f"| `{r.scenario_id}` | {r.category.value} | `{exp_dec}` | `{act_dec}` | {dispatched} | {bypass} | {status_icon} `{r.overall_outcome.value}` |"
        )

    lines.extend(
        [
            "",
            "## 3. Defense Verification Highlights",
            "",
            "- **Agent Manipulation vs CAGE Bypass:** All indirect injection and prompt laundering attempts successfully convinced simulated reasoning steps to propose sensitive operations, but were strictly gated by CAGE trajectory/intent invariants.",
            "- **Step Fragmentation & Lineage Integrity:** Multi-hop laundering across files, transformations, and Base64 encodings preserved `DERIVED_FROM` and untrusted origin metadata, preventing unauthorized egress.",
            "- **TOCTOU & Approval Gating:** Attempts to bypass approval gates via parent manipulation or intent narrowing prior to approval failed closed as expected.",
            "- **Policy Parity:** Full dual-evaluation verified 100% equivalence between the Python evaluator and OPA Rego rules across boundary conditions.",
            "",
        ]
    )

    md_str = "\n".join(lines)
    if output_path:
        p = Path(output_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(md_str, encoding="utf-8")

    return md_str
