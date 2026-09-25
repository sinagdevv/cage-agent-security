"""CAGE Attack Simulation Lab CLI and Benchmark Entry Point.

Executes all deterministic Phase 7 attack and benign scenarios against the real CAGE gateway,
verifies security invariants, and generates JSON and Markdown evaluation reports.
"""

import sys
from pathlib import Path

# Add backend to sys.path for app module imports
backend_dir = Path(__file__).resolve().parent / "backend"
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.schemas.enums import PolicyBackend  # noqa: E402
from attack_lab.reporting import (  # noqa: E402
    generate_attack_metrics,
    generate_json_report,
    generate_markdown_report,
)
from attack_lab.runner import AttackScenarioRunner  # noqa: E402
from attack_lab.scenarios import get_all_scenarios  # noqa: E402


def main():
    print("=" * 80)
    print("CAGE PHASE 7: ATTACK SIMULATION LAB")
    print("Deterministic Adversarial Evaluation and Governance Invariant Verification")
    print("=" * 80)

    # Initialize Runner with Shadow Policy Backend (Python + live OPA parity check)
    runner = AttackScenarioRunner(policy_backend=PolicyBackend.SHADOW)
    scenarios = get_all_scenarios()
    print(f"\n[+] Loaded {len(scenarios)} deterministic scenarios across Categories A-T.")
    print("[+] Executing scenarios through isolated real CAGE AgentGateway instances...\n")

    results = []
    for sc in scenarios:
        res = runner.run_scenario(sc)
        results.append(res)

        status_symbol = "[PASS]" if res.scenario_passed else "[FAIL]"
        bypass_symbol = "BYPASS DETECTED!" if res.cage_bypass_succeeded else "contained"
        print(
            f"  {status_symbol} {sc.scenario_id:<18} | {sc.category.value:<26} | "
            f"Bypass: {bypass_symbol:<16} | Outcome: {res.overall_outcome.value}"
        )

    # Generate Reports
    reports_dir = Path("attack_lab/reports")
    reports_dir.mkdir(parents=True, exist_ok=True)
    json_path = reports_dir / "attack_report.json"
    md_path = reports_dir / "attack_report.md"

    generate_json_report(results, output_path=json_path)
    generate_markdown_report(results, output_path=md_path)

    metrics = generate_attack_metrics(results)
    print("\n" + "=" * 80)
    print("EVALUATION SUMMARY")
    print("=" * 80)
    print(f"Total Scenarios Evaluated  : {metrics['total_scenarios']}")
    print(
        f"Passed Invariant Checks    : {metrics['passed_scenarios']} ({metrics['pass_rate_pct']}%)"
    )
    print(f"Failed Invariant Checks    : {metrics['failed_scenarios']}")
    print(f"CAGE Bypasses Detected     : {metrics['cage_bypasses']}")
    print(f"False Positives (Benign)   : {metrics['false_positives']}")
    print(f"False Negatives (Missed)   : {metrics['false_negatives']}")
    print(f"Policy Parity Failures     : {metrics['policy_parity_failures']}")
    print(f"Median Execution Latency   : {metrics['median_duration_ms']} ms")
    print(f"P95 Execution Latency      : {metrics['p95_duration_ms']} ms")
    print("\n[+] Reports generated:")
    print(f"    - JSON: {json_path}")
    print(f"    - MD  : {md_path}")
    print("=" * 80)

    if metrics["failed_scenarios"] > 0 or metrics["cage_bypasses"] > 0:
        print("\n[!] Attack Simulation Lab completed with failures or bypasses.")
        sys.exit(1)
    else:
        print("\n[+] All Attack Lab security invariants verified successfully!")
        sys.exit(0)


if __name__ == "__main__":
    main()
