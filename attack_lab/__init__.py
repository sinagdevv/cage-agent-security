"""CAGE Attack Simulation Lab.

Adversarial evaluation harness verifying Phase 1-6 causal governance and authorization invariants.
"""

from attack_lab.models import (
    AttackScenario,
    AttackScenarioResult,
    ScenarioOutcome,
    ScenarioStep,
)
from attack_lab.runner import AttackScenarioRunner

__all__ = [
    "AttackScenario",
    "AttackScenarioResult",
    "ScenarioOutcome",
    "ScenarioStep",
    "AttackScenarioRunner",
]
