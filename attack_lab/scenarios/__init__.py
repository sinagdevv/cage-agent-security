from attack_lab.scenarios.action_chain import get_action_chain_scenarios
from attack_lab.scenarios.authority_expansion import get_authority_expansion_scenarios
from attack_lab.scenarios.benign import get_benign_scenarios
from attack_lab.scenarios.delegation import get_delegation_scenarios
from attack_lab.scenarios.destination_attacks import get_destination_attacks_scenarios
from attack_lab.scenarios.exfiltration import get_exfiltration_scenarios
from attack_lab.scenarios.graph_and_limits import get_graph_and_limits_scenarios
from attack_lab.scenarios.injection import get_injection_scenarios
from attack_lab.scenarios.malicious_mcp import get_malicious_mcp_scenarios
from attack_lab.scenarios.policy_parity import get_policy_parity_scenarios
from attack_lab.scenarios.replay_attacks import get_replay_attacks_scenarios
from attack_lab.scenarios.unknown_entities import get_unknown_entities_scenarios


def get_all_scenarios():
    """Aggregate all deterministic attack scenarios across all categories."""
    scenarios = []
    scenarios.extend(get_benign_scenarios())
    scenarios.extend(get_injection_scenarios())
    scenarios.extend(get_action_chain_scenarios())
    scenarios.extend(get_exfiltration_scenarios())
    scenarios.extend(get_malicious_mcp_scenarios())
    scenarios.extend(get_unknown_entities_scenarios())
    scenarios.extend(get_authority_expansion_scenarios())
    scenarios.extend(get_destination_attacks_scenarios())
    scenarios.extend(get_replay_attacks_scenarios())
    scenarios.extend(get_graph_and_limits_scenarios())
    scenarios.extend(get_policy_parity_scenarios())
    scenarios.extend(get_delegation_scenarios())
    return scenarios
