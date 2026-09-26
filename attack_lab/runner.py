"""AttackScenarioRunner orchestrating isolated, deterministic adversarial simulations."""

import time
from uuid import UUID, uuid4

from app.delegation.analyzer import DelegationAnalyzer
from app.delegation.models import DelegationProposal, ResourceAuthorityScopeRequest
from app.delegation.service import DelegationService
from app.delegation.store import DelegationStore
from app.gateway.service import AgentGateway
from app.graph.causal_graph import (
    CrossSessionParentError,
    ParentActionNotFoundError,
    SessionGraphManager,
)
from app.identity.principal import AgentPrincipal, PrincipalAuthenticationSource
from app.intent.service import IntentService
from app.policies.engine import PolicyEngine
from app.policies.rules import DeterministicPolicyEvaluator
from app.provenance.analyzer import ProvenanceAnalyzer
from app.provenance.factory import ArtifactFactory
from app.provenance.store import ArtifactPayloadStore, ProvenanceStore
from app.schemas.action import AgentActionProposal
from app.schemas.enums import (
    AuthorityScopeMode,
    DataClassification,
    PolicyBackend,
    PolicyDecision,
    TargetEnvironment,
    TrajectoryStatus,
    TrustLevel,
)
from app.schemas.intent import IntentContractCreate, IntentContractNarrow
from app.trajectory.analyzer import TrajectoryAnalyzer, TrajectoryAnalyzerConfig
from app.trajectory.store import InvalidTrajectoryContinuationError, TrajectoryStore
from attack_lab.fixtures import (
    build_attack_resource_registry,
    build_attack_tool_registry,
    seed_initial_artifacts,
)
from attack_lab.models import (
    AttackScenario,
    AttackScenarioResult,
    ScenarioOutcome,
    ScenarioStep,
    StepResult,
)


class AttackScenarioRunner:
    """Orchestrates end-to-end attack scenarios through real CAGE AgentGateway instances."""

    def __init__(self, policy_backend: PolicyBackend = PolicyBackend.SHADOW) -> None:
        self.policy_backend = policy_backend

    def run_scenario(self, scenario: AttackScenario) -> AttackScenarioResult:
        """Run an attack scenario in complete isolation and produce an AttackScenarioResult."""
        start_time = time.perf_counter()

        # 1. Generate isolated identifiers
        session_id = uuid4()
        agent_id = uuid4()

        # 2. Build isolated components
        tool_registry, mock_recorder, tool_executor = build_attack_tool_registry()
        resource_registry = build_attack_resource_registry()
        graph_manager = SessionGraphManager()
        intent_service = IntentService()
        prov_store = ProvenanceStore()
        payload_store = ArtifactPayloadStore()
        traj_store = TrajectoryStore()

        prov_analyzer = ProvenanceAnalyzer(
            store=prov_store,
            max_depth=scenario.max_provenance_depth,
            max_artifacts=scenario.max_nodes,
        )
        traj_config = TrajectoryAnalyzerConfig(
            max_action_depth=scenario.max_action_depth or 20,
            max_nodes=scenario.max_nodes or 100,
        )
        traj_analyzer = TrajectoryAnalyzer(config=traj_config)
        evaluator = DeterministicPolicyEvaluator(tool_registry=tool_registry)
        engine = PolicyEngine(python_evaluator=evaluator, backend=self.policy_backend)

        delegation_store = DelegationStore()
        delegation_analyzer = DelegationAnalyzer()
        delegation_service = DelegationService(
            store=delegation_store,
            intent_service=intent_service,
            evaluator=evaluator,
            graph_manager=graph_manager,
            analyzer=delegation_analyzer,
        )

        gateway = AgentGateway(
            graph_manager=graph_manager,
            policy_engine=engine,
            intent_service=intent_service,
            tool_registry=tool_registry,
            tool_executor=tool_executor,
            provenance_store=prov_store,
            provenance_analyzer=prov_analyzer,
            artifact_factory=ArtifactFactory(),
            resource_registry=resource_registry,
            trajectory_store=traj_store,
            trajectory_analyzer=traj_analyzer,
            delegation_service=delegation_service,
            require_intent=True,
        )

        # 3. Create Intent Contract
        allowed_tools = scenario.intent_tools or ["web.search", "text.summarize", "file.read"]
        allowed_res = scenario.intent_resources or ["*"]
        allowed_envs = scenario.intent_environments or [
            TargetEnvironment.PRODUCTION,
            TargetEnvironment.LOCAL,
        ]
        allowed_cls = scenario.intent_classifications or [
            DataClassification.PUBLIC,
            DataClassification.INTERNAL,
            DataClassification.CONFIDENTIAL,
            DataClassification.RESTRICTED,
            DataClassification.SECRET,
            DataClassification.CREDENTIAL,
            DataClassification.PII,
        ]

        intent = intent_service.create_intent(
            IntentContractCreate(
                session_id=str(session_id),
                agent_id=str(agent_id),
                goal=f"Goal for {scenario.scenario_id}",
                description=f"Intent for {scenario.scenario_id}",
                allowed_tools=allowed_tools,
                allowed_resources=allowed_res,
                allowed_environments=allowed_envs,
                allowed_data_classifications=allowed_cls,
                maximum_tool_calls=scenario.intent_max_actions,
            )
        )

        # 4. Seed initial artifacts
        artifact_map = seed_initial_artifacts(
            scenario.initial_artifacts, session_id, prov_store, payload_store
        )

        # 5. Execute steps sequentially
        step_map: dict[str, UUID] = {}
        delegation_map: dict[str, UUID] = {}
        step_results: list[StepResult] = []
        last_action_id: UUID | None = None
        bypass_detected = False
        auth_weaker_detected = False
        containment_failed = False
        parity_failures: list[str] = []
        evidence_actions: list[UUID] = []
        evidence_artifacts: list[UUID] = list(artifact_map.values())
        notes: list[str] = []

        for step in scenario.steps:
            step_start = time.perf_counter()
            action_id: UUID | None = None
            actual_decision: PolicyDecision | None = None
            actual_rules: list[str] = []
            tool_dispatched = False
            side_effect = False
            error_msg: str | None = None
            parity_passed = True
            approval_attempted = False
            approval_succeeded: bool | None = None

            current_agent_id = str(step.agent_id) if step.agent_id else str(agent_id)
            principal = AgentPrincipal(
                agent_id=current_agent_id,
                session_id=session_id,
                authentication_source=PrincipalAuthenticationSource.TEST_FIXTURE,
                is_control_plane=bool(step.metadata.get("is_control_plane", False)),
            )

            # Check if this step is for direct delegation revocation / close
            if step.metadata.get("revoke_delegation_key"):
                rev_del_id = delegation_map.get(step.metadata["revoke_delegation_key"])
                if rev_del_id:
                    rev_principal = principal
                    if not step.metadata.get("revoke_as_caller", False):
                        # Default to authoritative root Intent owner / control plane for out-of-band revocation
                        rev_principal = AgentPrincipal(
                            agent_id=str(agent_id),
                            session_id=session_id,
                            authentication_source=PrincipalAuthenticationSource.TEST_FIXTURE,
                            is_control_plane=True,
                        )
                    try:
                        delegation_service.revoke_delegation(
                            delegation_id=rev_del_id,
                            principal=rev_principal,
                            reason="Revoked during scenario",
                        )
                    except Exception as e:
                        notes.append(f"Revocation error: {e}")
            elif step.metadata.get("close_delegation_key"):
                cls_del_id = delegation_map.get(step.metadata["close_delegation_key"])
                if cls_del_id:
                    grant_obj = delegation_store.get_grant(cls_del_id)
                    cls_agent_id = grant_obj.delegatee_agent_id if grant_obj else current_agent_id
                    cls_principal = AgentPrincipal(
                        agent_id=cls_agent_id,
                        session_id=session_id,
                        authentication_source=PrincipalAuthenticationSource.TEST_FIXTURE,
                    )
                    try:
                        delegation_service.close_delegation(
                            delegation_id=cls_del_id,
                            principal=cls_principal,
                        )
                    except Exception as e:
                        notes.append(f"Close error: {e}")
            elif step.metadata.get("create_cross_session_grant_key"):
                foreign_sess = uuid4()
                foreign_intent = intent_service.create_intent(
                    IntentContractCreate(
                        session_id=str(foreign_sess),
                        agent_id=str(agent_id),
                        goal="Foreign session intent",
                        allowed_tools=["web.search"],
                    )
                )
                foreign_princ = AgentPrincipal(
                    agent_id=str(agent_id),
                    session_id=foreign_sess,
                    authentication_source=PrincipalAuthenticationSource.TEST_FIXTURE,
                    is_control_plane=True,
                )
                foreign_res = delegation_service.propose_delegation(
                    DelegationProposal(
                        session_id=foreign_sess,
                        root_intent_id=foreign_intent.intent_id,
                        delegator_agent_id=str(agent_id),
                        delegatee_agent_id=current_agent_id,
                        delegated_task_id="task-foreign",
                        requested_tools=["web.search"],
                    ),
                    principal=foreign_princ,
                )
                delegation_map[step.metadata["create_cross_session_grant_key"]] = (
                    foreign_res.delegation_id
                )

            # Handle Delegation Creation Steps
            if step.is_delegation_creation:
                prop_data = step.delegation_proposal or {}
                parent_del_id = None
                if "parent_delegation_key" in prop_data:
                    parent_del_id = delegation_map.get(prop_data["parent_delegation_key"])
                elif "parent_delegation_id" in prop_data:
                    parent_del_id = prop_data["parent_delegation_id"]

                if "requested_resources" in prop_data:
                    req_scope = prop_data["requested_resources"]
                    if isinstance(req_scope, list):
                        res_scope = ResourceAuthorityScopeRequest.allowlist(req_scope)
                    elif isinstance(req_scope, ResourceAuthorityScopeRequest):
                        res_scope = req_scope
                    else:
                        res_scope = ResourceAuthorityScopeRequest.unconstrained()
                elif "requested_resource_scope" in prop_data:
                    res_scope = prop_data["requested_resource_scope"]
                else:
                    # Inherit in-scope resource bounds from parent / root intent
                    if parent_del_id:
                        parent_grant = delegation_store.get_grant(parent_del_id)
                        if parent_grant:
                            res_scope = (
                                ResourceAuthorityScopeRequest.allowlist(
                                    list(
                                        parent_grant.authority_envelope.resource_scope.allowed_resources
                                    )
                                )
                                if parent_grant.authority_envelope.resource_scope.mode
                                == AuthorityScopeMode.ALLOWLIST
                                else ResourceAuthorityScopeRequest.unconstrained()
                            )
                        else:
                            res_scope = ResourceAuthorityScopeRequest.allowlist(
                                list(intent.allowed_resources)
                            )
                    else:
                        res_scope = ResourceAuthorityScopeRequest.allowlist(
                            list(intent.allowed_resources)
                        )

                raw_delegatee = prop_data.get("delegatee_agent_id")
                if isinstance(raw_delegatee, str):
                    delegatee_id = raw_delegatee
                elif isinstance(raw_delegatee, UUID):
                    delegatee_id = str(raw_delegatee)
                else:
                    delegatee_id = str(uuid4())

                del_prop = DelegationProposal(
                    session_id=session_id,
                    delegator_agent_id=current_agent_id,
                    delegatee_agent_id=delegatee_id,
                    parent_delegation_id=parent_del_id,
                    delegated_task_id=prop_data.get("delegated_task_id", f"task-{step.step_id}"),
                    requested_tools=prop_data.get("requested_tools", ["web.search"]),
                    requested_resource_scope=res_scope,
                    requested_environments=prop_data.get(
                        "requested_environments", [TargetEnvironment.PRODUCTION]
                    ),
                    requested_classifications=prop_data.get(
                        "requested_classifications",
                        prop_data.get(
                            "requested_data_classifications",
                            [DataClassification.PUBLIC, DataClassification.INTERNAL],
                        ),
                    ),
                    requested_max_actions=prop_data.get("requested_max_actions", 10),
                    requested_ttl_seconds=prop_data.get("requested_ttl_seconds", 3600),
                    allow_subdelegation=prop_data.get("allow_subdelegation", True),
                    requested_depth=prop_data.get(
                        "requested_depth",
                        prop_data.get("requested_subdelegation_depth", 3),
                    ),
                )

                try:
                    create_res = delegation_service.propose_delegation(
                        proposal=del_prop, principal=principal
                    )
                    actual_decision = create_res.decision
                    actual_rules = list(create_res.matched_rules)
                    if create_res.delegation_id and step.delegation_key:
                        delegation_map[step.delegation_key] = create_res.delegation_id
                    elif (
                        create_res.delegation_request_id
                        and step.delegation_key
                        and not create_res.delegation_id
                    ):
                        delegation_map[step.delegation_key] = create_res.delegation_request_id
                    if (
                        step.metadata.get("save_request_id_as_delegation_key")
                        and create_res.delegation_request_id
                    ):
                        delegation_map[step.metadata["save_request_id_as_delegation_key"]] = (
                            create_res.delegation_request_id
                        )
                    if create_res.delegation_request_id:
                        action_id = create_res.delegation_request_id
                        step_map[step.step_id] = action_id
                        evidence_actions.append(action_id)

                    if actual_decision == PolicyDecision.REQUIRE_APPROVAL and step.request_approval:
                        approval_attempted = True
                        if step.mutate_intent_before_approval:
                            narrow_req = step.mutate_intent_before_approval
                            if "status" in narrow_req and narrow_req["status"] == "REVOKED":
                                intent_service.revoke_intent(intent.intent_id)
                            elif "tools" in narrow_req:
                                intent_service.narrow_intent(
                                    intent.intent_id,
                                    IntentContractNarrow(
                                        allowed_tools=narrow_req["tools"],
                                        allowed_resources=narrow_req.get("resources"),
                                        allowed_environments=narrow_req.get("environments"),
                                        allowed_data_classifications=narrow_req.get(
                                            "classifications"
                                        ),
                                    ),
                                )

                        appr_principal = AgentPrincipal(
                            agent_id=current_agent_id,
                            session_id=session_id,
                            authentication_source=PrincipalAuthenticationSource.TEST_FIXTURE,
                            is_control_plane=True,
                        )
                        try:
                            appr_res = delegation_service.resolve_pending_approval(
                                delegation_request_id=create_res.delegation_request_id,
                                principal=appr_principal,
                                approver_id="security-officer",
                                decision=PolicyDecision.ALLOW,
                            )
                            if appr_res.delegation_id:
                                approval_succeeded = True
                                if step.delegation_key:
                                    delegation_map[step.delegation_key] = appr_res.delegation_id
                            else:
                                approval_succeeded = False
                        except Exception as ae:
                            approval_succeeded = False
                            notes.append(f"Delegation approval rejected: {ae}")

                except Exception as e:
                    error_msg = type(e).__name__
                    notes.append(f"Step {step.step_id} delegation creation caught: {e}")

            else:
                # Regular Action Step
                # If step expects REQUIRE_APPROVAL, mutate intent between evaluation and approval resolution.
                # If step expects DENY or other, mutate intent before evaluation to test live root narrowing/revocation.
                if (
                    step.mutate_intent_before_approval
                    and step.expected_decision != PolicyDecision.REQUIRE_APPROVAL
                ):
                    narrow_req = step.mutate_intent_before_approval
                    if "status" in narrow_req and narrow_req["status"] == "REVOKED":
                        intent_service.revoke_intent(intent.intent_id)
                    elif "tools" in narrow_req:
                        intent_service.narrow_intent(
                            intent.intent_id,
                            IntentContractNarrow(
                                allowed_tools=narrow_req["tools"],
                                allowed_resources=narrow_req.get("resources"),
                                allowed_environments=narrow_req.get("environments"),
                                allowed_data_classifications=narrow_req.get("classifications"),
                            ),
                        )

                # Resolve Parent Action ID
                parent_id: UUID | None = None
                if step.omit_parent:
                    parent_id = None
                elif step.explicit_parent_action_id is not None:
                    parent_id = step.explicit_parent_action_id
                elif step.parent_step_id is not None:
                    parent_id = step_map.get(step.parent_step_id)
                else:
                    parent_id = last_action_id

                # Resolve Input Artifacts & Payload Bindings
                input_artifact_ids: list[UUID] = []
                for k in step.input_artifact_keys:
                    if k in artifact_map:
                        input_artifact_ids.append(artifact_map[k])

                tool_args = dict(step.tool_arguments)
                for param, art_key in step.payload_bindings.items():
                    if param == "destination_path":
                        if "destination" not in tool_args:
                            tool_args["destination"] = f"https://example.com{art_key}"
                    elif param in ("body", "data", "payload", "content", "token"):
                        art_id = artifact_map.get(art_key)
                        if art_id:
                            tool_args[f"{param}_artifact_id"] = str(art_id)
                            tool_args["body_artifact_id"] = str(art_id)
                        else:
                            tool_args[f"{param}_artifact_id"] = str(art_key)
                            tool_args["body_artifact_id"] = str(art_key)
                    else:
                        tool_args[param] = art_key

                input_trust = step.metadata.get("trust_level", TrustLevel.MEDIUM)
                if not isinstance(input_trust, TrustLevel):
                    try:
                        input_trust = TrustLevel(str(input_trust))
                    except ValueError:
                        input_trust = TrustLevel.MEDIUM

                # Resolve claimed delegation_id if any
                claimed_del_id: UUID | None = None
                if step.delegation_key:
                    claimed_del_id = delegation_map.get(step.delegation_key)
                elif step.delegation_proposal and "delegation_id" in step.delegation_proposal:
                    raw_id = step.delegation_proposal["delegation_id"]
                    claimed_del_id = UUID(raw_id) if isinstance(raw_id, str) else raw_id

                proposal = AgentActionProposal(
                    session_id=str(session_id),
                    agent_id=str(current_agent_id),
                    tool_name=step.tool_name,
                    action_type=step.action_type,
                    target_resource=step.resource_id,
                    target_environment=step.environment,
                    parent_action_id=parent_id,
                    input_artifact_ids=input_artifact_ids,
                    tool_arguments=tool_args,
                    input_trust_level=input_trust,
                    client_action_id=str(step.client_action_id) if step.client_action_id else None,
                    delegation_id=claimed_del_id,
                )

                # Process Proposal through Real Gateway
                try:
                    action, decision = gateway.evaluate_proposal(proposal, principal=principal)
                    action_id = action.action_id
                    step_map[step.step_id] = action_id
                    last_action_id = action_id
                    evidence_actions.append(action_id)

                    actual_decision = decision.decision
                    actual_rules = list(decision.matched_rules)

                    # If tool was authorized, execute through gateway
                    if actual_decision == PolicyDecision.ALLOW:
                        tool_result = gateway.execute_authorized_action(action.action_id)
                        if tool_result is not None:
                            tool_dispatched = True

                    # Check if simulated side effects were recorded
                    if any(c["action_id"] == action_id for c in mock_recorder.side_effects):
                        side_effect = True

                    # Handle Step Approval Flow if requested
                    approval_attempted = False
                    approval_succeeded = None
                    if actual_decision == PolicyDecision.REQUIRE_APPROVAL and step.request_approval:
                        approval_attempted = True
                        # Apply intent mutation before approval if specified (for TOCTOU testing)
                        if step.mutate_intent_before_approval:
                            narrow_req = step.mutate_intent_before_approval
                            if "status" in narrow_req and narrow_req["status"] == "REVOKED":
                                intent_service.revoke_intent(intent.intent_id)
                            elif "tools" in narrow_req:
                                intent_service.narrow_intent(
                                    intent.intent_id,
                                    IntentContractNarrow(
                                        allowed_tools=narrow_req["tools"],
                                        allowed_resources=narrow_req.get("resources"),
                                        allowed_environments=narrow_req.get("environments"),
                                        allowed_data_classifications=narrow_req.get(
                                            "classifications"
                                        ),
                                    ),
                                )

                        # Execute approval through Gateway
                        try:
                            appr_action, appr_res = gateway.resolve_pending_approval(
                                action_id=action_id,
                                approved=True,
                            )
                            if appr_res is not None and appr_res.get("success"):
                                tool_dispatched = True
                                approval_succeeded = True
                            else:
                                approval_succeeded = False
                            if any(c["action_id"] == action_id for c in mock_recorder.side_effects):
                                side_effect = True
                        except (ValueError, PermissionError) as ae:
                            approval_succeeded = False
                            notes.append(f"Approval for {step.step_id} rejected: {ae}")

                except (
                    ParentActionNotFoundError,
                    CrossSessionParentError,
                    InvalidTrajectoryContinuationError,
                    ValueError,
                    Exception,
                ) as e:
                    error_msg = type(e).__name__
                    notes.append(f"Step {step.step_id} caught exception: {error_msg} ({e})")

            step_duration = (time.perf_counter() - step_start) * 1000

            # Evaluate Step Outcome
            outcome = self._classify_step_outcome(
                step=step,
                actual_decision=actual_decision,
                actual_rules=actual_rules,
                error_msg=error_msg,
                parity_passed=parity_passed,
                tool_dispatched=tool_dispatched,
                side_effect=side_effect,
            )

            # Authorization weakening check: DENY -> REQUIRE_APPROVAL/ALLOW or REQUIRE_APPROVAL -> ALLOW
            if step.expected_decision in (PolicyDecision.DENY, PolicyDecision.QUARANTINE):
                if actual_decision == PolicyDecision.REQUIRE_APPROVAL:
                    auth_weaker_detected = True
                elif actual_decision == PolicyDecision.ALLOW:
                    auth_weaker_detected = True
                    if tool_dispatched:
                        bypass_detected = True
            elif step.expected_decision == PolicyDecision.REQUIRE_APPROVAL:
                if actual_decision == PolicyDecision.ALLOW:
                    auth_weaker_detected = True
                    if tool_dispatched and not (step.request_approval and approval_succeeded):
                        bypass_detected = True

            # Check for bypass
            if outcome == ScenarioOutcome.UNEXPECTED_ALLOW_SECURITY_FAILURE:
                bypass_detected = True
            elif step.expected_decision in (PolicyDecision.DENY, PolicyDecision.QUARANTINE):
                if tool_dispatched:
                    bypass_detected = True
            elif step.expected_decision == PolicyDecision.REQUIRE_APPROVAL:
                if tool_dispatched and not (step.request_approval and approval_succeeded):
                    bypass_detected = True

            if step.expect_error:
                decision_matches = error_msg == step.expect_error
            elif step.expected_decision in (PolicyDecision.DENY, PolicyDecision.QUARANTINE):
                decision_matches = actual_decision in (
                    PolicyDecision.DENY,
                    PolicyDecision.QUARANTINE,
                )
            else:
                decision_matches = actual_decision == step.expected_decision

            rules_match = (
                all(r in actual_rules for r in step.expected_rule_ids)
                if step.expected_rule_ids
                else True
            )

            step_results.append(
                StepResult(
                    step_id=step.step_id,
                    action_id=action_id,
                    expected_decision=step.expected_decision,
                    actual_decision=actual_decision,
                    outcome=outcome,
                    decision_matches=decision_matches,
                    expected_rule_ids=step.expected_rule_ids,
                    actual_rule_ids=actual_rules,
                    rules_match=rules_match,
                    tool_dispatched=tool_dispatched,
                    side_effect_occurred=side_effect,
                    policy_parity_passed=parity_passed,
                    error_raised=error_msg,
                    approval_attempted=approval_attempted,
                    approval_succeeded=approval_succeeded,
                    duration_ms=step_duration,
                )
            )

        # 6. Global Trajectory & Scenario Outcome Assessment
        traj_id = traj_store.get_trajectory_id_for_session(str(session_id))
        traj = traj_store.get_snapshot(traj_id) if traj_id else None
        final_traj_status = traj.status if traj else TrajectoryStatus.ACTIVE

        # Quarantine containment check
        if scenario.expected_final_trajectory_status != final_traj_status:
            if (
                scenario.expected_final_trajectory_status == TrajectoryStatus.QUARANTINED
                and final_traj_status == TrajectoryStatus.ACTIVE
            ):
                containment_failed = True
                bypass_detected = True

        # Determine scenario pass criteria
        step_outcomes_valid = all(
            sr.outcome
            in (
                ScenarioOutcome.BLOCKED_AS_EXPECTED,
                ScenarioOutcome.QUARANTINED_AS_EXPECTED,
                ScenarioOutcome.REQUIRE_APPROVAL_AS_EXPECTED,
                ScenarioOutcome.ALLOWED_AS_EXPECTED,
            )
            for sr in step_results
        )

        approval_steps = [sr for sr in step_results if sr.approval_attempted]
        if approval_steps:
            for sr, st in zip(step_results, scenario.steps, strict=False):
                if st.expected_approval_result is not None:
                    if sr.approval_succeeded != st.expected_approval_result:
                        step_outcomes_valid = False

        scenario_passed = (
            step_outcomes_valid
            and (final_traj_status == scenario.expected_final_trajectory_status)
            and not bypass_detected
            and not auth_weaker_detected
            and not containment_failed
        )

        # Determine overall lifecycle outcome
        if scenario.expected_overall_outcome is not None and scenario_passed:
            overall_outcome = scenario.expected_overall_outcome
        elif not scenario_passed:
            if bypass_detected:
                overall_outcome = ScenarioOutcome.UNEXPECTED_ALLOW_SECURITY_FAILURE
            elif containment_failed:
                overall_outcome = ScenarioOutcome.CONTAINMENT_STATE_FAILURE
            elif any(
                sr.outcome == ScenarioOutcome.UNEXPECTED_ALLOW_SECURITY_FAILURE
                for sr in step_results
            ):
                overall_outcome = ScenarioOutcome.UNEXPECTED_ALLOW_SECURITY_FAILURE
            elif any(
                sr.outcome == ScenarioOutcome.UNEXPECTED_APPROVAL_SECURITY_FAILURE
                for sr in step_results
            ):
                overall_outcome = ScenarioOutcome.UNEXPECTED_APPROVAL_SECURITY_FAILURE
            elif any(
                sr.outcome == ScenarioOutcome.UNEXPECTED_BLOCK_FALSE_POSITIVE for sr in step_results
            ):
                overall_outcome = ScenarioOutcome.UNEXPECTED_BLOCK_FALSE_POSITIVE
            elif any(
                sr.outcome == ScenarioOutcome.UNEXPECTED_QUARANTINE_FALSE_POSITIVE
                for sr in step_results
            ):
                overall_outcome = ScenarioOutcome.UNEXPECTED_QUARANTINE_FALSE_POSITIVE
            else:
                overall_outcome = ScenarioOutcome.SCENARIO_CONFIGURATION_ERROR
        elif final_traj_status == TrajectoryStatus.QUARANTINED:
            overall_outcome = ScenarioOutcome.QUARANTINED_AS_EXPECTED
        elif any(st.request_approval for st in scenario.steps):
            if any(sr.approval_succeeded is True for sr in step_results):
                overall_outcome = ScenarioOutcome.APPROVED_EXECUTION_AS_EXPECTED
            else:
                overall_outcome = ScenarioOutcome.APPROVAL_REJECTED_AS_EXPECTED
        elif all(sr.expected_decision == PolicyDecision.ALLOW for sr in scenario.steps):
            overall_outcome = ScenarioOutcome.ALLOWED_AS_EXPECTED
        elif any(
            sr.expected_decision in (PolicyDecision.DENY, PolicyDecision.QUARANTINE)
            for sr in scenario.steps
        ):
            overall_outcome = ScenarioOutcome.BLOCKED_AS_EXPECTED
        elif any(sr.expected_decision == PolicyDecision.REQUIRE_APPROVAL for sr in scenario.steps):
            overall_outcome = ScenarioOutcome.REQUIRE_APPROVAL_AS_EXPECTED
        else:
            overall_outcome = ScenarioOutcome.ALLOWED_AS_EXPECTED

        # Determine approval resolution string
        approval_resolution: str | None = None
        if any(st.request_approval for st in scenario.steps):
            if any(sr.approval_succeeded is True for sr in step_results):
                approval_resolution = "APPROVED"
            elif any(sr.approval_succeeded is False for sr in step_results):
                approval_resolution = "REJECTED"
        else:
            approval_resolution = "NOT_APPLICABLE"

        total_duration = (time.perf_counter() - start_time) * 1000

        initial_decision = step_results[0].actual_decision if step_results else None
        final_expected_dec = scenario.steps[-1].expected_decision if scenario.steps else None
        final_actual_dec = step_results[-1].actual_decision if step_results else None
        final_expected_rules = scenario.steps[-1].expected_rule_ids if scenario.steps else []
        final_actual_rules = step_results[-1].actual_rule_ids if step_results else []

        is_benign = scenario.category == "BENIGN_CONTROL" or scenario.scenario_id.startswith(
            "BENIGN"
        )
        false_positive = is_benign and (
            any(
                sr.outcome
                in (
                    ScenarioOutcome.UNEXPECTED_BLOCK_FALSE_POSITIVE,
                    ScenarioOutcome.UNEXPECTED_QUARANTINE_FALSE_POSITIVE,
                )
                for sr in step_results
            )
        )
        false_negative = (not is_benign) and (bypass_detected or auth_weaker_detected)

        return AttackScenarioResult(
            scenario_id=scenario.scenario_id,
            scenario_name=scenario.name,
            category=scenario.category,
            agent_manipulation_succeeded=scenario.expect_agent_manipulation_success,
            attack_goal_reached=scenario.expect_agent_manipulation_success,
            cage_bypass_succeeded=bypass_detected,
            scenario_passed=scenario_passed,
            overall_outcome=overall_outcome,
            expected_final_decision=final_expected_dec,
            actual_final_decision=final_actual_dec,
            expected_rule_ids=final_expected_rules,
            actual_rule_ids=final_actual_rules,
            tool_dispatched=any(sr.tool_dispatched for sr in step_results),
            simulated_side_effect_occurred=any(sr.side_effect_occurred for sr in step_results),
            step_results=step_results,
            final_trajectory_status=final_traj_status,
            initial_gate_decision=initial_decision,
            approval_resolution=approval_resolution,
            quarantine_triggered=(final_traj_status == TrajectoryStatus.QUARANTINED),
            authorization_weaker_than_expected=auth_weaker_detected,
            containment_state_failed=containment_failed,
            security_expectation_failed=(
                auth_weaker_detected or containment_failed or not scenario_passed
            ),
            false_positive=false_positive,
            false_negative=false_negative,
            policy_parity_passed=len(parity_failures) == 0,
            policy_parity_failures=parity_failures,
            evidence_action_ids=evidence_actions,
            evidence_artifact_ids=evidence_artifacts,
            notes=notes,
            execution_duration_ms=total_duration,
            total_duration_ms=total_duration,
        )

    def _classify_step_outcome(
        self,
        step: ScenarioStep,
        actual_decision: PolicyDecision | None,
        actual_rules: list[str],
        error_msg: str | None,
        parity_passed: bool,
        tool_dispatched: bool,
        side_effect: bool,
    ) -> ScenarioOutcome:
        """Deterministically classify step outcome based on expected vs actual behavior."""
        if not parity_passed:
            return ScenarioOutcome.POLICY_PARITY_MISMATCH

        if step.expect_error:
            if error_msg == step.expect_error:
                return ScenarioOutcome.BLOCKED_AS_EXPECTED
            return (
                ScenarioOutcome.UNEXPECTED_ALLOW_SECURITY_FAILURE
                if not error_msg
                else ScenarioOutcome.SCENARIO_CONFIGURATION_ERROR
            )

        if actual_decision is None:
            return ScenarioOutcome.ANALYSIS_FAILURE

        if actual_decision == step.expected_decision:
            if actual_decision == PolicyDecision.ALLOW:
                return ScenarioOutcome.ALLOWED_AS_EXPECTED
            if actual_decision == PolicyDecision.REQUIRE_APPROVAL:
                return ScenarioOutcome.REQUIRE_APPROVAL_AS_EXPECTED
            if actual_decision == PolicyDecision.QUARANTINE:
                return ScenarioOutcome.QUARANTINED_AS_EXPECTED
            return ScenarioOutcome.BLOCKED_AS_EXPECTED

        if step.expected_decision in (PolicyDecision.DENY, PolicyDecision.QUARANTINE):
            if actual_decision in (PolicyDecision.DENY, PolicyDecision.QUARANTINE):
                return (
                    ScenarioOutcome.QUARANTINED_AS_EXPECTED
                    if step.expected_decision == PolicyDecision.QUARANTINE
                    else ScenarioOutcome.BLOCKED_AS_EXPECTED
                )
            if actual_decision == PolicyDecision.ALLOW:
                return ScenarioOutcome.UNEXPECTED_ALLOW_SECURITY_FAILURE
            if actual_decision == PolicyDecision.REQUIRE_APPROVAL:
                return ScenarioOutcome.UNEXPECTED_APPROVAL_SECURITY_FAILURE

        if step.expected_decision == PolicyDecision.REQUIRE_APPROVAL:
            if actual_decision == PolicyDecision.ALLOW:
                return ScenarioOutcome.UNEXPECTED_ALLOW_SECURITY_FAILURE
            if actual_decision in (PolicyDecision.DENY, PolicyDecision.QUARANTINE):
                return ScenarioOutcome.UNEXPECTED_BLOCK_FALSE_POSITIVE

        if step.expected_decision == PolicyDecision.ALLOW:
            if actual_decision in (PolicyDecision.DENY, PolicyDecision.QUARANTINE):
                return ScenarioOutcome.UNEXPECTED_BLOCK_FALSE_POSITIVE
            if actual_decision == PolicyDecision.REQUIRE_APPROVAL:
                return ScenarioOutcome.UNEXPECTED_APPROVAL_SECURITY_FAILURE

        return ScenarioOutcome.SCENARIO_CONFIGURATION_ERROR
