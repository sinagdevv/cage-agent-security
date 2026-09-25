import logging
from urllib.parse import urlparse
from uuid import UUID

from app.core.config import settings
from app.gateway.registry import ToolSpec
from app.provenance.models import InformationArtifact
from app.provenance.store import ProvenanceStore, default_provenance_store
from app.schemas.action import AgentActionProposal
from app.schemas.enums import (
    ArtifactSourceType,
    DataClassification,
    PayloadBindingMode,
    ProvenanceAnalysisStatus,
    ProvenanceTrust,
    normalize_to_provenance_trust,
)
from app.schemas.policy import PolicyProvenanceContext

logger = logging.getLogger("cage.provenance.analyzer")

CREDENTIAL_CLASSIFICATIONS = frozenset(
    {
        DataClassification.CREDENTIAL,
        DataClassification.SECRET,
    }
)

GENERAL_SENSITIVE_CLASSIFICATIONS = frozenset(
    {
        DataClassification.CONFIDENTIAL,
        DataClassification.RESTRICTED,
        DataClassification.PII,
    }
)


class ProvenanceAnalyzer:
    """Server-authoritative analyzer for information provenance and data flow.

    Responsibilities:
    - Validate referenced input artifacts (presence, session bounds).
    - Perform bounded, cycle-safe upstream lineage traversal.
    - Derive authoritative trust and classification unions.
    - Evaluate artifact-backed payload binding for egress sinks.
    - Construct PolicyProvenanceContext without fabricating facts on failure.
    """

    def __init__(
        self,
        store: ProvenanceStore | None = None,
        max_depth: int | None = None,
        max_artifacts: int | None = None,
    ) -> None:
        self.store = store or default_provenance_store
        self.max_depth = max_depth or settings.max_provenance_depth
        self.max_artifacts = max_artifacts or settings.max_provenance_artifacts

    def analyze_provenance(
        self,
        proposal: AgentActionProposal,
        tool_spec: ToolSpec,
    ) -> tuple[PolicyProvenanceContext, list[InformationArtifact]]:
        """Validate input artifacts, perform bounded lineage analysis, and derive policy facts."""
        session_id = proposal.session_id
        requested_ids = proposal.input_artifact_ids

        validated_artifacts: list[InformationArtifact] = []
        all_referenced_valid = True

        # 1. Reference Validation
        for ref_id in requested_ids:
            is_valid, err = self.store.validate_artifact_reference(ref_id, session_id)
            if not is_valid:
                all_referenced_valid = False
                status = (
                    ProvenanceAnalysisStatus.CROSS_SESSION_REFERENCE
                    if err == "CROSS_SESSION_REFERENCE"
                    else ProvenanceAnalysisStatus.MISSING_ARTIFACT
                )
                logger.warning(
                    "Invalid artifact reference %s in session %s: %s",
                    ref_id,
                    session_id,
                    status.value,
                )
                return (
                    PolicyProvenanceContext(
                        analysis_status=status,
                        analysis_complete=False,
                        validated_input_artifact_ids=[],
                        input_artifact_count=0,
                        all_referenced_artifacts_valid=False,
                    ),
                    [],
                )
            art = self.store.get_artifact(ref_id)
            if art:
                validated_artifacts.append(art)

        # 2. Bounded Lineage Traversal & Cycle Detection
        all_ancestors: dict[UUID, InformationArtifact] = {}
        max_lineage_depth = 0

        for art in validated_artifacts:
            # Traversal queue: (artifact_id, current_depth, path_from_root)
            queue: list[tuple[UUID, int, tuple[UUID, ...]]] = [
                (pid, 1, (art.artifact_id, pid)) for pid in art.parent_artifact_ids
            ]

            while queue:
                curr_id, depth, path = queue.pop(0)

                # Check depth limit
                if depth > self.max_depth:
                    logger.warning(
                        "Lineage traversal depth limit exceeded (%d > %d) for artifact %s",
                        depth,
                        self.max_depth,
                        art.artifact_id,
                    )
                    return (
                        PolicyProvenanceContext(
                            analysis_status=ProvenanceAnalysisStatus.DEPTH_LIMIT_EXCEEDED,
                            analysis_complete=False,
                            validated_input_artifact_ids=[
                                str(a.artifact_id) for a in validated_artifacts
                            ],
                            input_artifact_count=len(validated_artifacts),
                            all_referenced_artifacts_valid=True,
                        ),
                        validated_artifacts,
                    )

                if depth > max_lineage_depth:
                    max_lineage_depth = depth

                # Check total artifacts limit
                if len(all_ancestors) >= self.max_artifacts:
                    logger.warning(
                        "Lineage traversal artifact limit exceeded (%d >= %d)",
                        len(all_ancestors),
                        self.max_artifacts,
                    )
                    return (
                        PolicyProvenanceContext(
                            analysis_status=ProvenanceAnalysisStatus.ARTIFACT_LIMIT_EXCEEDED,
                            analysis_complete=False,
                            validated_input_artifact_ids=[
                                str(a.artifact_id) for a in validated_artifacts
                            ],
                            input_artifact_count=len(validated_artifacts),
                            all_referenced_artifacts_valid=True,
                        ),
                        validated_artifacts,
                    )

                parent_art = self.store.get_artifact(curr_id)
                if not parent_art:
                    return (
                        PolicyProvenanceContext(
                            analysis_status=ProvenanceAnalysisStatus.INVALID_LINEAGE,
                            analysis_complete=False,
                            validated_input_artifact_ids=[
                                str(a.artifact_id) for a in validated_artifacts
                            ],
                            input_artifact_count=len(validated_artifacts),
                        ),
                        validated_artifacts,
                    )

                if parent_art.session_id != session_id:
                    return (
                        PolicyProvenanceContext(
                            analysis_status=ProvenanceAnalysisStatus.CROSS_SESSION_REFERENCE,
                            analysis_complete=False,
                            validated_input_artifact_ids=[
                                str(a.artifact_id) for a in validated_artifacts
                            ],
                            input_artifact_count=len(validated_artifacts),
                        ),
                        validated_artifacts,
                    )

                all_ancestors[curr_id] = parent_art

                for next_pid in parent_art.parent_artifact_ids:
                    if next_pid in path:
                        logger.error(
                            "Cyclic derivation detected in lineage path: %s -> %s", path, next_pid
                        )
                        return (
                            PolicyProvenanceContext(
                                analysis_status=ProvenanceAnalysisStatus.CYCLE_DETECTED,
                                analysis_complete=False,
                                validated_input_artifact_ids=[
                                    str(a.artifact_id) for a in validated_artifacts
                                ],
                                input_artifact_count=len(validated_artifacts),
                            ),
                            validated_artifacts,
                        )
                    queue.append((next_pid, depth + 1, path + (next_pid,)))

        # 3. Security Facts & Classifications Union
        classifications: set[DataClassification] = set()
        direct_trusts: set[ProvenanceTrust] = set()
        inherited_trusts: set[ProvenanceTrust] = set()

        for art in validated_artifacts:
            classifications.update(art.data_classifications)
            norm_direct = normalize_to_provenance_trust(
                art.direct_trust_level,
                source_type=art.source_type,
                is_trusted_human_origin=(art.source_type == ArtifactSourceType.HUMAN_INPUT),
            )
            direct_trusts.add(norm_direct)
            for inh in art.inherited_trust_levels:
                norm_inh = normalize_to_provenance_trust(inh)
                inherited_trusts.add(norm_inh)

        for anc in all_ancestors.values():
            classifications.update(anc.data_classifications)
            norm_direct = normalize_to_provenance_trust(
                anc.direct_trust_level,
                source_type=anc.source_type,
                is_trusted_human_origin=(anc.source_type == ArtifactSourceType.HUMAN_INPUT),
            )
            direct_trusts.add(norm_direct)
            for inh in anc.inherited_trust_levels:
                norm_inh = normalize_to_provenance_trust(inh)
                inherited_trusts.add(norm_inh)

        all_trusts = direct_trusts | inherited_trusts

        contains_credential = any(c in CREDENTIAL_CLASSIFICATIONS for c in classifications)
        contains_sensitive = any(c in GENERAL_SENSITIVE_CLASSIFICATIONS for c in classifications)
        contains_untrusted = ProvenanceTrust.EXTERNAL_UNTRUSTED in all_trusts
        contains_unknown = ProvenanceTrust.UNKNOWN in all_trusts

        has_tracked = len(validated_artifacts) > 0 and all_referenced_valid

        # 4. Outbound Channel Inventory & Per-Field Payload Binding Validation
        tool_args = proposal.tool_arguments or {}
        resolved_payload_bindings: dict[str, str] = {}
        valid_ids = {a.artifact_id for a in validated_artifacts}

        # Check for explicit artifact bindings in arguments
        bound_artifact_mapping = {
            "body": tool_args.get("body_artifact_id"),
            "data": tool_args.get("data_artifact_id") or tool_args.get("body_artifact_id"),
            "payload": tool_args.get("payload_artifact_id") or tool_args.get("body_artifact_id"),
            "content": tool_args.get("content_artifact_id") or tool_args.get("body_artifact_id"),
        }

        # Resolve payload bindings for any referenced artifacts
        for target_field, bound_raw in bound_artifact_mapping.items():
            if bound_raw is not None:
                try:
                    b_uuid = UUID(str(bound_raw)) if not isinstance(bound_raw, UUID) else bound_raw
                    if b_uuid in valid_ids:
                        resolved_payload_bindings[target_field] = str(b_uuid)
                except (ValueError, TypeError):
                    pass

        # Identify client-provided data-bearing arguments
        payload_arg_names = tool_spec.payload_argument_names or frozenset(
            {"body", "data", "payload", "content"}
        )
        has_payload_arg = any(arg in tool_args for arg in payload_arg_names)
        has_bound_artifact_arg = any(
            f"{p}_artifact_id" in tool_args for p in ("body", "data", "payload", "content")
        )
        is_payload_bearing = has_payload_arg or has_bound_artifact_arg or len(requested_ids) > 0

        payload_required = (
            tool_spec.payload_binding_mode == PayloadBindingMode.ARTIFACT_REQUIRED
            and is_payload_bearing
        )
        payload_satisfied = False

        if payload_required:
            # Channel A: Outbound data fields (body, data, payload, content)
            has_unbound_raw_channel = False
            for arg_name in payload_arg_names:
                val = tool_args.get(arg_name)
                if val is not None and isinstance(val, (str, bytes, dict, list)) and len(val) > 0:
                    has_unbound_raw_channel = True
                    logger.warning(
                        "Unbound raw outbound argument or raw body override detected in '%s'.",
                        arg_name,
                    )
                    break

            # Channel B: Headers channel (headers, custom_headers)
            has_client_header_data = False
            headers_val = tool_args.get("headers") or tool_args.get("custom_headers")
            if headers_val is not None:
                if isinstance(headers_val, dict) and len(headers_val) > 0:
                    non_static = {
                        k: v
                        for k, v in headers_val.items()
                        if k.lower() != "content-type" or v != "application/json"
                    }
                    if non_static:
                        has_client_header_data = True
                        logger.warning(
                            "Client-controlled non-static headers detected: %s", non_static
                        )
                elif isinstance(headers_val, (str, list)) and len(headers_val) > 0:
                    has_client_header_data = True

            # Channel C: Query parameter channels (params, query_params)
            has_client_query_params = False
            params_val = tool_args.get("params") or tool_args.get("query_params")
            if (
                params_val is not None
                and isinstance(params_val, (dict, list, str))
                and len(params_val) > 0
            ):
                has_client_query_params = True
                logger.warning("Client-controlled query parameters detected: %s", params_val)

            # Channel D: URL query string & userinfo channel
            url_str = str(tool_args.get("destination") or tool_args.get("url") or "")
            has_url_query_exfil = False
            has_unapproved_destination_path = False
            if url_str:
                parsed_url = urlparse(url_str)
                if parsed_url.query:
                    has_url_query_exfil = True
                    logger.warning(
                        "Client-controlled URL query string detected: %s", parsed_url.query
                    )
                if parsed_url.username or parsed_url.password:
                    has_url_query_exfil = True
                    logger.warning("Client-controlled URL embedded credentials detected.")

                # Channel E: URL destination path protection (prevent path-based exfiltration)
                parsed_path = parsed_url.path
                normalized_path = (
                    parsed_path if parsed_path in ("", "/") else parsed_path.rstrip("/")
                )
                allowed_paths = (
                    tool_spec.allowed_destination_paths
                    if tool_spec.allowed_destination_paths
                    else frozenset({"", "/"})
                )
                if ".." in parsed_path or normalized_path not in allowed_paths:
                    has_unapproved_destination_path = True
                    logger.warning(
                        "Client-controlled unapproved URL destination path '%s' not in allowed exact paths %s",
                        parsed_path,
                        allowed_paths,
                    )

            if (
                len(resolved_payload_bindings) > 0
                and not has_unbound_raw_channel
                and not has_client_header_data
                and not has_client_query_params
                and not has_url_query_exfil
                and not has_unapproved_destination_path
            ):
                payload_satisfied = True
            else:
                payload_satisfied = False
        else:
            payload_satisfied = True

        context = PolicyProvenanceContext(
            analysis_status=ProvenanceAnalysisStatus.SUCCESS,
            analysis_complete=True,
            validated_input_artifact_ids=[str(a.artifact_id) for a in validated_artifacts],
            input_artifact_count=len(validated_artifacts),
            input_classifications=sorted([c.value for c in classifications]),
            input_direct_trust_levels=sorted([t.value for t in direct_trusts]),
            input_inherited_trust_levels=sorted([t.value for t in inherited_trusts]),
            contains_sensitive_input=contains_sensitive,
            contains_credential_input=contains_credential,
            contains_untrusted_input=contains_untrusted,
            contains_unknown_input=contains_unknown,
            has_tracked_inputs=has_tracked,
            all_referenced_artifacts_valid=all_referenced_valid,
            payload_binding_required=payload_required,
            payload_binding_satisfied=payload_satisfied,
            resolved_payload_bindings=resolved_payload_bindings,
            provenance_depth=max_lineage_depth,
            ancestor_artifact_count=len(all_ancestors),
        )

        return context, validated_artifacts


default_provenance_analyzer = ProvenanceAnalyzer()
