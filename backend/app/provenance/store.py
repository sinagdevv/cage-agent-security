"""In-memory ProvenanceStore and ArtifactPayloadStore for Phase 5 data provenance."""

import hashlib
import json
import logging
import threading
from typing import Any
from uuid import UUID

from app.core.config import settings
from app.provenance.models import InformationArtifact

logger = logging.getLogger("cage.provenance.store")


class PayloadSizeLimitExceededError(ValueError):
    """Raised when an artifact payload exceeds configured memory limits."""


class MissingArtifactError(KeyError):
    """Raised when a referenced artifact does not exist in the store."""


class CrossSessionReferenceError(PermissionError):
    """Raised when an artifact references or accesses an artifact from a different session."""


class ProvenanceCycleError(ValueError):
    """Raised when an artifact derivation would create a cycle in the provenance graph."""


class ArtifactPayloadStore:
    """Ephemeral, process-local in-memory store for raw artifact payloads.

    Decouples raw payloads from metadata, causal graphs, logs, and diagnostics.
    Enforces maximum payload memory limits.
    """

    def __init__(self, max_payload_bytes: int | None = None) -> None:
        self.max_payload_bytes = max_payload_bytes or settings.max_artifact_payload_bytes
        self._payloads: dict[UUID, bytes] = {}
        self._lock = threading.Lock()

    def store_payload(self, artifact_id: UUID, payload: Any) -> tuple[int, str]:
        """Serialize payload canonically, enforce byte limits, compute SHA-256, and store.

        Returns (size_bytes, content_digest).
        """
        if payload is None:
            data = b""
        elif isinstance(payload, bytes):
            data = payload
        elif isinstance(payload, str):
            data = payload.encode("utf-8")
        elif isinstance(payload, (dict, list)):
            data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        else:
            data = str(payload).encode("utf-8")

        size_bytes = len(data)
        if size_bytes > self.max_payload_bytes:
            raise PayloadSizeLimitExceededError(
                f"Artifact payload size ({size_bytes} bytes) exceeds limit "
                f"({self.max_payload_bytes} bytes)."
            )

        content_digest = hashlib.sha256(data).hexdigest()

        with self._lock:
            self._payloads[artifact_id] = data

        return size_bytes, content_digest

    def get_payload(self, artifact_id: UUID) -> bytes | None:
        """Retrieve raw payload bytes safely."""
        with self._lock:
            return self._payloads.get(artifact_id)

    def get_payload_str(self, artifact_id: UUID, encoding: str = "utf-8") -> str | None:
        """Retrieve raw payload decoded as string."""
        data = self.get_payload(artifact_id)
        if data is None:
            return None
        return data.decode(encoding, errors="replace")

    def has_payload(self, artifact_id: UUID) -> bool:
        """Check if payload is stored."""
        with self._lock:
            return artifact_id in self._payloads

    def delete_payload(self, artifact_id: UUID) -> None:
        """Remove payload (used during rollback)."""
        with self._lock:
            self._payloads.pop(artifact_id, None)


class ProvenanceStore:
    """Process-local, thread-safe store for authoritative InformationArtifact metadata.

    Guarantees:
    - Server-authoritative atomic artifact registration.
    - Deep immutability of returned artifact instances.
    - Clean transaction-like rollback if any part of registration fails.
    """

    def __init__(self, payload_store: ArtifactPayloadStore | None = None) -> None:
        self.payload_store = payload_store or ArtifactPayloadStore()
        self._artifacts: dict[UUID, InformationArtifact] = {}
        self._session_artifacts: dict[str, set[UUID]] = {}
        self._lock = threading.Lock()

    def register_artifact(
        self,
        artifact: InformationArtifact,
        payload: Any = None,
        graph: Any = None,
    ) -> InformationArtifact:
        """Atomically validate, store payload, register metadata, and record graph projection.

        If any validation or commit step fails, all earlier Phase 5 in-memory writes
        are rolled back to ensure absolute state consistency.
        """
        session_id = artifact.session_id
        if not session_id:
            raise ValueError("Artifact must have a non-empty session_id.")

        with self._lock:
            # 1. Validate parent artifacts exist and belong to the same session
            for parent_id in artifact.parent_artifact_ids:
                if parent_id not in self._artifacts:
                    raise MissingArtifactError(
                        f"Referenced parent artifact '{parent_id}' not found in ProvenanceStore."
                    )
                parent_art = self._artifacts[parent_id]
                if parent_art.session_id != session_id:
                    raise CrossSessionReferenceError(
                        f"Referenced parent artifact '{parent_id}' belongs to session "
                        f"'{parent_art.session_id}', not '{session_id}'."
                    )

            # 2. Cycle detection: check that artifact_id is not already an ancestor of any parent
            if artifact.parent_artifact_ids:
                visited: set[UUID] = set()
                queue: list[UUID] = list(artifact.parent_artifact_ids)
                while queue:
                    current_id = queue.pop(0)
                    if current_id == artifact.artifact_id:
                        raise ProvenanceCycleError(
                            f"Cyclic derivation detected: artifact '{artifact.artifact_id}' "
                            f"is already an ancestor of parent '{current_id}'."
                        )
                    if current_id in visited:
                        continue
                    visited.add(current_id)
                    current_art = self._artifacts.get(current_id)
                    if current_art:
                        queue.extend(current_art.parent_artifact_ids)

            # 3. Store payload if provided (validates size limit before metadata commit)
            size_bytes = artifact.size_bytes
            content_digest = artifact.content_digest
            if payload is not None:
                size_bytes, content_digest = self.payload_store.store_payload(
                    artifact.artifact_id, payload
                )

            # 4. If digest or size changed from payload, recreate immutable artifact instance
            committed_artifact = artifact
            if size_bytes != artifact.size_bytes or content_digest != artifact.content_digest:
                committed_artifact = InformationArtifact(
                    artifact_id=artifact.artifact_id,
                    session_id=artifact.session_id,
                    created_by_action_id=artifact.created_by_action_id,
                    source_type=artifact.source_type,
                    source_resource=artifact.source_resource,
                    direct_trust_level=artifact.direct_trust_level,
                    inherited_trust_levels=artifact.inherited_trust_levels,
                    data_classifications=artifact.data_classifications,
                    parent_artifact_ids=artifact.parent_artifact_ids,
                    content_digest=content_digest,
                    size_bytes=size_bytes,
                    mime_type=artifact.mime_type,
                    created_at=artifact.created_at,
                )

            # 5. Commit metadata
            self._artifacts[committed_artifact.artifact_id] = committed_artifact
            if session_id not in self._session_artifacts:
                self._session_artifacts[session_id] = set()
            self._session_artifacts[session_id].add(committed_artifact.artifact_id)

            # 6. Commit graph projection if graph is provided
            if graph is not None:
                try:
                    graph.add_artifact_node(committed_artifact)
                    if committed_artifact.created_by_action_id is not None:
                        graph.add_produces_edge(
                            str(committed_artifact.created_by_action_id),
                            str(committed_artifact.artifact_id),
                        )
                    for parent_id in committed_artifact.parent_artifact_ids:
                        graph.add_derived_from_edge(
                            str(committed_artifact.artifact_id),
                            str(parent_id),
                        )
                except Exception as exc:
                    # Complete rollback: remove metadata, session index, payload, and graph projection
                    self._artifacts.pop(committed_artifact.artifact_id, None)
                    self._session_artifacts[session_id].discard(committed_artifact.artifact_id)
                    self.payload_store.delete_payload(committed_artifact.artifact_id)
                    try:
                        art_node_key = str(committed_artifact.artifact_id)
                        if graph._graph.has_node(art_node_key):
                            graph._graph.remove_node(art_node_key)
                    except Exception as g_err:
                        logger.error("Failed to clean up graph node during rollback: %s", g_err)
                    logger.error(
                        "Rolled back artifact %s due to graph projection error: %s",
                        committed_artifact.artifact_id,
                        exc,
                    )
                    raise

            return committed_artifact

    def get_artifact(self, artifact_id: UUID) -> InformationArtifact | None:
        """Retrieve an immutable InformationArtifact by UUID."""
        with self._lock:
            return self._artifacts.get(artifact_id)

    def get_artifacts_for_session(self, session_id: str) -> list[InformationArtifact]:
        """Retrieve safe copy list of all artifacts in a session."""
        with self._lock:
            art_ids = self._session_artifacts.get(session_id, set())
            return [self._artifacts[aid] for aid in art_ids if aid in self._artifacts]

    def get_parent_artifacts(self, artifact_id: UUID) -> list[InformationArtifact]:
        """Retrieve immediate parent artifacts."""
        with self._lock:
            art = self._artifacts.get(artifact_id)
            if not art:
                return []
            return [
                self._artifacts[pid] for pid in art.parent_artifact_ids if pid in self._artifacts
            ]

    def get_descendant_artifacts(self, artifact_id: UUID) -> list[InformationArtifact]:
        """Retrieve immediate children that derived from this artifact."""
        with self._lock:
            descendants: list[InformationArtifact] = []
            for art in self._artifacts.values():
                if artifact_id in art.parent_artifact_ids:
                    descendants.append(art)
            return descendants

    def get_lineage(self, artifact_id: UUID, max_depth: int = 25) -> list[InformationArtifact]:
        """Traverse upstream derivation lineage up to max_depth."""
        with self._lock:
            target = self._artifacts.get(artifact_id)
            if not target:
                return []

            lineage: list[InformationArtifact] = []
            visited: set[UUID] = {artifact_id}
            queue: list[tuple[UUID, int]] = [(pid, 1) for pid in target.parent_artifact_ids]

            while queue:
                curr_id, depth = queue.pop(0)
                if depth > max_depth or curr_id in visited:
                    continue
                visited.add(curr_id)
                parent_art = self._artifacts.get(curr_id)
                if parent_art:
                    lineage.append(parent_art)
                    for next_pid in parent_art.parent_artifact_ids:
                        queue.append((next_pid, depth + 1))

            return lineage

    def validate_artifact_reference(
        self, artifact_id: UUID, session_id: str
    ) -> tuple[bool, str | None]:
        """Validate whether an artifact exists and matches session bounds.

        Returns (is_valid, error_code).
        """
        with self._lock:
            art = self._artifacts.get(artifact_id)
            if art is None:
                return False, "MISSING_ARTIFACT"
            if art.session_id != session_id:
                return False, "CROSS_SESSION_REFERENCE"
            return True, None


default_provenance_store = ProvenanceStore()
