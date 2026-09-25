"""Phase 6 CAGE Trajectory Governance package."""

from app.trajectory.analyzer import TrajectoryAnalyzer
from app.trajectory.models import (
    AuthorityEnvelope,
    ControlPlaneAuthContext,
    ResourceAuthorityScope,
    TrajectorySnapshot,
    compute_trajectory_instance_fingerprint,
)
from app.trajectory.store import TrajectoryStore

default_trajectory_store = TrajectoryStore()
default_trajectory_analyzer = TrajectoryAnalyzer()

__all__ = [
    "AuthorityEnvelope",
    "ControlPlaneAuthContext",
    "ResourceAuthorityScope",
    "TrajectorySnapshot",
    "compute_trajectory_instance_fingerprint",
    "TrajectoryStore",
    "TrajectoryAnalyzer",
    "default_trajectory_store",
    "default_trajectory_analyzer",
]
