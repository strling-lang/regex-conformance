"""Deterministic sharding and restart-safe campaign attempt coordination."""

from .recovery import (
    CHECKPOINT_STATES,
    AttemptRecord,
    RecoveryConflictError,
    RecoveryDecision,
    RecoveryError,
    RecoveryIntegrityError,
    RecoveryJournal,
    build_restart_resume_reference_report,
    recovery_action_for_stage,
)
from .sharding import shard_by_selection_locality

__all__ = [
    "CHECKPOINT_STATES",
    "AttemptRecord",
    "RecoveryConflictError",
    "RecoveryDecision",
    "RecoveryError",
    "RecoveryIntegrityError",
    "RecoveryJournal",
    "build_restart_resume_reference_report",
    "recovery_action_for_stage",
    "shard_by_selection_locality",
]
