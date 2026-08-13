"""Portable STRling Regex Conformance Control Plane foundation."""

from .cache_manager import CacheManager, FilesystemCacheProvider, TransferManager
from .cache_models import (
    CacheEntry,
    CacheInventory,
    CacheReconciliation,
    CleanupPlan,
    CleanupReport,
    EvictionPolicy,
    TransferRecord,
)
from .configuration import DoctorConfiguration
from .controller import ControlPlaneController, ControlPlaneServices, build_default_controller
from .environment_models import AdmissionDecision, EnvironmentLifecycleRecord, EnvironmentRecipe
from .environment_providers import ProviderRegistry
from .models import DoctorReport
from .resource_models import AdmissionContext, AdmissionPolicy, ResourceAdmissionReport, ResourceEstimate
from .state_models import (
    ReconciliationObservation,
    ReconciliationPlan,
    ReconciliationReport,
    StateMutation,
    StateSnapshot,
    StateSourceReference,
)
from .state_store import (
    DurableStateService,
    IncompatibleStateVersionError,
    LocalStateStore,
    StateAdmissionError,
    StateConflictError,
    StateCorruptionError,
    StateReconciler,
    StateRecovery,
    StateStoreBusyError,
)

__all__ = [
    "CacheEntry",
    "CacheInventory",
    "CacheManager",
    "CacheReconciliation",
    "CleanupPlan",
    "CleanupReport",
    "ControlPlaneController",
    "ControlPlaneServices",
    "AdmissionDecision",
    "AdmissionContext",
    "AdmissionPolicy",
    "DoctorConfiguration",
    "DoctorReport",
    "DurableStateService",
    "EnvironmentLifecycleRecord",
    "EnvironmentRecipe",
    "EvictionPolicy",
    "FilesystemCacheProvider",
    "IncompatibleStateVersionError",
    "LocalStateStore",
    "ProviderRegistry",
    "ResourceAdmissionReport",
    "ResourceEstimate",
    "ReconciliationObservation",
    "ReconciliationPlan",
    "ReconciliationReport",
    "StateAdmissionError",
    "StateConflictError",
    "StateCorruptionError",
    "StateMutation",
    "StateReconciler",
    "StateRecovery",
    "StateSnapshot",
    "StateSourceReference",
    "StateStoreBusyError",
    "TransferManager",
    "TransferRecord",
    "build_default_controller",
]
