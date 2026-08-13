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
from .containment import (
    ContainedExecutionResult,
    ContainedProcessSupervisor,
    ExecutionLimits,
    NativeSafetyLimitAdapter,
    OciSafetyLimitAdapter,
    ProviderLimitPlan,
    UnsupportedContainmentError,
)
from .command_models import CommandDocument, CommandIssue, CommandModelError
from .controller import ControlPlaneController, ControlPlaneServiceUnavailable, ControlPlaneServices, build_default_controller
from .environment_models import AdmissionDecision, EnvironmentLifecycleRecord, EnvironmentRecipe
from .environment_providers import ProviderRegistry
from .fault_attribution import FaultAttributionError, build_reference_report, classify_fault, reference_stimuli
from .event_models import (
    EventBatch,
    EventCursor,
    EventDraft,
    EventModelError,
    LifecycleEvent,
    ProgressAggregator,
    ProgressProjection,
    StoredEvent,
)
from .event_store import (
    EventCursorGapError,
    EventJournal,
    EventJournalConflictError,
    EventJournalCorruptionError,
    EventSubscription,
)
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
from .telemetry_collector import OperationalTelemetryCollector, Uuid7TelemetryIds
from .telemetry_models import CalibrationPolicy, CalibrationSnapshot, TelemetryMetric, TelemetrySample
from .telemetry_store import (
    TelemetryStore,
    TelemetryStoreConflictError,
    TelemetryStoreCorruptionError,
    UnsafeTelemetryPathError,
)

__all__ = [
    "CacheEntry",
    "CacheInventory",
    "CacheManager",
    "CacheReconciliation",
    "CalibrationPolicy",
    "CalibrationSnapshot",
    "CleanupPlan",
    "CleanupReport",
    "CommandDocument",
    "CommandIssue",
    "CommandModelError",
    "ContainedExecutionResult",
    "ContainedProcessSupervisor",
    "ControlPlaneController",
    "ControlPlaneServiceUnavailable",
    "ControlPlaneServices",
    "AdmissionDecision",
    "AdmissionContext",
    "AdmissionPolicy",
    "DoctorConfiguration",
    "DoctorReport",
    "DurableStateService",
    "EnvironmentLifecycleRecord",
    "EnvironmentRecipe",
    "ExecutionLimits",
    "EvictionPolicy",
    "EventBatch",
    "EventCursor",
    "EventCursorGapError",
    "EventDraft",
    "EventJournal",
    "EventJournalConflictError",
    "EventJournalCorruptionError",
    "EventModelError",
    "EventSubscription",
    "FaultAttributionError",
    "FilesystemCacheProvider",
    "IncompatibleStateVersionError",
    "LocalStateStore",
    "LifecycleEvent",
    "NativeSafetyLimitAdapter",
    "OciSafetyLimitAdapter",
    "OperationalTelemetryCollector",
    "ProviderRegistry",
    "ProgressAggregator",
    "ProgressProjection",
    "ProviderLimitPlan",
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
    "StoredEvent",
    "TelemetryMetric",
    "TelemetrySample",
    "TelemetryStore",
    "TelemetryStoreConflictError",
    "TelemetryStoreCorruptionError",
    "TransferManager",
    "TransferRecord",
    "UnsupportedContainmentError",
    "UnsafeTelemetryPathError",
    "Uuid7TelemetryIds",
    "build_reference_report",
    "classify_fault",
    "reference_stimuli",
    "build_default_controller",
]
