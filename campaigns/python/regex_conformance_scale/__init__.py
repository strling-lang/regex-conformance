"""Deterministic six-figure campaign planning and segment materialization."""

from .capacity_plan import (
    MillionScaleCapacityPlanError,
    build_million_scale_capacity_plan,
    verify_million_scale_capacity_plan,
)

from .compiler import (
    ScaleCompileError,
    build_design_report,
    compile_scale_plan,
    reconstruct_request,
    verify_design_report,
    verify_materialized_segments,
    verify_scale_plan,
)
from .evidence_pack_v2 import (
    EvidencePack,
    EvidencePackError,
    PlatformCanaryResult,
    build_evidence_pack,
    plan_platform_expansion,
)
from .evidence_pack_v3 import (
    EvidencePackV3,
    EvidencePackV3Error,
    RetainedBlock,
    build_evidence_pack as build_compact_evidence_pack,
    derive_observation_identity,
    derive_physical_attempt_identity,
)
from .million_reconciliation import (
    MillionReconciliationError,
    verify_million_final_artifacts,
)
from .r2_publication import (
    CapacityAdmissionError,
    EvidencePackPublisher,
    PublicationError,
    PublicationReceiptLedger,
    R2Configuration,
    R2HttpTransport,
    publication_items_from_evidence_pack,
)

__all__ = [
    "MillionScaleCapacityPlanError",
    "CapacityAdmissionError",
    "EvidencePack",
    "EvidencePackError",
    "EvidencePackV3",
    "EvidencePackV3Error",
    "EvidencePackPublisher",
    "MillionReconciliationError",
    "PlatformCanaryResult",
    "RetainedBlock",
    "PublicationError",
    "PublicationReceiptLedger",
    "R2Configuration",
    "R2HttpTransport",
    "ScaleCompileError",
    "build_million_scale_capacity_plan",
    "build_design_report",
    "build_evidence_pack",
    "build_compact_evidence_pack",
    "compile_scale_plan",
    "derive_observation_identity",
    "derive_physical_attempt_identity",
    "reconstruct_request",
    "plan_platform_expansion",
    "publication_items_from_evidence_pack",
    "verify_design_report",
    "verify_materialized_segments",
    "verify_million_scale_capacity_plan",
    "verify_million_final_artifacts",
    "verify_scale_plan",
]
