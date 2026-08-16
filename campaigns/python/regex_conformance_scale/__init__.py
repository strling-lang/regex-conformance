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
    "EvidencePackPublisher",
    "PlatformCanaryResult",
    "PublicationError",
    "PublicationReceiptLedger",
    "R2Configuration",
    "R2HttpTransport",
    "ScaleCompileError",
    "build_million_scale_capacity_plan",
    "build_design_report",
    "build_evidence_pack",
    "compile_scale_plan",
    "reconstruct_request",
    "plan_platform_expansion",
    "publication_items_from_evidence_pack",
    "verify_design_report",
    "verify_materialized_segments",
    "verify_million_scale_capacity_plan",
    "verify_scale_plan",
]
