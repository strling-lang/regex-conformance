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

__all__ = [
    "MillionScaleCapacityPlanError",
    "ScaleCompileError",
    "build_million_scale_capacity_plan",
    "build_design_report",
    "compile_scale_plan",
    "reconstruct_request",
    "verify_design_report",
    "verify_materialized_segments",
    "verify_million_scale_capacity_plan",
    "verify_scale_plan",
]
