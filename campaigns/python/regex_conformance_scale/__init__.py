"""Deterministic six-figure campaign planning and segment materialization."""

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
    "ScaleCompileError",
    "build_design_report",
    "compile_scale_plan",
    "reconstruct_request",
    "verify_design_report",
    "verify_materialized_segments",
    "verify_scale_plan",
]
