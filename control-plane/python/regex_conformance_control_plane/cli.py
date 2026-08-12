"""Thin CLI client for the reusable Control Plane controller."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Mapping, TextIO

from .configuration import DoctorConfiguration, POOL_KINDS, TRUST_CLASSES
from .controller import ControlPlaneController, build_default_controller
from .rendering import render_human, render_json


def _inventory_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--format", choices=("human", "json"), default="human")
    parser.add_argument("--compact", action="store_true", help="emit compact JSON")
    parser.add_argument("--trust-class", choices=tuple(sorted(TRUST_CLASSES)))
    parser.add_argument("--max-age-seconds", type=int, default=300)
    parser.add_argument(
        "--pool-path",
        action="append",
        default=[],
        metavar="KIND=PATH",
        help=f"override one typed disk pool ({', '.join(POOL_KINDS)})",
    )


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(prog="regex-conformance", description="STRling Regex Conformance Control Plane")
    commands = value.add_subparsers(dest="command", required=True)
    doctor = commands.add_parser("doctor", help="inspect machine capabilities without mutation")
    _inventory_options(doctor)
    machine = commands.add_parser("machine", help="machine inventory commands")
    machine_commands = machine.add_subparsers(dest="machine_command", required=True)
    inspect = machine_commands.add_parser("inspect", help="emit the current machine inventory")
    _inventory_options(inspect)
    return value


def _pool_overrides(values: list[str]) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for value in values:
        kind, separator, path = value.partition("=")
        if not separator or not path:
            raise ValueError(f"pool path must have KIND=PATH form: {value!r}")
        if kind not in POOL_KINDS:
            raise ValueError(f"unknown pool kind {kind!r}; choose one of {', '.join(POOL_KINDS)}")
        if kind in result:
            raise ValueError(f"pool kind {kind!r} was configured more than once")
        result[kind] = Path(path)
    return result


def main(
    argv: list[str] | None = None,
    *,
    controller: ControlPlaneController | None = None,
    environment: Mapping[str, str] | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    output = stdout or sys.stdout
    errors = stderr or sys.stderr
    arguments = parser().parse_args(argv)
    try:
        if arguments.compact and arguments.format != "json":
            raise ValueError("--compact is valid only with --format json")
        configuration = DoctorConfiguration.from_environment(
            os.environ if environment is None else environment,
            trust_override=arguments.trust_class,
            pool_overrides=_pool_overrides(arguments.pool_path),
            inventory_max_age_seconds=arguments.max_age_seconds,
        )
        report = (controller or build_default_controller()).inspect_machine(configuration)
    except (OSError, ValueError) as error:
        errors.write(f"machine inspection rejected: {error}\n")
        return 2
    if arguments.format == "json":
        output.write(render_json(report, compact=arguments.compact))
    else:
        output.write(render_human(report))
    return 2 if report.status == "unsupported" else 0
