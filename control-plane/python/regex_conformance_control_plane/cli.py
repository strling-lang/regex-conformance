"""Thin CLI client for the reusable Control Plane controller."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any, Mapping, TextIO

from .cli_inputs import load_cache_entries, load_environment_recipe, load_resource_request
from .command_models import CommandDocument, CommandIssue, render_command_human, render_command_json
from .configuration import DoctorConfiguration, POOL_KINDS, TRUST_CLASSES
from .controller import ControlPlaneController, ControlPlaneServiceUnavailable, build_default_controller
from .event_models import EventCursor
from .rendering import render_human, render_json
from .state_models import canonical_json


class CliUsageError(ValueError):
    pass


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise CliUsageError(message)


def _output_options(parser: argparse.ArgumentParser, *, event: bool = False) -> None:
    choices = ("human", "json", "event") if event else ("human", "json")
    parser.add_argument("--format", choices=choices, default="human")
    parser.add_argument("--compact", action="store_true", help="emit compact JSON")


def _inventory_options(parser: argparse.ArgumentParser, *, output: bool = True) -> None:
    if output:
        _output_options(parser)
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
    value = SafeArgumentParser(prog="regex-conformance", description="STRling Regex Conformance Control Plane")
    commands = value.add_subparsers(dest="command", required=True, parser_class=SafeArgumentParser)
    doctor = commands.add_parser("doctor", help="inspect machine capabilities without mutation")
    _inventory_options(doctor)

    machine = commands.add_parser("machine", help="machine inventory commands")
    machine_commands = machine.add_subparsers(dest="machine_command", required=True, parser_class=SafeArgumentParser)
    inspect = machine_commands.add_parser("inspect", help="emit the current machine inventory")
    _inventory_options(inspect)

    environment = commands.add_parser("env", help="environment lifecycle commands")
    environment_commands = environment.add_subparsers(dest="env_command", required=True, parser_class=SafeArgumentParser)
    plan = environment_commands.add_parser("plan", help="derive a non-mutating provider plan")
    plan.add_argument("--recipe", required=True, metavar="FILE")
    plan.add_argument("--provider", required=True)
    _output_options(plan)
    acquire = environment_commands.add_parser("acquire", help="plan, preflight, and optionally realize an environment")
    acquire.add_argument("--recipe", required=True, metavar="FILE")
    acquire.add_argument("--provider", required=True)
    acquire.add_argument("--machine-provider", required=True)
    acquire.add_argument("--estimate-confidence", choices=("known", "measured", "estimated", "bounded", "unknown"), default="estimated")
    acquire.add_argument("--execute", action="store_true", help="perform the verified plan")
    acquire.add_argument("--yes", action="store_true", help="authorize the previewed mutation")
    _inventory_options(acquire)

    cache = commands.add_parser("cache", help="provider-neutral cache commands")
    cache_commands = cache.add_subparsers(dest="cache_command", required=True, parser_class=SafeArgumentParser)
    cache_inventory = cache_commands.add_parser("inventory", help="canonicalize a supplied local cache inventory")
    cache_inventory.add_argument("--entries", required=True, metavar="FILE")
    cache_inventory.add_argument("--observed-at")
    _output_options(cache_inventory)

    campaign = commands.add_parser("campaign", help="campaign planning commands")
    campaign_commands = campaign.add_subparsers(dest="campaign_command", required=True, parser_class=SafeArgumentParser)
    campaign_plan = campaign_commands.add_parser("plan", help="compile a non-mutating campaign resource plan")
    campaign_plan.add_argument("--request", required=True, metavar="FILE")
    _output_options(campaign_plan)

    worker = commands.add_parser("worker", help="local worker state and progress commands")
    worker_commands = worker.add_subparsers(dest="worker_command", required=True, parser_class=SafeArgumentParser)
    worker_state = worker_commands.add_parser("state", help="inspect non-canonical local operational state")
    _output_options(worker_state)
    worker_health = worker_commands.add_parser("health", help="inspect local state and event-journal health")
    _output_options(worker_health)
    worker_progress = worker_commands.add_parser("progress", help="derive progress and ETA for one operation stream")
    worker_progress.add_argument("--stream-id", required=True)
    _output_options(worker_progress)
    worker_events = worker_commands.add_parser("events", help="read bounded lifecycle events")
    worker_events.add_argument("--maximum-events", type=int, default=100)
    worker_events.add_argument("--cursor-journal")
    worker_events.add_argument("--cursor-offset", type=int)
    _output_options(worker_events, event=True)

    evidence = commands.add_parser("evidence", help="evidence-transfer planning commands")
    evidence_commands = evidence.add_subparsers(dest="evidence_command", required=True, parser_class=SafeArgumentParser)
    transfer = evidence_commands.add_parser("plan-transfer", help="plan a digest-bound transfer without mutation")
    transfer.add_argument("--operation", choices=("acquire", "download", "upload"), required=True)
    transfer.add_argument("--locator", required=True)
    transfer.add_argument("--sha256", required=True)
    transfer.add_argument("--size-bytes", type=int, required=True)
    transfer.add_argument("--relative-path", required=True)
    transfer.add_argument("--cache-key")
    _output_options(transfer)
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


def _configuration(arguments: argparse.Namespace, environment: Mapping[str, str] | None) -> DoctorConfiguration:
    return DoctorConfiguration.from_environment(
        os.environ if environment is None else environment,
        trust_override=arguments.trust_class,
        pool_overrides=_pool_overrides(arguments.pool_path),
        inventory_max_age_seconds=arguments.max_age_seconds,
    )


def _value(value: object) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    method = getattr(value, "to_dict", None)
    if method is None:
        raise RuntimeError("control-plane service returned an unsupported automation value")
    selected = method()
    if not isinstance(selected, dict):
        raise RuntimeError("control-plane service returned a non-object automation value")
    return selected


def _name(arguments: argparse.Namespace, raw: list[str]) -> str:
    parts = [getattr(arguments, "command", None)]
    mapping = {"machine": "machine_command", "env": "env_command", "cache": "cache_command", "campaign": "campaign_command", "worker": "worker_command", "evidence": "evidence_command"}
    if parts[0] in mapping:
        parts.append(getattr(arguments, mapping[parts[0]], None))
    selected = [item for item in parts if isinstance(item, str)]
    if selected:
        return " ".join(selected)
    tokens = [item for item in raw if item and not item.startswith("-")][:2]
    return " ".join(tokens) if tokens else "command"


def _action(arguments: argparse.Namespace | None) -> tuple[str, bool]:
    if arguments is None:
        return "plan", True
    if arguments.command == "env":
        execute = arguments.env_command == "acquire" and bool(arguments.execute)
        return ("execute", False) if execute else ("plan", True)
    if arguments.command in {"campaign", "evidence"}:
        return "plan", True
    return "inspect", False


def _issue(code: str, category: str, message: str, remediation: str | None = None) -> tuple[CommandIssue, ...]:
    return (CommandIssue(code, category, message, remediation),)


def _safe_error_message(error: BaseException) -> str:
    """Make untrusted parser/filesystem messages safe for the single-line contract."""

    message = "".join(character if character.isprintable() else " " for character in str(error)).strip()
    if not message:
        message = type(error).__name__
    return message[:1024]


def _document_for_environment_plan(control: ControlPlaneController, arguments: argparse.Namespace) -> CommandDocument:
    recipe = load_environment_recipe(arguments.recipe)
    record = control.plan_environment(recipe, arguments.provider)
    payload = {"environment": _value(record)}
    if getattr(record, "state", None) != "planned":
        return CommandDocument.build(
            command="env plan",
            action="plan",
            outcome="rejected",
            dry_run=True,
            changed=False,
            payload=payload,
            issues=_issue("environment-plan-rejected", "input", "environment provider rejected the plan request"),
        )
    return CommandDocument.build(command="env plan", action="plan", dry_run=True, changed=False, payload=payload)


def _document_for_environment_acquire(
    control: ControlPlaneController,
    arguments: argparse.Namespace,
    environment: Mapping[str, str] | None,
) -> CommandDocument:
    if arguments.execute and not arguments.yes:
        raise ValueError("--execute requires --yes after plan inspection")
    if arguments.yes and not arguments.execute:
        raise ValueError("--yes is valid only with --execute")
    recipe = load_environment_recipe(arguments.recipe)
    record = control.plan_environment(recipe, arguments.provider)
    payload: dict[str, Any] = {"environment": _value(record)}
    if getattr(record, "state", None) != "planned":
        return CommandDocument.build(
            command="env acquire",
            action="execute" if arguments.execute else "plan",
            outcome="rejected",
            dry_run=not arguments.execute,
            changed=False,
            payload=payload,
            issues=_issue("environment-plan-rejected", "input", "environment provider rejected the plan request"),
        )
    plan = control.plan_environment_resources(
        record,
        machine_provider_name=arguments.machine_provider,
        estimate_confidence=arguments.estimate_confidence,
    )
    inventory = control.inspect_machine(_configuration(arguments, environment))
    admission = control.preflight_resources(plan, inventory)
    payload.update({"admission": _value(admission), "resource_plan": _value(plan)})
    if not arguments.execute:
        return CommandDocument.build(command="env acquire", action="plan", dry_run=True, changed=False, payload=payload)
    if getattr(admission, "outcome", None) != "admitted":
        return CommandDocument.build(
            command="env acquire",
            action="execute",
            outcome="rejected",
            dry_run=False,
            changed=False,
            payload=payload,
            issues=_issue(
                "resource-admission-rejected",
                "admission",
                "resource preflight did not admit environment realization",
                "Inspect the admission report and resolve its safe remediation before retrying.",
            ),
        )
    try:
        admitted = control.admit_environment_from_preflight(record, admission)
        if getattr(admitted, "state", None) != "admitted":
            payload["environment"] = _value(admitted)
            return CommandDocument.build(
                command="env acquire",
                action="execute",
                outcome="rejected",
                dry_run=False,
                changed=False,
                payload=payload,
                issues=_issue("environment-admission-rejected", "admission", "environment lifecycle rejected admission"),
            )
        realized = control.realize_environment(admitted)
    except (OSError, ValueError, RuntimeError) as error:
        payload["failure_class"] = type(error).__name__
        return CommandDocument.build(
            command="env acquire",
            action="execute",
            outcome="failed",
            dry_run=False,
            changed=True,
            payload=payload,
            issues=_issue(
                "environment-execution-failed",
                "runtime",
                "environment execution failed after mutation was authorized",
                "Inspect provider reality and lifecycle diagnostics before retrying or cleanup.",
            ),
        )
    payload["environment"] = _value(realized)
    if getattr(realized, "state", None) != "ready":
        return CommandDocument.build(
            command="env acquire",
            action="execute",
            outcome="failed",
            dry_run=False,
            changed=True,
            payload=payload,
            issues=_issue(
                "environment-verification-failed",
                "runtime",
                "environment mutation completed without a verified ready state",
                "Inspect lifecycle diagnostics and cleanup requirements; do not execute workloads in this environment.",
            ),
        )
    return CommandDocument.build(command="env acquire", action="execute", dry_run=False, changed=True, payload=payload)


def _dispatch(
    control: ControlPlaneController,
    arguments: argparse.Namespace,
    environment: Mapping[str, str] | None,
) -> tuple[CommandDocument, str | None]:
    if arguments.command == "env" and arguments.env_command == "plan":
        return _document_for_environment_plan(control, arguments), None
    if arguments.command == "env" and arguments.env_command == "acquire":
        return _document_for_environment_acquire(control, arguments, environment), None
    if arguments.command == "cache" and arguments.cache_command == "inventory":
        inventory = control.inventory_cache(load_cache_entries(arguments.entries), observed_at=arguments.observed_at)
        return CommandDocument.build(command="cache inventory", action="inspect", dry_run=False, changed=False, payload={"inventory": _value(inventory)}), None
    if arguments.command == "campaign" and arguments.campaign_command == "plan":
        request = load_resource_request(arguments.request)
        plan = control.plan_resources(operation_kind="campaign", **request)
        return CommandDocument.build(command="campaign plan", action="plan", dry_run=True, changed=False, payload={"resource_plan": _value(plan)}), None
    if arguments.command == "worker" and arguments.worker_command == "state":
        snapshot = control.inspect_local_state()
        return CommandDocument.build(command="worker state", action="inspect", dry_run=False, changed=False, payload={"state": _value(snapshot)}), None
    if arguments.command == "worker" and arguments.worker_command == "health":
        payload = {"event_journal": control.inspect_event_journal_health(), "local_state": control.inspect_local_state_health()}
        return CommandDocument.build(command="worker health", action="inspect", dry_run=False, changed=False, payload=payload), None
    if arguments.command == "worker" and arguments.worker_command == "progress":
        projection = control.inspect_progress(arguments.stream_id)
        return CommandDocument.build(command="worker progress", action="inspect", dry_run=False, changed=False, payload={"progress": _value(projection)}), None
    if arguments.command == "worker" and arguments.worker_command == "events":
        if (arguments.cursor_journal is None) != (arguments.cursor_offset is None):
            raise ValueError("event cursor journal and offset must be supplied together")
        cursor = None if arguments.cursor_journal is None else EventCursor(arguments.cursor_journal, arguments.cursor_offset)
        batch = control.read_lifecycle_events(cursor, maximum_events=arguments.maximum_events)
        document = CommandDocument.build(command="worker events", action="inspect", dry_run=False, changed=False, payload={"batch": _value(batch)})
        if arguments.format == "event":
            lines = [canonical_json(item.event.to_dict()).decode("utf-8") for item in batch.events]
            return document, "\n".join(lines) + ("\n" if lines else "")
        return document, None
    if arguments.command == "evidence" and arguments.evidence_command == "plan-transfer":
        record = control.plan_transfer(
            operation=arguments.operation,
            locator=arguments.locator,
            expected_sha256=arguments.sha256,
            expected_size_bytes=arguments.size_bytes,
            relative_path=arguments.relative_path,
            cache_key=arguments.cache_key,
        )
        return CommandDocument.build(command="evidence plan-transfer", action="plan", dry_run=True, changed=False, payload={"transfer": _value(record)}), None
    raise ControlPlaneServiceUnavailable("command is not backed by an available control-plane service")


def _requested_format(raw: list[str]) -> str:
    for value in raw:
        if value.startswith("--format=") and value[9:] in {"human", "json", "event"}:
            return value[9:]
    for index, value in enumerate(raw[:-1]):
        if value == "--format" and raw[index + 1] in {"human", "json", "event"}:
            return raw[index + 1]
    return "human"


def _emit_document(document: CommandDocument, format_name: str, compact: bool, output: TextIO) -> None:
    if format_name == "json":
        output.write(render_command_json(document, compact=compact))
    else:
        output.write(render_command_human(document))


def main(
    argv: list[str] | None = None,
    *,
    controller: ControlPlaneController | None = None,
    environment: Mapping[str, str] | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    output = stdout or sys.stdout
    errors = stderr or sys.stderr
    selected_format = _requested_format(raw)
    arguments: argparse.Namespace | None = None
    try:
        arguments = parser().parse_args(raw)
        if arguments.compact and arguments.format != "json":
            raise ValueError("--compact is valid only with --format json")
        control = controller or build_default_controller()
        if arguments.command == "doctor" or (arguments.command == "machine" and arguments.machine_command == "inspect"):
            report = control.inspect_machine(_configuration(arguments, environment))
            if arguments.format == "json":
                output.write(render_json(report, compact=arguments.compact))
            else:
                output.write(render_human(report))
            return 2 if report.status == "unsupported" else 0
        document, event_output = _dispatch(control, arguments, environment)
        if event_output is not None:
            output.write(event_output)
        else:
            target = output if document.outcome == "succeeded" else errors
            _emit_document(document, arguments.format, arguments.compact, target)
        return document.exit_code
    except (CliUsageError, OSError, ValueError) as error:
        command = _name(arguments, raw) if arguments is not None else "command"
        if command in {"doctor", "machine inspect"} and selected_format == "human":
            errors.write(f"machine inspection rejected: {_safe_error_message(error)}\n")
            return 2
        action, dry_run = _action(arguments)
        document = CommandDocument.build(
            command=command,
            action=action,
            outcome="rejected",
            dry_run=dry_run,
            changed=False,
            issues=_issue("invalid-command-input", "input", _safe_error_message(error)),
        )
        _emit_document(document, "json" if selected_format in {"json", "event"} else "human", False, errors)
        return document.exit_code
    except ControlPlaneServiceUnavailable:
        command = _name(arguments, raw) if arguments is not None else "command"
        action, dry_run = _action(arguments)
        document = CommandDocument.build(
            command=command,
            action=action,
            outcome="unavailable",
            dry_run=dry_run,
            changed=False,
            issues=_issue("service-unavailable", "unavailable", "required control-plane service is unavailable"),
        )
        _emit_document(document, "json" if selected_format in {"json", "event"} else "human", False, errors)
        return document.exit_code
    except RuntimeError as error:
        command = _name(arguments, raw) if arguments is not None else "command"
        action, dry_run = _action(arguments)
        document = CommandDocument.build(
            command=command,
            action=action,
            outcome="failed",
            dry_run=dry_run,
            changed=False,
            issues=_issue("control-plane-failure", "runtime", f"control-plane operation failed ({type(error).__name__})"),
        )
        _emit_document(document, "json" if selected_format in {"json", "event"} else "human", False, errors)
        return document.exit_code
