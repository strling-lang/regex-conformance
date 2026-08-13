"""Provider-neutral coordination of immutable logical executions and physical attempts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol

from regex_conformance_schema.identity import NamespaceRegistry, generate_assigned_id


class CampaignExecutionError(RuntimeError):
    """A campaign produced incomplete or contradictory physical attempts."""


class ShardWorker(Protocol):
    def execute_shard(
        self,
        selection_key: str,
        logical_executions: list[dict[str, Any]],
    ) -> list[dict[str, Any]]: ...


class CampaignEvidenceSink(Protocol):
    def publish(
        self,
        compiled: dict[str, Any],
        attempts_by_shard: list[tuple[dict[str, Any], list[dict[str, Any]]]],
    ) -> dict[str, Any]: ...


def _stamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


@dataclass
class CampaignCoordinator:
    registry: NamespaceRegistry

    def execute(
        self,
        compiled: dict[str, Any],
        worker: ShardWorker,
        evidence: CampaignEvidenceSink,
    ) -> dict[str, Any]:
        logical_by_id = {
            item["logical_execution_id"]: item for item in compiled["logical_executions"]
        }
        if len(logical_by_id) != len(compiled["logical_executions"]):
            raise CampaignExecutionError("logical execution identities are not unique")
        attempts_by_shard: list[tuple[dict[str, Any], list[dict[str, Any]]]] = []
        infrastructure_failures = 0
        for shard in compiled["shards"]:
            logicals = [logical_by_id[item] for item in shard["logical_execution_ids"]]
            raw_attempts = worker.execute_shard(shard["selection_key"], logicals)
            observed = [item.get("logical_execution_id") for item in raw_attempts]
            if sorted(observed) != sorted(shard["logical_execution_ids"]) or len(observed) != len(set(observed)):
                raise CampaignExecutionError("worker result set did not equal the shard denominator")
            attempts: list[dict[str, Any]] = []
            for raw in raw_attempts:
                attempt = dict(raw)
                attempt["physical_run_id"] = generate_assigned_id(
                    self.registry, "rcid", "physical-run"
                )
                attempt.setdefault("attempt_number", 1)
                attempt.setdefault("observed_at", _stamp())
                target = attempt.get("response") is not None
                infrastructure = attempt.get("infrastructure_failure") is not None
                if target == infrastructure:
                    raise CampaignExecutionError(
                        "physical attempt must contain exactly one target response or infrastructure failure"
                    )
                if infrastructure:
                    infrastructure_failures += 1
                attempts.append(attempt)
            attempts_by_shard.append((shard, attempts))
        manifest = evidence.publish(compiled, attempts_by_shard)
        if infrastructure_failures:
            raise CampaignExecutionError(
                f"campaign preserved {infrastructure_failures} infrastructure failure(s); denominator remains incomplete"
            )
        if not manifest.get("complete") or manifest.get("accepted_observation_count") != len(logical_by_id):
            raise CampaignExecutionError("evidence manifest did not reconcile the complete logical denominator")
        return manifest
