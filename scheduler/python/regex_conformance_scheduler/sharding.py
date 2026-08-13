"""Partition logical executions exactly once by environment locality then identity."""

from __future__ import annotations

from typing import Any, Callable


def shard_by_selection_locality(
    logical_executions: list[dict[str, Any]],
    maximum_size: int,
    identity: Callable[[dict[str, Any]], str],
) -> list[dict[str, Any]]:
    if isinstance(maximum_size, bool) or maximum_size < 1:
        raise ValueError("maximum shard size must be a positive integer")
    result: list[dict[str, Any]] = []
    selections = sorted({item["selection_key"] for item in logical_executions})
    for selection_key in selections:
        members = sorted(
            item["logical_execution_id"]
            for item in logical_executions
            if item["selection_key"] == selection_key
        )
        for offset in range(0, len(members), maximum_size):
            logical_ids = members[offset : offset + maximum_size]
            body = {"logical_execution_ids": logical_ids, "selection_key": selection_key}
            result.append({"shard_id": identity(body), **body})
    return sorted(result, key=lambda item: item["shard_id"])
