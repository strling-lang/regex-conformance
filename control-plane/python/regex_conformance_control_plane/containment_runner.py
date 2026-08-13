"""Internal POSIX exec trampoline for applying resource limits safely."""

from __future__ import annotations

import os
import resource
import sys


def main(arguments: list[str] | None = None) -> int:
    values = list(sys.argv[1:] if arguments is None else arguments)
    memory: int | None = None
    cpu: int | None = None
    while values and values[0] != "--":
        option = values.pop(0)
        if option not in {"--memory-bytes", "--cpu-seconds"} or not values:
            raise SystemExit("invalid containment runner arguments")
        try:
            amount = int(values.pop(0))
        except ValueError as error:
            raise SystemExit("invalid containment runner limit") from error
        if amount < 1:
            raise SystemExit("invalid containment runner limit")
        if option == "--memory-bytes":
            memory = amount
        else:
            cpu = amount
    if not values or values.pop(0) != "--" or not values:
        raise SystemExit("containment runner requires a target command")
    if memory is not None:
        resource.setrlimit(resource.RLIMIT_AS, (memory, memory))
    if cpu is not None:
        resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu + 1))
    try:
        os.execvpe(values[0], values, dict(os.environ))
    except OSError:
        os.write(2, b"contained target exec failed\n")
        return 127


if __name__ == "__main__":
    raise SystemExit(main())
