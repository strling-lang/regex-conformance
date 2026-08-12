# Tests

Cross-module fixtures and structural, positive, negative, boundary, fault,
regression, security, reproducibility, and integration tests live here. Test
fixtures are not published empirical evidence.

The bootstrap identity/schema suite is under `schema/`; its immutable inputs and
published expected bytes/IDs are under `fixtures/identity/`.

The public-CI trust-boundary suite lives under `ci/`. It deliberately mutates
workflow text to prove that self-hosted runners, dangerous triggers, write
permissions, secret references, and floating action tags fail closed.

The Control Plane foundation suite lives under `control_plane/`. It drives
Linux, Windows, and macOS fixtures through the same controller service, validates
the machine-inventory schema and deterministic JSON, exercises actionable
failure diagnostics, proves unknown telemetry remains unknown, confirms the CLI
is only a client, and runs a read-only real-host smoke test.
