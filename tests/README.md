# Tests

Cross-module fixtures and structural, positive, negative, boundary, fault,
regression, security, reproducibility, and integration tests live here. Test
fixtures are not published empirical evidence.

The bootstrap identity/schema suite is under `schema/`; its immutable inputs and
published expected bytes/IDs are under `fixtures/identity/`.

The public-CI trust-boundary suite lives under `ci/`. It deliberately mutates
workflow text to prove that self-hosted runners, dangerous triggers, write
permissions, secret references, and floating action tags fail closed.
