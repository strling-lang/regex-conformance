## Objective

Describe the exact repository outcome and the architecture contract it realizes.

## Verification

- [ ] Positive, negative, boundary, and affected regression checks pass.
- [ ] Generated canonical artifacts are reproducible and internally consistent.
- [ ] The complete diff contains no credentials, runtime images, raw evidence,
      execution spools, caches, or machine-local state.
- [ ] Documentation describes the implemented state.

## Trust-boundary declaration

- [ ] This pull request does not route public code or outputs to a self-hosted
      runner, trusted evidence job, publication credential, or administrative
      workflow.
- [ ] New actions and dependencies are immutable-version or digest pinned.

Public validation is untrusted and secretless. A green public check qualifies
the contribution for review; it never qualifies evidence for publication.
