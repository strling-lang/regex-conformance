# Oracle validation fixtures

`oracle-validation-cases.v1.json` is deterministic synthetic test material. It
contains one admissible example for each oracle class, one frozen vector-binding
canary, and adversarial mutations that must fail closed. It contains no
production expectation, vector, execution, observation, or verdict.

Regenerate and verify it with `tools/oracle/compile_oracle_foundation.py`.
