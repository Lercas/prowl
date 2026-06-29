<!-- Prowl PR checklist. The adversarial-review ritual below is the project's most reliable quality
signal — it has caught regressions that tests and self-review missed every single round. Don't skip it. -->

## What & why


## Adversarial-review checklist
Run a hostile pass on your OWN diff before requesting review (or `/deep-review`):

- [ ] **Refute the diff** — for each change, try to prove it WRONG, not right. What input breaks it?
- [ ] **No half-wired flags** — a new flag/option is parsed AND threaded AND reaches its gate on every subcommand/path that advertises it (not just the happy path).
- [ ] **Gate-path coverage** — every code path that can emit/suppress a finding was checked (baseline, gitleaksignore, min-severity, allowlist, example/lockfile demotion, image label-prefix).
- [ ] **Fail closed** — on abort / budget trip / cancel / error, the scan does NOT exit 0 "clean".
- [ ] **Concurrency** — shared state touched under a lock; verified with `go test -race`.
- [ ] **Gated on REAL data, not synthetic** — ML/detector/rule changes pass `benchmark/ci_gate.py` (real-origin held-out recall + T4-FP), not just an injected synthetic class. A retrain that aces a synthetic FP class can be a wash on real data.
- [ ] **No secrets in the diff** — no real keys in tests/fixtures/goldens (push-protection will block them); raw research keys stay out of the repo tree.

## Checks
- [ ] `go test -race ./...` green · `gofmt`/`vet` clean
- [ ] rules/verifiers `MANIFEST.sha256` regenerated if a bundled rule/verifier changed
- [ ] ProwlBench gate (`ci_gate.py`) not regressed
