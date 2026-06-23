# Data Flywheel

Every secret scanner faces the same wall: a regex that is loose enough to catch real leaks also fires on data that merely *looks* like a leak. The usual answer is to hand-write more rules — narrower regexes, more allowlists, more special cases. That answer is O(human effort) and it has a ceiling: some false positives cannot be expressed as a regex at all.

Prowl's answer is a **data flywheel**. A trained model makes the "is this actually a secret, given its context?" judgment that rules can't, and every scan it runs produces the labeled data that makes the next model better: **scan → confirmed false positives become training negatives → retrain → fewer false positives → more trust → more scans → more feedback**. The loop compounds. This page tells how we arrived at it, why we chose it over more rules, exactly how it works in the code today, and why a self-improving detector is the right long-term shape for this problem.

## The problem: noise drowns signal

Prowl's deterministic core is a three-stage cascade plus a nuclei-style template library — see [Architecture](Architecture.md) and [Rules](Rules.md). It is precise on structured tokens (an `AKIA…`, a `ghp_…` with a valid CRC32, a JWT that decodes). But every scanner also needs a generic safety net for the long tail of secrets that carry no fixed prefix, and Prowl's is two shape-only detectors: `generic_high_entropy` and `generic_password` (the two types `taxonomy.GenericLast` marks as generic, and the two `scan.isGenericType` lets a specific template supersede).

Those two detectors are where the noise lives. Run Prowl across 10,000 recently-created public GitHub repositories and the generic net catches the world: base64 blobs in game-level data, hash columns in CSVs, minified bundles, embedding dumps, digest lists — high-entropy strings that are *data*, not *credentials*. On that 10k benchmark the raw run produced roughly **118,931 findings, about 96.7% of them noise from just those two generic detectors firing on data files.** The real leaks were in there; they were buried.

> The 10,000-repo benchmark figures on this page are measurements from that run, not values checked into the repository. The committed, reproducible benchmark is [ProwlBench](https://github.com/Lercas/prowlbench) (24,603 cases); the mechanisms each number describes — the two generic detectors, the per-file cap, the ML filter, the rule fixes — are all verifiable in the code referenced below.

## How we got here

### Whack-a-mole: hand-fixing rules

The first instinct was to fix the worst offenders by hand, and for *structured* false positives that works well. Concretely:

- `oracle-cloud-api-key` used to fire on any 16-byte colon-hex *fingerprint* — but that format is a public identifier shared by SSH, TLS, and GPG keys, so it matched key fingerprints everywhere (on the 10k, ~1,240 false positives, almost all in `.pem` files). It is now anchored on the `ocid1` OCID that a real OCI signing key always travels with: `tool/rules/cloud/oracle-cloud-api-key.yaml` requires the literal `ocid1` and the regex `\bocid1\.(?:user|tenancy)\.oc1\.\.…`.
- `twitter-bearer-token` used to match any `AAAA…` base64 blob — but that prefix is just base64 of leading zero bytes and shows up in SVG path data, `.resx` blobs, and notebook outputs. It now requires Twitter/X or auth context near the token: `tool/rules/messaging/twitter-bearer-token.yaml` regex demands `bearer|twitter|x[_-]?api` within 40 characters of the prefix.
- Similar structural hardening for `azure-sas-token` (the signature must sit in a real SAS query string), provider-anchored JWT rules, and the placeholder guards in `detect.IsTemplatePlaceholder` / `detect.ConnURICredentialIsPlaceholder` that drop `${VAR}`-style template references.

Each fix is correct and worth keeping. But hand-fixing does not scale. Every new false-positive class needs a new hand-written regex, and the rule library only grows. Worse, **some false-positive classes have no regex to key on at all.** "A connection string pointing at `localhost` is not a leak" is true and obvious to a human, but there is no literal substring, no prefix, no entropy threshold that separates `postgres://postgres:postgres@localhost:5432/app` from `postgres://admin:hunter2@prod.example.com:5432/app`. Rules are blind to that distinction because the distinction is contextual, not lexical.

### The unplugged model

The project already had the tool for contextual judgment, sitting unused: a trained sklearn `HistGradientBoostingClassifier` that scores "does this fragment contain a leaked credential" over **44 features** (`internal/mlfeatures.FeatureNames`, mirroring `src/features/extract.py`). The features are not just entropy — they are entropy *variants* (Shannon, normalized, base64-alphabet, hex-alphabet, bigram, compression ratio), character-class statistics, format flags (is-UUID, is-hex, is-JWT, is-PEM, is-DSN, known-prefix, hash-like length), placeholder flags, and crucially **context**: does the variable name or line contain a secret keyword, is it an assignment, is it inside quotes, is it in a URL, is it a comment, what is the source type. That context is the precision signal a regex can't see. The classifier was wired in as an opt-in L2 stage.

### The reality-check

The model nailed exactly the classes we had been hand-fixing, and the ones we couldn't. A data-file blob scored ~0.01, an Oracle-style key fingerprint ~0.006, a documentation placeholder 0.00 — while real AWS, database, and Stripe secrets scored 0.97–1.00. It makes the judgment rules can't: *is this actually a secret, given where it appears?*

### The manual cycles — the seed of the flywheel

We then improved the model by hand, twice, each time measuring the result:

- **Cycle 1 — the data-file flood.** We generated ~10,000 synthetic hard-negatives of the data-file class — base64/hex blobs in CSV rows, JSON data fields, hash lists, and `.level`/embedding dumps, all labeled not-a-secret (`src/generation/hard_negatives.py`, `generate(n)`). Retraining on them dropped data-blob false-positive retention from **56.6% to 19.7%** at the drop threshold, held real-secret recall at 100%, and pulled the worst single miss (a base64 blob in a CSV) from **0.944 down to 0.342** — from "kept" to "dropped."
- **Cycle 2 — example keys and local DSNs.** We added AWS documentation-example keys (`AKIAIOSFODNN7EXAMPLE`-shaped ids and their `wJalrXUtnFEMI…EXAMPLEKEY` secrets) and localhost/dev connection strings as negatives (`src/generation/fp_specific.py`, `generate(n)`). The AWS-docs-example false positive roughly halved. But the localhost connection strings **did not improve** — because there is no feature for "the URL host is local or private." That was the key lesson: **augmentation can't fix what the feature set can't express.** More data only helps where a feature already separates the classes; the roadmap therefore pairs data with feature engineering, not just more rows.

### The realization

That manual loop — find a false-positive class, turn it into labeled negatives, retrain, measure, redeploy — is mechanical. It should be automated, and it should be driven by **real scan feedback**, not only synthetic data. That is the data flywheel.

## Why a data flywheel, not more rules

The choice is not "ML instead of rules" — the cascade stays, and structured detection is still where rules win. The choice is *how you handle the contextual long tail*, and there the two approaches diverge sharply:

- **Rules cost human effort per false-positive class; the model costs data.** A new regex requires a person to notice the class, design a pattern, and not regress the others. A new negative requires appending labeled rows. Data is cheap and accumulates; expert regex-authoring time does not.
- **Rules can't express context; features can.** The localhost-DSN case is the proof. The moment the feature set gains a "host is local/private" signal, one batch of negatives teaches it — no regex could have.
- **Every cycle was measurable.** Retention 56.6% → 19.7%, worst miss 0.944 → 0.342, recall held at 100%. A model change has a number attached; a rule change usually doesn't.
- **The benchmark *is* labeled data.** A 10,000-repo scan whose findings get triaged is, by definition, a labeled corpus — the false positives are negatives, the confirmed leaks are positives. The thing that exposes the problem also feeds the fix.
- **There is no recall cliff.** The model never overrides proof. A checksum-validated hit (`L1-checksum`) is never dropped on a model miss (`scan.mlFilter` keeps any finding whose stage contains `checksum`, regardless of score). The flywheel tunes precision on the *generic, unproven* tail; the structured core is untouched. So a bad retrain can add noise but cannot silently lose a CRC-valid `ghp_…`.

## How it works

### The retrain pipeline

`src/flywheel.py` is one reproducible command that consolidates the manual cycles:

```sh
python -m src.flywheel                      # base corpus + synthetic hard-negatives
python -m src.flywheel --feedback fb.jsonl  # + real labeled feedback from scans
```

It builds a corpus from three sources — the base corpus, the synthetic hard-negatives (`hard_negatives.generate(10000)` + `fp_specific.generate(6000)`), and optional real feedback — then trains the binary + type `HistGradientBoostingClassifier` pair (`src/models/train.py`, `max_iter=400`, `class_weight="balanced"`, with a `not_a_secret` type class so the cascade can abstain). It dumps the binary model to `model_binary.json` (a baseline score plus 400 regression trees as flat node arrays), **verifies the dump re-evaluates to sklearn parity** (max absolute error `< 1e-9`), and installs it: into `tool/internal/mlmodel/model_binary.json` so the next Go build embeds it, and into `~/.prowl/model_binary.json` so a running binary picks it up immediately.

Feedback is JSONL, one object per line — `{"value", "context": {name,line,path,source}, "label": 0|1}` — where label `0` is a confirmed false positive (the strongest signal) and `1` a confirmed real secret. A confirmed false positive from a [baseline](CI-CD-Integration.md), an allowlist, or a triage queue is exactly a `label: 0` row.

### The model runs in-process, in Go

There is no Python at scan time. The dumped model is evaluated by a hand-written Go port — `internal/mlmodel` over the 44 features ported in `internal/mlfeatures` — that matches the Python reference essentially to float64 epsilon. The package test `TestParity` reproduces this live: **max absolute error 4.441e-16 over 206 rows.** The hot path is allocation-free: trees are flattened into contiguous slices, `Predict` walks them with zero heap allocation (`BenchmarkPredict` reports **0 allocs/op**, a few thousand nanoseconds per candidate on a modern core — hardware-dependent, not a fixed figure). It is safe for concurrent use across the scan's worker pool.

### Embedded, external, or lean — the model is a file

Model resolution is a three-step fallback (`mlscore.resolveModel`):

1. `--ml-model FILE` — an explicit path (implies `--ml`);
2. else `$PROWL_HOME/model_binary.json` (default `~/.prowl/model_binary.json`) — exactly where the flywheel drops a fresh model;
3. else the model baked into the binary by `go:embed` (`mlmodel_embed.go`, the default build).

Two consequences fall out of this design:

- **A flywheel retrain updates the deployed model without rebuilding the binary.** Drop a new `model_binary.json` into `~/.prowl` and the next scan uses it. The model is data, shipped and refreshed like data.
- **A lean build can omit the model entirely.** `go build -tags noml_embed` produces a binary about 1 MB smaller (the embedded JSON is ~1.1 MB) with no model inside — handy for fast CI scans that never pass `--ml`. That build still runs the ML stage if given an external model via `--ml-model` or `~/.prowl/model_binary.json`.

### The scan integration

The L2 stage is opt-in and merely a precision filter (`scan.mlFilter`):

- `--ml` runs the embedded/external model in-process; `--ml-url URL` calls an optional localhost sidecar (`src/serve.py`) instead. The two are interchangeable behind one `mlscore.Scorer` interface.
- Both **drop** a candidate the model judges not-a-secret — score below `--ml-threshold` (default **0.2**) — **except** a checksum-proven hit, which is never dropped.
- It **fails open**: any scoring error keeps every finding. The ML stage can only remove noise; it can never be the reason a scan misses a leak because a model failed to load or a sidecar was down.
- It **skips data-file floods**: an item that produces more than 200 candidates is left to the per-file cap (`scan.capGenericPerFile`, default 30 generic findings per file), since scoring hundreds of values from one artifact adds nothing the cap doesn't already handle.

`--ml-threshold` is the precision/recall knob: lower it to keep more borderline findings, raise it to cut more aggressively. On a real data-heavy repository, the in-process model alone took a scan from **11,138 to 10,646 findings** with no sidecar.

### Active learning — the highest-leverage feedback

Not all labels are worth the same. An obvious case — a blob the model already scores 0.01, a real key it scores 0.99 — teaches it almost nothing. The rows that move the model most are the **uncertain** ones, where the score sits around 0.4–0.6 and the model is genuinely on the fence. One such label is worth many obvious ones. The natural next step is a `--ml-review` queue that surfaces exactly those uncertain findings for a human to label, feeding them straight back into `src/flywheel.py --feedback`. *This review queue is on the roadmap, not yet a shipped flag* — today you assemble the feedback JSONL yourself — but the pipeline that consumes it already exists.

## Why this is the future of secret detection

The dominant tools (gitleaks, trufflehog, detect-secrets) are hand-maintained rule lists. They are good, and Prowl's cascade beats them on the committed benchmark before any model loads (see the [Architecture](Architecture.md) leaderboard). But a rule list improves only when a human edits it, and it is structurally blind to context. A data-driven detector improves on a different curve:

- **The loop compounds.** Each scan that gets triaged produces negatives the next model learns from. Precision rises, which earns trust, which earns more scans, which produce more feedback. Rules don't have this property — using a rule list more does not improve it.
- **Active learning maximizes signal per label.** Because the most valuable rows are the uncertain ones, a small amount of human attention spent on the right findings produces an outsized improvement. The system tells you which findings to look at.
- **The model is a file, so improvement is continuous and decoupled from releases.** A retrain ships as `model_binary.json`, picked up from `~/.prowl` without a rebuild or a binary upgrade. The detector can get better between releases, on the operator's own feedback.
- **It shifts the work from authoring patterns to curating data.** Maintaining a detector becomes labeling what was wrong, not designing regexes for every false-positive shape — and the labels come from scans you were already running.

We are honest about the limits. The flywheel only fixes what the feature set can express — the localhost-DSN case stalled because no feature encodes host-locality, so progress depends on feature engineering as much as on data. It needs a human in the loop to label, especially the uncertain cases. And the drop threshold is a tuning decision, not a free lunch: more aggressive means fewer false positives but more risk to borderline-real specific secrets, which is precisely why the structured, checksum-proven core is held outside the model's reach.

On the same 10,000 repositories, the layered system moved the numbers it was built to move: **118,931 raw findings → 84,810 with the rule fixes and per-file cap (−29%) → 31,078 at an aggressive ML threshold (−74%), or 41,554 at the conservative default (−65%)** that preserves more borderline-real specific secrets. The ML did the heavy lifting on exactly the generic noise the cap couldn't reach (`generic_password` 49,510 → 17,403; `generic_high_entropy` 31,553 → 11,753). Every one of those reductions is a number we can attach to a change — and every scan that runs makes the model that produced them a little better.

## See also

- [Architecture](Architecture.md) — the detection cascade the flywheel filters
- [Rules](Rules.md) — the hand-authored templates and where context fails them
- [CI/CD Integration](CI-CD-Integration.md) — baselines and allowlists, the source of confirmed false positives
- [Configuration](Configuration.md) — flags, environment variables, `$PROWL_HOME`
- [Security Model](Security-Model.md) — the trust boundary the in-process model keeps
- [Home](README.md)
