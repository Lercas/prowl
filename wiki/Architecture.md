# Architecture

Prowl's shipped runtime is a layered pipeline: deterministic candidate detection (L1), optional ML
false-positive filtering (L2), and optional post-detection live verification. L1 is pure Go and
self-contained. L2 scores only candidates already produced by L1 or external rules; it does not add
new findings. Verification annotates supported findings as live, dead, or inconclusive.

The separate research stack includes a text model and multilingual encoder combined with L1 as an
ensemble. Those models are benchmarked independently and can be integrated through a custom scorer,
but they are not automatic union stages in the shipped binary.

## Source normalization

Before L1, the source pipeline turns containers and documents into virtual text items. It recursively
opens bounded archives and mail attachments, joins visible Office XML runs, and extracts PDF text
layers. With explicit `--ocr`, PNG/JPEG/WebP payloads and PDF pages without text are sent to the
configured local OpenAI-compatible VLM; the returned text then enters the same L1/L2/verification
pipeline. OCR is a source adapter, not an extra finding stage. See [OCR Scanning](OCR-Scanning.md).

## L1 — candidate detection (Go, embedded, self-contained)

L1 is the deterministic core. For each secret type it runs a regex anchored to a literal keyword, but only after a cheap pre-filter clears the block, and then validates the candidate with checksums, entropy, and line-context cues before accepting it.

**Aho-Corasick pre-filter.** Every type contributes the literal substrings its regex requires (a prefix like `ghp_`, `sk_live_`, or a supplement like `aws`, `private key`, `://`). All of these — plus the multilingual password cues — are compiled into a single Aho-Corasick automaton. One pass over the (ASCII-lowercased) text flags which keywords are present, and a type's regex is skipped entirely unless one of its keywords appeared. This is what makes a large rule library nearly free: a 159-rule set costs one linear scan, not 159 regex passes. A few types with no literal anchor (the Telegram and Discord bot tokens) are instead gated on a precomputed structural signal — a long digit run followed by `:`, or a long dotted token — computed in the same byte scan.

**Per-type regex.** Types are ordered structured-first, generic-last, so a precise high-value token wins a position over a wide generic run. Matching prefers capture group 1 when the rule defines one, so the reported span is the secret, not the surrounding assignment.

**Checksums.** Where a token carries a verifiable check, Prowl computes it and rejects a candidate that fails:

- GitHub classic tokens (`ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_`) carry a trailing 6-char base62 CRC32 over the body, which is recomputed and compared.
- JWTs are validated structurally: three base64url segments whose header decodes to JSON containing an `"alg"` field.

A checksum-validated finding is reported at the highest confidence (0.99) with stage `L1-checksum`; an unchecked regex hit lands at 0.9 (`L1-regex`).

**Shannon entropy.** The generic high-entropy catch-all uses the base64-class byte runs found during the structural scan (not a separate regex pass). A run is dropped below an entropy floor (~3.5 bits/char), so low-entropy strings never reach a finding.

**Line-context cues.** A high-entropy run is only kept when its line names it like a secret (`secret`, `password`, `token`, `apikey`, `client_secret`, `private`, …). A bare 32-hex value is treated as an md5/etag unless the line cues it as a key.

**Example / placeholder / hash / public-key filtering.** Before any candidate is accepted, Stage 1 discards:

- documentation examples and placeholders (`AKIAIOSFODNN7EXAMPLE`, `your_`, `changeme`, `${...}`, `process.env`, `user:password@`, runs of `xxxx`/`0000`, …);
- pure-hex digests (40/56/64/96/128-hex are always sha1…sha512; 32-hex unless cued as a secret);
- known non-secret blobs by context: SSH public keys (`ssh-rsa`, `ssh-ed25519`), data URIs, bcrypt hashes (`$2a$`/`$2b$`/`$2y$`), certificates and public-key PEM, and SRI integrity hashes (`sha384-`, `integrity=`).

**Base64 unmasking.** Any high-entropy base64 run that decodes to printable text is re-scanned for structured secrets hidden inside it (e.g. a token embedded in a JS source map or a config blob). A structured hit inside reports the outer blob's position with stage `L1-base64`; generic-inside-generic is dropped.

**Multilingual password context.** For passwords with no `=`/`:` anchor, Stage 1 scans any line carrying a credential cue — `pass`, `pwd`, plus non-English roots `kennwort`, `mot de passe`, `contrase`, `wachtwoord`, `пароль`, `salasana`, and more — for a plausible password token (length, mixed character classes, not a path/version/hash). These land as `generic_password`, stage `L1-context-pw`.

Кандидат contextual-password должен иметь признак учётных данных вне собственного
токена. Подстрока `pass` внутри одного слова не создаёт контекст сама по себе.
При равной confidence точное regex/checksum-совпадение имеет приоритет над contextual
догадкой: для `password=…` находка содержит значение, а не имя поля вместе со значением.
Fingerprint также вычисляется по самому значению; baseline, созданный прежней версией
для ошибочно расширенного токена, потребуется обновить после полного сканирования.

Stage 1's hot path is allocation-free: it folds the keyword scan and the structural byte scan into a single loop, lowercases into a pooled buffer with a zero-copy view, and reuses a pooled keyword-presence bitset per block.

## L2 — optional ML candidate filter

`--ml` scores L1 and template-rule candidates with an embedded `HistGradientBoosting` classifier over
49 numeric value/context features. `--ml-url` delegates the same batch-scoring contract to a sidecar.
Non-checksum candidates below `--ml-threshold` are removed; checksum-proven and private-key findings
are exempt. An unavailable sidecar fails open and keeps the candidates, while an explicitly requested
embedded model that cannot load fails the command preflight.

L2 improves precision. Because it receives candidates rather than the original input stream, it cannot
discover a secret that L1 and external rules did not produce.

## Optional live verification

`--verify` runs after candidate detection and ML filtering. Data-driven verifiers call read-only
provider endpoints and annotate supported findings with `verified: true`, `false`, or no verdict when
the result is inconclusive. `--verified-only` is a report filter over that state. Verification is not
an ML stage and does not participate in candidate generation.

## Experimental encoder

The published [`Podric/prowl-secret-encoder`](https://huggingface.co/Podric/prowl-secret-encoder) is a
standalone multilingual research model. It can back a custom scorer or participate in the separately
reproduced research ensemble, but the shipped scanner does not automatically run it as a third stage.

## Deduplication

Overlapping L1/template spans collapse to the stronger match. A checksum-valid token (0.99) wins over a
wide low-confidence entropy run (0.55) that merely contains it. The surviving findings are returned in
positional order before optional report filters.

## Performance

- **~310 MB/s single-thread** throughput.
- **Allocation-free hot path** — pooled buffers, a zero-copy lowercase view, one fused keyword+structure scan per block.
- **Linear scaling across cores** — files are sharded across `--workers` (default `NumCPU`); the detector is stateless per block.
- The Aho-Corasick pre-filter means library size barely affects cost — a 159-rule set is one extra linear pass.

## Benchmark

[ProwlBench](https://github.com/Lercas/prowlbench) is a 24,603-case, leakage-safe benchmark spanning structured tokens, generic high-entropy keys, multilingual free-form prose (8 languages), and adversarial hard negatives (hashes, JWT-shaped non-tokens, SSH public keys, placeholders, localhost DSNs) across code, Jira, Confluence, Slack, and logs. Every tool runs as a real subprocess on cases that are value-disjoint from the training data.

| Tool | Precision | Recall | F1 | Accuracy |
|------|:--:|:--:|:--:|:--:|
| **Prowl** (shipped Go binary, L1) | **0.951** | **0.823** | **0.883** | **0.853** |
| detect-secrets | 0.848 | 0.423 | 0.564 | 0.561 |
| gitleaks | 0.931 | 0.413 | 0.573 | 0.585 |
| deepsecrets | 0.921 | 0.309 | 0.462 | 0.517 |
| TruffleHog | 0.940 | 0.303 | 0.458 | 0.518 |

This is the canonical, clean-checkout result for the shipped binary. Separately reproduced research
ensembles report higher recall/F1 with the external LR/encoder, but require models outside a clean
checkout and carry the benchmark-overlap caveat documented by ProwlBench; they are not presented as
the default runtime result here.

## Data contracts

Findings cross stage and format boundaries as the `model.Finding` record (`type`, `confidence`, `severity`, `source`, `path`, `line`, `col`, `redacted`, `stage`, optional `verified`/`rationale`/`fingerprint`). Values are redacted at finding-construction time; the raw secret exists only long enough to compute the entropy/checksum, the stable `fingerprint` (sha256 over `type|path|raw`), and an optional live check. See [Output Formats](Output-Formats.md) for the serialized shape.

## See also

- [Output Formats](Output-Formats.md)
- [Rules](Rules.md)
- [Data Flywheel](Data-Flywheel.md)
- [Live Verification](Live-Verification.md)
- [Security Model](Security-Model.md)
- [Home](README.md)
