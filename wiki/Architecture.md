# Architecture

Prowl detects secrets with a three-stage cascade. Each stage targets a different kind of credential; the stages run independently and their outputs are merged by a union, then de-duplicated by position. The first stage is pure Go and self-contained — it ships in the binary and needs nothing else. The two machine-learning stages add recall on free-form and multilingual text and are optional: the cascade is fully functional with neither.

This design exists to beat the usual precision/recall trade-off. Regex scanners (gitleaks, trufflehog) are precise on structured tokens but blind to anything without a fixed prefix; ML/semantic detectors (deepsecrets) read prose but collapse on structured keys. Prowl runs both as one pipeline and leads each on its own tier — see [ProwlBench](https://github.com/Lercas/prowlbench).

## Stage 1 — the cascade (Go, embedded, self-contained)

Stage 1 is the deterministic core. For each secret type it runs a regex anchored to a literal keyword, but only after a cheap pre-filter clears the block, and then validates the candidate with checksums, entropy, and line-context cues before accepting it.

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

Stage 1's hot path is allocation-free: it folds the keyword scan and the structural byte scan into a single loop, lowercases into a pooled buffer with a zero-copy view, and reuses a pooled keyword-presence bitset per block.

## Stage 2 — the text model

A TF-IDF logistic regression over character and word n-grams classifies generic and multilingual passwords the regexes can't anchor — high-entropy free-form strings and prose passwords in several languages. It catches the tail Stage 1's keyword anchoring necessarily misses, at a modest, calibrated confidence.

## Stage 3 — the encoder

A fine-tuned multilingual transformer encoder ([`Podric/prowl-secret-encoder`](https://huggingface.co/Podric/prowl-secret-encoder) on Hugging Face) handles the free-form and in-code tail — the cases where neither a fixed prefix nor a simple n-gram signal is enough. Stage 3 is optional. It is the only stage with an external dependency, and when it is absent the cascade (Stage 1, or Stage 1 ∪ Stage 2) runs unchanged. On the benchmark below the cascade alone already beats every other tool; Stage 3 is what lifts recall to the headline number.

## Combination

The three stages are combined as a **union**: a finding is anything any stage is confident about. Results are then de-duplicated by position — overlapping spans collapse to the single highest-confidence match, so a checksum-valid token (0.99) wins over a wide low-confidence entropy run (0.55) that merely contains it, even when the wide run starts earlier. The surviving findings are returned in positional order.

## Performance

- **~310 MB/s single-thread** throughput.
- **Allocation-free hot path** — pooled buffers, a zero-copy lowercase view, one fused keyword+structure scan per block.
- **Linear scaling across cores** — files are sharded across `--workers` (default `NumCPU`); the detector is stateless per block.
- The Aho-Corasick pre-filter means library size barely affects cost — a 159-rule set is one extra linear pass.

## Benchmark

[ProwlBench](https://github.com/Lercas/prowlbench) is a 24,603-case, leakage-safe benchmark spanning structured tokens, generic high-entropy keys, multilingual free-form prose (8 languages), and adversarial hard negatives (hashes, JWT-shaped non-tokens, SSH public keys, placeholders, localhost DSNs) across code, Jira, Confluence, Slack, and logs. Every tool runs as a real subprocess on cases that are value-disjoint from the training data.

| Tool | Precision | Recall | F1 |
|------|:--:|:--:|:--:|
| **Prowl** (3-way) | 0.936 | **0.989** | **0.962** |
| Prowl (cascade ∪ LR) | 0.940 | 0.872 | 0.905 |
| Prowl (cascade only, no ML) | **0.958** | 0.823 | 0.885 |
| DeepPass2 | 0.893 | 0.567 | 0.694 |
| gitleaks | 0.931 | 0.413 | 0.573 |
| detect-secrets | 0.848 | 0.423 | 0.564 |
| deepsecrets | 0.921 | 0.309 | 0.462 |
| TruffleHog | 0.940 | 0.303 | 0.458 |

Headline **F1 ≈ 0.962** on the harder v2 benchmark. Prowl leads every tier and every language; per-language recall reaches 1.00 on German, French, and Russian prose. The cascade-only row shows the pure-Go core already outperforming every competitor on F1 before any model is loaded; the 3-way's structural-negative retraining lifted recall to 0.99 while cutting the hard-negative false-positive rate from 0.23 to 0.14.

## Data contracts

Findings cross stage and format boundaries as the `model.Finding` record (`type`, `confidence`, `severity`, `source`, `path`, `line`, `col`, `redacted`, `stage`, optional `verified`/`rationale`/`fingerprint`). Values are redacted at finding-construction time; the raw secret exists only long enough to compute the entropy/checksum, the stable `fingerprint` (sha256 over `type|path|raw`), and an optional live check. See [Output Formats](Output-Formats.md) for the serialized shape.

## See also

- [Output Formats](Output-Formats.md)
- [Rules](Rules.md)
- [Data Flywheel](Data-Flywheel.md)
- [Live Verification](Live-Verification.md)
- [Security Model](Security-Model.md)
- [Home](README.md)
