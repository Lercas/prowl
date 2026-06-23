# Using the Prowl model on its own

Prowl's "is this candidate actually a secret?" judgment is a small model you can run **independently of
the scanner** - as an HTTP service, as an embedded classifier in your own program, or as the published
transformer. This guide documents the three integration surfaces and their exact contracts.

## The model stack (what you're integrating)

Prowl scores a candidate string (plus optional context) through a cascade:

| Stage | What it is | Where it lives |
|-------|------------|----------------|
| **L1** | regex / checksum / entropy rules (deterministic) | the Go scanner (`internal/detect`) |
| **L2** | a gradient-boosted binary classifier (`HistGradientBoosting`) over **49 numeric features** - "secret vs. not-secret" | `model_binary.json`, embedded in the binary (`tool/internal/mlmodel/`) |
| **type** | a multiclass classifier that labels the provider/type | the (private) training repo / the sidecar |
| **stage-3 encoder** | an experimental multilingual transformer | Hugging Face: [`Podric/prowl-secret-encoder`](https://huggingface.co/Podric/prowl-secret-encoder) |

The Python training/serving code is not part of the public scanner repo. The three public integration
surfaces are: the **HTTP `/score` contract** (A), the embedded **`model_binary.json`** L2 classifier (B),
and the **HF encoder** (C). Pick the one that fits - you do not need the scanner to use any of them.

---

## A) As an HTTP sidecar - the `/score` contract (language-agnostic)

This is the cleanest way to reuse the model from anything. A scorer is any HTTP service that answers two
endpoints. You can either **point the scanner at your own scorer** (`prowl scan --ml-url http://host:port`)
or **call a scorer directly** from your own tool - same contract either way.

### `GET /health`
The scanner pings this before scoring; reply `200` with any JSON body. The scanner only checks the status
code.
```json
{ "status": "ok", "threshold": 0.5 }
```

### `POST /score`
Request - a batch of candidates; `context` and all its fields are optional:
```json
{
  "records": [
    { "value": "AKIA....", "context": { "name": "aws_key", "line": "aws_key = \"AKIA...\"", "path": "cfg.py", "source": "code" } },
    { "value": "hunter2",  "context": {} }
  ]
}
```
Response - **one result per record, in the same order**:
```json
{
  "results": [
    { "score": 0.98, "is_secret": true,  "type": "aws_access_key_id", "stage": "L2-ml" },
    { "score": 0.03, "is_secret": false, "type": "not_a_secret",      "stage": "L2-ml" }
  ]
}
```
Contract notes:
- **`score` is the only field the scanner requires** - a probability in `[0, 1]`. The scanner keeps a
  finding when `score >= --ml-threshold` (default `0.3`); `is_secret`, `type`, and `stage` are advisory.
- Return **exactly `len(records)` results, in order** - the scanner rejects a length mismatch and fails
  open (keeps all findings).
- The scanner POSTs through an SSRF-hardened client (cross-host redirects refused, private IPs blocked
  unless `PROWL_ALLOW_PRIVATE_IPS=1`); a loopback sidecar needs that env when called from the scanner.

### Minimal reference scorer (Python, stdlib)
A drop-in that satisfies the contract over the embedded L2 model is the project sidecar
(`python -m src.serve`, listens on `127.0.0.1:8771`). To build your own in any framework, implement the
two endpoints above and return a probability per record. Example with FastAPI:
```python
from fastapi import FastAPI
app = FastAPI()

@app.get("/health")
def health(): return {"status": "ok"}

@app.post("/score")
def score(body: dict):
    recs = body.get("records", [])
    return {"results": [{"score": my_model(r["value"], r.get("context", {})),
                         "is_secret": False, "type": "", "stage": "custom"} for r in recs]}
```
Then: `prowl scan ./repo --ml-url http://127.0.0.1:8000` (run it with `PROWL_ALLOW_PRIVATE_IPS=1` for a
loopback sidecar).

### Calling it from your own tool (no scanner)
```bash
curl -s localhost:8771/score -H 'content-type: application/json' \
  -d '{"records":[{"value":"AKIAIOSFODNN7EXAMPLE","context":{"name":"key"}}]}' | jq .results
```

---

## B) Embed the L2 classifier (`model_binary.json`) in your own code

The L2 "secret vs. not-secret" model ships as `tool/internal/mlmodel/model_binary.json` - a self-contained
gradient-boosted-trees dump you can score without Python or the scanner:
```json
{ "baseline": -1.7, "feature_names": ["length", "shannon_entropy", ...49 names...], "trees": [ ... ] }
```
To score a candidate:
1. Build the **49-feature vector** for the value (+ context), in the order given by `feature_names`. The
   reference implementation is `tool/internal/mlfeatures/extract.go` (`FeatureNames` + `Extract`) - features
   are entropy measures, character-class stats, format/structure flags, and context flags.
2. Run the trees: `raw = baseline + Σ tree(features)`, then `probability = sigmoid(raw)`.
3. Compare to your own threshold (the scanner uses `0.3`).

The Go reference inference is `tool/internal/mlmodel` (`Load` / `Predict`); the file is also loadable via
`prowl scan --ml-model path/to/model_binary.json` or `~/.prowl/model_binary.json` if you want the scanner
to use an externally-trained model.

**Caveat - `compression_ratio` parity:** one of the 49 features uses zlib. A cgo build matches the
Python trainer's zlib byte-for-byte; a pure-Go (nocgo) build differs by a few bytes on that single
feature, shifting the score slightly. Match the trainer's zlib if you reimplement the feature extractor.

This path gives you the **L2 binary classifier only** - not the L1 rules or the type classifier (those
live in the scanner and the private training code). It answers "does this look like a real secret?", not
"which provider is it?".

---

## C) The stage-3 encoder from Hugging Face

The heavier, experimental multilingual model is published standalone:
- **Model:** [`Podric/prowl-secret-encoder`](https://huggingface.co/Podric/prowl-secret-encoder) - a
  multilingual transformer classifier over candidate strings + context.
- **Dataset:** [`Podric/prowl-secrets-corpus`](https://huggingface.co/datasets/Podric/prowl-secrets-corpus)
  - 503k labeled records (code, tickets, logs, prose) with provenance, for fine-tuning/evaluation.

```python
from transformers import AutoTokenizer, AutoModelForSequenceClassification
tok = AutoTokenizer.from_pretrained("Podric/prowl-secret-encoder")
model = AutoModelForSequenceClassification.from_pretrained("Podric/prowl-secret-encoder")
# tokenize "<name> <value>"-style input, run the model, read the secret probability from the logits.
```
Use this when you want a single neural model (no feature engineering) and can afford transformer
inference; use (A)/(B) when you want the lightweight, low-latency cascade the scanner ships.

---

## Honest limitations

- **The public surfaces are (A) the contract, (B) the embedded HGB, (C) the HF encoder.** The full Python
  cascade (L1 rules + L2 + type classifier + calibration) is the project's private training/serving code;
  it is not redistributed in the scanner repo.
- **`score` is a probability, not a verdict.** Choose a threshold for your precision/recall target - the
  scanner defaults to `0.3` and exposes it as `--ml-threshold` / `performance.ml_threshold`.
- **The feature contract is fixed at 49 features.** A vector of a different length is rejected; reimplement
  the extractor exactly (names + order) from `model_binary.json`'s `feature_names`.
- **No secret leaves your machine in any of these paths.** The sidecar is loopback by design; nothing here
  calls a third-party API.
