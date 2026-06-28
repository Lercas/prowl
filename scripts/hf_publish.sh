#!/usr/bin/env bash
# Publish the model card (#1), the ProwlBench v2 cases (#2), and the full schema-normalized corpus (#3).
# The write token is read from passage in YOUR terminal, so it never enters the chat transcript.
# Run from the repo root:  bash scripts/hf_publish.sh
set -euo pipefail
cd "$(dirname "$0")/.."

TOKEN="$(passage show dev/north-star/hf-write-token | head -1)"
[ -n "$TOKEN" ] || { echo "no token from passage"; exit 1; }

# Normalize corpus + prowlbench to parquet first: HF applies one builder across all configs, so a mix
# of parquet and jsonl configs makes it read the jsonl as parquet and fail (SplitsNotFoundError).
.venv/bin/python scripts/hf_normalize_corpus.py

HF_TOKEN="$TOKEN" .venv/bin/python - <<'PY'
import os
from huggingface_hub import HfApi
api = HfApi(token=os.environ["HF_TOKEN"])

# #1 — model card
api.upload_file(
    path_or_fileobj="data/processed/models/encoder_mbert/README.md", path_in_repo="README.md",
    repo_id="Podric/prowl-secret-encoder", repo_type="model",
    commit_message="Reframe card on the model's own terms (recall lift + multilingual reach)",
)
print("#1 model card -> Podric/prowl-secret-encoder")

D = dict(repo_id="Podric/prowl-secrets-corpus", repo_type="dataset")
# #2 — ProwlBench v2 (parquet is the config; jsonl kept as a convenience copy)
for f in ("prowlbench.parquet", "prowlbench.jsonl"):
    api.upload_file(path_or_fileobj=f"benchmark/{f}", path_in_repo=f,
                    commit_message="ProwlBench v2.0: 24,603 cases (8 languages, adversarial hard negatives)", **D)
    print(f"#2 {f} -> Podric/prowl-secrets-corpus")
# #3 — full schema-normalized corpus
for f in ("corpus.parquet", "corpus.jsonl"):
    api.upload_file(path_or_fileobj=f"data/processed/{f}", path_in_repo=f,
                    commit_message="Sync full corpus (schema-normalized: extra->json string, uniform keys)", **D)
    print(f"#3 {f} -> Podric/prowl-secrets-corpus")
PY
echo "done."
