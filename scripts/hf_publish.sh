#!/usr/bin/env bash
# Publish the reframed model card (#1) and the ProwlBench v2 cases (#2) to Hugging Face.
# The write token is read from passage in YOUR terminal, so it never enters the chat transcript.
# Run from the repo root:  bash scripts/hf_publish.sh
set -euo pipefail
cd "$(dirname "$0")/.."

TOKEN="$(passage show dev/north-star/hf-write-token | head -1)"
[ -n "$TOKEN" ] || { echo "no token from passage"; exit 1; }

HF_TOKEN="$TOKEN" .venv/bin/python - <<'PY'
import os
from huggingface_hub import HfApi
api = HfApi(token=os.environ["HF_TOKEN"])

# #1 — model card (reframed: about the encoder's own value, no "beat DeepPass2")
api.upload_file(
    path_or_fileobj="data/processed/models/encoder_mbert/README.md",
    path_in_repo="README.md",
    repo_id="Podric/prowl-secret-encoder", repo_type="model",
    commit_message="Reframe card on the model's own terms (recall lift + multilingual reach)",
)
print("#1 model card -> Podric/prowl-secret-encoder")

# #2 — ProwlBench v2 cases (24,603), mirroring the github push
api.upload_file(
    path_or_fileobj="benchmark/prowlbench.jsonl",
    path_in_repo="prowlbench.jsonl",
    repo_id="Podric/prowl-secrets-corpus", repo_type="dataset",
    commit_message="ProwlBench v2.0: 24,603 cases (8 languages, adversarial hard negatives)",
)
print("#2 prowlbench.jsonl (v2, 24603 cases) -> Podric/prowl-secrets-corpus")
PY
echo "done."
