#!/usr/bin/env bash
# Upload the retrained v2 encoder weights to Hugging Face (Podric/prowl-secret-encoder).
# The write token is read from passage in YOUR terminal, so it never enters the chat transcript.
# Run from the repo root:  bash scripts/hf_push_encoder.sh
#
# Uploads only the model artifacts (config + weights + tokenizer) and leaves the existing model card
# (README.md) on the Hub untouched — the reframed card was pushed earlier and still describes the
# encoder's role; the v2 weights only improve its standalone recall, so the card does not overclaim.
set -euo pipefail
cd "$(dirname "$0")/.."

TOKEN="$(passage show dev/north-star/hf-write-token | head -1)"
[ -n "$TOKEN" ] || { echo "no token from passage"; exit 1; }

DIR="data/processed/models/encoder_mbert"
[ -f "$DIR/model.safetensors" ] || { echo "no v2 weights at $DIR"; exit 1; }

HF_TOKEN="$TOKEN" .venv/bin/python - "$DIR" <<'PY'
import os, sys
from huggingface_hub import HfApi
src = sys.argv[1]
api = HfApi(token=os.environ["HF_TOKEN"])
api.upload_folder(
    folder_path=src,
    repo_id="Podric/prowl-secret-encoder",
    repo_type="model",
    allow_patterns=["config.json", "*.safetensors", "tokenizer*", "special_tokens_map.json", "vocab.txt"],
    commit_message="v2 encoder: retrained on structural hard negatives (3-way F1 0.935 -> 0.962)",
)
print("v2 weights -> Podric/prowl-secret-encoder")
PY
echo "done."
