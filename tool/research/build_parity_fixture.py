"""Build a public synthetic parity fixture with the Python feature reference.

No private corpus or trained sklearn pickle is required. The model JSON is the
immutable release model. The feature reference lives in the research checkout.
"""
import argparse
import hashlib
import json
import math
import random
import string
import sys
from pathlib import Path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--research-root", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    sys.path.insert(0, str(args.research_root))
    from src.features.extract import extract_features

    model_path = Path(__file__).resolve().parents[1] / "internal/mlmodel/model_binary.json"
    data = model_path.read_bytes()
    model = json.loads(data)
    rng = random.Random(1400)
    rows = []
    fixed = ["", "short", "changeme", "Autumn!7Road", "AKIANAFGYOEYPXU1DSYP",
             "ПарольСентябрь42", "postgres://user:synthetic@db:5432/data",
             "sha256:" + "abcdef01" * 8, "ssh-ed25519 " + "ABCdef012" * 7]
    for i in range(256):
        value = fixed[i] if i < len(fixed) else "".join(rng.choices(
            [string.ascii_letters + string.digits, string.hexdigits[:16], "ab", string.ascii_letters + "-_!."][i % 4],
            k=[8, 20, 32, 48, 128, 512][i % 6]))
        ctx = {"name": ["api_key", "checksum", "password", "example_token"][i % 4],
               "line": [f'password="{value}"', f'// checksum: {value}', f'key = "{value}"'][i % 3],
               "path": ["src/app.py", "deploy/config.yaml", "README.md", "package-lock.json"][i % 4],
               "source": ["code", "jira", "confluence", "unknown"][i % 4]}
        features = extract_features(value, ctx)
        x = [features[name] for name in model["feature_names"]]
        def predict(tolerance):
            raw = model["baseline"]
            for tree in model["trees"]:
                node = 0
                while not tree["is_leaf"][node]:
                    value = x[tree["feature_idx"][node]]
                    threshold = tree["threshold"][node]
                    left = value <= threshold or abs(value - threshold) <= tolerance
                    node = tree["left"][node] if left else tree["right"][node]
                raw += tree["value"][node]
            return 1 / (1 + math.exp(-raw))
        rows.append({"value": value, "context": ctx, "features": x,
                     "l2_prob": predict(1e-12), "reference_l2_prob": predict(0)})
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({"seed": 1400, "model_sha256": hashlib.sha256(data).hexdigest(),
                                       "comparison_policy": "absolute_split_tolerance_1e-12",
                                       "numerical_boundary_changes": sum(abs(r["l2_prob"] - r["reference_l2_prob"]) > 1e-12 for r in rows),
                                       "feature_names": model["feature_names"], "rows": rows}, ensure_ascii=False, indent=2) + "\n")


if __name__ == "__main__":
    main()
