"""Train and qualify the portable binary model using the Go inference extractor.

All outputs go to a new directory; neither the corpus nor the installed model is
modified. Raw values are never written to metrics, feature caches or fixtures.
"""

from __future__ import annotations

import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import random
import re
import subprocess
import zlib

import numpy as np
import sklearn
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import average_precision_score, precision_score, recall_score, f1_score


def partition(records, seed):
    """Merge connected template/value groups before assigning complete groups."""
    parent = list(range(len(records)))

    def root(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    seen_values, seen_templates = {}, {}
    for i, record in enumerate(records):
        value = record["value"]
        text = record.get("text") or value
        span = record.get("span")
        if isinstance(span, (list, tuple)) and len(span) == 2:
            text = text[:span[0]] + "\x00" + text[span[1]:]
        elif value:
            text = text.replace(value, "\x00")
        template = re.sub(r"\s+", " ", text).strip()
        for seen, key in ((seen_values, value), (seen_templates, template)):
            if key in seen:
                parent[root(i)] = root(seen[key])
            else:
                seen[key] = i
    groups = defaultdict(list)
    for i in range(len(records)):
        groups[root(i)].append(i)
    strata = defaultdict(list)
    for indices in groups.values():
        strata[records[indices[0]]["label_type"]].append(indices)
    rng = random.Random(seed)
    buckets = {key: [] for key in ("train", "val", "test")}
    for groups in strata.values():
        rng.shuffle(groups)
        for i, indices in enumerate(groups):
            bucket = "train" if i < int(len(groups) * .7) else (
                "val" if i < int(len(groups) * .85) else "test")
            buckets[bucket].extend(indices)
    return {key: np.asarray(indices, dtype=int) for key, indices in buckets.items()}


def export_model(clf, names):
    trees = []
    for predictors in clf._predictors:
        nodes = predictors[0].nodes
        leaf = nodes["is_leaf"].astype(bool)
        trees.append({
            "feature_idx": np.where(leaf, -1, nodes["feature_idx"]).astype(int).tolist(),
            "threshold": nodes["num_threshold"].tolist(),
            "left": nodes["left"].astype(int).tolist(),
            "right": nodes["right"].astype(int).tolist(),
            "value": nodes["value"].tolist(),
            "missing_left": nodes["missing_go_to_left"].astype(int).tolist(),
            "is_leaf": leaf.astype(int).tolist(),
        })
    return {"baseline": float(clf._baseline_prediction.ravel()[0]),
            "feature_names": names, "trees": trees}


def metrics(y, probabilities, threshold=.3):
    predicted = probabilities >= threshold
    return {"pr_auc": float(average_precision_score(y, probabilities)),
            "precision": float(precision_score(y, predicted, zero_division=0)),
            "recall": float(recall_score(y, predicted, zero_division=0)),
            "f1": float(f1_score(y, predicted, zero_division=0))}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--extractor", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=13)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    names = json.loads(subprocess.check_output([str(args.extractor), "--names"]))
    assert names[7] == "compression_ratio_go_flate_v1"
    print("Extracting canonical Go features", flush=True)
    with args.corpus.open("rb") as corpus, (args.out / "features.jsonl").open("wb") as features:
        subprocess.run([str(args.extractor)], stdin=corpus, stdout=features, check=True)
    print("Loading corpus and feature matrix", flush=True)
    records = [json.loads(line) for line in args.corpus.open() if line.strip()]
    X = np.asarray([json.loads(line) for line in (args.out / "features.jsonl").open()], dtype=float)
    assert X.shape == (len(records), len(names)) and np.isfinite(X).all()
    y = np.asarray([r["label_binary"] for r in records])
    split = partition(records, args.seed)
    for indices in split.values():
        assert len(indices) and set(y[indices]) == {0, 1}
    old_ratio = np.asarray([len(zlib.compress(r["value"].encode())) / len(r["value"].encode())
                            if r["value"] else 0. for r in records])
    report = {"corpus_sha256": hashlib.sha256(args.corpus.read_bytes()).hexdigest(),
              "seed": args.seed, "numpy": np.__version__, "sklearn": sklearn.__version__,
              "extractor_sha256": hashlib.sha256(args.extractor.read_bytes()).hexdigest(),
              "n": len(records), "split": {k: len(v) for k, v in split.items()},
              "threshold": .3, "max_regression": .005, "models": {},
              "selection": "portable max_leaf_nodes in [31,63,127] selected by validation F1 at threshold 0.3"}
    portable = None
    for name in ("zlib_control", "go_flate"):
        print(f"Training {name}: {len(split['train'])} records", flush=True)
        data = X.copy()
        if name == "zlib_control":
            data[:, 7] = old_ratio
        clf = HistGradientBoostingClassifier(
            max_iter=400, learning_rate=.08, l2_regularization=1.,
            early_stopping=True, validation_fraction=.1, random_state=args.seed,
            class_weight="balanced")
        clf.fit(data[split["train"]], y[split["train"]])
        threshold = .3
        if name == "go_flate":
            candidates = {31: metrics(y[split["val"]], clf.predict_proba(data[split["val"]])[:, 1])}
            for leaves in (63, 127):
                print(f"Training portable validation candidate: {leaves} leaves", flush=True)
                candidate = HistGradientBoostingClassifier(
                    max_iter=400, learning_rate=.08, l2_regularization=1., max_leaf_nodes=leaves,
                    early_stopping=True, validation_fraction=.1, random_state=args.seed,
                    class_weight="balanced")
                candidate.fit(data[split["train"]], y[split["train"]])
                candidates[leaves] = metrics(y[split["val"]], candidate.predict_proba(data[split["val"]])[:, 1])
                if candidates[leaves]["f1"] > max(v["f1"] for k, v in candidates.items() if k != leaves):
                    clf = candidate
            report["validation_candidates"] = candidates
            report["selected_max_leaf_nodes"] = clf.max_leaf_nodes
        report["models"][name] = {bucket: metrics(y[indices], clf.predict_proba(data[indices])[:, 1], threshold)
                                  for bucket, indices in split.items() if bucket != "train"}
        print(json.dumps(report["models"][name]), flush=True)
        if name == "go_flate":
            portable = clf
    report["qualified"] = all(
        report["models"]["go_flate"][bucket][metric] >=
        report["models"]["zlib_control"][bucket][metric] - report["max_regression"]
        for bucket in ("val", "test") for metric in ("pr_auc", "precision", "recall", "f1"))
    (args.out / "qualification.json").write_text(json.dumps(report, indent=2) + "\n")
    if not report["qualified"]:
        raise SystemExit("Portable model failed the quality regression gate")
    model = export_model(portable, names)
    model_bytes = (json.dumps(model, separators=(",", ":")) + "\n").encode()
    (args.out / "model_binary_go.json").write_bytes(model_bytes)
    report["model_sha256"] = hashlib.sha256(model_bytes).hexdigest()
    (args.out / "qualification.json").write_text(json.dumps(report, indent=2) + "\n")
    fixture_indices = np.concatenate([split["val"][:128], split["test"][:128]])
    probabilities = portable.predict_proba(X[fixture_indices])[:, 1]
    fixtures = [{"features": X[index].tolist(), "l2_prob": float(probability)}
                for index, probability in zip(fixture_indices, probabilities)]
    (args.out / "prediction_golden.json").write_text(json.dumps(fixtures) + "\n")
    print("Portable model qualified; candidate outputs are ready for Go parity checks", flush=True)


if __name__ == "__main__":
    main()
