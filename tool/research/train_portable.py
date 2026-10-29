"""Train a versioned portable HGB contract without the C-zlib-dependent feature.

Requires the private research corpus and scikit-learn. No plaintext records are exported.
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import average_precision_score, precision_score, recall_score


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--research-root", type=Path, required=True)
    ap.add_argument("--corpus", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--baseline", type=Path)
    args = ap.parse_args()
    sys.path.insert(0, str(args.research_root))
    from src.features.extract import FEATURE_NAMES, extract_features
    from src.benchmark.dataset import template_signature
    from src.models.export_binary import export_binary

    records = [json.loads(x) for x in args.corpus.open() if x.strip()]
    # Union both template and value identities, including transitive collisions.
    parents = list(range(len(records)))
    def root(i):
        while parents[i] != i:
            parents[i] = parents[parents[i]]
            i = parents[i]
        return i
    seen = {}
    for i, rec in enumerate(records):
        for key in (("v", rec["value"]), ("t", template_signature(rec))):
            if key in seen:
                parents[root(i)] = root(seen[key])
            else:
                seen[key] = i
    groups = {}
    for i, rec in enumerate(records):
        groups.setdefault(root(i), []).append(rec)
    splits = {"train": [], "validation": [], "test": []}
    # Pack indivisible groups by size, balancing both binary classes against
    # target ratios. A giant connected group must not dominate validation.
    totals = [sum(r["label_binary"] == label for r in records) for label in (0, 1)]
    ratios = {"train": .7, "validation": .15, "test": .15}
    counts = {name: [0, 0] for name in splits}
    ordered = sorted(groups.values(), key=lambda g: (-len(g), min(template_signature(r) for r in g)))
    for group in ordered:
        size = [sum(r["label_binary"] == label for r in group) for label in (0, 1)]
        def cost(name):
            return sum(((counts[name][label] + size[label] - totals[label] * ratios[name]) ** 2
                       - (counts[name][label] - totals[label] * ratios[name]) ** 2)
                       / max(totals[label] * ratios[name], 1) for label in (0, 1))
        name = min(splits, key=cost)
        splits[name].extend(group)
        counts[name] = [counts[name][i] + size[i] for i in (0, 1)]
    print("split sizes", {k: len(v) for k, v in splits.items()}, flush=True)
    arrays = {}
    legacy = {}
    for name, rows in splits.items():
        vectors = []
        original_vectors = []
        for r in rows:
            features = extract_features(r["value"], r.get("context"))
            vector = [features[k] for k in FEATURE_NAMES]
            if name != "train":
                original_vectors.append(list(vector))
            vector[7] = 0.0
            vectors.append(vector)
        arrays[name] = (np.asarray(vectors, dtype="float64"), np.array([r["label_binary"] for r in rows]))
        if name != "train":
            legacy[name] = np.asarray(original_vectors, dtype="float64")
        print("vectorized", name, flush=True)
    clf = HistGradientBoostingClassifier(max_iter=400, learning_rate=0.08,
        l2_regularization=1.0, early_stopping=True, random_state=13, class_weight="balanced")
    clf.fit(*arrays["train"])
    metrics = {}
    for name in ("validation", "test"):
        x, y = arrays[name]
        scores = clf.predict_proba(x)[:, 1]
        metrics[name] = {"n": len(y), "positives": int(y.sum()),
            "pr_auc": average_precision_score(y, scores),
            "precision_05": precision_score(y, scores >= .5),
            "recall_05": recall_score(y, scores >= .5)}
    if args.baseline:
        old = json.loads(args.baseline.read_text())
        for name in ("validation", "test"):
            x = legacy[name]
            raw = np.full(len(x), old["baseline"])
            for t in old["trees"]:
                idx = np.zeros(len(x), dtype=np.int64)
                leaf = np.array(t["is_leaf"], dtype=bool)
                feat = np.array(t["feature_idx"])
                th = np.array(t["threshold"])
                left, right = np.array(t["left"]), np.array(t["right"])
                for _ in range(128):
                    active = np.flatnonzero(~leaf[idx])
                    if not len(active):
                        break
                    nodes = idx[active]
                    idx[active] = np.where(x[active, feat[nodes]] <= th[nodes], left[nodes], right[nodes])
                else:
                    raise ValueError("unbounded baseline tree")
                raw += np.array(t["value"])[idx]
            scores = 1 / (1 + np.exp(-raw))
            y = arrays[name][1]
            metrics[name]["legacy_1_3_comparison"] = {"pr_auc": average_precision_score(y, scores),
                "precision_05": precision_score(y, scores >= .5), "recall_05": recall_score(y, scores >= .5),
                "limitation": "legacy training may overlap this corpus; only v2 split has verified group separation"}
    dumped = export_binary(clf, FEATURE_NAMES)
    dumped["feature_contract"] = "portable-v2"
    assert not any(f == 7 and not leaf for t in dumped["trees"] for f, leaf in zip(t["feature_idx"], t["is_leaf"]))
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "model_portable.json").write_text(json.dumps(dumped))
    provenance = {"feature_contract": "portable-v2", "seed": 13,
        "corpus_sha256": hashlib.sha256(args.corpus.read_bytes()).hexdigest(),
        "split_sizes": {k: len(v) for k, v in splits.items()}, "groups": len(groups), "split_policy": "transitive-template-value-groups-class-balanced-packing", "metrics": metrics}
    (args.output / "model_portable_validation.json").write_text(json.dumps(provenance, indent=2)+"\n")
    x, _ = arrays["test"]
    subset = x[:128]
    (args.output / "portable_prediction_fixture.json").write_text(json.dumps({"features": subset.tolist(), "scores": clf.predict_proba(subset)[:, 1].tolist()}))
    print(json.dumps(provenance, indent=2), flush=True)


if __name__ == "__main__":
    main()
