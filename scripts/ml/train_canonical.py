"""Train a parser-scoped calibration while preserving the base forest off-scope.

The output is an experiment until Go parity, native integration and ProwlBench
also pass. Neither installed models nor the base model are modified.
"""

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier

from train_portable import export_model, metrics, partition, select_candidate


ARRAYS = ("feature_idx", "threshold", "left", "right", "value", "missing_left", "is_leaf")


def validate_inputs(records, x, names):
    if (x.shape != (len(records), len(names)) or not np.isfinite(x).all()
            or len(names) < 2
            or names[-2:] != ["ctx_parser_literal_sensitive_v1", "ctx_ui_namespace_v1"]):
        raise ValueError("Calibration input must match the explicit parser feature schema")
    if not np.isin(x[:, -2:], [0., 1.]).all():
        raise ValueError("Parser facts must be boolean features")
    for row in records:
        if row.get("label_binary") not in (0, 1):
            raise ValueError("Calibration labels must be binary")


def gate_tree(tree, feature, active):
    n = len(tree["is_leaf"])
    # The original tree occupies [1,n]; a zero leaf follows. Missing proof
    # takes the original base route, never the scoped calibration route.
    out = {key: [0] + list(tree[key]) + [0] for key in ARRAYS}
    for i in range(n):
        if not tree["is_leaf"][i]:
            out["left"][i + 1] = tree["left"][i] + 1
            out["right"][i + 1] = tree["right"][i] + 1
    out["feature_idx"][0] = feature
    out["threshold"][0] = .5
    out["left"][0], out["right"][0] = (n + 1, 1) if active else (1, n + 1)
    out["missing_left"][0] = 1
    out["feature_idx"][-1] = -1
    out["is_leaf"][-1] = 1
    return out


def constant_tree(value):
    return dict(feature_idx=[-1], threshold=[0.], left=[0], right=[0],
                value=[value], missing_left=[0], is_leaf=[1])


def compose(base, calibration, names):
    if names[-2:] != ["ctx_parser_literal_sensitive_v1", "ctx_ui_namespace_v1"] or names[:-2] != base["feature_names"]:
        raise ValueError("The base feature layout must be preserved exactly")
    if calibration["feature_names"] != names:
        raise ValueError("Calibration feature layout differs")
    proof = len(names) - 2
    trees = [gate_tree(tree, proof, False) for tree in base["trees"]]
    trees.append(gate_tree(constant_tree(calibration["baseline"] - base["baseline"]), proof, True))
    trees.extend(gate_tree(tree, proof, True) for tree in calibration["trees"])
    return dict(baseline=base["baseline"], feature_names=names, trees=trees,
                canonical_context=dict(version=1, proof_feature=proof,
                                       policy="base forest is unchanged outside parser-sensitive literal context"))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--corpus", type=Path, required=True)
    p.add_argument("--features", type=Path, required=True)
    p.add_argument("--extractor", type=Path, required=True)
    p.add_argument("--base-model", type=Path, required=True)
    p.add_argument("--reference-golden", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    a = p.parse_args()
    a.out.mkdir(parents=True, exist_ok=False)
    names = json.loads(subprocess.check_output([str(a.extractor), "--names"]))
    records = [json.loads(s) for s in a.corpus.open()]
    x = np.asarray([json.loads(s) for s in a.features.open()], dtype=float)
    validate_inputs(records, x, names)
    y = np.asarray([r["label_binary"] for r in records])
    all_split = partition(records, 13)
    split = {bucket: ids[x[ids, -2] == 1] for bucket, ids in all_split.items()}
    for bucket in split.values():
        if set(y[bucket]) != {0, 1}:
            raise ValueError("Each partition must contain positive and negative candidates")
    models, validation = {}, {}
    for leaves in (31, 63, 127):
        print("Training scoped calibration:", leaves, flush=True)
        clf = HistGradientBoostingClassifier(max_iter=400, learning_rate=.08,
                l2_regularization=1., max_leaf_nodes=leaves, early_stopping=True,
                validation_fraction=.1, random_state=13, class_weight="balanced")
        clf.fit(x[split["train"]], y[split["train"]])
        models[leaves] = clf
        validation[leaves] = metrics(y[split["val"]], clf.predict_proba(x[split["val"]])[:, 1])
    chosen = select_candidate(validation)
    clf = models[chosen]
    results = {b: metrics(y[ids], clf.predict_proba(x[ids])[:, 1]) for b, ids in split.items() if b != "train"}
    qualified = all(results[b][m] >= .995 for b in ("val", "test") for m in ("pr_auc", "precision", "recall", "f1"))
    report = dict(status="candidate, not release-qualified", seed=13, threshold=.3,
                  corpus_sha256=hashlib.sha256(a.corpus.read_bytes()).hexdigest(),
                  features_sha256=hashlib.sha256(a.features.read_bytes()).hexdigest(),
                  base_model_sha256=hashlib.sha256(a.base_model.read_bytes()).hexdigest(),
                  n=len(records), calibration_rows=int((x[:, -2] == 1).sum()), out_of_scope_rows=int((x[:, -2] == 0).sum()), split={k:len(v) for k,v in split.items()},
                  selected_max_leaf_nodes=chosen, validation_candidates=validation,
                  metrics=results, calibration_gate=qualified, minimum_metric=.995)
    (a.out / "qualification.json").write_text(json.dumps(report, indent=2)+"\n")
    if not qualified:
        raise SystemExit("Scoped calibration failed its quality gate")
    base = json.loads(a.base_model.read_text())
    calibration = export_model(clf, names)
    candidate = compose(base, calibration, names)
    encoded = (json.dumps(candidate, separators=(",", ":"))+"\n").encode()
    (a.out / "model_binary_go.json").write_bytes(encoded)
    reference = dict(base, feature_names=names)
    (a.out / "base_reference_not_candidate.json").write_text(json.dumps(reference, separators=(",", ":"))+"\n")
    golden = json.loads(a.reference_golden.read_text())
    for row in golden:
        if len(row["features"]) != len(base["feature_names"]):
            raise ValueError("Reference prediction fixture does not match the base model")
        row["features"].extend([0., 0.])
    rng = np.random.default_rng(13)
    for bucket in ("val", "test"):
        ids = rng.choice(split[bucket], min(256,len(split[bucket])), replace=False)
        probs = clf.predict_proba(x[ids])[:,1]
        golden.extend(dict(features=x[i].tolist(),l2_prob=float(prob)) for i,prob in zip(ids,probs))
    (a.out / "prediction_golden.json").write_text(json.dumps(golden)+"\n")
    report["model_sha256"] = hashlib.sha256(encoded).hexdigest()
    (a.out / "qualification.json").write_text(json.dumps(report, indent=2)+"\n")
    print(json.dumps(report),flush=True)


if __name__ == "__main__":
    main()
