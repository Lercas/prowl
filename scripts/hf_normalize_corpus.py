"""Normalize data/processed/corpus_all.jsonl to a HF-loadable schema and write corpus.parquet +
corpus.jsonl. The raw corpus has optional `span`/`extra` keys and `extra` is a nested dict whose
sub-keys vary by row, which breaks HF's schema inference (DatasetGenerationError). Here every row
carries the same keys, `extra` becomes a JSON string, and `span` a nullable int list.

  .venv/bin/python scripts/hf_normalize_corpus.py
"""
import json
import pyarrow as pa
import pyarrow.parquet as pq

SRC = "data/processed/corpus_all.jsonl"
OUT_PARQUET = "data/processed/corpus.parquet"
OUT_JSONL = "data/processed/corpus.jsonl"

SCHEMA = pa.schema([
    ("value", pa.string()), ("text", pa.string()), ("source", pa.string()), ("origin", pa.string()),
    ("label_binary", pa.int8()), ("label_type", pa.string()),
    ("context", pa.struct([("line", pa.string()), ("name", pa.string()),
                           ("path", pa.string()), ("source", pa.string())])),
    ("span", pa.list_(pa.int64())), ("extra", pa.string()),
])
KEYS = [f.name for f in SCHEMA]


def norm(o):
    c = o.get("context") or {}
    span = o.get("span")
    extra = o.get("extra")
    return {
        "value": o.get("value", ""), "text": o.get("text", ""), "source": o.get("source", ""),
        "origin": o.get("origin", ""), "label_binary": int(o.get("label_binary", 0)),
        "label_type": o.get("label_type", ""),
        "context": {"line": c.get("line", ""), "name": c.get("name", ""),
                    "path": c.get("path", ""), "source": c.get("source", "")},
        "span": [int(x) for x in span] if isinstance(span, list) else None,
        "extra": json.dumps(extra, ensure_ascii=False) if extra is not None else "",
    }


def main():
    cols = {k: [] for k in KEYS}
    n = 0
    with open(OUT_JSONL, "w") as jf:
        for line in open(SRC):
            line = line.strip()
            if not line:
                continue
            r = norm(json.loads(line))
            for k in KEYS:
                cols[k].append(r[k])
            jf.write(json.dumps(r, ensure_ascii=False) + "\n")
            n += 1
    pq.write_table(pa.Table.from_pydict(cols, schema=SCHEMA), OUT_PARQUET, compression="zstd")
    print(f"normalized {n} rows -> {OUT_PARQUET} + {OUT_JSONL}")

    # ProwlBench: convert to parquet too, so every config on HF uses the parquet builder (a mix of
    # parquet + jsonl configs makes HF apply one builder to all and fail the jsonl one).
    bench = [json.loads(l) for l in open("benchmark/prowlbench.jsonl") if l.strip()]
    for r in bench:
        s = r.get("span")
        r["span"] = [int(x) for x in s] if isinstance(s, list) else None
    pq.write_table(pa.Table.from_pylist(bench), "benchmark/prowlbench.parquet", compression="zstd")
    print(f"prowlbench {len(bench)} rows -> benchmark/prowlbench.parquet")


if __name__ == "__main__":
    main()
