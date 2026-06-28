"""Regenerate tool/internal/mlfeatures/testdata/parity_golden.jsonl from the Python reference extractor.
The Go TestExtractorParity asserts its extractor matches these vectors. Run after changing the feature
set; never hand-author vectors.

  .venv/bin/python scripts/gen_parity_golden.py
"""
import json, random, string
from src.features.extract import extract_features, FEATURE_NAMES

OUT = "tool/internal/mlfeatures/testdata/parity_golden.jsonl"
rr = random.Random(1234)

vals = [
    "", "a", "AB", "12", "2Landroid", "6Lookahead", "SHA-256-Digest", "arm64-v8a", "EcKeyPair$1",
    "purchasepoliciesregional", "my-api-key", "com.example.App", "/inc/ajs/Avatar", "snake_case_x",
    "getUserById", "ParseHTTPBody", "Пароль123", "naive-cafe", "Omega",
    "AKIAEXAMPLE", "AIzaSyEXAMPLEnotreal", "ghp_EXAMPLEnotreal",
    "sk_live_EXAMPLEnotreal", "550e8400-e29b-41d4-a716-446655440000",
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcDEF", "xoxb-12345-67890-AbCdEf",
    "your_api_key_here", "XXXXXXXXXXXX", "${SECRET}", "changeme", "password", "AKIAIOSFODNN7EXAMPLE",
    "-----BEGIN RSA PRIVATE KEY-----", "https://user:pass@example.com/p",
    "arn:aws:iam::123456789012:role/x", "ssh-rsa AAAAB3NzaC1yc2E", "data:image/png;base64,iVBOR",
    "507f1f77bcf86cd799439011", "ALLCAPS", "alllower", "1234567890", "....", "____", "  sp  ", "t\tk", "m\nl",
    "1" * 64, "-" * 30, "a-b_c.d/e:f@g",
    # url_host_local=1 across its sub-branches (localhost / loopback / private / docker host / link-local)
    "redis://localhost:6379", "postgres://user:pass@127.0.0.1:5432/db", "http://10.0.0.1/api",
    "mongodb://192.168.1.1:27017", "amqp://host.docker.internal:5672", "redis://169.254.169.254/",
    "http://db:5432/x", "mysql://root:pw@db.local/app", "https://internal:8443/v1",
]
for n in (8, 16, 24, 32, 40, 64):
    vals.append("".join(rr.choice(string.ascii_letters + string.digits + "+/") for _ in range(n)))
    vals.append("".join(rr.choice("0123456789abcdef") for _ in range(n)))

ctxs = [
    {"name": "", "line": "", "path": "", "source": "code"},
    {"name": "key", "line": 'key = "V"', "path": "src/m.go", "source": "code"},
    {"name": "password", "line": "password: V", "path": "test/x.py", "source": "code"},
    {"name": "api_secret", "line": "// V secret", "path": "", "source": "unknown"},
    {"name": "", "line": "https://h/V", "path": "a/b.js", "source": "jira"},
    {"name": "token", "line": "V", "path": "", "source": "confluence"},
    {"name": "x", "line": "<V>", "path": "vendor/l.js", "source": "slack"},
]

with open(OUT, "w") as o:
    for i, v in enumerate(vals):
        c = dict(ctxs[i % len(ctxs)])
        c["line"] = c["line"].replace("V", v)
        f = extract_features(v, {"name": c["name"], "line": c["line"], "path": c["path"], "source": c["source"]})
        o.write(json.dumps({"value": v, "name": c["name"], "line": c["line"], "path": c["path"],
                            "source": c["source"], "feats": [float(f[n]) for n in FEATURE_NAMES]},
                           ensure_ascii=False) + "\n")
print(f"wrote {len(vals)} rows x {len(FEATURE_NAMES)} features -> {OUT}")
