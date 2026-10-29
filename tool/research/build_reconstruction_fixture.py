"""Generate trusted synthetic expressions and record their Node.js reference values."""
import argparse
import base64
import json
import random
import subprocess
import urllib.parse
from pathlib import Path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--suite", choices=["default", "templates"], default="default")
    args = ap.parse_args()
    rng = random.Random(1400)
    cases = []
    for i in range(256):
        value = ["AKIA", "Пароль", "🔑", "sk_live_"][i % 4] + "".join(rng.choices("abcdefABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=24))
        literal = json.dumps(value, ensure_ascii=True)
        prefix, tail = value[:4], value[4:]
        encoded = base64.b64encode(value.encode()).decode()
        expressions = [
            literal,
            f"{json.dumps(prefix)}+{json.dumps(tail)}",
            f"[{json.dumps(prefix)},{json.dumps(tail)}].join('')",
            f"atob({json.dumps(encoded.rstrip('='))})",
            f"atob({json.dumps(' '.join(encoded[j:j+4] for j in range(0, len(encoded), 4)))})",
            f"decodeURIComponent({json.dumps(urllib.parse.quote(value, safe=''))})",
            "`" + value + "`",
            "`" + "${prefix}" + tail + "`",
        ]
        code = f"const prefix={json.dumps(prefix)};const key={expressions[i % 8]};key;"
        cases.append({"code": code})
    for expression in [r"'\x41KIA\u004eAFGYOEYPXU1DSYP'", r"'\u{1f511}unicode-secret'", r"'\uD83D\uDD11unicode-secret'", "'AKIA\\\nNAFGYOEYPXU1DSYP'", "atob('w6lzeW50aGV0aWM=')"]:
        cases.append({"code": f"const key={expression};key;"})
    if args.suite == "templates":
        cases = []
        for prefix in [r"\x24{prefix}", r"\u0024{prefix}", r"$\u007bprefix}", r"\${prefix}", r"${prefix}", r"\\${prefix}"]:
            for tail in [r"NAFGYOEYPXU1DSYP", r"\x4eAFGYOEYPXU1DSYP", r"\u004eAFGYOEYPXU1DSYP"]:
                cases.append({"code": "const prefix='AKIA';const key=`" + prefix + tail + "`;key;"})
    # These programs are generated above, never imported from scanned repositories.
    reference = """const fs=require('fs'), vm=require('vm');
const cases=JSON.parse(fs.readFileSync(0,'utf8'));
for (const row of cases) row.value=vm.runInNewContext(row.code,{atob,decodeURIComponent},{timeout:50});
process.stdout.write(JSON.stringify(cases));"""
    result = subprocess.run(["node", "-e", reference], input=json.dumps(cases), capture_output=True, text=True, check=True, timeout=60)
    output = {"seed": 1400, "reference": subprocess.check_output(["node", "--version"], text=True).strip(), "rows": json.loads(result.stdout)}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as destination:
        json.dump(output, destination, ensure_ascii=False, indent=2)
        destination.write("\n")


if __name__ == "__main__":
    main()
