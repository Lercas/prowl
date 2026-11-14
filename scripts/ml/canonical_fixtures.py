"""Generate independent synthetic canonical-literal annotations for offline training.

This emits annotations, not hand-written ML contexts. prowl-ml-corpus must run
these documents through the real pipeline before feature extraction. Evaluation
fixtures and their exact values are deliberately absent.
"""

import argparse
import json
from pathlib import Path
import random
import string

NAMES = ["password", "db_password", "login_password", "passwd", "passphrase", "pwd", "пароль", "contraseña", "senha", "kennwort", "wachtwoord", "salasana"]
PREFIXES = ["Quartz", "Harbor", "Velvet", "Mango", "Cobalt", "Linen", "Meadow", "Copper"]
HELD_OUT = {'ЖукЖук🚀', '"Winter42"\nAutumn\\53', 'Winter<42>Autumn', 'Winter${42}Autumn', 'Winter{{42}}Autumn'}


def annotations(per_family=400, seed=718103):
    rng = random.Random(seed)
    for family in range(8):
        for index in range(per_family):
            name = NAMES[index % len(NAMES)]
            a, b = rng.sample(PREFIXES, 2)
            n, m = str(rng.randrange(100, 10000)), str(rng.randrange(100, 10000))
            if family == 0:
                syllable = rng.choice("БВГДЗКЛМНРСТФ") + "".join(rng.choice("абвгдежзиклмнопрстуфцчш") for _ in range(2))
                value = syllable * 2 + rng.choice(["🦋", "🌿", "🔷", "🪶", "🐳"])
            elif family == 1:
                value = '"' + a + n + '"\n' + b + "\\" + m
            elif family == 2:
                value = a + "<" + n + ">" + b
            elif family == 3:
                value = a + "${" + n + "}" + b
            elif family == 4:
                value = a + "{{" + n + "}}" + b
            elif family == 5:
                value = a + n + "\n" + b + m
            elif family == 6:
                value = a + n + " " + b + m
            else:
                value = a + n + "!" + "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(8))
            assert value not in HELD_OUT
            for ext, text in carriers(name, value, "settings"):
                yield dict(name=f"positive-{family}-{index}", path=f"src/config/credentials{ext}", text=text, value=value, label_binary=1, label_type="generic_password")

    # Explicit UI namespaces establish that these strings are instructions,
    # rather than weak literal passwords. Wording differs by binding so shared
    # template/value components remain useful leakage-safe partition units.
    for index in range(per_family * 8):
        group = index % len(NAMES)
        name = NAMES[group]
        count = index // len(NAMES) + 6
        value = [
            f"Password must contain at least {count} characters.",
            f"Database password length must be at least {count} characters.",
            f"Login password requires a minimum of {count} characters.",
            f"The password field accepts at most {count} characters.",
            f"Passphrase must include at least {count} printable characters.",
            f"Please enter a password containing {count} or more characters.",
            f"Длина пароля должна быть не менее {count} символов.",
            f"La contraseña debe tener al menos {count} caracteres.",
            f"A senha deve conter pelo menos {count} caracteres.",
            f"Das Kennwort muss mindestens {count} Zeichen enthalten.",
            f"Het wachtwoord moet minimaal {count} tekens bevatten.",
            f"Salasanassa on oltava vähintään {count} merkkiä.",
        ][group]
        for ext, text in carriers(name, value, "validation"):
            yield dict(name=f"negative-ui-{index}", path=f"app/translations/messages{ext}", text=text, value=value, label_binary=0, label_type="neg_canonical_ui")


def carriers(name, value, namespace):
    yield ".json", json.dumps({namespace: {name: value}}, ensure_ascii=True)
    yield ".yaml", namespace + ":\n  " + json.dumps(name, ensure_ascii=False) + ": " + json.dumps(value, ensure_ascii=False) + "\n"
    yield ".toml", "[" + namespace + "]\n" + json.dumps(name, ensure_ascii=False) + "=" + json.dumps(value, ensure_ascii=False) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--per-family", type=int, default=400)
    args = parser.parse_args()
    if args.per_family < len(NAMES):
        parser.error("--per-family must cover every binding")
    with args.out.open("x") as stream:
        for row in annotations(args.per_family):
            stream.write(json.dumps(row, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    main()
