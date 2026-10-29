"""Serialize synthetic fixture values without literal provider-shaped examples."""
import json
import re

_VALUE = re.compile(r'("(?:text|value)"\s*:\s*)("(?:\\.|[^"\\])*")')


def fixture_json(rows):
    raw = json.dumps(rows, ensure_ascii=False, indent=2)

    def escape_value(match):
        value = json.loads(match.group(2))
        encoded = ''.join(
            f'\\u{ord(c):04x}' if c.isascii() and c.isalnum()
            else json.dumps(c, ensure_ascii=False)[1:-1]
            for c in value
        )
        return match.group(1) + '"' + encoded + '"'

    return _VALUE.sub(escape_value, raw) + '\n'
