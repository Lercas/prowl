"""Generate trusted literal-only binding references; never execute scanned input."""
import json
import subprocess
from pathlib import Path

key = "13ad45b4d0a2f6ea65ecbddf6aa260f2"
expressions = [
    '"ABCDEF1234"', "'ABCDEF1234'", '`ABCDEF1234`',
    '"ABCDE" + "F1234"', '("ABCDE" + "F1234")',
    r'"\x41BCDEF1234"', r'"\u0041BCDEF1234"', r'"\u{41}BCDEF1234"',
    r'"ABCDEF\x31\x32\x33\x34"', '"ABCDE\\\nF1234"',
    '"ABC" + `DEF` + "1234"', '"ABCDEF" + "" + "1234"',
]
rows = []
for number, expression in enumerate(expressions):
    object_source = '{app_id:' + expression + ',algolia_api_key:"' + key + '"}'
    sources = [
        'const c=' + object_source + ';',
        'function f(){return ' + object_source + ';}',
        'const c=[' + object_source + '];',
        'export default ' + object_source + ';',
        'const c={nested:' + object_source + '};',
        'const app_id=' + expression + ',algolia_api_key="' + key + '";',
    ]
    for context, source in enumerate(sources):
        start = source.index(key)
        rows.append({'id': f'encoding-{number}-context-{context}', 'source': source,
                     'start': start, 'end': start + len(key),
                     'expression': '(' + object_source + ')'})
node_code = r'''
const fs = require('fs');
const vm = require('vm');
const rows = JSON.parse(fs.readFileSync(0, 'utf8'));
process.stdout.write(JSON.stringify(rows.map(row => JSON.parse(vm.runInNewContext(
  'JSON.stringify(' + row.expression + ')', {}, {timeout: 50}
)))));
'''
result = subprocess.run(['node', '-e', node_code], input=json.dumps(rows),
                        text=True, capture_output=True, check=True, timeout=15)
expected = json.loads(result.stdout)
for row, fields in zip(rows, expected, strict=True):
    del row['expression']
    row['fields'] = fields
version = subprocess.check_output(['node', '--version'], text=True).strip()
output = {'node_version': version, 'cases': rows}
path = Path(__file__).with_name('binding_reference.json')
with path.open('x') as stream:
    json.dump(output, stream, indent=2)
    stream.write('\n')
print(f'{len(rows)} trusted Node references, {version}')
