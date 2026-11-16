"""Generate trusted Node string-order references; never execute scanned input."""
import json
from pathlib import Path
import subprocess

key = 'AKIANAFGYOEYPXU1DSYP'
texts = [key[::-1], ' '.join(key), 'left::middle::right::end', 'prefix🚀middle😀suffix']
rows = []
for text in texts:
    for split in ('', ' ', '::', '🚀'):
        for reverse in (False, True):
            for join in ('', '-', '🚀'):
                call = '.reverse()' if reverse else ''
                literal = json.dumps(text, ensure_ascii=True)
                split_arg, join_arg = json.dumps(split), json.dumps(join)
                expression = f'{literal}.split({split_arg}){call}.join({join_arg})'
                for mode in ('direct', 'parentheses', 'constants'):
                    prefix = '/*🚀*/ const key='
                    used = expression
                    if mode == 'parentheses':
                        used = '(' + expression + ')'
                    if mode == 'constants':
                        prefix = f'const data={literal};const separator={split_arg};const joiner={join_arg};const key='
                        used = f'data.split(separator){call}.join(joiner)'
                    code = prefix + used + ';'
                    rows.append({'code': code, 'start': len(prefix.encode()),
                                 'end': len((prefix + used).encode())})
node_code = r'''
const vm = require('vm');
const fs = require('fs');
const rows = JSON.parse(fs.readFileSync(0, 'utf8'));
process.stdout.write(JSON.stringify(rows.map(row => {
 const value = vm.runInNewContext(row.code + '\nkey', {}, {timeout: 50});
 return {value, well_formed: value.isWellFormed()};
})));
'''
result = subprocess.run(['node', '-e', node_code], input=json.dumps(rows),
                        text=True, capture_output=True, check=True, timeout=30)
expected = json.loads(result.stdout)
for row, answer in zip(rows, expected, strict=True):
    row.update(answer)
output = {'node_version': subprocess.check_output(['node', '--version'], text=True).strip(), 'rows': rows}
path = Path(__file__).with_name('string_order_reference.json')
with path.open('x') as stream:
    json.dump(output, stream, indent=2, ensure_ascii=True)
    stream.write('\n')
print(f'{len(rows)} trusted Node references')
