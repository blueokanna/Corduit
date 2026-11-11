"""CI-only checkout of the reviewed RecurseX sibling revision."""
import os
from pathlib import Path
import re
import subprocess
import sys

revision = os.environ.get('RECURSEX_REVISION', '')
if not re.fullmatch(r'[0-9a-fA-F]{40}', revision):
    sys.exit('RECURSEX_REVISION must be the full SHA of the reviewed and pushed resolver changes')
target = Path(__file__).resolve().parents[2] / 'RecurseX'
if target.exists():
    sys.exit(f'Refusing to overwrite existing repository: {target}')
subprocess.run(['git', 'init', str(target)], check=True)
subprocess.run(['git', '-C', str(target), 'remote', 'add', 'origin',
                'https://github.com/blueokanna/RecurseX.git'], check=True)
subprocess.run(['git', '-C', str(target), 'fetch', '--depth=1', 'origin', revision], check=True)
subprocess.run(['git', '-C', str(target), 'checkout', '--detach', 'FETCH_HEAD'], check=True)
actual = subprocess.check_output(['git', '-C', str(target), 'rev-parse', 'HEAD'], text=True).strip()
if actual != revision.lower():
    sys.exit('RecurseX checkout does not match the requested commit')
print(f'RecurseX: {actual}')
