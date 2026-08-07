"""Regression tests for the license gate. Run: python test_check_licenses.py

Every case here is a way the gate was, or could be, made to pass something it
should fail. That is the only defect class that matters for a compliance gate —
a false failure is noticed and argued about, a false pass ships GPL code and
nobody finds out. Deliberately stdlib-only so it runs anywhere the action does.
"""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).parent
SCRIPT = HERE / 'check_licenses.py'
POLICY = HERE / 'license-policy.txt'

GOOD = {'Name': 'goodpkg', 'Version': '1.0', 'Licenses': ['MIT']}


def evil(*licenses):
    return {'Name': 'evilpkg', 'Version': '1.0', 'Licenses': list(licenses)}


def main():
    tmp = Path(tempfile.mkdtemp())
    site = tmp / 'venv' / 'lib' / 'python3.12' / 'site-packages'
    site.mkdir(parents=True)
    for name in ('goodpkg-1.0.dist-info', 'evilpkg-1.0.dist-info'):
        (site / name).mkdir()

    def scan(*packages):
        path = tmp / 'scan.json'
        path.write_text(json.dumps({'Results': [{'Packages': list(packages)}]}), encoding='utf-8')
        return path

    def run(scan_path, venv=None, extra_policy=None):
        policy = ['--policy', str(POLICY)]
        if extra_policy is not None:
            path = tmp / 'extra-policy.txt'
            path.write_text(extra_policy, encoding='utf-8')
            policy += ['--policy', str(path)]
        result = subprocess.run(
            [sys.executable, str(SCRIPT), '--scan', str(scan_path),
             '--venv', str(venv or tmp / 'venv')] + policy,
            capture_output=True, text=True)
        return result.returncode, result.stdout + result.stderr

    cases = [
        # A blank license read as "nothing disallowed" and reported success.
        ('empty string license', [GOOD, evil('')], 1),
        ('whitespace-only license', [GOOD, evil('   ')], 1),
        # A truncated compound must not pass on the half that survived.
        ('truncated "MIT AND "', [GOOD, evil('MIT AND ')], 1),
        ('blank beside a good license', [GOOD, evil('MIT', '')], 1),
        # Malformed report, not a license: must read as undeclared, not crash.
        ('null in the license list', [GOOD, evil(None)], 1),
        ('genuine GPL', [GOOD, evil('GPL-3.0-only')], 1),
        ('no license declared', [GOOD, evil()], 1),
        ('GPL hidden behind WITH', [GOOD, evil('GPL-3.0-only WITH Classpath-exception')], 1),
        ('approved license', [GOOD, evil('Apache-2.0')], 0),
        ('compound, all atoms approved', [GOOD, evil('MPL-2.0 AND (Apache-2.0 OR MIT)')], 0),
        ('free-text name with parens', [GOOD, evil('CMU License (MIT-CMU)')], 0),
    ]

    failures = 0
    for label, packages, expected in cases:
        code, out = run(scan(*packages))
        failures += code != expected
        print(f'  {"PASS" if code == expected else "FAIL"}  {label:32} exit={code} want={expected}')
        if code != expected:
            print('        ' + out.strip().replace('\n', '\n        ')[:400])

    # Two empty sets compare equal, so "nothing missed" must not read as success.
    code, _ = run(scan(), venv=tmp / 'does_not_exist')
    failures += code != 1
    print(f'  {"PASS" if code == 1 else "FAIL"}  {"empty scan + absent venv":32} exit={code} want=1')

    # The completeness check must still catch a partial read.
    code, out = run(scan(GOOD))
    ok = code == 1 and 'evilpkg' in out
    failures += not ok
    print(f'  {"PASS" if ok else "FAIL"}  {"partial scan caught":32} exit={code} want=1')

    # Assertions stand in for a license the scanner could not read — but are
    # checked like any other, so nobody can assert their way past the policy.
    assertion_cases = [
        ('assertion covers no license', evil(), 'evilpkg = MIT', 0),
        ('assertion covers a text:// blob', evil('text://MIT License Copyright (c) x'),
         'evilpkg = MIT', 0),
        ('assertion covers UNKNOWN', evil('UNKNOWN'), 'evilpkg = MIT', 0),
        ('assertion of a REFUSED license fails', evil(), 'evilpkg = GPL-3.0-only', 1),
        # The scanner read this one perfectly well, so an assertion must not
        # stand in for it — that is how a GPL package gets laundered into MIT.
        ('assertion cannot override a read license', evil('GPL-3.0-only'), 'evilpkg = MIT', 1),
        ('...not even onto an approved one', evil('Apache-2.0'), 'evilpkg = MIT', 1),
    ]
    for label, package, policy, expected in assertion_cases:
        code, _ = run(scan(GOOD, package), extra_policy=policy + '\n')
        failures += code != expected
        print(f'  {"PASS" if code == expected else "FAIL"}  {label:32} exit={code} want={expected}')

    # A license name containing "://" must not parse as a per-package waiver.
    sys.path.insert(0, str(HERE))
    from check_licenses import load_policy
    allowed, waivers, assertions = load_policy([str(POLICY)])
    url_entry = '3-clause bsd <http://www.opensource.org/licenses/bsd-license.php>'
    ok = not waivers and not assertions and url_entry in allowed
    failures += not ok
    print(f'  {"PASS" if ok else "FAIL"}  {"URL entry stays a license":32} waivers={len(waivers)}')

    print(f'\n{failures} failure(s)')
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
