"""Fail the build on a dependency license the organisation has not approved.

Trivy is the license extractor here, not the judge. Its license *findings* —
the surface `--exit-code` and `license.ignored` act on — went empty for a
53-package venv on Trivy 0.73.0, while `Results[].Packages[].Licenses` resolved
every one of them on every version and platform tried. The policy is therefore
applied here, where it is reviewable, testable, and cannot be disarmed by a
scanner upgrade (sc-24172).
"""

import argparse
import json
import re
import sys
from pathlib import Path

SPLIT_EXPRESSION = re.compile(r'\bAND\b|\bOR\b|\bWITH\b|[()]')
PACKAGE_NAME = re.compile(r'[A-Za-z0-9._-]+')


def load_policy(policy_files):
    """Read policy files into (allowed licenses, per-package waivers).

    A bare line is a license everything may use. A `package: license` line is a
    waiver naming both, because a waiver has to say *what* it forgives — if the
    package relicenses, the waiver stops covering it and the build fails, where
    a bare package name would keep waving it through unseen.
    """
    allowed, waivers = set(), {}
    for policy_file in policy_files:
        for line in Path(policy_file).read_text(encoding='utf-8').splitlines():
            entry = line.strip()
            if not entry or entry.startswith('#'):
                continue
            package, separator, licenses = entry.partition(':')
            # A colon alone does not make a waiver — one license name in the
            # list is `3-Clause BSD <http://...>`, whose `//` would otherwise
            # be read as a waiver for a package called `3-Clause BSD <http`,
            # silently losing the license entry as well.
            if separator and PACKAGE_NAME.fullmatch(package.strip()):
                waived = waivers.setdefault(normalise(package.strip()), set())
                waived.update(value.strip().lower() for value in licenses.split(',') if value.strip())
            else:
                allowed.add(entry.lower())
    return allowed, waivers


def scanned_packages(trivy_json):
    report = json.loads(Path(trivy_json).read_text(encoding='utf-8'))
    return [pkg for result in report.get('Results') or [] for pkg in result.get('Packages') or []]


def installed_distributions(venv_dir):
    """PEP 503-normalised names of every distribution present in the venv.

    Vendored dist-info nested inside another package is excluded: Trivy reports
    those too, but they are not what the completeness check measures.
    """
    return {normalise(dist_info.name.split('-')[0])
            for site_packages in Path(venv_dir).glob('lib/python*/site-packages')
            for dist_info in site_packages.glob('*.dist-info')}


def normalise(name):
    return re.sub(r'[-_.]+', '-', name).lower()


def disallowed_atoms(expression, allowed):
    """The parts of `expression` the policy does not allow, or an empty set.

    Trivy does not normalise everything to SPDX — it passes a package's declared
    text through verbatim when it cannot, so `CMU License (MIT-CMU)` and `Python
    Software Foundation License` arrive alongside `MPL-2.0 AND (Apache-2.0 OR
    MIT)`. The whole string is matched against the policy first; only an
    unmatched one is treated as an SPDX expression and split. Splitting first
    would shred a free-text name on its own parentheses.

    A split expression is evaluated conservatively: every atom must be approved,
    including both sides of an OR. That can fail a package we could legally take
    under the permitted half of a dual license, which is the right way for a
    compliance gate to be wrong — it asks for a human instead of choosing.
    """
    if expression.strip().lower() in allowed:
        return set()
    atoms = {atom.strip() for atom in SPLIT_EXPRESSION.split(expression)}
    return {atom for atom in atoms if atom and atom.lower() not in allowed}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scan', required=True, help='Trivy JSON report')
    parser.add_argument('--venv', required=True, help='the venv the report was taken from')
    parser.add_argument('--policy', required=True, action='append',
                        help='policy file; repeatable, entries are unioned')
    args = parser.parse_args()

    allowed, waivers = load_policy(args.policy)
    packages = scanned_packages(args.scan)
    print(f'Policy allows {len(allowed)} license spellings and {len(waivers)} package waiver(s) '
          f'from {len(args.policy)} file(s). Trivy reported {len(packages)} packages.')

    # A scanner that cannot read the venv reports nothing and exits 0, so a gate
    # with no completeness check passes a tree it never looked at. Trivy also
    # read a *subset* on one version, which a bare "more than zero" floor would
    # not catch.
    missed = installed_distributions(args.venv) - {normalise(pkg['Name']) for pkg in packages}
    if missed:
        print(f'\nERROR: {len(missed)} installed distributions were not scanned:')
        for name in sorted(missed):
            print(f'  {name}')
        return 1

    violations, unlicensed, applied = [], [], []
    for pkg in packages:
        licenses = pkg.get('Licenses') or []
        if not licenses:
            # A waiver names a license, so it cannot cover a package that
            # declares none. That is deliberate: an undeclared license is a
            # question for a human, not something to wave through by name.
            unlicensed.append(pkg)
            continue
        waived = waivers.get(normalise(pkg['Name']), set())
        for expression in licenses:
            bad = disallowed_atoms(expression, allowed | waived)
            if bad:
                violations.append((pkg['Name'], pkg.get('Version', ''), expression, sorted(bad)))
            elif waived and disallowed_atoms(expression, allowed):
                applied.append((pkg['Name'], pkg.get('Version', ''), expression))

    for name, version, expression in applied:
        print(f'  waived: {name} {version} is {expression}')

    # Stale waivers are how an exemption list rots into a list of things nobody
    # remembers approving — liccheck.ini accumulated 22 of them across the org.
    unused = sorted(set(waivers) - {normalise(pkg['Name']) for pkg in packages})
    if unused:
        print(f'  notice: {len(unused)} waiver(s) matched no scanned package: {", ".join(unused)}')

    for pkg in unlicensed:
        print(f'\nERROR: {pkg["Name"]} {pkg.get("Version", "")} declares no license.')
    for name, version, expression, bad in violations:
        print(f'\nERROR: {name} {version} is {expression} — not approved: {", ".join(bad)}')

    if violations or unlicensed:
        print(f'\n{len(violations) + len(unlicensed)} package(s) failed the license policy.')
        return 1

    print('All dependency licenses are approved.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
