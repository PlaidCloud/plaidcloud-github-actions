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

SPLIT_EXPRESSION = re.compile(r'\bAND\b|\bOR\b|\bWITH\b')
GROUPING = re.compile(r'[()]')
PACKAGE_NAME = re.compile(r'[A-Za-z0-9._-]+')
BLANK_LICENSE = '<blank>'


def load_policy(policy_files):
    """Read policy files into (allowed licenses, waivers, assertions).

    Three kinds of line:

    - A bare license name, which everything may use.
    - `package: license` — a waiver, naming both, because a waiver has to say
      *what* it forgives. If the package relicenses the waiver stops covering
      it and the build fails, where a bare package name would keep waving it
      through unseen.
    - `package = license` — an assertion, for a package whose license the
      scanner cannot read at all: one that declares nothing, or that puts its
      whole license *text* where an identifier belongs. The asserted license
      replaces what was scanned and is then checked like any other, so nobody
      can assert their way to something the policy refuses.

    Only the first separator counts, so a license name containing one stays
    part of the value. Both forms require the left side to look like a package
    name: one license in the list is `3-Clause BSD <http://...>`, whose `//`
    would otherwise be read as a waiver for a package called
    `3-Clause BSD <http`, silently losing the license entry as well.
    """
    allowed, waivers, assertions = set(), {}, {}
    for policy_file in policy_files:
        for line in Path(policy_file).read_text(encoding='utf-8').splitlines():
            entry = line.strip()
            if not entry or entry.startswith('#'):
                continue
            package, separator, value = entry.partition('=')
            if separator and PACKAGE_NAME.fullmatch(package.strip()):
                assertions[normalise(package.strip())] = value.strip()
                continue
            package, separator, licenses = entry.partition(':')
            if separator and PACKAGE_NAME.fullmatch(package.strip()):
                waived = waivers.setdefault(normalise(package.strip()), set())
                waived.update(value.strip().lower() for value in licenses.split(',') if value.strip())
            else:
                allowed.add(entry.lower())
    return allowed, waivers, assertions


def scanned_packages(trivy_json):
    report = json.loads(Path(trivy_json).read_text(encoding='utf-8'))
    return [pkg for result in report.get('Results') or [] for pkg in result.get('Packages') or []]


def installed_distributions(venv_dir):
    """PEP 503-normalised names of every distribution present in the venv.

    Vendored dist-info nested inside another package is excluded: Trivy reports
    those too, but they are not what the completeness check measures.

    Only `.dist-info` is counted. `.egg-info` layouts come from legacy
    `setup.py develop` installs, which the action never performs — it always
    does a non-editable `uv pip install`, and uv installs from a wheel, which
    always yields `.dist-info`. A caller that installs some other way would
    weaken this check rather than break it.
    """
    return {normalise(dist_info.name.split('-')[0])
            for site_packages in Path(venv_dir).glob('lib/python*/site-packages')
            for dist_info in site_packages.glob('*.dist-info')}


def normalise(name):
    return re.sub(r'[-_.]+', '-', name).lower()


def is_unreadable(licenses):
    """Did the scanner fail to produce a license identifier for this package?

    Three shapes, all seen in real Trivy output: nothing at all (the package
    declares no license), a `text://` blob (its declaration is the whole license
    *text*, which Trivy passes through rather than naming), and a literal
    `UNKNOWN`. An assertion may only stand in for one of these — overriding a
    license the scanner read correctly is what a waiver is for, and is visible
    as one.
    """
    values = [value.strip() for value in licenses if value.strip()]
    return not values or all(
        value.startswith('text://') or value.upper() == 'UNKNOWN' for value in values)


def abbreviate(value, limit=90):
    """Keep a failure readable.

    When Trivy cannot name a license it falls back to the whole license text
    under a `text://` prefix — thousands of characters that split into dozens of
    prose fragments. Reporting those verbatim buries the packages that actually
    need attention.
    """
    collapsed = ' '.join(value.split())
    return collapsed if len(collapsed) <= limit else collapsed[:limit] + '…'


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

    Parentheses are removed before splitting, not treated as separators, so an
    empty atom afterwards means a genuinely missing operand rather than an
    artefact of adjacent delimiters. Such an atom is refused: `''` and a
    truncated `'MIT AND '` would otherwise answer "nothing disallowed" — the
    first for a package that declared nothing, the second on the strength of the
    half that survived.
    """
    if expression.strip().lower() in allowed:
        return set()
    atoms = {atom.strip() for atom in SPLIT_EXPRESSION.split(GROUPING.sub(' ', expression))}
    return {atom or BLANK_LICENSE for atom in atoms if atom.lower() not in allowed}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scan', required=True, help='Trivy JSON report')
    parser.add_argument('--venv', required=True, help='the venv the report was taken from')
    parser.add_argument('--policy', required=True, action='append',
                        help='policy file; repeatable, entries are unioned')
    args = parser.parse_args()

    allowed, waivers, assertions = load_policy(args.policy)
    packages = scanned_packages(args.scan)
    print(f'Policy allows {len(allowed)} license spellings, {len(waivers)} waiver(s) and '
          f'{len(assertions)} assertion(s) from {len(args.policy)} file(s). '
          f'Trivy reported {len(packages)} packages.')

    # A scanner that cannot read the venv reports nothing and exits 0, so a gate
    # with no completeness check passes a tree it never looked at. Trivy also
    # read a *subset* on one version, which a bare "more than zero" floor would
    # not catch.
    #
    # Both sides are required to be non-empty first. Comparing two empty sets
    # yields "nothing missed" and reports success having verified nothing, so
    # a scan pointed at the wrong tree, or a venv path that does not exist,
    # would pass — the precise failure this check exists to prevent. Every venv
    # this runs against installs at least one distribution.
    installed = installed_distributions(args.venv)
    if not packages or not installed:
        print(f'\nERROR: nothing to check — the scan reported {len(packages)} packages and '
              f'{args.venv} contains {len(installed)} installed distributions. '
              f'Expected both to be non-empty; check that --scan and --venv name the same tree.')
        return 1

    missed = installed - {normalise(pkg.get('Name', '')) for pkg in packages}
    if missed:
        print(f'\nERROR: {len(missed)} installed distributions were not scanned:')
        for name in sorted(missed):
            print(f'  {name}')
        return 1

    violations, unlicensed, applied = [], [], []
    for pkg in packages:
        name = pkg.get('Name', '<unnamed>')
        # Coerced to str because a null in the JSON list is a malformed report,
        # not a license, and must read as undeclared rather than crash.
        licenses = [str(value) for value in (pkg.get('Licenses') or []) if value is not None]
        asserted = assertions.get(normalise(name))
        if asserted:
            if is_unreadable(licenses):
                licenses = [asserted]
                applied.append((name, pkg.get('Version', ''), f'asserted {asserted}'))
            else:
                violations.append((name, pkg.get('Version', ''), '; '.join(licenses),
                                   [f'asserted {asserted}, but the scanner read this package '
                                    f'— drop the assertion, or waive the license it reports']))
                continue
        if not any(value.strip() for value in licenses):
            # A waiver names a license it forgives, so it cannot cover a package
            # that declares none — there is nothing to name. Assert the license
            # instead, which says what we believe it to be and is checked.
            unlicensed.append(pkg)
            continue
        waived = waivers.get(normalise(name), set())
        for expression in licenses:
            bad = disallowed_atoms(expression, allowed | waived)
            if bad:
                violations.append((name, pkg.get('Version', ''), expression, sorted(bad)))
            elif waived and disallowed_atoms(expression, allowed):
                applied.append((name, pkg.get('Version', ''), f'waived {expression}'))

    for name, version, note in applied:
        print(f'  {note}: {name} {version}')

    # Stale entries are how an exemption list rots into a list of things nobody
    # remembers approving — liccheck.ini accumulated 22 of them across the org.
    scanned = {normalise(pkg.get('Name', '')) for pkg in packages}
    unused = sorted((set(waivers) | set(assertions)) - scanned)
    if unused:
        print(f'  notice: {len(unused)} waiver(s)/assertion(s) matched no scanned '
              f'package: {", ".join(unused)}')

    for pkg in unlicensed:
        print(f'\nERROR: {pkg.get("Name", "<unnamed>")} {pkg.get("Version", "")} declares no license.')
    for name, version, expression, bad in violations:
        print(f'\nERROR: {name} {version} is {abbreviate(expression)} — '
              f'not approved: {", ".join(abbreviate(atom) for atom in bad)}')

    if violations or unlicensed:
        print(f'\n{len(violations) + len(unlicensed)} package(s) failed the license policy.')
        return 1

    print('All dependency licenses are approved.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
