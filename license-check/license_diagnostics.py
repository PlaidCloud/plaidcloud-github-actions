"""Report what each Trivy scan surface actually saw. Temporary — see sc-24172.

Two observations shaped the license job, and both were made off-runner (Windows
and WSL). This prints the evidence from the real CI environment so the wiring
can be confirmed or corrected rather than inferred:

  * `trivy fs` vs `trivy rootfs` over the same venv.
  * Trivy's license *findings* (Results[].Licenses) vs its per-package licenses
    (Results[].Packages[].Licenses).

Usage: license_diagnostics.py <rootfs-json> <fs-json> <venv-dir>
"""

import json
import sys
from pathlib import Path


def summarise(label, path):
    report = json.loads(Path(path).read_text(encoding='utf-8'))
    results = report.get('Results') or []
    packages = [pkg for result in results for pkg in result.get('Packages') or []]
    findings = [lic for result in results for lic in result.get('Licenses') or []]
    licensed = [pkg for pkg in packages if pkg.get('Licenses')]

    print(f'--- {label} ({path})')
    print(f'    trivy version:        {report.get("Trivy", {}).get("Version", "?")}')
    print(f'    result blocks:        {len(results)}')
    for result in results:
        print(f'      Class={result.get("Class")} Type={result.get("Type")} '
              f'Packages={len(result.get("Packages") or [])} '
              f'Licenses={len(result.get("Licenses") or [])}')
    print(f'    packages reported:    {len(packages)}')
    print(f'    packages w/ licenses: {len(licensed)}')
    print(f'    license findings:     {len(findings)}')
    return packages, findings


def main(rootfs_json, fs_json, venv_dir):
    dist_infos = [d for sp in Path(venv_dir).glob('lib/python*/site-packages')
                  for d in sp.glob('*.dist-info')]
    print(f'venv contains {len(dist_infos)} top-level .dist-info directories\n')

    rootfs_packages, rootfs_findings = summarise('rootfs', rootfs_json)
    print()
    fs_packages, fs_findings = summarise('fs', fs_json)

    print('\n--- distinct license strings from rootfs Packages[].Licenses')
    for value in sorted({lic for pkg in rootfs_packages for lic in (pkg.get('Licenses') or [])}):
        print(f'    {value!r}')

    print('\n--- rootfs license findings (PkgName | Name | Category | Severity)')
    for finding in rootfs_findings:
        print(f'    {finding.get("PkgName")} | {finding.get("Name")} | '
              f'{finding.get("Category")} | {finding.get("Severity")}')
    if not rootfs_findings:
        print('    (none — this is the Linux behaviour the job is wired around)')

    print('\n--- packages reporting no license at all')
    for pkg in rootfs_packages:
        if not pkg.get('Licenses'):
            print(f'    {pkg.get("Name")} {pkg.get("Version", "")}')

    return 0


if __name__ == '__main__':
    sys.exit(main(*sys.argv[1:4]))
