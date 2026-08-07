# plaidcloud-github-actions

Shared GitHub Actions for PlaidCloud repositories.

## `license-check`

Fails a build on a Python dependency whose license the organisation has not
approved. Replaces `liccheck`, which imports `pkg_resources` — removed in
setuptools 82 — and was last released in September 2023
([sc-24172](https://app.shortcut.com/plaidcloud/story/24172)).

```yaml
  license:
    name: Check Dependency Licenses
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: PlaidCloud/plaidcloud-github-actions/license-check@v1
        with:
          extras: full,tracing
```

### Inputs

| Input | Default | Notes |
|---|---|---|
| `package` | `.` | What to install and scan. |
| `extras` | `''` | Comma-separated, e.g. `full,tracing`. Empty installs base dependencies. |
| `policy` | `''` | Repo-local policy file, applied **in addition to** `license-policy.txt`, not instead of it. |
| `python-version` | `3.12` | |
| `uv-version` | `0.11.10` | |
| `trivy-version` | `v0.70.0` | Pinned deliberately — see below. |
| `diagnostics` | `false` | Print what each Trivy scan surface saw. Run once when onboarding a repo. |

### How it decides

Trivy is the license **extractor**; the policy is applied by
`check_licenses.py` in this repo. That split is not stylistic:

- **Trivy's license *findings* are not dependable.** On 0.73.0 the findings
  block — the surface `--exit-code` and `license.ignored` act on — came back
  empty for a 53-package venv, while `Results[].Packages[].Licenses` resolved
  every package on every version and platform tried. A findings-based gate
  would have kept passing, green, enforcing nothing, after a routine action
  bump. `trivy-version` is pinned for the same reason.
- **`trivy rootfs`, never `trivy fs`.** On the same venv, `fs` returns no
  result blocks at all.
- **Completeness is checked, not just violations.** A scanner that cannot read
  the venv reports nothing and exits 0 — a pass for a tree it never looked at.
  Every `.dist-info` in the venv must appear in Trivy's package list, so the
  check self-calibrates as dependencies change rather than resting on a
  hardcoded floor.

### The policy file

`license-check/license-policy.txt` is the organisation allow-list. There is no
deny-list: anything not named fails, as does a package declaring no license at
all. That reproduces `liccheck`'s `level: cautious`.

Entries are matched case-insensitively, and both SPDX identifiers and free-text
names are listed on purpose — Trivy normalises many packages to SPDX but passes
the declared text through verbatim when it cannot, so `Apache-2.0` and
`Apache Software License` both reach the policy. A license's whole declared
string is matched first; only an unmatched one is treated as an SPDX expression
and split on `AND`/`OR`/`WITH`. Compound expressions are evaluated
conservatively — both sides of an `OR` must be approved, so a package we could
legally take under the permitted half asks for a human rather than passing
quietly.

Changing this file changes the gate for every repository on the same tag.
Review it as policy, not as configuration.

### Versioning

Consumers pin a tag. A moving `v1` propagates a policy change everywhere at
once, which is the point of a shared gate and also its risk — prefer bumping
`v1.x` deliberately over force-moving `v1`.
