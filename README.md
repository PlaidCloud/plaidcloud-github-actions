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
| `package` | `.` | What to install and scan. Ignored when `requirements` is set. |
| `requirements` | `''` | Install a requirements file instead of `package`, for a repo that ships an image and has nothing pip-installable of its own. |
| `extras` | `''` | Comma-separated, e.g. `full,tracing`. Empty installs base dependencies. |
| `policy` | `''` | Repo-local policy file, applied **in addition to** `license-policy.txt`, not instead of it. |
| `python-version` | `3.12` | |
| `uv-version` | `0.11.10` | |
| `trivy-version` | `v0.70.0` | An exact release whose checksums are committed here; `latest` is refused. Pinned deliberately — see below. |
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

### How Trivy is installed

The action fetches Trivy from its release assets itself rather than through
`aquasecurity/setup-trivy`.

That action shells out to Trivy's `contrib/install.sh`, which turns a tag into a
download by making one unauthenticated, un-retried request to `github.com` and
treating any non-200 as *"unable to find `<tag>`"*. A rate-limited moment
therefore arrives looking like a deleted release. It is not hypothetical: one
job installed `v0.70.0` successfully twice and lost the third attempt forty
seconds later, and the error named the pin rather than the network.

An asset URL needs no tag lookup at all, so the install is:

- **Downloaded directly**, with `curl --retry 5 --retry-all-errors`, so a 429 or
  a 5xx is retried rather than fatal.
- **Verified against `license-check/trivy-checksums.txt`**, which is the release's
  own checksums file, committed here.
- **Cached** as the *tarball*, under `trivy-tarball-<version>-<os>-<arch>`.
- **Installed once per job.** The version names the install directory, so a repo
  scanning several requirements files calls the action several times and still
  installs Trivy once.

The verification runs on every path — a fresh download and a cache hit alike —
because a cache entry is written by anyone who can run a workflow on the repo. A
Trivy trusted on sight is a scanner someone else chose, and one that fabricated a
clean report would satisfy the completeness check too, by reading the very same
`.dist-info` the check counts. That is why the tarball is what gets cached: it is
the thing the committed checksums can vouch for.

The checksums are committed rather than fetched for the same reason. Pulled from
the network beside the tarball they would vouch for transit only; read from the
cache they would be chosen by whoever wrote the cache.

`trivy-version` must therefore name an exact release **whose checksums are
committed here**. Changing it means committing that release's `checksums.txt`
alongside it — the gate pins its scanner by hash, not only by tag, and a version
it cannot vouch for fails loudly rather than quietly. `latest` is refused.

Two things `aquasecurity/setup-trivy` did that this does not: it accepted
`github-server-url` and `token` inputs for GHES or a private mirror, and it staged
Trivy's `contrib/*.tpl` report templates next to the binary. This action only ever
asks for `--format json`, so nothing here wanted either, but a repo running its own
`trivy` off the `PATH` this action sets will no longer find those templates.

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

### Per-package waivers

A line of the form `package: license[, license…]` forgives one package a
license the organisation otherwise refuses. It replaces liccheck's
`[Authorized Packages]`, and unlike that section it names **what** it forgives:

```
# PyInstaller is GPLv2-or-later with the bootloader exception, which permits
# distributing non-free programs built with it. That exception is prose — PyPI
# declares the bare GPLv2 classifier and no License-Expression, so no scanner
# reading metadata can see it. Permanent, not a migration convenience.
pyinstaller: GPL-2.0-or-later, GPL-2.0-only, GNU General Public License v2 (GPLv2)
```

Put repo-specific waivers in a repo-local file and pass it as `policy:`. Naming
the license matters: if the package relicenses, the waiver stops covering it and
the build fails, where a bare package name would keep waving it through.

**Waivers that match no scanned package are reported** on every run. An
exemption list rots silently otherwise — liccheck's accumulated 22 entries
across the org, most of them for packages whose licenses Trivy now reads
without help.

### Assertions

A waiver forgives a license the scanner *read*. When the scanner cannot read one
at all, assert what it is with `=`:

```
# Declares no license of any kind. Google's, Apache-2.0 upstream.
google-crc32c = Apache-2.0
# Puts its whole license text in the `license` field, so Trivy passes it
# through as `text://MIT License Copyright (c) 2022 OpenAI…`.
tiktoken = MIT
```

The asserted license replaces what was scanned and is then **checked like any
other**, so nobody can assert their way to something the policy refuses.

It applies **only** where the scanner produced nothing usable: no license, a
`text://` blob, or a literal `UNKNOWN`. Asserting over a license Trivy read
correctly is an error, not an override — that is how a GPL package would get
laundered into MIT, and it is what a waiver is for. This is the capability
liccheck's `[Authorized Packages]` provided, except that it names the license
rather than just the package, so it can be reviewed and can go stale loudly.

### Versioning

- **`@v1`** — moving, and what consumers should normally pin. A policy change
  reaches every repository on the next run, which is the entire point of
  putting the policy in one place; pinning exact versions everywhere would mean
  ten pull requests to disallow one license.
- **`@v1.0.0`** — frozen. Use it to hold a repository back deliberately, and
  say why in the workflow.

`v1` is moved only for a change we intend to propagate, and only from a green
`main`. A change to an input's name or meaning is a `v2`, not a `v1` move — the
gate failing everywhere at once is acceptable, a gate silently doing nothing
everywhere at once is not.
