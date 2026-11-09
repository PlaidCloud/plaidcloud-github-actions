#!/usr/bin/env bash
# Runs the clean-room-review gate's own `run:` script against fixture review
# lists, with `gh` replaced by a shim that prints the fixture pages.
# Usage: clean-room-review/test_gate.sh [path/to/clean-room-review.yaml]
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
wf=${1:-$here/../.github/workflows/clean-room-review.yaml}
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
yq '.jobs."clean-room-review".steps[0].run' "$wf" > "$work/gate.sh"
mkdir "$work/bin"
cat > "$work/bin/gh" <<'SHIM'
#!/usr/bin/env bash
case "$*" in
  "api --paginate repos/o/r/pulls/7/reviews") jq -c '.pages[]' "$CASE" ;;
  "api repos/o/r/collaborators/"*"/permission --jq "*)
    login=${2#repos/o/r/collaborators/}; login=${login%/permission}
    jq --arg u "$login" '{permission: (.perm[$u] // "write"), user: {login: $u}}' "$CASE" | jq -r "$4" ;;
  *) echo "unexpected gh call: $*" >&2; exit 2 ;;
esac
SHIM
chmod +x "$work/bin/gh"
fail=0; n=$(jq length "$here/fixtures/cases.json")
for i in $(seq 0 $((n - 1))); do
  jq ".[$i]" "$here/fixtures/cases.json" > "$work/case.json"
  name=$(jq -r .name "$work/case.json"); expect=$(jq -r .expect "$work/case.json")
  got=pass
  (cd "$work" && CASE="$work/case.json" PATH="$work/bin:$PATH" REPO=o/r PR=7 DEFAULT=master \
     BASE=$(jq -r '.base // "master"' case.json) HEAD_SHA=$(jq -r .head case.json) \
     bash gate.sh > out.txt 2>&1) || got=fail
  if [ "$got" = "$expect" ]; then echo "ok   $name"; else echo "FAIL $name (expected $expect, got $got)"; sed 's/^/     /' "$work/out.txt"; fail=1; fi
done
exit $fail
