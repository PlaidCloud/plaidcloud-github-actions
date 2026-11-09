#!/usr/bin/env bash
# Copies the canonical clean-room-review workflow (this repo's main) to every
# PlaidCloud repo whose default branch still holds the previous gate, one draft
# PR each. Repos with any other copy are listed, not touched. Marking ready,
# recording the review and merging stay separate commands (printed at the end).
# Usage: clean-room-review/rollout.sh [repo ...]     DRY_RUN=1 to only survey.
set -euo pipefail
ORG=PlaidCloud
F=.github/workflows/clean-room-review.yaml
OLD=c4b002e0c6a3260fd4d67be821691cbd2b967323
BR=sc-36322-clean-room-gate-stale-reviews
read -r NEW B64 < <(gh api "repos/$ORG/plaidcloud-github-actions/contents/$F?ref=main" --jq '"\(.sha) \(.content | gsub("\n"; ""))"')
[ "$NEW" != "$OLD" ] || { echo "Canonical copy on main is still the old gate; merge the fix first."; exit 1; }
TITLE="ci: clean-room-review counts only current-head, latest, write-access verdicts (sc-36322)"
MSG="$TITLE

Byte-identical copy of $ORG/plaidcloud-github-actions:$F (blob $OLD -> $NEW).

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
BODY="Rolls out the fixed clean-room-review merge gate (sc-36322): blob \`${OLD:0:8}\` → \`${NEW:0:8}\`, byte-identical to $ORG/plaidcloud-github-actions main, where its regression tests live. Workflow file only.

🤖 Generated with [Claude Code](https://claude.com/claude-code)"

if [ $# -gt 0 ]; then repos=$(printf '%s\n' "$@")
else repos=$(gh api --paginate "orgs/$ORG/repos" --jq '.[] | select(.archived | not) | .name' | grep -vx plaidcloud-github-actions); fi

prs=(); exists=()
trap 'rm -f ref-err.txt' EXIT
for r in $repos; do
  def=$(gh api "repos/$ORG/$r" --jq .default_branch) || { echo "ERROR    $r (rerun with: rollout.sh $r)"; continue; }
  cur=$(gh api "repos/$ORG/$r/contents/$F?ref=$def" --jq .sha 2>/dev/null) || cur=none
  case $cur in
    "$NEW") echo "done     $r"; continue ;;
    "$OLD") ;;
    *) echo "SKIP     $r ($def holds $cur, not the old gate)"; continue ;;
  esac
  if [ -n "${DRY_RUN:-}" ]; then echo "would-PR $r ($def)"; continue; fi
  base=$(gh api "repos/$ORG/$r/git/ref/heads/$def" --jq .object.sha)
  if ! gh api "repos/$ORG/$r/git/refs" -f ref="refs/heads/$BR" -f sha="$base" > /dev/null 2> ref-err.txt; then
    if grep -q '(HTTP 422)' ref-err.txt; then echo "EXISTS   $r (branch $BR already there)"; exists+=("$r"); continue; fi
    echo "ERROR    $r: $(cat ref-err.txt)"; continue
  fi
  gh api -X PUT "repos/$ORG/$r/contents/$F" -f branch="$BR" -f sha="$OLD" -f message="$MSG" -f content="$B64" > /dev/null
  url=$(gh pr create --draft -R "$ORG/$r" --base "$def" --head "$BR" --title "$TITLE" --body "$BODY")
  echo "PR       $url"; prs+=("$url")
done

[ ${#exists[@]} -eq 0 ] || { echo; echo "Branch exists, check manually: ${exists[*]}"; }
[ ${#prs[@]} -eq 0 ] || { echo; echo "Next, per PR (run each as its own command, never batched):"
  echo "  1. mark it ready (gh pr ready <url>) so its required checks run;"
  echo "  2. once they are SUCCESS, record a clean-room review pinned to the head commit; the gate stays red until one exists:"
  echo "     gh api repos/$ORG/<repo>/pulls/<n>/reviews -f event=COMMENT -f commit_id=<head sha> -f body='✅ Clean-room review (canonical) — **APPROVE** ...'"
  echo "  3. clean-room-review green -> gh pr merge <url> --squash"
  printf '  %s\n' "${prs[@]}"; }
