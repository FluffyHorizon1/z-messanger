#!/usr/bin/env bash
#
# One command that reproduces every claim in docs/AUDIT_SCOPE.md.
#
# An external reviewer's first hour should not be spent discovering that this
# project needs four toolchains, that two of the verifiers are Python packages
# nobody mentioned pinning, and that a green "147 tests passed" says nothing
# about which of the thirty claims it just backed. This script runs everything
# and reports the result the way the brief is organised — by claim.
#
#   tool/audit_verify.sh              everything (~6 minutes)
#   tool/audit_verify.sh --quick      skip the app suite (~1 minute)
#   tool/audit_verify.sh --list       what would run, and what each backs
#
# Exit code is 0 only if every suite passed. Anything else means at least one
# claim in the brief is currently unsupported by this working tree, which is a
# finding regardless of whose fault it is.

set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
ROOT="$PWD"

QUICK=0
LIST=0
for a in "$@"; do
  case "$a" in
    --quick) QUICK=1 ;;
    --list)  LIST=1 ;;
    -h|--help) sed -n '2,20p' "$0" | sed 's/^# \?//'; exit 0 ;;
    *) echo "unknown option: $a (try --help)" >&2; exit 2 ;;
  esac
done

bold=$(tput bold 2>/dev/null || true); dim=$(tput dim 2>/dev/null || true)
red=$(tput setaf 1 2>/dev/null || true); grn=$(tput setaf 2 2>/dev/null || true)
ylw=$(tput setaf 3 2>/dev/null || true); rst=$(tput sgr0 2>/dev/null || true)

LOGDIR=$(mktemp -d)
declare -a NAMES STATUS SECS BACKS
FAILED=0
SKIPPED=0

# Which claims a suite backs, asked of the brief rather than hardcoded here.
claims_for() {
  local pattern="$1"
  python3 tool/check_audit_scope.py --map 2>/dev/null \
    | awk -F'\t' -v p="$pattern" '$1 ~ p { printf "%s,", $2 }' \
    | tr ',' '\n' | grep -E '^C[0-9]+$' | sort -u -V | paste -sd' ' -
}

have() { command -v "$1" >/dev/null 2>&1; }

run() {
  local name="$1" backs="$2" dir="$3"; shift 3
  local log="$LOGDIR/$(echo "$name" | tr ' /' '__').log"
  printf '%s' "  ${name} ... "
  local t0=$SECONDS
  if ( cd "$ROOT/$dir" && "$@" ) >"$log" 2>&1; then
    local st="pass"; printf '%s\n' "${grn}pass${rst} ${dim}($(( SECONDS - t0 ))s)${rst}"
  else
    local st="FAIL"; FAILED=1
    printf '%s\n' "${red}FAIL${rst} ${dim}($(( SECONDS - t0 ))s — ${log})${rst}"
    tail -15 "$log" | sed 's/^/      /'
  fi
  NAMES+=("$name"); STATUS+=("$st"); SECS+=("$(( SECONDS - t0 ))"); BACKS+=("$backs")
}

skip() {
  local name="$1" backs="$2" why="$3"
  printf '  %s ... %sskipped%s %s(%s)%s\n' "$name" "$ylw" "$rst" "$dim" "$why" "$rst"
  NAMES+=("$name"); STATUS+=("skip"); SECS+=("0"); BACKS+=("$backs")
  SKIPPED=1
}


echo
echo "${bold}Z — reproducing the claims in docs/AUDIT_SCOPE.md${rst}"
echo "${dim}commit $(git rev-parse --short HEAD 2>/dev/null || echo '?')  ·  $(date -u '+%Y-%m-%d %H:%MZ')${rst}"
echo

if [ "$LIST" = 1 ]; then
  printf '%s\n' "${bold}suite → claims${rst}"
  python3 tool/check_audit_scope.py --map | while IFS=$'\t' read -r s c; do
    printf '  %-42s %s\n' "$s" "$c"
  done
  exit 0
fi

echo "${bold}0. The brief itself, and the tools${rst}"
run "audit brief describes this repository" "all" "." \
    python3 tool/check_audit_scope.py
run "reproducibility tool's own tests" "C25" "." \
    python3 tool/test_verify_reproducible.py
run "CI jobs check out what they use" "C25 C26" "." \
    python3 tool/check_workflow.py

echo
echo "${bold}1. Protocol library — every cryptographic construction${rst}"
if have dart; then
  run "protocol/ dart test" "$(claims_for '^protocol/test/')" "protocol" \
      dart test --reporter=compact
else
  skip "protocol/ dart test" "C2 C4 C5 C7 C8 C12 C15 C16 C17 C21 C23" "dart not on PATH"
fi

echo
echo "${bold}2. Relay — including the clean-room vector replay${rst}"
if have node && have npm; then
  [ -d server/node_modules ] || ( cd server && npm install --silent >/dev/null 2>&1 )
  run "server/ npm test" "$(claims_for '^server/test/')" "server" npm test --silent
else
  skip "server/ npm test" "C1 C4 C12 C27" "node/npm not on PATH"
fi

echo
echo "${bold}3. Vectors re-derived by unrelated FIPS implementations${rst}"
echo "${dim}   These are the checks that do not use any of our code: if they${rst}"
echo "${dim}   agree, the post-quantum values are right for a reason other${rst}"
echo "${dim}   than that we computed them the same way twice.${rst}"
if python3 -c 'import kyber_py' 2>/dev/null; then
  run "ML-KEM-768 vs kyber-py (FIPS 203)" "C5 C6" "." python3 protocol/tool/verify_mlkem.py
else
  skip "ML-KEM-768 vs kyber-py (FIPS 203)" "C5 C6" "pip install kyber-py==1.2.0"
fi
if python3 -c 'import dilithium_py' 2>/dev/null; then
  run "ML-DSA-65 vs dilithium-py (FIPS 204)" "C15 C17 C23" "." python3 protocol/tool/verify_mldsa.py
else
  skip "ML-DSA-65 vs dilithium-py (FIPS 204)" "C15 C17 C23" "pip install dilithium-py"
fi

echo
echo "${bold}4. Application — real clients through a real relay${rst}"
if [ "$QUICK" = 1 ]; then
  skip "app/ flutter test" "C3 C9 C10 C11 C13 C14 C18 C20 C22 C24 C30" "--quick"
elif have flutter; then
  [ -f app/.dart_tool/package_config.json ] || ( cd app && flutter pub get >/dev/null 2>&1 )
  run "app/ flutter test" "$(claims_for '^app/test/')" "app" flutter test --reporter=compact
else
  skip "app/ flutter test" "C3 C9 C10 C11 C13 C14 C18 C20 C22 C24 C30" "flutter not on PATH"
fi

echo
echo "${bold}5. The vector freeze${rst}"
echo "${dim}   Regenerating must not change a byte. A diff here means the wire${rst}"
echo "${dim}   format moved, which PROTOCOL.md 14 says is a version bump.${rst}"
if have dart && have git; then
  run "vectors regenerate identically" "C12" "." bash -c \
    'cd protocol && dart run tool/gen_vectors.dart >/dev/null 2>&1 && cd .. && git diff --quiet -- docs/vectors || { git --no-pager diff --stat -- docs/vectors; exit 1; }'
else
  skip "vectors regenerate identically" "C12" "needs dart and git"
fi

echo
echo "${bold}Summary${rst}"
printf '  %-44s %-8s %6s  %s\n' "suite" "result" "time" "backs"
printf '  %s\n' "$(printf '─%.0s' $(seq 1 96))"
for i in "${!NAMES[@]}"; do
  c=""; case "${STATUS[$i]}" in pass) c=$grn ;; FAIL) c=$red ;; skip) c=$ylw ;; esac
  printf '  %-44s %s%-8s%s %5ss  %s\n' \
    "${NAMES[$i]}" "$c" "${STATUS[$i]}" "$rst" "${SECS[$i]}" "${dim}${BACKS[$i]}${rst}"
done
echo

# Which claims did nothing in this run touch? Some have no test suite at all —
# reproducibility, provenance and the published documents are evidenced by CI
# runs and by prose. Saying "all thirty claims are backed" when four of them
# were never going to be is exactly the overclaim this script exists to catch
# elsewhere, so it is spelled out instead.
ALL_CLAIMS=$(grep -oE '^\| C[0-9]+' docs/AUDIT_SCOPE.md | tr -d '| ' | sort -u -V)
RAN_CLAIMS=$(for i in "${!NAMES[@]}"; do
  [ "${STATUS[$i]}" = "pass" ] && printf '%s\n' ${BACKS[$i]}
done | grep -E '^C[0-9]+$' | sort -u -V)
# Set difference by exact line: comm would need lexical order, and C9
# sorts after C30 lexically, which silently mislabels the result.
UNCOVERED=$(printf '%s\n' "$ALL_CLAIMS" \
  | grep -vxF -f <(printf '%s\n' "$RAN_CLAIMS") | sort -V | paste -sd' ' -)

echo
if [ -n "$UNCOVERED" ]; then
  echo "${bold}Claims no suite in this run backs:${rst} ${UNCOVERED}"
  echo "${dim}  Their evidence is a CI run or a document, not a test — see the${rst}"
  echo "${dim}  evidence column in AUDIT_SCOPE.md §3. Read them; do not assume${rst}"
  echo "${dim}  a green run above says anything about them.${rst}"
  echo
fi

if [ "$FAILED" = 1 ]; then
  echo "${red}${bold}At least one suite failed.${rst} Logs in $LOGDIR"
  echo "A failure here means a claim in the brief is not supported by this"
  echo "working tree. Please report it as a finding — including if the cause"
  echo "turns out to be the test rather than the code."
  exit 1
fi
if [ "$SKIPPED" = 1 ]; then
  echo "${ylw}Everything that ran passed, but some suites were skipped.${rst}"
  echo "The claims they back are unverified in this run — see the 'backs'"
  echo "column above for which ones."
  exit 0
fi
COUNT=$(printf '%s\n' "$RAN_CLAIMS" | grep -c .)
TOTAL=$(printf '%s\n' "$ALL_CLAIMS" | grep -c .)
echo "${grn}${bold}Every suite passed.${rst} ${COUNT} of ${TOTAL} claims in AUDIT_SCOPE.md"
echo "were exercised by something that ran on this commit."
rm -rf "$LOGDIR"
