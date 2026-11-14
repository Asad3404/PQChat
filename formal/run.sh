#!/usr/bin/env bash
# Run every ProVerif scenario and compare with the results the design predicts.
#
# Exit code 1 if any query differs from its expected result. CLAUDE.md §8 says CI fails when a
# query that should hold returns false; we also fail when a query that should FAIL (an attack we
# expect, e.g. classical mode vs. harvest-now-decrypt-later) suddenly holds, because that would
# mean the model no longer tests what we think it tests.
#
# Usage: formal/run.sh [--quick]     (--quick skips the authentication runs, ~4 min each)
# Needs `proverif` 2.05 on PATH (or PROVERIF=/path/to/proverif).
set -euo pipefail
cd "$(dirname "$0")"
PROVERIF="${PROVERIF:-proverif}"
QUICK="${1:-}"
OUT="out"
mkdir -p "$OUT"

# name | tags enabled in handshake.pv | expected result ("true" = proved, "false" = attack found)
HANDSHAKE=(
  "hybrid-secrecy|HY SEC|true"
  "hybrid-auth|HY AUTH|true"
  "hybrid-forward-secrecy|HY FS SEC|true"
  "hybrid-hndl|HY HNDL SEC|true"
  "hybrid-x25519-ed25519-broken-secrecy|HY BREAKCL SEC|true"
  "hybrid-x25519-ed25519-broken-auth|HY BREAKCL AUTH|false"
  "hybrid-mlkem-mldsa-broken-secrecy|HY BREAKPQ SEC|true"
  "hybrid-mlkem-mldsa-broken-auth|HY BREAKPQ AUTH|true"
  "hybrid-all-broken-secrecy|HY BREAKCL BREAKPQ SEC|false"
  "classical-secrecy|CL SEC|true"
  "classical-auth|CL AUTH|true"
  "classical-forward-secrecy|CL FS SEC|true"
  "classical-hndl|CL HNDL SEC|false"
)
ALL_TAGS="HY CL FS HNDL BREAKCL BREAKPQ AUTH SEC"

status=0
row() { printf '%-40s %-9s %-9s %8s %s\n' "$@"; }
row model/scenario result expected seconds ""

run_one() {  # name file expected-list
  local name="$1" file="$2" expected="$3" start secs results
  start=$(date +%s)
  if ! "$PROVERIF" "$file" > "$OUT/$name.log" 2>&1; then
    echo "ProVerif error in $name:"; tail -5 "$OUT/$name.log"; exit 1
  fi
  secs=$(( $(date +%s) - start ))
  results=$(grep -E '^RESULT' "$OUT/$name.log" | grep -oE 'is (true|false|cannot be proved)' | awk '{print $2}' | paste -sd',')
  local mark=""
  [[ "$results" == "$expected" ]] || { mark="<-- UNEXPECTED"; status=1; }
  row "$name" "$results" "$expected" "$secs" "$mark"
}

for entry in "${HANDSHAKE[@]}"; do
  IFS='|' read -r name tags expected <<<"$entry"
  if [[ "$QUICK" == "--quick" && " $tags " == *" AUTH "* ]]; then
    row "$name" skipped "$expected" - "(--quick)"
    continue
  fi
  file="$OUT/$name.pv"
  cp handshake.pv "$file"
  for tag in $ALL_TAGS; do
    if [[ " $tags " == *" $tag "* ]]; then
      sed -i "s/(\*#$tag\*)//" "$file"
    else
      sed -i "/(\*#$tag\*)/d" "$file"
    fi
  done
  run_one "$name" "$file" "$expected"
done

# Bounded ratchet model: m1 and m2c leak (expected attacks), m2 stays secret.
run_one "ratchet-pcs-m1,m2c,m2" ratchet_bounded.pv "false,false,true"

exit $status
