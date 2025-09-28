#!/usr/bin/env bash
set -euo pipefail

# Generate tests/fixtures/{package-lock.bad.json,package-lock.good.json}
# from compromised-packages.txt in repo root.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIST="$ROOT_DIR/compromised-packages.txt"
OUT_DIR="$ROOT_DIR/tests/fixtures"
BAD="$OUT_DIR/package-lock.bad.json"
GOOD="$OUT_DIR/package-lock.good.json"

mkdir -p "$OUT_DIR"

if [[ ! -f "$LIST" ]]; then
  echo "ERROR: $LIST not found" >&2
  exit 1
fi

# Take first N non-comment entries to keep fixtures small & deterministic
N=${N:-3}
mapfile -t entries < <(grep -E '^[[:space:]]*[^#[:space:]]' "$LIST" | head -n "$N")

if (( ${#entries[@]} == 0 )); then
  echo "ERROR: No non-comment entries in list" >&2
  exit 2
fi

# Helper: emit JSON arrays of (pkg,ver) in 3 places: packages, dependencies, flat_versions
build_package_lock() {
  local outfile="$1" bump="$2" # bump=no|yes (good fixture gets bumped versions)
  {
    echo '{'
    echo '  "name": "fixture-test",'
    echo '  "version": "1.0.0",'
    echo '  "lockfileVersion": 2,'
    echo '  "requires": true,'
    echo '  "packages": {'
    echo '    "": { "name": "fixture-test", "version": "1.0.0" },'

    for ((i=0;i<${#entries[@]};i++)); do
      l="${entries[$i]}"
      pkg="${l%%:*}"
      vers="${l#*:}"; vers="${vers%% *}" # first version on the line
      if [[ "$bump" == "yes" ]]; then
        # bump patch by +1000 to avoid matching; keeps valid semver
        if [[ "$vers" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)(.*)?$ ]]; then
          major="${BASH_REMATCH[1]}"; minor="${BASH_REMATCH[2]}"; patch="${BASH_REMATCH[3]}"
          tail="${BASH_REMATCH[4]}"
          vers="${major}.${minor}.$((patch+1000))${tail}"
        else
          vers="${vers}.9999"
        fi
      fi
      printf '    "node_modules/%s": { "version": "%s" }' "$pkg" "$vers"
      [[ $i -lt $(( ${#entries[@]} - 1 )) ]] && echo ',' || echo
    done
    echo '  },'

    echo '  "dependencies": {'
    for ((i=0;i<${#entries[@]};i++)); do
      l="${entries[$i]}"
      pkg="${l%%:*}"
      vers="${l#*:}"; vers="${vers%% *}"
      if [[ "$bump" == "yes" ]]; then
        if [[ "$vers" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)(.*)?$ ]]; then
          major="${BASH_REMATCH[1]}"; minor="${BASH_REMATCH[2]}"; patch="${BASH_REMATCH[3]}"
          tail="${BASH_REMATCH[4]}"
          vers="${major}.${minor}.$((patch+1000))${tail}"
        else
          vers="${vers}.9999"
        fi
      fi
      printf '    "%s": { "version": "%s" }' "$pkg" "$vers"
      [[ $i -lt $(( ${#entries[@]} - 1 )) ]] && echo ',' || echo
    done
    echo '  },'

    echo '  "flat_versions": {'
    for ((i=0;i<${#entries[@]};i++)); do
      l="${entries[$i]}"
      pkg="${l%%:*}"
      vers="${l#*:}"; vers="${vers%% *}"
      if [[ "$bump" == "yes" ]]; then
        if [[ "$vers" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)(.*)?$ ]]; then
          major="${BASH_REMATCH[1]}"; minor="${BASH_REMATCH[2]}"; patch="${BASH_REMATCH[3]}"
          tail="${BASH_REMATCH[4]}"
          vers="${major}.${minor}.$((patch+1000))${tail}"
        else
          vers="${vers}.9999"
        fi
      fi
      printf '    "%s": "%s"' "$pkg" "$vers"
      [[ $i -lt $(( ${#entries[@]} - 1 )) ]] && echo ',' || echo
    done
    echo '  }'
    echo '}'
  } > "$outfile"
}

build_package_lock "$BAD"  "no"
build_package_lock "$GOOD" "yes"

echo "Wrote:"
echo " - $BAD"
echo " - $GOOD"
