#!/usr/bin/env bash
set -o pipefail

# ------------------------------------------------------------
# Defaults / CLI
# ------------------------------------------------------------
LIST_URL_DEFAULT="https://raw.githubusercontent.com/oweitman/compromisedPackages/main/compromised-packages.txt"
LIST_URL="$LIST_URL_DEFAULT"
CACHE_FILE=""
SHOW_CONTENT=0
SHOW_LINES=200

usage() {
  cat <<EOF
Usage: $0 [options]

Options:
  -u, --list-url URL      URL of the compromised package list (Default: $LIST_URL_DEFAULT)
  -c, --cache-file FILE   Cache file for storing/reading the list (optional)
      --show-content      Print the first lines of the list (debug)
      --show-lines N      Number of lines to print with --show-content (Default: $SHOW_LINES)
  -h, --help              Show this help

Note: Only lockfiles in the current directory will be scanned (no recursive search).
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    -u|--list-url)   [ $# -lt 2 ] && { echo "Missing value for $1"; usage; exit 1; }; LIST_URL="$2"; shift 2 ;;
    -c|--cache-file) [ $# -lt 2 ] && { echo "Missing value for $1"; usage; exit 1; }; CACHE_FILE="$2"; shift 2 ;;
    --show-content)  SHOW_CONTENT=1; shift ;;
    --show-lines)    [ $# -lt 2 ] && { echo "Missing value for $1"; usage; exit 1; }; SHOW_LINES="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1"; usage; exit 1 ;;
  esac
done

# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------
progress_print() {
  local p="$1"
  if [ -t 1 ]; then
    printf "\r[Progress] %3d%% complete" "$p"
    [ "$p" -ge 100 ] && printf "\n"
  else
    echo "[Progress] ${p}%"
  fi
}

escape_re() {
  # Regex-escape for grep -E / sed (including '/' and '&')
  local s="$1"
  s="$(printf '%s' "$s" | sed -e 's/[\/&]/\\&/g' \
                               -e 's/[][(){}.^$+*?|\\-]/\\&/g')"
  printf '%s' "$s"
}

# Parse multi-line JSON objects without jq
# Checks if in file $1 there is an object with key "<keyPrefix><pkg>"
# that contains a line "version": "<ver>"
json_obj_has_version() {
  # $1=file, $2=keyPrefix, $3=pkg, $4=ver
  awk -v keyPrefix="$2" -v pkg="$3" -v ver="$4" '
    BEGIN { inobj=0; found=0; key="\"" keyPrefix pkg "\""; }
    {
      if (!inobj) {
        if (index($0, key) > 0 && index($0, ":") > 0) { inobj=1 }
      } else {
        if (index($0, "\"version\"") > 0 && index($0, "\"" ver "\"") > 0) { found=1 }
        if (index($0, "}") > 0) {
          if (found) { print "FOUND"; exit 0 }
          inobj=0; found=0
        }
      }
    }
  ' "$1" | grep -q FOUND
}

download_to_file() {
  local url="$1" out="$2"
  if ! curl -fsSL "$url" -o "$out"; then
    return 1
  fi
  if head -n 6 "$out" | grep -Ei '<!doctype|<html|<head' >/dev/null 2>&1; then
    return 2
  fi
  return 0
}

# ------------------------------------------------------------
# Load list (with optional cache)
# ------------------------------------------------------------
echo "⬇️  Downloading compromised package list from: $LIST_URL"

declare -a _list_lines
_download_failed=0

if [ -n "$CACHE_FILE" ]; then
  tmp="${CACHE_FILE}.tmp"
  if download_to_file "$LIST_URL" "$tmp"; then
    mv -f "$tmp" "$CACHE_FILE" 2>/dev/null || true
    if ! mapfile -t _list_lines < "$CACHE_FILE"; then
      _download_failed=1
    else
      echo "List successfully downloaded and cached at: $CACHE_FILE"
    fi
  else
    rc=$?
    [ "$rc" -eq 2 ] && echo "⚠️  Download looks like HTML/Preview."
    if [ -f "$CACHE_FILE" ]; then
      if mapfile -t _list_lines < "$CACHE_FILE"; then
        echo "⚠️  Using existing cache file: $CACHE_FILE"
      else
        _download_failed=1
      fi
    else
      echo "❌  Failed to load list: $LIST_URL"
      _download_failed=1
    fi
    rm -f "$tmp" 2>/dev/null || true
  fi
else
  if ! mapfile -t _list_lines < <(curl -fsSL "$LIST_URL"); then
    echo "❌  Failed to load list: $LIST_URL"
    _download_failed=1
  else
    if printf '%s\n' "${_list_lines[@]:0:6}" | grep -Ei '<!doctype|<html|<head' >/dev/null 2>&1; then
      echo "⚠️  Download looks like HTML/Preview. Aborting."
      _download_failed=1
    fi
  fi
fi

if [ "$_download_failed" -ne 0 ]; then
  echo "❌  No valid content available. Abort."
  exit 2
fi

if [ "$SHOW_CONTENT" -eq 1 ]; then
  echo
  echo "--- First $SHOW_LINES lines of the list ---"
  printf '%s\n' "${_list_lines[@]}" | head -n "$SHOW_LINES"
  echo "--- End ---"
  echo
fi

# ------------------------------------------------------------
# Parse list -> compromised["pkg"]="v1 v2 ..."
# ------------------------------------------------------------
declare -A compromised
_noncomment_lines=0
while IFS= read -r line; do
  line="${line#"${line%%[![:space:]]*}"}"
  line="${line%"${line##*[![:space:]]}"}"
  [ -z "$line" ] && continue
  [ "${line:0:1}" = "#" ] && continue
  _noncomment_lines=$((_noncomment_lines + 1))
  pkg="${line%%:*}"
  vers="${line#*:}"
  pkg="${pkg%"${pkg##*[![:space:]]}"}"; pkg="${pkg#"${pkg%%[![:space:]]*}"}"
  vers="${vers%"${vers##*[![:space:]]}"}"; vers="${vers#"${vers%%[![:space:]]*}"}"
  [ -z "$pkg" ] || [ -z "$vers" ] && continue
  compromised["$pkg"]="$vers"
done < <(printf '%s\n' "${_list_lines[@]}")

echo "Info: $_noncomment_lines non-comment lines; ${#compromised[@]} package(s) parsed."

# ------------------------------------------------------------
# Lockfiles ONLY in current directory
# ------------------------------------------------------------
echo "🔍 Scanning lockfiles in $(pwd) (current directory only)..."
lockfiles=()
for f in "package-lock.json" "yarn.lock" "pnpm-lock.yaml"; do
  [ -f "./$f" ] && lockfiles+=("./$f")
done

echo "Info: ${#lockfiles[@]} lockfile(s) found."
for f in "${lockfiles[@]}"; do
  size=$(stat --printf="%s" "$f" 2>/dev/null || wc -c <"$f")
  echo " - $f ($size bytes)"
done

[ "${#lockfiles[@]}" -eq 0 ] && { echo "No lockfiles found."; exit 0; }

# ------------------------------------------------------------
# Workload
# ------------------------------------------------------------
total_versions=0
for pkg in "${!compromised[@]}"; do
  # shellcheck disable=SC2206
  _vers=( ${compromised[$pkg]} )
  total_versions=$(( total_versions + ${#_vers[@]} ))
done
total_checks=$(( total_versions * ${#lockfiles[@]} ))
[ "$total_checks" -eq 0 ] && { echo "Nothing to check. (total_versions=$total_versions, lockfiles=${#lockfiles[@]})"; exit 0; }

# ------------------------------------------------------------
# Scan (dedup + aggregation)
# ------------------------------------------------------------
found_any=0
done_checks=0
next_threshold=0
progress_print 0

declare -A hit_map          # key: "file|pkg@ver" -> 1
declare -A per_file_counts  # key: file -> count

for file in "${lockfiles[@]}"; do
  for pkg in "${!compromised[@]}"; do
    # shellcheck disable=SC2206
    vers=( ${compromised[$pkg]} )
    for ver in "${vers[@]}"; do
      done_checks=$(( done_checks + 1 ))
      percent=$(( done_checks * 100 / total_checks ))
      while [ "$percent" -ge "$next_threshold" ] && [ "$next_threshold" -le 100 ]; do
        progress_print "$next_threshold"
        next_threshold=$(( next_threshold + 1 ))
      done

      key="$file|$pkg@$ver"
      [ -n "${hit_map[$key]+x}" ] && continue

      pkg_re="$(escape_re "$pkg")"
      ver_re="$(escape_re "$ver")"

      hit=0

      # (A) flat_versions or inline:  "<pkg>": "<ver>"
      if grep -Eq "\"$pkg_re\"[[:space:]]*:[[:space:]]*\"$ver_re\"([[:space:]]*,|[[:space:]]*)$" "$file"; then
        hit=1
      fi

      # (B) dependencies object (multi-line)
      if [ "$hit" -eq 0 ] && json_obj_has_version "$file" "" "$pkg" "$ver"; then
        hit=1
      fi

      # (C) packages object (multi-line, node_modules)
      if [ "$hit" -eq 0 ] && json_obj_has_version "$file" "node_modules/" "$pkg" "$ver"; then
        hit=1
      fi

      # (D) yarn.lock header
      if [ "$hit" -eq 0 ] && grep -Eq "^$pkg_re@(\^|~)?$ver_re(:|\b)" "$file"; then
        hit=1
      fi

      if [ "$hit" -eq 1 ]; then
        found_any=1
        hit_map["$key"]=1
        per_file_counts["$file"]=$(( ${per_file_counts["$file"]:-0} + 1 ))
      fi
    done
  done
done

# progress_print 100

# ------------------------------------------------------------
# Aggregated output
# ------------------------------------------------------------
if [ "$found_any" -eq 0 ]; then
  echo "✅ No compromised packages found in lockfiles."
  exit 0
fi

echo
echo "🚨 Results (aggregated):"
total_hits=0
for f in "${lockfiles[@]}"; do
  count=${per_file_counts["$f"]:-0}
  [ "$count" -eq 0 ] && continue
  echo "• $f  —  $count match(es)"
  while IFS= read -r kv; do
    pkgver="${kv#*|}"
    printf "   - %s\n" "$pkgver"
    total_hits=$(( total_hits + 1 ))
  done < <(printf '%s\n' "${!hit_map[@]}" | grep -F "$f|" | sort)
done

echo
echo "Total: $total_hits match(es) in ${#lockfiles[@]} file(s)."
echo "⚠️  Please update/remove the affected packages and regenerate your lockfiles."
