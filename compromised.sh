#!/usr/bin/env bash
set -o pipefail

# === Konfiguration ===
LIST_URL="https://raw.githubusercontent.com/oweitman/compromisedPackages/main/compromised-packages.txt"

# === Liste laden ===
echo "⬇️  Lade Kompromittiertenliste von: $LIST_URL"
if ! mapfile -t _list_lines < <(curl -fsSL "$LIST_URL"); then
  echo "❌ Konnte Liste nicht laden: $LIST_URL"
  exit 2
fi

# === Parsen in assoziatives Array: compromised["pkg"]="v1 v2 v3" ===
declare -A compromised
while IFS= read -r line; do
  # Trim
  line="${line#"${line%%[![:space:]]*}"}"; line="${line%"${line##*[![:space:]]}"}"
  # Skip comments/blank
  [[ -z "$line" || "${line:0:1}" == "#" ]] && continue
  # Split "name: v1 v2 ..."
  pkg="${line%%:*}"
  vers="${line#*:}"
  # Trim again
  pkg="${pkg%"${pkg##*[![:space:]]}"}"; pkg="${pkg#"${pkg%%[![:space:]]*}"}"
  vers="${vers%"${vers##*[![:space:]]}"}"; vers="${vers#"${vers%%[![:space:]]*}"}"
  [[ -z "$pkg" || -z "$vers" ]] && continue
  compromised["$pkg"]="$vers"
done < <(printf '%s\n' "${_list_lines[@]}")

echo "🔍 Scanning lockfiles in $(pwd) for compromised NPM packages..."

# Lockfiles sammeln
mapfile -t lockfiles < <(find . -type f \( -name "package-lock.json" -o -name "yarn.lock" -o -name "pnpm-lock.yaml" \))
if (( ${#lockfiles[@]} == 0 )); then
  echo "No lockfiles found."
  exit 0
fi

# Fortschritt
is_tty=0; [ -t 1 ] && is_tty=1
progress_print() { local p="$1"; if (( is_tty )); then printf "\r[Progress] %3d%% complete" "$p"; (( p>=100 )) && printf "\n"; else echo "[Progress] ${p}%"; fi; }

# Gesamtchecks
total_versions=0
for pkg in "${!compromised[@]}"; do
  read -r -a _vers <<< "${compromised[$pkg]}"
  (( total_versions += ${#_vers[@]} ))
done
total_checks=$(( total_versions * ${#lockfiles[@]} ))
(( total_checks == 0 )) && { echo "Nothing to check."; exit 0; }

found=0; done_checks=0; next_threshold=0
progress_print 0

# Regex-escape Helper
escape_re() { sed 's/[.[\*^$()+?{}|]/\\&/g'; }

for file in "${lockfiles[@]}"; do
  for pkg in "${!compromised[@]}"; do
    read -r -a vers <<< "${compromised[$pkg]}"
    for ver in "${vers[@]}"; do
      (( done_checks++ ))
      percent=$(( done_checks * 100 / total_checks ))
      while (( percent >= next_threshold )); do progress_print "$next_threshold"; (( next_threshold += 1 )); (( next_threshold > 100 )) && break; done

      pkg_re=$(printf '%s' "$pkg" | escape_re)
      ver_re=$(printf '%s' "$ver" | escape_re)

      # Variante 1: JSON:  "<pkg>" : "<...ver...>"
      if grep -Eq "\"$pkg_re\"[[:space:]]*:[[:space:]]*\".*$ver_re\"" "$file"; then
        echo -e "\n[!] Gefunden in $file → $pkg@$ver"
        grep -En --color=always "\"$pkg_re\"[[:space:]]*:[[:space:]]*\".*$ver_re\"" "$file" || true
        found=1
      fi
      # Variante 2: yarn.lock:  pkg@ver
      if grep -Eq "^$pkg_re@$ver_re\b" "$file"; then
        echo -e "\n[!] Gefunden in $file → $pkg@$ver"
        grep -En --color=always "^$pkg_re@$ver_re\b" "$file" || true
        found=1
      fi
    done
  done
done

#progress_print 100
if (( found == 0 )); then
  echo "✅ No compromised packages found in lockfiles."
else
  echo "⚠️ Please remove the affected packages and regenerate the lockfiles!"
fi
