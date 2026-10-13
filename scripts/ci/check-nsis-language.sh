#!/usr/bin/env bash
# ============================================================================
# MR-1606 / REVIEW-WIN2-018: the uninstaller's confirm page has to say that
# "Delete the application data" keeps the DNS-restore journal
# (%APPDATA%\BirdoVPN\dns-restore.json*; nsis-hooks.nsh keeps it on purpose).
# The checkbox label is the bundler's `deleteAppData` string. The repo
# overrides it with a custom English.nsh (tauri.conf.json
# bundle.windows.nsis.customLanguageFiles), which REPLACES the bundler's
# built-in English.nsh as a whole. After `tauri build --bundles nsis`
# (.github/workflows/nsis-installer.yml), this checks:
#   1. every language the installer offers has a custom file, and the
#      generated installer.nsi includes exactly one file with the text of the
#      repo's English.nsh. That proves customLanguageFiles reached the bundler;
#   2. its deleteAppData says that the DNS-restore journal is kept;
#   3. it defines exactly the strings that the locked CLI's built-in English
#      defines, word for word, except deleteAppData. A CLI bump that adds,
#      drops or rewords a string fails here, rather than shipping an empty
#      label or stale wording.
#
# Usage, from the repo root after the build:
#   check-nsis-language.sh [nsis-dir] [lang-file] [cli-dir]
# Defaults: src-tauri/target/release/nsis/x64, src-tauri/nsis/English.nsh,
# node_modules/@tauri-apps (whose cli-*/*.node holds the built-in strings).
# Self-test (run by the same job): scripts/ci/check-nsis-language.tests.sh.
# ============================================================================
set -euo pipefail

nsis_dir=${1:-src-tauri/target/release/nsis/x64}
lang=${2:-src-tauri/nsis/English.nsh}
cli_dir=${3:-node_modules/@tauri-apps}
needle='keeps the DNS-restore journal'

fail() {
  echo "::error::check-nsis-language: $*"
  exit 1
}
# The bundler writes its files as UTF-8 with a BOM, and a Windows checkout
# gives ours CRLF line endings: compare plain text.
plain() { sed -e '1s/^\xEF\xBB\xBF//' -e 's/\r$//' "$1"; }
resolve() {
  case "$1" in
    [A-Za-z]:[\\/]* | /*)
      if command -v cygpath >/dev/null 2>&1; then cygpath -u "$1"; else printf '%s\n' "$1"; fi
      ;;
    *) printf '%s/%s\n' "$nsis_dir" "${1//\\//}" ;;
  esac
}
# The English LangString lines of a text: "LangString <name> ${LANG_ENGLISH} "<text>"".
# shellcheck disable=SC2016 # a literal ${LANG_ENGLISH}
english_re='LangString [A-Za-z0-9_]+ \$\{LANG_ENGLISH\} "[^"]*"'
names() { awk '{ print $2 }' <<<"$1"; }

nsi="$nsis_dir/installer.nsi"
[ -f "$nsi" ] || fail "no generated script at $nsi - did tauri build the nsis bundle?"
[ -f "$lang" ] || fail "language file missing: $lang"

# -- 1. the custom file reaches the bundler, for every language --------------
missing=$(node -e '
  const n = require("./src-tauri/tauri.conf.json").bundle.windows.nsis;
  const custom = n.customLanguageFiles || {};
  console.log((n.languages || ["English"]).filter((l) => !custom[l]).join(" "));
')
[ -z "$missing" ] ||
  fail "bundle.windows.nsis.languages offers [ $missing ] without a customLanguageFiles entry: that page would show the template's deleteAppData, which never mentions the DNS-restore journal"
wanted=$(plain "$lang")
included=()
while IFS= read -r inc; do
  path=$(resolve "$inc")
  if [ -f "$path" ] && [ "$(plain "$path")" = "$wanted" ]; then included+=("$inc"); fi
done < <(plain "$nsi" | sed -n 's/^[[:space:]]*![Ii][Nn][Cc][Ll][Uu][Dd][Ee] "\([^"]*\)"[[:space:]]*$/\1/p')
[ "${#included[@]}" -eq 1 ] ||
  fail "installer.nsi includes the text of $lang ${#included[@]} times (want 1): bundle.windows.nsis.customLanguageFiles is not reaching the bundler"
echo "OK 1/3 installer.nsi includes ${included[0]} (the text of $lang)"

# -- 2. the confirm page says the journal is kept ----------------------------
ours=$(plain "$lang" | grep -oE "^$english_re" | sort -u || true)
delete=$(grep '^LangString deleteAppData ' <<<"$ours" || true)
[ -n "$delete" ] || fail "$lang defines no deleteAppData: the confirm page's checkbox would have no label"
grep -qF -- "$needle" <<<"$delete" ||
  fail "$lang's deleteAppData does not say '$needle': $delete"
echo "OK 2/3 $delete"

# -- 3. the other strings are the locked CLI's, word for word ----------------
shopt -s nullglob
bins=("$cli_dir"/cli-*/*.node)
shopt -u nullglob
[ "${#bins[@]}" -gt 0 ] || fail "no @tauri-apps/cli native binary under $cli_dir - run npm ci first"
builtin=$(grep -a -o -h -E "$english_re" "${bins[@]}" | sort -u || true)
[ -n "$builtin" ] || fail "no built-in English LangString in the CLI binary: the bundler's language files moved - re-check $lang by hand"
dupes=$(names "$builtin" | sort | uniq -d | tr '\n' ' ')
[ -z "$dupes" ] || fail "the CLI binary defines [ $dupes] in more than one wording - decide by hand which $lang must follow"
added=$(comm -23 <(names "$builtin" | sort) <(names "$ours" | sort) | tr '\n' ' ')
[ -z "$added" ] || fail "the locked CLI defines [ $added] but $lang does not: copy them from the bundler's English.nsh"
extra=$(comm -13 <(names "$builtin" | sort) <(names "$ours" | sort) | tr '\n' ' ')
[ -z "$extra" ] || fail "$lang defines [ $extra] that the locked CLI no longer does: drop them"
differs=$(comm -13 <(grep -v '^LangString deleteAppData ' <<<"$builtin") <(grep -v '^LangString deleteAppData ' <<<"$ours") || true)
[ -z "$differs" ] ||
  fail "[ $(names "$differs" | tr '\n' ' ')] in $lang differ from the locked CLI's built-in English: take the CLI's wording (only deleteAppData is ours)"
others=$(grep -vc '^LangString deleteAppData ' <<<"$ours" || true)
echo "OK 3/3 $others others in the locked CLI's wording, plus deleteAppData"
