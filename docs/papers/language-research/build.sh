#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

SRC="${1:-manuscript/main.md}"
[ -f "$SRC" ] || { echo "no such file: $SRC" >&2; exit 1; }

OUT_BASENAME="$(basename "${SRC%.md}")"
OUT="build/local/${OUT_BASENAME}.pdf"
mkdir -p build/local

pandoc "$SRC" \
  --from markdown+raw_tex \
  --output "$OUT" \
  --pdf-engine=xelatex \
  --include-in-header=preamble.tex \
  --citeproc \
  --bibliography=bib/references.bib \
  -V geometry:margin=0.88in \
  -V fontsize=10pt \
  -V colorlinks=true \
  --highlight-style=tango

echo "wrote $OUT"
