#!/usr/bin/env bash
set -euo pipefail

REPOSITORY_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)

if (( $# > 1 )); then
  printf 'usage: %s [OUTPUT_PDF]\n' "$0" >&2
  exit 2
fi

if (( $# == 1 )); then
  PAPER_OUTPUT_REQUEST=$1
  if [[ "$PAPER_OUTPUT_REQUEST" != /* ]]; then
    PAPER_OUTPUT_REQUEST="$PWD/$PAPER_OUTPUT_REQUEST"
  fi
else
  PAPER_OUTPUT_REQUEST="$REPOSITORY_ROOT/paper/main.pdf"
fi

PAPER_OUTPUT_PARENT_REQUEST=$(dirname -- "$PAPER_OUTPUT_REQUEST")
PAPER_OUTPUT_NAME=$(basename -- "$PAPER_OUTPUT_REQUEST")
if [[ -z "$PAPER_OUTPUT_NAME" || "$PAPER_OUTPUT_NAME" == . || "$PAPER_OUTPUT_NAME" == .. ]]; then
  printf 'ERROR: invalid output path: %s\n' "$PAPER_OUTPUT_REQUEST" >&2
  exit 2
fi
mkdir -p -- "$PAPER_OUTPUT_PARENT_REQUEST"
PAPER_OUTPUT_PARENT=$(cd "$PAPER_OUTPUT_PARENT_REQUEST" && pwd -P)
PAPER_OUTPUT="$PAPER_OUTPUT_PARENT/$PAPER_OUTPUT_NAME"
if [[ -d "$PAPER_OUTPUT" || -L "$PAPER_OUTPUT" ]]; then
  printf 'ERROR: output must not be a directory or symbolic link: %s\n' "$PAPER_OUTPUT" >&2
  exit 2
fi

for PAPER_COMMAND in pdflatex bibtex sha256sum cmp mktemp; do
  if ! command -v "$PAPER_COMMAND" >/dev/null 2>&1; then
    printf 'ERROR: required paper-build command is unavailable: %s\n' "$PAPER_COMMAND" >&2
    exit 2
  fi
done

if [[ -n ${SOURCE_DATE_EPOCH:-} ]]; then
  PAPER_SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH
elif git -C "$REPOSITORY_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  PAPER_SOURCE_DATE_EPOCH=$(git -C "$REPOSITORY_ROOT" log -1 --format=%ct)
else
  # Stable fallback for source archives without .git: timestamp of the pinned
  # export source commit (2026-08-20T19:08:06Z).
  PAPER_SOURCE_DATE_EPOCH=1787252886
fi
if [[ ! "$PAPER_SOURCE_DATE_EPOCH" =~ ^[0-9]+$ ]]; then
  printf 'ERROR: SOURCE_DATE_EPOCH must be a non-negative integer.\n' >&2
  exit 2
fi

export SOURCE_DATE_EPOCH=$PAPER_SOURCE_DATE_EPOCH
export FORCE_SOURCE_DATE=1
export TZ=UTC
export LC_ALL=C.UTF-8
export openout_any=p

PAPER_BUILD_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/vdw-rabung-paper.XXXXXXXX")
PAPER_OUTPUT_TEMP=$(mktemp "$PAPER_OUTPUT_PARENT/.${PAPER_OUTPUT_NAME}.tmp.XXXXXXXX")
cleanup_paper_build() {
  rm -rf -- "$PAPER_BUILD_ROOT"
  rm -f -- "$PAPER_OUTPUT_TEMP"
}
trap cleanup_paper_build EXIT

run_paper_command() {
  local log_path=$1
  shift
  if ! "$@" >"$log_path" 2>&1; then
    printf 'ERROR: paper build command failed; log follows: %s\n' "$log_path" >&2
    sed -n '1,400p' "$log_path" >&2
    exit 1
  fi
}

build_once() {
  local build_dir=$1
  mkdir -p "$build_dir/tex"
  cp -a "$REPOSITORY_ROOT/paper/tex/." "$build_dir/tex/"
  cp "$REPOSITORY_ROOT/paper/references.bib" "$build_dir/references.bib"

  (
    cd "$build_dir/tex"
    run_paper_command "$build_dir/pdflatex-1.log" \
      pdflatex -interaction=nonstopmode -halt-on-error -file-line-error main.tex
    run_paper_command "$build_dir/bibtex.log" bibtex main
    run_paper_command "$build_dir/pdflatex-2.log" \
      pdflatex -interaction=nonstopmode -halt-on-error -file-line-error main.tex
    run_paper_command "$build_dir/pdflatex-3.log" \
      pdflatex -interaction=nonstopmode -halt-on-error -file-line-error main.tex
  )

  if grep -Eiq \
    'undefined (references|citations)|citation .* undefined|reference .* undefined|there were undefined references' \
    "$build_dir/tex/main.log"; then
    printf 'ERROR: unresolved citation or reference in %s.\n' "$build_dir/tex/main.log" >&2
    exit 1
  fi
  if grep -Eq '^Warning--' "$build_dir/tex/main.blg"; then
    printf 'ERROR: BibTeX warning in %s.\n' "$build_dir/tex/main.blg" >&2
    sed -n '1,240p' "$build_dir/tex/main.blg" >&2
    exit 1
  fi
  if [[ ! -s "$build_dir/tex/main.pdf" ]]; then
    printf 'ERROR: paper build did not produce a non-empty PDF.\n' >&2
    exit 1
  fi
}

printf '[paper] deterministic build 1/2\n'
build_once "$PAPER_BUILD_ROOT/first"
printf '[paper] deterministic build 2/2\n'
build_once "$PAPER_BUILD_ROOT/second"

if ! cmp -s \
  "$PAPER_BUILD_ROOT/first/tex/main.pdf" \
  "$PAPER_BUILD_ROOT/second/tex/main.pdf"; then
  printf 'ERROR: two clean paper builds produced different PDF bytes.\n' >&2
  sha256sum \
    "$PAPER_BUILD_ROOT/first/tex/main.pdf" \
    "$PAPER_BUILD_ROOT/second/tex/main.pdf" >&2
  exit 1
fi

cp "$PAPER_BUILD_ROOT/first/tex/main.pdf" "$PAPER_OUTPUT_TEMP"
chmod 0644 "$PAPER_OUTPUT_TEMP"
mv -f -- "$PAPER_OUTPUT_TEMP" "$PAPER_OUTPUT"

printf 'PAPER_BUILD_OK  '
sha256sum "$PAPER_OUTPUT"
