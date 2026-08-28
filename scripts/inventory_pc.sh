#!/usr/bin/env bash
set -euo pipefail

if (( $# != 2 )); then
  printf 'usage: %s SOURCE_CHECKOUT NEW_OUTPUT_DIR\n' "$0" >&2
  exit 2
fi

for INVENTORY_COMMAND in git python3 realpath sha256sum; do
  if ! command -v "$INVENTORY_COMMAND" >/dev/null 2>&1; then
    printf 'ERROR: required inventory command is unavailable: %s\n' "$INVENTORY_COMMAND" >&2
    exit 2
  fi
done

INVENTORY_SOURCE_REQUEST=$1
INVENTORY_OUTPUT_REQUEST=$2

if [[ ! -d "$INVENTORY_SOURCE_REQUEST" ]]; then
  printf 'ERROR: source checkout is not a directory: %s\n' "$INVENTORY_SOURCE_REQUEST" >&2
  exit 2
fi

git_read() {
  GIT_OPTIONAL_LOCKS=0 git \
    -c core.fsmonitor=false \
    -c core.untrackedCache=false \
    -C "$INVENTORY_SOURCE_REQUEST" "$@"
}

if [[ $(git_read rev-parse --is-inside-work-tree 2>/dev/null) != true ]]; then
  printf 'ERROR: source is not a Git worktree: %s\n' "$INVENTORY_SOURCE_REQUEST" >&2
  exit 2
fi

INVENTORY_SOURCE=$(git_read rev-parse --show-toplevel)
INVENTORY_SOURCE=$(cd "$INVENTORY_SOURCE" && pwd -P)
INVENTORY_OUTPUT=$(realpath -m -- "$INVENTORY_OUTPUT_REQUEST")

case "$INVENTORY_OUTPUT/" in
  "$INVENTORY_SOURCE/"*)
    printf 'ERROR: output must be outside the source checkout.\n' >&2
    exit 2
    ;;
esac
if [[ -e "$INVENTORY_OUTPUT" || -L "$INVENTORY_OUTPUT" ]]; then
  printf 'ERROR: output path already exists; choose a new directory: %s\n' "$INVENTORY_OUTPUT" >&2
  exit 2
fi

umask 077
mkdir -p -- "$(dirname -- "$INVENTORY_OUTPUT")"
mkdir -- "$INVENTORY_OUTPUT"

git_source_read() {
  GIT_OPTIONAL_LOCKS=0 git \
    -c core.fsmonitor=false \
    -c core.untrackedCache=false \
    -C "$INVENTORY_SOURCE" "$@"
}

INVENTORY_STARTED_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)
INVENTORY_HEAD=$(git_source_read rev-parse --verify 'HEAD^{commit}')
INVENTORY_TREE=$(git_source_read rev-parse --verify 'HEAD^{tree}')
INVENTORY_COMMIT_DATE=$(git_source_read show -s --format=%cI HEAD)
INVENTORY_BRANCH=$(git_source_read symbolic-ref --quiet --short HEAD || printf 'DETACHED')

# The -z files preserve arbitrary Git paths without reinterpretation.  Git's
# optional locks and index refreshes are disabled so this script never writes
# the source checkout.
git_source_read status --porcelain=v2 --branch --untracked-files=all --ignored=matching -z \
  >"$INVENTORY_OUTPUT/git-status-v2.z"
git_source_read ls-files --others --exclude-standard -z \
  >"$INVENTORY_OUTPUT/git-untracked.z"
git_source_read ls-files --others --ignored --exclude-standard -z \
  >"$INVENTORY_OUTPUT/git-ignored.z"

export VDW_INVENTORY_SOURCE=$INVENTORY_SOURCE
export VDW_INVENTORY_OUTPUT=$INVENTORY_OUTPUT
export VDW_INVENTORY_STARTED_UTC=$INVENTORY_STARTED_UTC
export VDW_INVENTORY_HEAD=$INVENTORY_HEAD
export VDW_INVENTORY_TREE=$INVENTORY_TREE
export VDW_INVENTORY_COMMIT_DATE=$INVENTORY_COMMIT_DATE
export VDW_INVENTORY_BRANCH=$INVENTORY_BRANCH

python3 - <<'PY'
import hashlib
import json
import os
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path

source = Path(os.environ["VDW_INVENTORY_SOURCE"])
output = Path(os.environ["VDW_INVENTORY_OUTPUT"])
manifest_path = output / "candidate-files.jsonl"
temporary_path = output / "candidate-files.jsonl.tmp"
tokens = (
    "campaign", "checkpoint", "chunk", "claim", "cuda", "prime",
    "rescan", "scan", "verify", "witness",
)


def is_candidate(relative: Path) -> bool:
    parts = relative.parts
    if parts and parts[0].lower() in {"results", "logs"}:
        return True
    lowered = relative.as_posix().lower()
    return any(token in lowered for token in tokens)


def digest_file(path: Path):
    digest = hashlib.sha256()
    with path.open("rb", buffering=0) as handle:
        before = os.fstat(handle.fileno())
        while True:
            block = handle.read(8 * 1024 * 1024)
            if not block:
                break
            digest.update(block)
        after = os.fstat(handle.fileno())
    current = os.lstat(path)
    stable = (
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        == (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns)
    )
    return digest.hexdigest(), after, stable


candidates = []
for directory, names, files in os.walk(source, topdown=True, followlinks=False):
    names[:] = sorted(name for name in names if name != ".git")
    directory_path = Path(directory)
    for name in sorted(files):
        path = directory_path / name
        relative = path.relative_to(source)
        if is_candidate(relative):
            candidates.append((relative, path))

errors = []
records = 0
with temporary_path.open("w", encoding="utf-8", newline="\n") as output_file:
    for relative, path in sorted(candidates, key=lambda item: item[0].as_posix()):
        try:
            metadata = os.lstat(path)
            record = {
                "mtime_ns": metadata.st_mtime_ns,
                "path": relative.as_posix(),
                "size": metadata.st_size,
            }
            if stat.S_ISREG(metadata.st_mode):
                digest, _, stable = digest_file(path)
                record.update({
                    "sha256": digest,
                    "stable_during_read": stable,
                    "type": "regular",
                })
                if not stable:
                    errors.append(f"changed during read: {relative.as_posix()}")
            elif stat.S_ISLNK(metadata.st_mode):
                record.update({"target": os.readlink(path), "type": "symlink"})
            else:
                record.update({"type": "other"})
            output_file.write(json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
            output_file.write("\n")
            records += 1
        except OSError as exc:
            errors.append(f"{relative.as_posix()}: {exc}")

os.replace(temporary_path, manifest_path)


def nul_count(path: Path) -> int:
    raw = path.read_bytes()
    return raw.count(b"\0")


metadata = {
    "branch": os.environ["VDW_INVENTORY_BRANCH"],
    "candidate_count": records,
    "commit_date": os.environ["VDW_INVENTORY_COMMIT_DATE"],
    "completed_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    "git_commit": os.environ["VDW_INVENTORY_HEAD"],
    "git_tree": os.environ["VDW_INVENTORY_TREE"],
    "ignored_path_count": nul_count(output / "git-ignored.z"),
    "inventory_errors": errors,
    "schema": "vdw-pc-read-only-inventory/v1",
    "source_checkout_name": source.name,
    "started_utc": os.environ["VDW_INVENTORY_STARTED_UTC"],
    "untracked_path_count": nul_count(output / "git-untracked.z"),
}
(output / "metadata.json").write_text(
    json.dumps(metadata, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)

if errors:
    for error in errors:
        print(f"INVENTORY_ERROR: {error}", file=sys.stderr)
    raise SystemExit(1)
PY

(
  cd "$INVENTORY_OUTPUT"
  sha256sum \
    candidate-files.jsonl \
    git-ignored.z \
    git-status-v2.z \
    git-untracked.z \
    metadata.json \
    >inventory-files.sha256
)

printf 'PC_INVENTORY_OK  %s\n' "$INVENTORY_OUTPUT"
printf 'source commit: %s\n' "$INVENTORY_HEAD"
