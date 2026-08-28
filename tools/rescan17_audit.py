#!/usr/bin/env python3
"""Fail-closed audit of the historical aggregate re-scan of chunks 1--17.

The July 2026 re-scan predates the current structured scanner protocol.  This
parser is deliberately version-specific: it accepts exactly the historical
combined transcript and checks every TARGET, candidate, COLQ, HISTO, and TOP
record before comparing the eight aggregate histogram totals with the
separate-source counts committed before the re-scan completed.

It does *not* turn one aggregate run into 17 per-chunk observations, and it
does not infer prime-list identity from matching counts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path


EXPECTED_TARGETS = {
    (2, 25), (2, 26), (2, 27), (2, 28),
    (3, 17), (3, 18), (3, 19), (3, 20), (3, 21),
    (3, 22), (3, 23), (3, 24), (3, 25),
}
LISTED_CANDIDATES = {(2, 25), (3, 17)}
EXPECTED_MODULI = set(range(2, 10))

DEVICE_RE = re.compile(r"^\[scan_gpu\] (.+)$")
HEADER_RE = re.compile(r"^# SCAN \[([0-9]+),([0-9]+)\] : ([0-9]+) premiers$")
TARGET_RE = re.compile(
    r"^TARGET r=([0-9]+) k=([0-9]+) count=([0-9]+) "
    r"max_p=([0-9]+) bound=([0-9]+)$"
)
CHECKSUM_RE = re.compile(r"^CHECKSUM ([0-9]+)$")
CANDIDATES_RE = re.compile(r"^CANDIDATS r=([0-9]+) k=([0-9]+) :(.*)$")
COLQ_RE = re.compile(r"^COLQ r=([0-9]+) k=([0-9]+) cnt=([0-9]+) :(.*)$")
HISTO_RE = re.compile(r"^HISTO r=([0-9]+) :(.*)$")
TOP_RE = re.compile(r"^TOP r=([0-9]+) :(.*)$")


class RescanAuditError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def strict_uint_list(raw: str, label: str) -> list[int]:
    tokens = raw.split()
    if any(not token.isascii() or not token.isdecimal() for token in tokens):
        raise RescanAuditError(f"{label}: malformed integer list")
    return [int(token) for token in tokens]


def load_registry(path: Path) -> dict:
    try:
        registry = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RescanAuditError(f"cannot read registry: {exc}") from exc
    if registry.get("schema_version") != 1:
        raise RescanAuditError("unsupported registry schema")
    interval = registry.get("interval", {})
    if interval.get("campaign_chunk_count") != 17:
        raise RescanAuditError("registry does not describe 17 chunks")
    lo = interval.get("lower_inclusive")
    hi = interval.get("upper_exclusive")
    width = interval.get("campaign_chunk_width")
    if not all(isinstance(value, int) for value in (lo, hi, width)):
        raise RescanAuditError("non-integral interval in registry")
    if lo >= hi or width <= 0 or hi - lo != 17 * width:
        raise RescanAuditError("registry interval is not exactly 17 campaign chunks")
    counts = registry.get("preregistered_independent_counts", {})
    expected = counts.get("congruence_classes", {})
    if set(expected) != {str(r) for r in EXPECTED_MODULI}:
        raise RescanAuditError("registry lacks one or more congruence-class counts")
    if any(not isinstance(value, int) or value < 0 for value in expected.values()):
        raise RescanAuditError("invalid registered congruence-class count")
    return registry


def parse_transcript(text: str, lo: int, hi: int) -> dict:
    # The GitHub-preserved historical artifact has a final newline.  Requiring
    # it helps detect a common form of truncation before structural parsing.
    if not text.endswith("\n"):
        raise RescanAuditError("historical transcript lacks its final newline")
    device: str | None = None
    header: tuple[int, int, int] | None = None
    targets: dict[tuple[int, int], dict] = {}
    checksum: int | None = None
    candidates: dict[tuple[int, int], list[int]] = {}
    colq: dict[tuple[int, int], tuple[int, list[int]]] = {}
    histo: dict[int, list[int]] = {}
    top: dict[int, list[tuple[int, int]]] = {}

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            raise RescanAuditError("blank line in historical transcript")
        match = DEVICE_RE.fullmatch(line)
        if match:
            if device is not None:
                raise RescanAuditError("duplicate device line")
            device = match.group(1)
            continue
        match = HEADER_RE.fullmatch(line)
        if match:
            if header is not None:
                raise RescanAuditError("duplicate scan header")
            header = tuple(map(int, match.groups()))
            continue
        match = TARGET_RE.fullmatch(line)
        if match:
            values = list(map(int, match.groups()))
            key = (values[0], values[1])
            if key in targets:
                raise RescanAuditError(f"duplicate TARGET {key}")
            targets[key] = {"count": values[2], "max_p": values[3], "bound": values[4]}
            continue
        match = CHECKSUM_RE.fullmatch(line)
        if match:
            if checksum is not None:
                raise RescanAuditError("duplicate CHECKSUM")
            checksum = int(match.group(1))
            if checksum >= 1 << 64:
                raise RescanAuditError("CHECKSUM is outside uint64")
            continue
        match = CANDIDATES_RE.fullmatch(line)
        if match:
            key = (int(match.group(1)), int(match.group(2)))
            if key in candidates:
                raise RescanAuditError(f"duplicate CANDIDATS {key}")
            candidates[key] = strict_uint_list(match.group(3), f"CANDIDATS {key}")
            continue
        match = COLQ_RE.fullmatch(line)
        if match:
            key = (int(match.group(1)), int(match.group(2)))
            if key in colq:
                raise RescanAuditError(f"duplicate COLQ {key}")
            colq[key] = (
                int(match.group(3)), strict_uint_list(match.group(4), f"COLQ {key}")
            )
            continue
        match = HISTO_RE.fullmatch(line)
        if match:
            modulus = int(match.group(1))
            if modulus in histo:
                raise RescanAuditError(f"duplicate HISTO r={modulus}")
            histo[modulus] = strict_uint_list(match.group(2), f"HISTO r={modulus}")
            continue
        match = TOP_RE.fullmatch(line)
        if match:
            modulus = int(match.group(1))
            if modulus in top:
                raise RescanAuditError(f"duplicate TOP r={modulus}")
            entries = match.group(2).split()
            if any(not re.fullmatch(r"[0-9]+:[0-9]+", entry) for entry in entries):
                raise RescanAuditError(f"malformed TOP r={modulus}")
            top[modulus] = [tuple(map(int, entry.split(":"))) for entry in entries]
            continue
        raise RescanAuditError(f"unknown transcript line: {line[:160]}")

    if device is None or header is None:
        raise RescanAuditError("device line or scan header missing")
    # The historical header used square brackets at both ends.  The requested
    # campaign interval was half-open; the even upper endpoint is composite.
    if header[:2] != (lo, hi):
        raise RescanAuditError(f"wrong scan interval in header: {header[:2]}")
    prime_count = header[2]
    if set(targets) != EXPECTED_TARGETS:
        raise RescanAuditError("incomplete or unexpected TARGET set")
    if checksum is None:
        raise RescanAuditError("CHECKSUM missing")
    if set(candidates) != LISTED_CANDIDATES:
        raise RescanAuditError("incomplete or unexpected CANDIDATS set")
    if set(colq) != EXPECTED_TARGETS:
        raise RescanAuditError("incomplete or unexpected COLQ set")
    if set(histo) != EXPECTED_MODULI or set(top) != EXPECTED_MODULI:
        raise RescanAuditError("HISTO/TOP records must cover r=2,...,9 exactly")

    for key, values in targets.items():
        count, max_p, bound = values["count"], values["max_p"], values["bound"]
        if count < 0 or count > prime_count:
            raise RescanAuditError(f"TARGET {key}: impossible count")
        if count == 0:
            if max_p != 0 or bound != 0:
                raise RescanAuditError(f"TARGET {key}: nonzero maximum for zero count")
        elif not lo <= max_p < hi or bound != (key[1] - 1) * max_p + 1:
            raise RescanAuditError(f"TARGET {key}: inconsistent maximum or bound")

    for key, values in candidates.items():
        if values != sorted(set(values)):
            raise RescanAuditError(f"CANDIDATS {key}: not strictly canonical")
        if any(not lo <= value < hi for value in values):
            raise RescanAuditError(f"CANDIDATS {key}: value outside interval")
        target = targets[key]
        if len(values) != target["count"] or (values and values[-1] != target["max_p"]):
            raise RescanAuditError(f"CANDIDATS {key}: count or maximum mismatch")

    for key, (reported_count, values) in colq.items():
        if reported_count != targets[key]["count"] or len(values) != 6:
            raise RescanAuditError(f"COLQ {key}: denominator or width mismatch")
        if any(value > reported_count for value in values):
            raise RescanAuditError(f"COLQ {key}: value exceeds denominator")

    class_counts: dict[int, int] = {}
    for modulus in sorted(EXPECTED_MODULI):
        bins = histo[modulus]
        if len(bins) != 64:
            raise RescanAuditError(f"HISTO r={modulus}: expected 64 bins")
        total = sum(bins)
        if total > prime_count:
            raise RescanAuditError(f"HISTO r={modulus}: total exceeds prime count")
        class_counts[modulus] = total
        entries = top[modulus]
        if len(entries) != min(20, total):
            raise RescanAuditError(f"TOP r={modulus}: wrong length")
        primes = [prime for prime, _ in entries]
        if len(primes) != len(set(primes)) or any(not lo <= prime < hi for prime in primes):
            raise RescanAuditError(f"TOP r={modulus}: duplicate or out-of-range prime")
        if entries != sorted(entries, key=lambda item: (-item[1], item[0])):
            raise RescanAuditError(f"TOP r={modulus}: noncanonical order")
        top_bins = [0] * 64
        for _, maxrun in entries:
            if maxrun < 1:
                raise RescanAuditError(f"TOP r={modulus}: invalid maxrun")
            top_bins[min(maxrun, 63)] += 1
        if any(top_bins[index] > bins[index] for index in range(64)):
            raise RescanAuditError(f"TOP r={modulus}: profile absent from HISTO")
        remaining = min(20, total)
        expected_bins: list[int] = []
        for index in range(63, -1, -1):
            take = min(bins[index], remaining)
            expected_bins.extend([index] * take)
            remaining -= take
            if remaining == 0:
                break
        if [min(maxrun, 63) for _, maxrun in entries] != expected_bins:
            raise RescanAuditError(f"TOP r={modulus}: does not occupy highest HISTO bins")

    for (modulus, k), values in targets.items():
        implied = sum(histo[modulus][: min(k, 64)])
        if values["count"] != implied:
            raise RescanAuditError(
                f"TARGET {(modulus, k)}: count {values['count']} != HISTO implication {implied}"
            )

    return {
        "device": device,
        "prime_count": prime_count,
        "checksum": checksum,
        "targets": {f"{r},{k}": targets[(r, k)] for r, k in sorted(targets)},
        "candidate_counts": {
            f"{r},{k}": len(candidates[(r, k)]) for r, k in sorted(candidates)
        },
        "candidate_overlap_ready": {
            "3,17": candidates[(3, 17)],
        },
        "class_counts": {str(r): class_counts[r] for r in sorted(class_counts)},
    }


def audit(registry_path: Path) -> dict:
    registry = load_registry(registry_path)
    repo_root = registry_path.resolve().parent.parent
    transcript_path = repo_root / registry["transcript"]["path"]
    if not transcript_path.is_file():
        raise RescanAuditError(f"transcript missing: {transcript_path}")
    digest = sha256_file(transcript_path)
    if digest != registry["transcript"]["sha256"]:
        raise RescanAuditError("transcript SHA-256 mismatch")
    try:
        text = transcript_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise RescanAuditError(f"cannot decode transcript: {exc}") from exc
    interval = registry["interval"]
    parsed = parse_transcript(
        text, interval["lower_inclusive"], interval["upper_exclusive"]
    )
    registered = registry["preregistered_independent_counts"]
    if parsed["prime_count"] != registered["prime_count"]:
        raise RescanAuditError("prime total differs from preregistered separate-source count")
    if parsed["class_counts"] != registered["congruence_classes"]:
        raise RescanAuditError("HISTO totals differ from preregistered separate-source counts")
    return {
        "schema": "vdw-rescan17-audit/v1",
        "status": "PASS_AGGREGATE_COUNTS",
        "registry": str(registry_path.resolve().relative_to(repo_root)),
        "interval": interval,
        "transcript": {
            **registry["transcript"],
            "verified_sha256": digest,
        },
        "execution": registry["execution"],
        "preregistered_independent_counts": registered,
        "parsed": parsed,
        "interpretation": registry["interpretation"],
    }


def render_markdown(result: dict) -> str:
    counts = result["parsed"]["class_counts"]
    lines = [
        "# Audit of the aggregate re-scan of chunks 1--17",
        "",
        f"Status: **{result['status']}**.",
        "",
        "| modulus `r` | re-scan `sum(HISTO[r])` | preregistered separate-source count |",
        "|---:|---:|---:|",
    ]
    expected = result["preregistered_independent_counts"]["congruence_classes"]
    for modulus in map(str, range(2, 10)):
        lines.append(f"| {modulus} | {counts[modulus]:,} | {expected[modulus]:,} |")
    lines.extend([
        "",
        "The comparison is aggregate over one 34,000,000-wide invocation. It does not",
        "supply 17 per-chunk histograms and does not prove identity of ordered prime lists.",
        "",
    ])
    return "\n".join(lines)


def render_latex(result: dict) -> str:
    counts = result["parsed"]["class_counts"]
    rows = []
    for left, right in ((2, 6), (3, 7), (4, 8), (5, 9)):
        rows.append(
            f"{left} & {counts[str(left)]:,} & {right} & {counts[str(right)]:,} \\\\".replace(",", "\\,")
        )
    return "\n".join([
        "\\begin{table}[ht]",
        "\\centering\\small",
        "\\begin{tabular}{r r r r}",
        "\\toprule",
        "$r$ & $\\#\\{p:p\\equiv1\\pmod r\\}$ & $r$ & $\\#\\{p:p\\equiv1\\pmod r\\}$ \\\\",
        "\\midrule",
        *rows,
        "\\bottomrule",
        "\\end{tabular}",
        "\\caption{Aggregate congruence-class totals from the post-campaign re-scan of",
        "the first 17 chunks.  All eight equal the separate-source counts committed before",
        "the re-scan completed.  This is one aggregate comparison, not 17 per-chunk",
        "comparisons and not an ordered-prime identity test.}",
        "\\label{tab:rescan17}",
        "\\end{table}",
        "",
    ])


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--registry", type=Path, default=Path("audit/rescan17.json"))
    parser.add_argument("--json", type=Path, default=Path("audit/generated/rescan17_audit.json"))
    parser.add_argument("--markdown", type=Path, default=Path("audit/generated/rescan17_audit.md"))
    parser.add_argument("--latex", type=Path, default=Path("paper/tex/generated_rescan17_table.tex"))
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    try:
        result = audit(args.registry)
    except RescanAuditError as exc:
        raise SystemExit(f"rescan17 audit failed: {exc}") from exc
    outputs = {
        args.json: json.dumps(result, indent=2, sort_keys=True) + "\n",
        args.markdown: render_markdown(result),
        args.latex: render_latex(result),
    }
    if args.check:
        stale = []
        for path, expected in outputs.items():
            try:
                actual = path.read_text(encoding="utf-8")
            except OSError:
                stale.append(str(path))
                continue
            if actual != expected:
                stale.append(str(path))
        if stale:
            raise SystemExit("stale or missing rescan17 outputs: " + ", ".join(stale))
    else:
        for path, content in outputs.items():
            write_text(path, content)
    print("PASS: aggregate re-scan transcript matches all eight preregistered counts")


if __name__ == "__main__":
    main()
