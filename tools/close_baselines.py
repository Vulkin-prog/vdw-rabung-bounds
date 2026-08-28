#!/usr/bin/env python3
"""Close van der Waerden lower-bound baselines under published recurrences.

The input convention is always a strict integer bound W(r,k) > B, with the
number of colors first.  The output retains a provenance DAG and generates the
LaTeX table consumed by the records paper.  No table cell in the paper is meant
to be edited by hand.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLAIMS_PATH = ROOT / "audit" / "claims.json"
BASELINES_PATH = ROOT / "audit" / "baselines.json"
OUT_JSON = ROOT / "audit" / "generated" / "bounds_closure.json"
OUT_MD = ROOT / "audit" / "generated" / "bounds_closure.md"
OUT_TEX = ROOT / "paper" / "tex" / "generated_bounds_table.tex"
OUT_COR = ROOT / "paper" / "tex" / "generated_bct_corollaries.tex"

METHOD_RANK = {
    "direct_rabung": 5,
    "published_seed": 4,
    "archived_verified_seed": 4,
    "bct2018": 3,
    "xu2013": 2,
    "one_color_exact": 1,
}


def load_json(path: Path):
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def primes_up_to(n: int):
    out = []
    for value in range(2, n + 1):
        if all(value % q for q in range(2, math.isqrt(value) + 1)):
            out.append(value)
    return out


def tex_int(value: int) -> str:
    return f"{value:,}".replace(",", r"\,")


def xu_strict_bound(ring_bound: int, ordinary_bound: int) -> int:
    """Return the strict-bound integer produced by Xu's recurrence.

    Here ``ring_bound`` and ``ordinary_bound`` encode ``WR(s,k) > R`` and
    ``W(t,k) > B``.  Taking ``n=R`` in Xu's recurrence gives
    ``W(st,k) >= R * (W(t,k) - 1) + 1 >= R * B + 1``, hence the strict
    integer convention used by this program is ``W(st,k) > R * B``.
    """
    return int(ring_bound) * int(ordinary_bound)


def add_node(nodes, candidates, *, kind, colors, length, bound, method,
             source=None, parents=None, parameters=None, label=None):
    payload = {
        "kind": kind,
        "colors": int(colors),
        "length": int(length),
        "lower_bound": int(bound),
        "method": method,
        "source": source,
        "parents": parents or [],
        "parameters": parameters or {},
        "label": label,
    }
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()[:16]
    node_id = f"{kind}-r{colors}-k{length}-{digest}"
    if node_id not in nodes:
        payload["id"] = node_id
        nodes[node_id] = payload
        candidates.setdefault((kind, int(colors), int(length)), []).append(node_id)
    return node_id


def best_id(nodes, ids):
    return max(
        ids,
        key=lambda node_id: (
            nodes[node_id]["lower_bound"],
            METHOD_RANK.get(nodes[node_id]["method"], 0),
            node_id,
        ),
    )


def closure():
    claims_doc = load_json(CLAIMS_PATH)
    baselines = load_json(BASELINES_PATH)
    claims = {claim["id"]: claim for claim in claims_doc["claims"]}
    scope = baselines["scope"]
    lengths = range(scope["length_min"], scope["length_max"] + 1)
    max_colors = scope["max_colors"]
    nodes = {}
    candidates = {}

    for claim in claims.values():
        expected = (claim["length"] - 1) * claim["prime"] + 1
        if claim["lower_bound"] != expected:
            raise ValueError(f"{claim['id']}: {claim['lower_bound']} != {expected}")

    for length in lengths:
        add_node(
            nodes, candidates, kind="ordinary", colors=1, length=length,
            bound=length - 1, method="one_color_exact", source="exact",
            label=f"W(1,{length})={length}",
        )

    def resolve_seed(seed, kind):
        if "claim_id" in seed:
            claim = claims[seed["claim_id"]]
            bound = claim["lower_bound"] if kind == "ordinary" else claim["prime"]
            method = "direct_rabung"
            source = claim["origin"]
            return claim["colors"], claim["length"], bound, method, source, claim["id"]
        return (
            seed["colors"], seed["length"], seed["lower_bound"],
            "published_seed", seed["source"], seed["id"],
        )

    for kind, key in (("ordinary", "ordinary_seeds"), ("ring", "ring_seeds")):
        for seed in baselines[key]:
            colors, length, bound, method, source, label = resolve_seed(seed, kind)
            add_node(
                nodes, candidates, kind=kind, colors=colors, length=length,
                bound=bound, method=method, source=source, label=label,
            )

    changed = True
    while changed:
        changed = False
        winners = {key: best_id(nodes, ids) for key, ids in candidates.items()}

        # Blankenship--Cummings--Taranchuk, Theorem 2.1, with q the largest
        # prime not exceeding k:
        # W(r,k) > q ( W(r-ceil(r/q),k) - 1 ).
        # A strict child bound W(...) > B therefore gives the strict bound q*B.
        for length in lengths:
            q = max(primes_up_to(length))
            for colors in range(2, max_colors + 1):
                child_colors = colors - math.ceil(colors / q)
                parent = winners.get(("ordinary", child_colors, length))
                if not parent:
                    continue
                node_id = add_node(
                    nodes, candidates, kind="ordinary", colors=colors,
                    length=length,
                    bound=q * nodes[parent]["lower_bound"], method="bct2018",
                    source="bct2018", parents=[parent], parameters={"prime_q": q},
                )
                if node_id not in winners.values():
                    old = winners.get(("ordinary", colors, length))
                    if old is None or best_id(nodes, [old, node_id]) != old:
                        changed = True

        winners = {key: best_id(nodes, ids) for key, ids in candidates.items()}
        # Xu's concatenation recurrence in Monroe's notation:
        # if 5 <= n < WR(s,k), then W(st,k) >= n (W(t,k)-1) + 1.
        # From WR(s,k)>R and W(t,k)>B we may take n=R and obtain
        # W(st,k) >= R*B+1, i.e. the strict bound W(st,k)>R*B.
        for length in lengths:
            for s in range(2, max_colors + 1):
                ring_parent = winners.get(("ring", s, length))
                if not ring_parent:
                    continue
                ring_bound = nodes[ring_parent]["lower_bound"]
                if ring_bound < 5:
                    continue
                for t in range(1, max_colors + 1):
                    colors = s * t
                    if colors > max_colors:
                        break
                    ordinary_parent = winners.get(("ordinary", t, length))
                    if not ordinary_parent:
                        continue
                    node_id = add_node(
                        nodes, candidates, kind="ordinary", colors=colors,
                        length=length,
                        bound=xu_strict_bound(
                            ring_bound,
                            nodes[ordinary_parent]["lower_bound"],
                        ),
                        method="xu2013", source="xu2013",
                        parents=[ring_parent, ordinary_parent],
                        parameters={"s": s, "t": t, "n": ring_bound},
                    )
                    old = winners.get(("ordinary", colors, length))
                    if old is None or best_id(nodes, [old, node_id]) != old:
                        changed = True

    winners = {key: best_id(nodes, ids) for key, ids in candidates.items()}
    direct = {
        (claim["colors"], claim["length"]): claim
        for claim in claims.values()
    }
    result = {
        "schema_version": 1,
        "notation": baselines["notation"],
        "inputs": {
            "claims": str(CLAIMS_PATH.relative_to(ROOT)),
            "claims_sha256": hashlib.sha256(CLAIMS_PATH.read_bytes()).hexdigest(),
            "baselines": str(BASELINES_PATH.relative_to(ROOT)),
            "baselines_sha256": hashlib.sha256(BASELINES_PATH.read_bytes()).hexdigest(),
        },
        "sources": baselines["sources"],
        "nodes": sorted(nodes.values(), key=lambda item: item["id"]),
        "winners": [],
    }
    for length in lengths:
        for colors in range(1, max_colors + 1):
            node_id = winners.get(("ordinary", colors, length))
            if node_id:
                result["winners"].append({
                    "colors": colors,
                    "length": length,
                    "node_id": node_id,
                    "lower_bound": nodes[node_id]["lower_bound"],
                    "method": nodes[node_id]["method"],
                })
    return result, nodes, winners, direct


def method_tex(node, nodes):
    if node["method"] == "direct_rabung":
        return r"direct Rabung"
    if node["method"] == "bct2018":
        q = node["parameters"]["prime_q"]
        parent = nodes[node["parents"][0]]
        if parent["source"] == "monroe2026":
            source = r"published $W(2,k)$"
        else:
            source = r"archived input"
        return rf"BCT, $q={q}$ ({source})"
    if node["method"] == "xu2013":
        return "Xu recurrence"
    return node["method"].replace("_", r"\_")


def render_tex(nodes, winners, direct):
    lines = [
        "% Generated by tools/close_baselines.py; do not edit by hand.",
        r"\begin{table}[ht]",
        r"\centering\footnotesize",
        r"\begin{tabular}{c r r r l}",
        r"\toprule",
        r"$k$ & direct $p$ & direct bound & best closed bound & method \\",
        r"\midrule",
    ]
    for length in range(17, 29):
        claim = direct.get((3, length))
        prime = rf"${tex_int(claim['prime'])}$" if claim else "--"
        direct_bound = rf"${tex_int(claim['lower_bound'])}$" if claim else "--"
        node = nodes[winners[("ordinary", 3, length)]]
        lines.append(
            f"{length} & {prime} & {direct_bound} & "
            f"${tex_int(node['lower_bound'])}$ & {method_tex(node, nodes)} " + r"\\"
        )
    lines += [
        r"\bottomrule",
        r"\end{tabular}",
        r"\caption{Direct three-colour Rabung certificates and the best general lower bounds",
        r"obtained after closing the registered baselines under the published",
        r"Blankenship--Cummings--Taranchuk and Xu recurrences.  A dash means that the",
        r"GPU campaign made no direct three-colour claim for that length.  For",
        r"$k=22,23,24,25$ the direct certificates are new champions within the direct Rabung",
        r"family but are not general records.  Every entry is generated together with a",
        r"machine-readable provenance path in \texttt{audit/generated/bounds\_closure.json}.}",
        r"\label{tab:r3}",
        r"\end{table}",
        "",
    ]
    return "\n".join(lines)


def render_corollaries(nodes, winners):
    lines = [
        "% Generated by tools/close_baselines.py; do not edit by hand.",
        r"\begin{align*}",
    ]
    for length in range(25, 29):
        bound = nodes[winners[("ordinary", 3, length)]]["lower_bound"]
        suffix = r" \\" if length < 28 else ""
        lines.append(rf"W(3,{length}) &> {tex_int(bound)}{suffix}")
    lines += [r"\end{align*}", ""]
    return "\n".join(lines)


def render_md(result, nodes, winners):
    lines = [
        "# Closed lower-bound baselines",
        "",
        "Generated by `tools/close_baselines.py`.  Convention: `W(r,k) > B`.",
        "",
        "| k | W(3,k) > | method |",
        "|---:|---:|---|",
    ]
    for length in range(17, 29):
        node = nodes[winners[("ordinary", 3, length)]]
        lines.append(f"| {length} | {node['lower_bound']:,} | {node['method']} |")
    lines.append("")
    return "\n".join(lines)


def write_or_check(path: Path, content: str, check: bool):
    if check:
        if not path.exists() or path.read_text(encoding="utf-8") != content:
            raise SystemExit(f"stale generated file: {path.relative_to(ROOT)}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="fail if generated files are stale")
    args = parser.parse_args()
    result, nodes, winners, direct = closure()
    write_or_check(OUT_JSON, json.dumps(result, indent=2, sort_keys=True) + "\n", args.check)
    write_or_check(OUT_MD, render_md(result, nodes, winners), args.check)
    write_or_check(OUT_TEX, render_tex(nodes, winners, direct), args.check)
    write_or_check(OUT_COR, render_corollaries(nodes, winners), args.check)
    if not args.check:
        for length in range(17, 29):
            node = nodes[winners[("ordinary", 3, length)]]
            print(f"W(3,{length}) > {node['lower_bound']:,} [{node['method']}]")


if __name__ == "__main__":
    main()
