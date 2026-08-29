#!/usr/bin/env python3
"""Close van der Waerden lower-bound baselines under audited operations.

The input convention is always a strict integer bound W(r,k) > B, with the
number of colors first.  The output retains a provenance DAG and generates the
LaTeX table consumed by the computational-evidence paper. No table cell is meant
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
    "direct_rabung": 6,
    "published_seed": 5,
    "archived_verified_seed": 5,
    "length_monotonicity": 4,
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


def least_prime_factor(n: int) -> int:
    """Return the least prime divisor of an integer n >= 2."""
    if n < 2:
        raise ValueError("least_prime_factor requires n >= 2")
    if n % 2 == 0:
        return 2
    divisor = 3
    while divisor * divisor <= n:
        if n % divisor == 0:
            return divisor
        divisor += 2
    return n


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


def berlekamp_condition_denominator(t: int, field_order: int) -> int:
    """Return the strongest denominator in Berlekamp's Theorem 1.

    In Berlekamp's notation the progression length is ``t+1``. Conditions
    (4) and (5) require comparison with ``field_order**d - 1`` for every
    proper divisor ``d`` of ``t``, and with every divisor ``D < t`` of
    ``field_order**t - 1``. The maximum of those denominators determines the
    largest registered integer specialization.
    """
    if t < 2 or field_order < 2:
        raise ValueError("Berlekamp parameters must be at least 2")
    proper_divisor_terms = [
        field_order**d - 1 for d in range(1, t) if t % d == 0
    ]
    power_minus_one = field_order**t - 1
    small_divisors = [d for d in range(1, t) if power_minus_one % d == 0]
    return max(proper_divisor_terms + small_divisors)


def berlekamp_strict_bound(t: int, field_order: int) -> int:
    """Return the largest strict integer from the registered specialization."""
    denominator = berlekamp_condition_denominator(t, field_order)
    numerator = t * (field_order**t - 1)
    if numerator % denominator:
        raise ValueError("Berlekamp specialization is not integral")
    return numerator // denominator


def cfs_max_product_specialization(length: int):
    """Maximize the explicit CFS product over distinct-prime decompositions.

    Lemmas 2 and 4 of Campos--Fox--Schildkraut give the strict integer
    ``(length-1) * product(2**p - 1)`` when the distinct primes ``p`` sum to
    ``length-1``. The audited range is tiny, so exhaustive subset enumeration
    is preferable to relying on a hand-selected decomposition.
    """
    target = length - 1
    primes = primes_up_to(target)
    best = None
    for mask in range(1, 1 << len(primes)):
        factors = tuple(
            prime for index, prime in enumerate(primes) if mask & (1 << index)
        )
        if sum(factors) != target:
            continue
        bound = target * math.prod(2**prime - 1 for prime in factors)
        candidate = (bound, factors)
        if best is None or candidate > best:
            best = candidate
    if best is None:
        raise ValueError(f"no distinct-prime CFS decomposition for length {length}")
    return best


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
    lengths = range(
        scope.get("closure_length_min", scope["length_min"]),
        scope["length_max"] + 1,
    )
    report_lengths = range(scope["length_min"], scope["length_max"] + 1)
    max_colors = scope["max_colors"]
    nodes = {}
    candidates = {}

    berlekamp_seeds = [
        seed for seed in baselines["ordinary_seeds"]
        if seed.get("source") == "berlekamp1968"
    ]
    if berlekamp_seeds:
        registered_lengths = sorted(seed["length"] for seed in berlekamp_seeds)
        expected_lengths = list(range(min(lengths), scope["length_max"] + 1))
        if registered_lengths != expected_lengths:
            raise ValueError(
                "Berlekamp seeds must cover the full closure interval: "
                f"{registered_lengths} != {expected_lengths}"
            )
        first_seed = next(
            seed for seed in berlekamp_seeds if seed["length"] == min(lengths)
        )
        earlier_max = max(
            berlekamp_strict_bound(t, 3) for t in range(2, min(lengths) - 1)
        )
        if earlier_max > first_seed["lower_bound"]:
            raise ValueError(
                "an omitted earlier Berlekamp specialization would improve "
                "the closure interval"
            )

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
        if seed.get("source") == "berlekamp1968":
            parameters = seed.get("parameters", {})
            t = parameters.get("berlekamp_t")
            field_order = parameters.get("field_order")
            denominator = parameters.get("condition_denominator")
            if t != seed["length"] - 1:
                raise ValueError(f"{seed['id']}: inconsistent Berlekamp length")
            expected_denominator = berlekamp_condition_denominator(t, field_order)
            if denominator != expected_denominator:
                raise ValueError(
                    f"{seed['id']}: Berlekamp denominator {denominator} "
                    f"!= {expected_denominator}"
                )
            expected_bound = berlekamp_strict_bound(t, field_order)
            if seed["lower_bound"] != expected_bound:
                raise ValueError(
                    f"{seed['id']}: Berlekamp bound {seed['lower_bound']} "
                    f"!= {expected_bound}"
                )
        if seed.get("source") == "cfs2026":
            factors = seed.get("parameters", {}).get("distinct_primes", [])
            if (
                not factors
                or len(factors) != len(set(factors))
                or sum(factors) != seed["length"] - 1
                or any(factor not in primes_up_to(factor) for factor in factors)
            ):
                raise ValueError(f"{seed['id']}: invalid CFS prime decomposition")
            expected_bound = (seed["length"] - 1) * math.prod(
                2**factor - 1 for factor in factors
            )
            if seed["lower_bound"] != expected_bound:
                raise ValueError(
                    f"{seed['id']}: CFS bound {seed['lower_bound']} "
                    f"!= {expected_bound}"
                )
            maximal_bound, maximal_factors = cfs_max_product_specialization(
                seed["length"]
            )
            if seed["lower_bound"] != maximal_bound:
                raise ValueError(
                    f"{seed['id']}: CFS bound {seed['lower_bound']} is not "
                    f"the exhaustive maximum {maximal_bound} from "
                    f"{list(maximal_factors)}"
                )
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
                parameters=seed.get("parameters"),
            )

    changed = True
    while changed:
        changed = False
        winners = {key: best_id(nodes, ids) for key, ids in candidates.items()}

        # Length monotonicity: a colouring with no k-term progression also has
        # no (k+1)-term progression. Thus W(r,k) > B implies W(r,k+1) > B.
        # Recording this elementary closure step makes inherited literature
        # bounds machine-traceable instead of duplicating them as input seeds.
        for length in range(
            scope.get("closure_length_min", scope["length_min"]),
            scope["length_max"],
        ):
            for colors in range(1, max_colors + 1):
                parent = winners.get(("ordinary", colors, length))
                if not parent:
                    continue
                node_id = add_node(
                    nodes, candidates, kind="ordinary", colors=colors,
                    length=length + 1,
                    bound=nodes[parent]["lower_bound"],
                    method="length_monotonicity",
                    source="elementary",
                    parents=[parent],
                    parameters={"from_length": length},
                )
                old = winners.get(("ordinary", colors, length + 1))
                if old is None or best_id(nodes, [old, node_id]) != old:
                    changed = True

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
        # Xu's concatenation recurrence in colour-first notation:
        # if k >= 3, s >= 2, t >= 1, 5 <= n < WR(s,k), and the least prime
        # divisor of n exceeds k, then
        # W(st,k) >= n (W(t,k)-1) + 1.
        # From WR(s,k)>R and W(t,k)>B we may take n=R and obtain
        # W(st,k) >= R*B+1, i.e. the strict bound W(st,k)>R*B.
        for length in lengths:
            for s in range(2, max_colors + 1):
                ring_parent = winners.get(("ring", s, length))
                if not ring_parent:
                    continue
                ring_bound = nodes[ring_parent]["lower_bound"]
                ring_lpf = least_prime_factor(ring_bound)
                if ring_bound < 5 or ring_lpf <= length:
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
                        parameters={
                            "s": s,
                            "t": t,
                            "n": ring_bound,
                            "least_prime_factor_n": ring_lpf,
                        },
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
        "scope": scope,
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
    for length in report_lengths:
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
        if parent["source"] in {"monroe2016v1", "monroe2017v4", "monroe2026"}:
            source = r"published $W(2,k)$"
        else:
            source = r"archived input"
        return rf"BCT, $q={q}$ ({source})"
    if node["method"] == "xu2013":
        return "Xu recurrence"
    if node["method"] == "published_seed" and node["source"] == "berlekamp1968":
        return r"Berlekamp (1968)"
    if node["method"] == "length_monotonicity":
        parent = nodes[node["parents"][0]]
        if parent["source"] == "berlekamp1968":
            return r"Berlekamp + length monotonicity"
        return r"length monotonicity"
    return node["method"].replace("_", r"\_")


def render_tex(nodes, winners, direct):
    lines = [
        "% Generated by tools/close_baselines.py; do not edit by hand.",
        r"\begin{table}[ht]",
        r"\centering\footnotesize",
        r"\begin{tabular}{c r r r l}",
        r"\toprule",
        r"$k$ & direct $p$ & direct bound & winning admitted bound & method \\",
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
        r"\caption{Direct three-colour Rabung certificates and the winning lower bounds",
        r"obtained after closing the audited, admitted baselines under length monotonicity and the published",
        r"Blankenship--Cummings--Taranchuk and Xu recurrences.  A dash means that the",
        r"GPU campaign made no direct three-colour claim for that length.  For",
        r"$k=22,23,24,25$ the direct certificates are the strongest direct Rabung bounds",
        r"located in the audited corpus but do not win the admitted comparison. Every entry is generated with a",
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
