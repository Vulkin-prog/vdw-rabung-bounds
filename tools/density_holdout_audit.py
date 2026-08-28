#!/usr/bin/env python3
"""Reproduce the held-out (3,17) density comparison from versioned events.

The sole observational input is ``results/valid_3_17/valid_3_17_full.txt``.
In particular, this audit does not read the unversioned campaign checkpoint.
It validates the event list, reconstructs every chunk count, integrates the
three frozen intensities over the complete half-open chunk intervals, and
emits the machine-readable and paper-facing artifacts used in Section 5.

All numerical work uses the Python standard library.  The conditional
Poisson, NB2, Ljung--Box, and moving-block calculations are retrospective
diagnostics; generating them does not make them part of the repository-recorded rule.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import math
import random
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EVENTS_PATH = ROOT / "results" / "valid_3_17" / "valid_3_17_full.txt"
OUT_JSON = ROOT / "audit" / "generated" / "density_holdout_audit.json"
OUT_CSV = ROOT / "audit" / "generated" / "density_holdout_chunks.csv"
OUT_TEX = ROOT / "paper" / "tex" / "generated_density_holdout_table.tex"

WINDOW_START = 970_000_000
WINDOW_END = 2_000_000_000
CHUNK_WIDTH = 2_000_000
CHUNK_COUNT = 515
TRAINING_LAST_CHUNK = 180
EXPECTED_EVENT_COUNT = 1859
EXPECTED_TRAINING_COUNT = 1727
HOLDOUT_RANGES = ((181, 250), (251, 300), (301, 400), (401, 515))

R = 3
K = 17
M = 8.0e-4
BETA = 0.5
ETA = 1.62e-5
SIMPSON_PANELS = 32

BOOTSTRAP_BLOCK_LENGTH = 10
BOOTSTRAP_REPLICATES = 20_000
BOOTSTRAP_SEED = 20_260_803

MODEL_KEYS = ("bare", "decaying", "constant_floor")


def file_digests(data: bytes) -> dict[str, str]:
    """Return both a transport-independent SHA-256 and the Git blob SHA-1."""

    header = f"blob {len(data)}\0".encode("ascii")
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "git_blob_sha1": hashlib.sha1(header + data).hexdigest(),
    }


def is_prime_32(value: int) -> bool:
    """Deterministic Miller--Rabin primality check for unsigned 32-bit input."""

    if value < 2:
        return False
    small = (2, 3, 5, 7, 11)
    if value in small:
        return True
    if any(value % prime == 0 for prime in small):
        return False

    odd_part = value - 1
    powers_of_two = 0
    while odd_part % 2 == 0:
        powers_of_two += 1
        odd_part //= 2
    # These bases are deterministic well beyond the < 2e9 campaign window.
    for base in small:
        witness = pow(base, odd_part, value)
        if witness in (1, value - 1):
            continue
        for _ in range(powers_of_two - 1):
            witness = witness * witness % value
            if witness == value - 1:
                break
        else:
            return False
    return True


def load_events(path: Path = EVENTS_PATH) -> tuple[list[int], dict[str, str]]:
    data = path.read_bytes()
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{path}: expected UTF-8 text") from exc

    events: list[int] = []
    for line_number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if not line.isascii() or not line.isdigit():
            raise ValueError(f"{path}:{line_number}: expected one decimal prime")
        events.append(int(line))

    if len(events) != EXPECTED_EVENT_COUNT:
        raise ValueError(
            f"{path}: expected {EXPECTED_EVENT_COUNT} events, found {len(events)}"
        )
    if any(left >= right for left, right in zip(events, events[1:])):
        raise ValueError(f"{path}: events must be strictly increasing and unique")
    for value in events:
        if not WINDOW_START <= value < WINDOW_END:
            raise ValueError(f"{path}: event {value} lies outside the campaign window")
        if value % R != 1:
            raise ValueError(f"{path}: event {value} is not 1 modulo {R}")
        if not is_prime_32(value):
            raise ValueError(f"{path}: event {value} is composite")
    return events, file_digests(data)


def chunk_number(value: int) -> int:
    if not WINDOW_START <= value < WINDOW_END:
        raise ValueError(f"value {value} lies outside the campaign window")
    return (value - WINDOW_START) // CHUNK_WIDTH + 1


def observed_by_chunk(events: list[int]) -> list[int]:
    counts = [0] * CHUNK_COUNT
    for value in events:
        counts[chunk_number(value) - 1] += 1
    return counts


def model_intensities(
    value: float, *, lambda_subtract_one: bool = False
) -> tuple[float, float, float]:
    numerator = value - 1.0 if lambda_subtract_one else value
    lambda_value = (R - 1) * numerator / (2.0 * R**K)
    bare_probability = math.exp(-lambda_value)
    decaying_probability = bare_probability + M * math.exp(-BETA * lambda_value)
    floor_probability = bare_probability + ETA
    prime_density = 1.0 / (2.0 * math.log(value))
    return (
        bare_probability * prime_density,
        decaying_probability * prime_density,
        floor_probability * prime_density,
    )


def integrate_chunk(
    chunk: int,
    panels: int = SIMPSON_PANELS,
    *,
    lambda_subtract_one: bool = False,
) -> tuple[float, ...]:
    """Composite Simpson integration on the complete chunk boundaries."""

    if not 1 <= chunk <= CHUNK_COUNT:
        raise ValueError(f"invalid chunk {chunk}")
    if panels <= 0 or panels % 2:
        raise ValueError("Simpson panel count must be a positive even integer")
    lower = WINDOW_START + (chunk - 1) * CHUNK_WIDTH
    upper = lower + CHUNK_WIDTH
    step = (upper - lower) / panels
    totals = [0.0] * len(MODEL_KEYS)
    for index in range(panels + 1):
        coefficient = 1 if index in (0, panels) else (4 if index % 2 else 2)
        values = model_intensities(
            lower + index * step,
            lambda_subtract_one=lambda_subtract_one,
        )
        for model_index, value in enumerate(values):
            totals[model_index] += coefficient * value
    return tuple(total * step / 3.0 for total in totals)


def poisson_deviance_term(observed: int, mean: float) -> float:
    if observed == 0:
        return 2.0 * mean
    return 2.0 * (observed * math.log(observed / mean) - (observed - mean))


def deviance_residual(observed: int, mean: float) -> float:
    magnitude = math.sqrt(poisson_deviance_term(observed, mean))
    return magnitude if observed >= mean else -magnitude


def poisson_log_score_difference(
    observed: int, preferred_mean: float, comparison_mean: float
) -> float:
    # log(observed!) cancels between the two fixed Poisson forecasts.
    return (
        observed * math.log(preferred_mean / comparison_mean)
        - (preferred_mean - comparison_mean)
    )


def chi_square_survival_even_df(statistic: float, degrees_of_freedom: int) -> float:
    """Exact finite sum for a chi-square survival function with even df."""

    if statistic < 0 or degrees_of_freedom <= 0 or degrees_of_freedom % 2:
        raise ValueError("requires a nonnegative statistic and positive even df")
    half = statistic / 2.0
    return math.exp(-half) * sum(
        half**power / math.factorial(power)
        for power in range(degrees_of_freedom // 2)
    )


def ljung_box(residuals: list[float], lags: int = 12) -> dict[str, object]:
    count = len(residuals)
    if not 0 < lags < count:
        raise ValueError("lags must be between zero and the residual count")
    average = math.fsum(residuals) / count
    centered = [value - average for value in residuals]
    denominator = math.fsum(value * value for value in centered)
    autocorrelations = []
    for lag in range(1, lags + 1):
        numerator = math.fsum(
            centered[index] * centered[index - lag]
            for index in range(lag, count)
        )
        autocorrelations.append(numerator / denominator)
    statistic = count * (count + 2) * math.fsum(
        autocorrelation**2 / (count - lag)
        for lag, autocorrelation in enumerate(autocorrelations, start=1)
    )
    return {
        "lags": lags,
        "statistic": statistic,
        "conditional_chi_square_p_value": chi_square_survival_even_df(statistic, lags),
        "autocorrelations": autocorrelations,
        "reference": f"asymptotic chi-square({lags}); fixed-model conditional diagnostic",
    }


def block_pearson_scales(
    observed: list[int], means: list[float], block_lengths: tuple[int, ...]
) -> list[dict[str, object]]:
    output = []
    for block_length in block_lengths:
        blocks = []
        for start in range(0, len(observed), block_length):
            block_observed = sum(observed[start : start + block_length])
            block_mean = math.fsum(means[start : start + block_length])
            blocks.append((block_observed, block_mean))
        statistic = math.fsum(
            (block_observed - block_mean) ** 2 / block_mean
            for block_observed, block_mean in blocks
        )
        output.append(
            {
                "block_length": block_length,
                "block_count": len(blocks),
                "last_block_length": len(observed) % block_length or block_length,
                "pearson_statistic": statistic,
                "scale_statistic_over_block_count": statistic / len(blocks),
            }
        )
    return output


def poisson_log_likelihood(observed: list[int], means: list[float]) -> float:
    return math.fsum(
        count * math.log(mean) - mean - math.lgamma(count + 1)
        for count, mean in zip(observed, means)
    )


def nb2_log_likelihood(observed: list[int], means: list[float], alpha: float) -> float:
    """Stable NB2 log likelihood with Var(Y_i)=mu_i+alpha*mu_i^2."""

    if alpha < 0:
        raise ValueError("NB2 alpha must be nonnegative")
    if alpha == 0:
        return poisson_log_likelihood(observed, means)
    terms = []
    for count, mean in zip(observed, means):
        log_one_plus = math.log1p(alpha * mean)
        terms.append(
            math.fsum(math.log1p(alpha * index) for index in range(count))
            - count * log_one_plus
            + count * math.log(mean)
            - math.lgamma(count + 1)
            - log_one_plus / alpha
        )
    return math.fsum(terms)


def nb2_boundary_diagnostic(observed: list[int], means: list[float]) -> dict[str, object]:
    """Profile the nonnegative NB2 dispersion, including its Poisson boundary."""

    poisson_value = poisson_log_likelihood(observed, means)
    score_at_zero = 0.5 * math.fsum(
        (count - mean) ** 2 - count for count, mean in zip(observed, means)
    )
    # The log grid is deliberately included in the artifact.  Stable evaluation
    # avoids the gamma-function cancellation that otherwise creates a false tiny
    # positive alpha near the Poisson boundary.
    positive_alphas = [10.0 ** (-12.0 + index / 16.0) for index in range(241)]
    profile = [
        (alpha, nb2_log_likelihood(observed, means, alpha) - poisson_value)
        for alpha in positive_alphas
    ]
    best_alpha, best_delta = max(profile, key=lambda pair: pair[1])
    boundary = score_at_zero <= 0.0 and best_delta <= 0.0
    return {
        "variance": "mu + alpha * mu^2",
        "alpha_hat": 0.0 if boundary else best_alpha,
        "status": "Poisson boundary" if boundary else "positive grid optimum",
        "score_at_alpha_zero": score_at_zero,
        "profile_grid": {
            "alpha_min": positive_alphas[0],
            "alpha_max": positive_alphas[-1],
            "point_count": len(positive_alphas),
            "best_positive_alpha": best_alpha,
            "best_log_likelihood_delta_from_poisson": best_delta,
        },
        "dependency": "Python standard library only",
    }


def interpolated_quantile(sorted_values: list[float], probability: float) -> float:
    if not sorted_values or not 0.0 <= probability <= 1.0:
        raise ValueError("invalid sample or probability")
    position = (len(sorted_values) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    fraction = position - lower
    return (
        sorted_values[lower] * (1.0 - fraction)
        + sorted_values[upper] * fraction
    )


def circular_moving_block_bootstrap(
    series: dict[str, list[float]],
    *,
    block_length: int = BOOTSTRAP_BLOCK_LENGTH,
    replicates: int = BOOTSTRAP_REPLICATES,
    seed: int = BOOTSTRAP_SEED,
) -> dict[str, object]:
    """Paired circular moving-block bootstrap of each series mean."""

    if not series:
        raise ValueError("at least one series is required")
    count = len(next(iter(series.values())))
    if any(len(values) != count for values in series.values()):
        raise ValueError("bootstrap series must have equal lengths")
    if not 0 < block_length <= count or replicates <= 0:
        raise ValueError("invalid bootstrap configuration")

    full_blocks, remainder = divmod(count, block_length)
    full_sums: dict[str, list[float]] = {}
    partial_sums: dict[str, list[float]] = {}
    for name, values in series.items():
        doubled = values + values
        full_sums[name] = [
            math.fsum(doubled[start : start + block_length])
            for start in range(count)
        ]
        if remainder:
            partial_sums[name] = [
                math.fsum(doubled[start : start + remainder])
                for start in range(count)
            ]

    generator = random.Random(seed)
    samples = {name: [] for name in series}
    for _ in range(replicates):
        totals = {name: 0.0 for name in series}
        for _ in range(full_blocks):
            start = generator.randrange(count)
            for name in series:
                totals[name] += full_sums[name][start]
        if remainder:
            start = generator.randrange(count)
            for name in series:
                totals[name] += partial_sums[name][start]
        for name in series:
            samples[name].append(totals[name] / count)

    summaries = {}
    for name, values in samples.items():
        ordered = sorted(values)
        summaries[name] = {
            "observed_mean": math.fsum(series[name]) / count,
            "bootstrap_mean": math.fsum(values) / replicates,
            "percentile_95_interval": [
                interpolated_quantile(ordered, 0.025),
                interpolated_quantile(ordered, 0.975),
            ],
            "bootstrap_probability_nonpositive": (
                sum(value <= 0.0 for value in values) / replicates
            ),
        }
    return {
        "method": "paired circular moving-block bootstrap of per-chunk means",
        "block_length": block_length,
        "replicates": replicates,
        "seed": seed,
        "summaries": summaries,
        "dependency": "Python standard library random.Random",
    }


def build_rows(events: list[int]) -> list[dict[str, object]]:
    counts = observed_by_chunk(events)
    rows = []
    for chunk in range(TRAINING_LAST_CHUNK + 1, CHUNK_COUNT + 1):
        means = integrate_chunk(chunk)
        observed = counts[chunk - 1]
        decaying_mean = means[1]
        lower = WINDOW_START + (chunk - 1) * CHUNK_WIDTH
        rows.append(
            {
                "chunk": chunk,
                "p_start_inclusive": lower,
                "p_end_exclusive": lower + CHUNK_WIDTH,
                "observed": observed,
                "mu_bare": means[0],
                "mu_decaying": means[1],
                "mu_constant_floor": means[2],
                "pearson_residual_decaying": (
                    (observed - decaying_mean) / math.sqrt(decaying_mean)
                ),
                "deviance_residual_decaying": deviance_residual(
                    observed, decaying_mean
                ),
                "log_score_decaying_minus_bare": poisson_log_score_difference(
                    observed, means[1], means[0]
                ),
                "log_score_decaying_minus_constant_floor": (
                    poisson_log_score_difference(observed, means[1], means[2])
                ),
            }
        )
    return rows


def sum_rows(rows: list[dict[str, object]], first: int, last: int, key: str) -> float:
    return math.fsum(
        float(row[key]) for row in rows if first <= int(row["chunk"]) <= last
    )


def build_report(
    events_path: Path = EVENTS_PATH,
    *,
    bootstrap_replicates: int = BOOTSTRAP_REPLICATES,
) -> tuple[dict[str, object], list[dict[str, object]]]:
    events, digests = load_events(events_path)
    all_counts = observed_by_chunk(events)
    if sum(all_counts[:TRAINING_LAST_CHUNK]) != EXPECTED_TRAINING_COUNT:
        raise ValueError("event list does not reproduce the frozen training count")
    rows = build_rows(events)

    theoretical_totals = [0.0] * len(MODEL_KEYS)
    for chunk in range(TRAINING_LAST_CHUNK + 1, CHUNK_COUNT + 1):
        theoretical = integrate_chunk(chunk, lambda_subtract_one=True)
        for model_index, value in enumerate(theoretical):
            theoretical_totals[model_index] += value

    increments = []
    for first, last in HOLDOUT_RANGES:
        increments.append(
            {
                "chunks": f"{first}--{last}",
                "first_chunk": first,
                "last_chunk": last,
                "observed": int(sum_rows(rows, first, last, "observed")),
                "mu_bare": sum_rows(rows, first, last, "mu_bare"),
                "mu_decaying": sum_rows(rows, first, last, "mu_decaying"),
                "mu_constant_floor": sum_rows(
                    rows, first, last, "mu_constant_floor"
                ),
            }
        )

    observed = [int(row["observed"]) for row in rows]
    decaying_means = [float(row["mu_decaying"]) for row in rows]
    pearson_residuals = [
        float(row["pearson_residual_decaying"]) for row in rows
    ]
    pearson_statistic = math.fsum(value * value for value in pearson_residuals)
    deviance_statistic = math.fsum(
        poisson_deviance_term(count, mean)
        for count, mean in zip(observed, decaying_means)
    )
    bootstrap_series = {
        "decaying_minus_bare": [
            float(row["log_score_decaying_minus_bare"]) for row in rows
        ],
        "decaying_minus_constant_floor": [
            float(row["log_score_decaying_minus_constant_floor"]) for row in rows
        ],
    }

    report: dict[str, object] = {
        "schema_version": 1,
        "generated_by": "tools/density_holdout_audit.py",
        "input": {
            "path": str(events_path.relative_to(ROOT)),
            **digests,
            "source_event_count": len(events),
            "source": "versioned event list; no campaign checkpoint is read",
        },
        "campaign": {
            "p_start_inclusive": WINDOW_START,
            "p_end_exclusive": WINDOW_END,
            "chunk_width": CHUNK_WIDTH,
            "chunk_count": CHUNK_COUNT,
            "training_last_chunk": TRAINING_LAST_CHUNK,
            "training_observed": sum(all_counts[:TRAINING_LAST_CHUNK]),
            "holdout_chunk_count": len(rows),
            "holdout_observed": sum(observed),
        },
        "models": {
            "operational_lambda": "p/3^17",
            "natural_theoretical_lambda": "(p-1)/3^17",
            "prime_intensity_factor": "1/(2 log p)",
            "bare": "exp(-lambda)",
            "decaying": "exp(-lambda) + m exp(-beta lambda)",
            "constant_floor": "exp(-lambda) + eta",
            "parameters": {"m": M, "beta": BETA, "eta": ETA},
            "integration": {
                "method": "composite Simpson rule on each complete chunk",
                "panels_per_chunk": SIMPSON_PANELS,
                "interval_convention": "full half-open chunk boundaries",
            },
            "formula_sensitivity": {
                "purpose": (
                    "compare the frozen operational p/3^17 formula with the "
                    "natural theoretical (p-1)/3^17 formula"
                ),
                "theoretical_formula_holdout_totals": {
                    key: theoretical_totals[index]
                    for index, key in enumerate(MODEL_KEYS)
                },
                "operational_minus_theoretical_holdout_totals": {
                    "bare": math.fsum(float(row["mu_bare"]) for row in rows)
                    - theoretical_totals[0],
                    "decaying": math.fsum(decaying_means) - theoretical_totals[1],
                    "constant_floor": math.fsum(
                        float(row["mu_constant_floor"]) for row in rows
                    )
                    - theoretical_totals[2],
                },
                "maximum_absolute_total_difference": max(
                    abs(
                        operational - theoretical
                    )
                    for operational, theoretical in zip(
                        (
                            math.fsum(float(row["mu_bare"]) for row in rows),
                            math.fsum(decaying_means),
                            math.fsum(
                                float(row["mu_constant_floor"]) for row in rows
                            ),
                        ),
                        theoretical_totals,
                    )
                ),
                "printed_table_effect": "none at two decimal places",
                "source_note": "src/campaign.py freezes exp(-p*(r-1)/(2*r**k))",
            },
        },
        "increments": increments,
        "totals": {
            "observed": sum(observed),
            "mu_bare": math.fsum(float(row["mu_bare"]) for row in rows),
            "mu_decaying": math.fsum(decaying_means),
            "mu_constant_floor": math.fsum(
                float(row["mu_constant_floor"]) for row in rows
            ),
        },
        "diagnostics_for_frozen_decaying_model": {
            "scope": "335 post-freeze chunks; all diagnostics are retrospective",
            "pearson": {
                "statistic": pearson_statistic,
                "fixed_model_scale_statistic_over_chunk_count": (
                    pearson_statistic / len(rows)
                ),
                "denominator": len(rows),
            },
            "poisson_deviance": {"statistic": deviance_statistic},
            "ljung_box_pearson_residuals": ljung_box(pearson_residuals, 12),
            "block_pearson": block_pearson_scales(
                observed, decaying_means, (5, 10, 20, 25, 50)
            ),
            "nb2_sensitivity": nb2_boundary_diagnostic(observed, decaying_means),
            "moving_block_log_score_sensitivity": circular_moving_block_bootstrap(
                bootstrap_series, replicates=bootstrap_replicates
            ),
        },
        "interpretation_limits": [
            "The Poisson, Ljung--Box, NB2, and bootstrap calculations are post hoc.",
            "Their reference distributions are conditional on the fixed intensity model.",
            "The event list reproduces this (3,17) count analysis, not omitted campaign logs.",
        ],
        "outputs": {
            "json": str(OUT_JSON.relative_to(ROOT)),
            "csv": str(OUT_CSV.relative_to(ROOT)),
            "latex": str(OUT_TEX.relative_to(ROOT)),
        },
    }
    return report, rows


def render_json(report: dict[str, object]) -> str:
    return json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def render_csv(rows: list[dict[str, object]]) -> str:
    columns = (
        "chunk",
        "p_start_inclusive",
        "p_end_exclusive",
        "observed",
        "mu_bare",
        "mu_decaying",
        "mu_constant_floor",
        "pearson_residual_decaying",
        "deviance_residual_decaying",
        "log_score_decaying_minus_bare",
        "log_score_decaying_minus_constant_floor",
    )
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=columns, lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow(
            {
                key: (f"{row[key]:.12f}" if isinstance(row[key], float) else row[key])
                for key in columns
            }
        )
    return output.getvalue()


def render_tex(report: dict[str, object]) -> str:
    lines = [
        "% Generated by tools/density_holdout_audit.py; do not edit by hand.",
        r"\begin{table}[ht]\centering",
        r"\caption{Repository-recorded scheduled $(3,17)$ readings, reported as disjoint",
        r"increments.  The model columns are means integrated over the full",
        r"half-open chunk intervals.}",
        r"\label{tab:milestones}",
        r"\begin{tabular}{@{}crrrr@{}}",
        r"\toprule",
        r"chunks & observed & bare $\widetilde g_0$ & decaying $\widetilde g_1$ & constant floor $\widetilde g_2$ \\",
        r"\midrule",
    ]
    for increment in report["increments"]:
        lines.append(
            f"{increment['chunks']} & {increment['observed']} & "
            f"{increment['mu_bare']:.2f} & {increment['mu_decaying']:.2f} & "
            f"{increment['mu_constant_floor']:.2f} " + r"\\"
        )
    totals = report["totals"]
    lines.extend(
        [
            r"\midrule",
            f"total & {totals['observed']} & {totals['mu_bare']:.2f} & "
            f"{totals['mu_decaying']:.2f} & {totals['mu_constant_floor']:.2f} "
            + r"\\",
            r"\bottomrule",
            r"\end{tabular}",
            r"\end{table}",
            "",
        ]
    )
    return "\n".join(lines)


def write_or_check(path: Path, content: str, check: bool) -> bool:
    if check:
        if not path.exists() or path.read_text(encoding="utf-8") != content:
            print(f"stale or missing generated artifact: {path.relative_to(ROOT)}", file=sys.stderr)
            return False
        return True
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="")
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail if generated JSON, CSV, or LaTeX differs from the audit",
    )
    parser.add_argument(
        "--bootstrap-replicates",
        type=int,
        default=BOOTSTRAP_REPLICATES,
        help="deterministic moving-block bootstrap replicate count",
    )
    arguments = parser.parse_args(argv)
    report, rows = build_report(bootstrap_replicates=arguments.bootstrap_replicates)
    artifacts = (
        (OUT_JSON, render_json(report)),
        (OUT_CSV, render_csv(rows)),
        (OUT_TEX, render_tex(report)),
    )
    current = all(
        write_or_check(path, content, arguments.check) for path, content in artifacts
    )
    if not current:
        return 1
    action = "verified" if arguments.check else "generated"
    print(
        f"{action}: {len(report['increments'])} increments, "
        f"{report['totals']['observed']} holdout events, "
        f"input {report['input']['git_blob_sha1']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
