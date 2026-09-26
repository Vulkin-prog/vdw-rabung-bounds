# vdw-rabung-bounds

**Version 1.0.0 — preprint and reproducibility files for Zenodo DOI [10.5281/zenodo.22980965](https://doi.org/10.5281/zenodo.22980965).**

The DOI was reserved by the author for a single deposit of the manuscript and
its supporting files. Publication on Zenodo is performed by the author; the
metadata and local freeze do not attest that the deposit is already public.

This repository is the publication-oriented reproducibility package for
*Succinct Rabung certificates and recurrence-closed lower bounds for van der
Waerden numbers*. It was assembled under an explicit allowlist from
[`Vulkin-prog/vdw-gpu-starter`](https://github.com/Vulkin-prog/vdw-gpu-starter)
at the immutable source commit
`02796ae9e08da5b051a94b2d9001763908375f6e`.

The manuscript has been prepared for publication following the bibliographic
review of 26 September 2026. The new contribution is three primitive
three-colour certificates giving nine direct inequalities; five improve the
identified prior comparators. The published Landman–Robertson statement is
shown separately and is included conservatively in the priority comparison.
The four two-colour certificates remain credited to Monroe's phase-2 project.

The complete existing PC evidence is preserved. Finalization requires no
new GPU campaign and no large-certificate rerun on the author's PC. The
public deposit uses the reserved identifier above; see `publication/ZENODO_2026-09-26_FR.md` and the archival protocol in `REPRODUCIBILITY.md`.
The author approved MIT for the code and CC BY 4.0 for the manuscript and
original data on 26 September 2026. The release ledger records this decision.

The exposition audit supplied on 26 September led to an exact-modulus
formulation of the Xu input, two regression tests, a revised abstract and
worked examples. The current manuscript has 27 A4 pages. Numerical inputs,
all closure nodes and the five improvements are unchanged. See
`publication/editorial-review/RESPONSE_AUDIT_2026-09-26_FR.md`.
Clean source candidate `84ee9d583f3c1a27e922a44b197779bc567cfd88` passes all 230 Python tests,
native CPU smoke checks, the separate arithmetic check and a byte-identical
PDF rebuild. Commands, environment, exit codes and raw logs are preserved in
`results/publication-finalization/2026-09-26-audit/`. The earlier checks remain
historical records. The Zenodo revision adds the actual DOI and release fields, and validates the
combined preprint record with its distinct component licences. Its light-check
evidence is recorded separately during the freeze.

## What is already here

- the CUDA search source and the separate-source CPU reference/verifier sources;
- the canonical 13-claim and baseline registries;
- fail-closed parsers, generators, and their CPU test suite;
- the accepted 13-claim evidence set (67 required executions, including two
  Montgomery-free high-range witnesses);
- the authenticated 515-chunk campaign record, with 514 journal/checkpoint
  matches and the missing chunk-7 journal case resolved from the checkpoint;
- 498 per-chunk histograms for chunks 18--515 and the preserved aggregate
  re-scan for chunks 1--17;
- byte-identical scanner/CPU prime streams on all 515 chunks, containing
  48,823,489 primes, and a passing SM120 CUDA qualification;
- the paper source and its currently available aggregate evidence;
- the four historical scanner blobs used across the campaign, preserved by
  exact Git blob identity;
- a release contract that refuses to treat missing evidence as passed.

Search and certification are separate. `src/scan_gpu.cu` finds candidates;
`tools/rabung_criterion.cpp`, `tools/verify_claim.cpp`, and
`tools/highp_witness.c` re-establish the relevant certificate properties by
different paths. A candidate from the scanner is not publication evidence by
itself.

No independently administered external replication has been performed. The
accepted local certificate rechecks use separately written source and distinct
arithmetic paths, but they were run within the author-controlled project
environment and are not independent replications. External replication would
be useful additional corroboration; it is not a condition of publication.

## Checks available without the campaign PC

```bash
./scripts/run_cpu_checks.sh
./scripts/build_paper.sh
python3 tools/check_publication_contract.py --mode staging
```

The frozen release also supports the complete structural publication-contract check:

```bash
python3 tools/check_publication_contract.py --mode release
```

It is not by itself the archival freeze. Immediately before the inner-freeze
transaction, the complete candidate and its release-form `STATUS.json` are
staged; `tools/freeze_release.py create` must succeed before
`MANIFEST.sha256` is committed and the local tag is created. A failed `create`
is neither committed nor published. The exact local tag must then pass
`tools/freeze_release.py check --require-head-tag`, followed by
`tools/build_release_archive.py build` and `check` for the outer container and
the external `tools/deposit_receipt.py create`/`check` draft-deposit comparison
described in
[`REPRODUCIBILITY.md`](REPRODUCIBILITY.md).

Within the staged release payload, the DOI gate's `passed` state means
"metadata final and inner-freeze transaction ready". It does not claim that the
tag or deposit is already public. The post-tag deposit receipt stays outside the
payload as a separate JSON file and is not evidence embedded by that gate.

See [`REPRODUCIBILITY.md`](REPRODUCIBILITY.md) for the evidence tiers, the
completed read-only recovery record, and the remaining release procedure.

## Scope

This package covers the Rabung/GPU computational-evidence paper only. The cyclic \(W_c\)
pilot, the second and third papers, companion projects, exploratory Chowla and
Liouville work, internal review transcripts, and conversational journals are
outside this repository. The enforced scope is in
[`publication/scope.json`](publication/scope.json).

## Citation and rights

`CITATION.cff` identifies version 1.0.0, dated 26 September 2026, with the
reserved DOI and a preferred citation for the preprint. The software component
retains MIT as its top-level licence.
Original code is licensed under MIT; the manuscript, PDF and original data
are licensed under CC BY 4.0. See [`RIGHTS-STATUS.md`](RIGHTS-STATUS.md),
[`LICENSE`](LICENSE) and `release/rights-map.json` for the component scope.
The local freeze and the author-controlled Zenodo publication are separate
steps. No GitHub release URL is invented for the private development repository.
