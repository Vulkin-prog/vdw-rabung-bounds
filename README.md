# vdw-rabung-bounds

**Private preparation repository — no citable release yet.**

This repository is the publication-oriented reproducibility package for
*Succinct Rabung certificates and recurrence-closed lower bounds for van der
Waerden numbers*. It is being assembled under an explicit allowlist from
[`Vulkin-prog/vdw-gpu-starter`](https://github.com/Vulkin-prog/vdw-gpu-starter)
at the immutable source commit
`02796ae9e08da5b051a94b2d9001763908375f6e`.

The current repository is deliberately private and is not a scientific release.
The local PC package now contains the accepted 13-manifest claim set, the
authenticated 515-chunk campaign archive, the 515-of-515 ordered-prime identity
audit, and the passing SM120 CUDA qualification. Open gates include clean final
CPU and document replays, licensing decisions, and the DOI/tag freeze. The
machine-readable state is
[`STATUS.json`](STATUS.json).

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

The structural publication-contract check is expected to fail while any gate
remains open:

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

This package covers the Rabung/GPU records paper only. The cyclic \(W_c\)
pilot, the second and third papers, companion projects, exploratory Chowla and
Liouville work, internal review transcripts, and conversational journals are
outside this repository. The enforced scope is in
[`publication/scope.json`](publication/scope.json).

## Citation and rights

`CITATION.cff` intentionally has no DOI, version, or release date yet. No
repository-wide reuse licence has been granted; see
[`RIGHTS-STATUS.md`](RIGHTS-STATUS.md). Public visibility and archival deposit
remain blocked until the author makes the outbound-licensing decisions and all
scientific gates pass.
