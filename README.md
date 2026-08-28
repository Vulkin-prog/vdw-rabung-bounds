# vdw-rabung-bounds

**Private preparation repository — no citable release yet.**

This repository is the publication-oriented reproducibility package for
*Certified lower bounds for van der Waerden numbers from a GPU scan and
recurrence closure*. It is being assembled under an explicit allowlist from
[`Vulkin-prog/vdw-gpu-starter`](https://github.com/Vulkin-prog/vdw-gpu-starter)
at the immutable source commit
`02796ae9e08da5b051a94b2d9001763908375f6e`.

The current repository is deliberately private and is not a scientific release:
the 13 final claim manifests, the complete 515-chunk campaign archive, the
ordered-prime identity audit, external replications, licensing decisions, and
the DOI freeze are still open gates. The machine-readable state is
[`STATUS.json`](STATUS.json).

## What is already here

- the CUDA search source and the independent CPU reference/verifier sources;
- the canonical 13-claim and baseline registries;
- fail-closed parsers, generators, and their CPU test suite;
- the paper source and its currently available aggregate evidence;
- the four historical scanner blobs used across the campaign, preserved by
  exact Git blob identity;
- a release contract that refuses to treat missing evidence as passed.

Search and certification are separate. `src/scan_gpu.cu` finds candidates;
`tools/rabung_criterion.cpp`, `tools/verify_claim.cpp`, and
`tools/highp_witness.c` re-establish the relevant certificate properties by
different paths. A candidate from the scanner is not publication evidence by
itself.

## Checks available without the campaign PC

```bash
./scripts/run_cpu_checks.sh
./scripts/build_paper.sh
python3 tools/check_publication_contract.py --mode staging
```

The release check is expected to fail while any publication gate remains open:

```bash
python3 tools/check_publication_contract.py --mode release
```

See [`REPRODUCIBILITY.md`](REPRODUCIBILITY.md) for the evidence tiers and the
read-only recovery procedure to run later on the campaign PC.

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
