# Reproducibility protocol

This package distinguishes four evidence levels. Passing a lower level does not
stand in for a higher one.

## 1. CPU and document checks available now

Run from the repository root:

```bash
./scripts/run_cpu_checks.sh
./scripts/build_paper.sh
```

The CPU suite runs unit tests; checks every committed generated audit artifact;
compiles and exercises the reference oracle, Rabung criterion, stand-alone
claim verifier, high-range witness, and independent prime enumerator; and
validates the staging publication contract. It neither launches the full GPU
campaign nor claims to reproduce the 13 large certificates.

## 2. Read-only recovery on the campaign PC

Do not rerun the 515-chunk search first. Preserve the historical state before
changing or cleaning the source checkout. From a separate output directory:

```bash
./scripts/inventory_pc.sh /absolute/path/to/vdw-gpu-starter /absolute/path/to/inventory-output
```

The script only reads the source checkout. It records the Git state, ignored
and untracked paths, candidate campaign/claim files, sizes, mtimes, and SHA-256
digests. It does not copy, delete, compile, or execute campaign software. Review
that inventory before selecting files for import.

The recovery gate requires the complete 515-row checkpoint/campaign evidence,
raw or derived per-chunk artifacts, the missing journal case for chunk 7
resolved from checkpoint evidence, historical transition outputs, and the
sampled CPU-check evidence described by the manuscript. Every imported object
must be hashed and mapped; do not reconstruct unavailable historical metadata.

## 3. Targeted release-candidate calculations

After the candidate source is committed and the worktree is clean:

1. build CUDA and CPU executables from that exact commit;
2. capture compiler, CUDA, driver, GPU, command, source, and binary identities;
3. run the SM120 qualification suite;
4. create exactly one directory per canonical claim under
   `results/claims/<claim-id>/`;
5. preserve two `scan_gpu --verify1` runs, two `rabung_criterion -q` runs, and
   one `verify_claim` run for each of 13 claims;
6. additionally preserve a Montgomery-free `highp_witness` run for each of the
   two claims that requires one;
7. validate the resulting 67-or-more recorded executions with
   `tools/claim_audit.py validate-set results/claims`;
8. compare the ordered scanner and independent CPU prime streams on all 515
   campaign chunks with `tools/prime_identity_audit.py`.

The exact Git commit must exist before these runs because it is part of every
manifest. A full campaign rerun is not a default requirement; it becomes
necessary only if the historical recovery or ordered-prime audit reveals a
material gap that cannot otherwise be closed.

## 4. Independent replication and archival freeze

An independently administered machine must recheck the four fixed claim IDs in
`publication/external-replication.json`, preserving commit and verifier hashes,
commands, environment, stdout, stderr, exit codes, and verdicts. CPU-only use of
the stand-alone verifier is acceptable if the final protocol and resource
record show that this is the independent path being claimed.

Only after every gate in `STATUS.json` is `passed` should the author reserve an
archive DOI, insert DOI/version/tag metadata, rebuild from a clean clone,
create `MANIFEST.sha256`, sign the tag, produce a deterministic archive, and
compare the uploaded objects byte-for-byte. Public visibility is the last
step, not evidence that earlier steps passed.
