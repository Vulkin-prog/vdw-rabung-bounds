# Reproducibility protocol

The September finalization adds `tools/publication_comparison.py --check` for
the five improvements, including the unresolved published comparator. It uses
exact small integer calculations and does not rerun the large certificates.

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
claim verifier, high-range witness, and separate-source prime enumerator; and
validates the staging publication contract. It neither launches the full GPU
campaign nor claims to reproduce the 13 large certificates.

A fresh full criterion/oracle sweep through `p < 10000` is archived under
`results/cpu/`.  Its 20,170 cases and 190 stronger finite checks have zero
disagreements, but its record explicitly remains preliminary because the
worktree was not the final clean release candidate. A clean CPU replay and a
clean deterministic document replay from the exact final candidate, with
durable outputs and environment metadata, are therefore still required before
that candidate is tagged and published.

## 2. Completed read-only recovery on the campaign PC

The campaign state was inventoried read-only before any rerun or cleanup.  The
replayable command, from a separate output directory, is:

```bash
./scripts/inventory_pc.sh --public-campaign-scope \
  /absolute/path/to/vdw-gpu-starter /absolute/path/to/inventory-output
```

The script only reads the source checkout. It records the Git state, ignored
and untracked paths, files, sizes, mtimes, and SHA-256 digests strictly below
`results/campaign/`.  The scope is authenticated in the v2 inventory metadata,
and the validator rejects any candidate or Git-path record outside that prefix.
The explicit option is mandatory so a future public recovery cannot silently
inventory filenames and hashes from unrelated private work. The script does not
copy, delete, compile, or execute campaign software. Review that inventory before
selecting files for import.

The authenticated import contains a complete 515-row manifest: 514 chunks have
matching journal and checkpoint records, while chunk 7 is explicitly
checkpoint-only.  It also preserves 498 per-chunk histograms for chunks
18--515 and the one aggregate re-scan for chunks 1--17; it does not reconstruct
the unavailable first-17 per-chunk histogram cells. Every imported object is
hashed and mapped in the recovery ledger.

## 3. Completed targeted calculations (historical reproduction only)

The original qualification procedure below is documented for optional historical
reproduction. It has already been completed; it is not a task for finalizing this
manuscript. Do not rerun it merely to rebuild the publication files.

```bash
./scripts/validate_cuda.sh
```

The wrapper creates `results/release/cuda-qualification/manifest.json` only
after the complete SM120 suite passes. This fixed repository-relative location
is part of the publication contract. The
manifest pins the commit, relative source and binary paths with their hashes,
the CUDA/compiler/driver/GPU identities, the command, logs, exit status, and
verdict. A hardware preflight failure creates no evidence directory; a test
failure may preserve diagnostic logs but never creates `manifest.json`.

The targeted PC evidence package then records:

1. CPU executables built from that same exact commit, with their
   command, environment, source, and binary identities;
2. exactly one directory per canonical claim under
   `results/claims/<claim-id>/`;
3. two `scan_gpu --verify1` runs, two `rabung_criterion -q` runs, and
   one `verify_claim` run for each of 13 claims;
4. a Montgomery-free `highp_witness` run for each of the
   two claims that require one;
5. a fail-closed validation of exactly 13 manifests and 67 required executions;
6. byte-for-byte agreement of the ordered scanner and separate-source CPU prime
   streams on all 515 campaign chunks, totaling 48,823,489 primes.

The CUDA qualification is `PASS` for the complete SM120 suite.  The exact Git
commit existed before these runs because it is part of every manifest.  The
authenticated recovery and ordered-prime audit revealed no material gap, so a
full campaign rerun is not required.  These completed PC calculations do not
replace the still-open clean final CPU/PDF replays.

## 4. Optional external replication and archival freeze

No independently administered external replication has been performed.  The
accepted local evidence combines GPU verification runs with CPU rechecks whose
source and arithmetic paths are separated from the GPU scanner.  All runs were
performed on one author-controlled PC; none is an independent replication.
This absence is disclosed and does not block publication.

The repository nevertheless retains an optional protocol for external
corroboration of the four fixed claim IDs in
`publication/external-replication.json`.  A future operator can preserve commit
and verifier hashes, commands, environment, stdout, stderr, exit codes, and
verdicts. CPU-only use of the stand-alone verifier is suitable for that
optional path.

The ready-to-send CPU-only operator procedure is in
`replication/README.md`. It can assign one frozen claim to each of four distinct
operators. The runner requires a clean committed checkout, a persistent
operator ID, and an explicit attestation; it builds and self-tests the verifier
source extracted from that commit, executes exactly the assigned claim, and
emits a self-verifying bundle without changing the optional ledger:

```bash
python3 tools/external_replication.py run \
  --claim-id w2_k25_p1138900957 \
  --operator-id operator-01 \
  --attestation /absolute/path/operator-attestation.txt \
  --output /absolute/path/replication-package
python3 tools/external_replication.py validate-bundle \
  --package /absolute/path/replication-package
python3 tools/external_replication.py validate-set \
  --set-dir /absolute/path/four-bundle-set
```

The archival freeze has two layers and one deliberately narrow transactional
meaning for the final status change:

1. First complete the scientific, campaign-recovery, ordered-prime,
   bibliography, and rights gates that do not depend on final DOI metadata or
   a final tag. Reserving a draft archive DOI comes
   **after those pre-freeze gates**, not after the DOI/tag gate itself.
2. Insert the reserved DOI, version, and release metadata, replace the
   preparation-only manuscript wording, and rerun the CPU and PDF checks on the
   exact final candidate. Stage the entire intended payload. Immediately before
   the inner-freeze transaction, stage `STATUS.json` with
   `repository_state: archived_release`, `citable_release: true`, and every gate
   marked `passed`. In this not-yet-published staged payload, `passed` for
   `doi-tag-archive-freeze` means only **metadata final and inner-freeze
   transaction ready**. It does not claim that a tag, deposit, outer archive, or
   deposit receipt already exists.
3. Invoke the inner transaction:

   ```bash
   python3 tools/freeze_release.py create --tag vX.Y.Z
   ```

   `create` validates the staged payload, performs the clean PDF rebuild, and
   writes `MANIFEST.sha256`. That manifest is the **inner layer**: it binds the
   tracked payload files, including the PDF, sources, certificates, logs, and
   data. If `create` fails, do not commit, tag, upload, or publish the staged
   release state; repair and restage the candidate instead.
4. Only after `create` succeeds, stage `MANIFEST.sha256`, commit the exact tree,
   create the local unpublished immutable tag, and verify it:

   ```bash
   git add MANIFEST.sha256
   git commit -m "Freeze vX.Y.Z"
   git tag vX.Y.Z
   python3 tools/freeze_release.py check --tag vX.Y.Z --require-head-tag
   ```

   If the post-commit/tag check fails, do not publish the tag or deposit.
5. Produce a deterministic archive from that checked local tag. This archive is the
   **outer layer**. Its own SHA-256 cannot be stored inside the archive without
   a hash cycle, so record the archive filename, byte length, SHA-256, draft
   deposit identifiers, and byte-for-byte upload comparison in an
   out-of-repository deposit receipt or release record. The implemented builder
   and byte-identity check are run with destinations outside the repository:

   ```bash
   python3 tools/build_release_archive.py build /absolute/path/vdw-rabung-bounds-vX.Y.Z.tar.gz
   python3 tools/build_release_archive.py check /absolute/path/vdw-rabung-bounds-vX.Y.Z.tar.gz
   ```

   After uploading the draft, download it to a distinct external file and
   create, then recheck, the deposit receipt:

   ```bash
   python3 tools/deposit_receipt.py create \
     --commit <FULL_COMMIT> --tag vX.Y.Z --version X.Y.Z \
     --doi 10.5281/zenodo.<ID> --operator release-operator:<ID> \
     --draft-identifier zenodo-draft:<ID> \
     --draft-url https://zenodo.org/uploads/<ID> \
     /absolute/path/vdw-rabung-bounds-vX.Y.Z.tar.gz \
     /absolute/path/downloaded-draft.tar.gz \
     /absolute/path/deposit-receipt-vX.Y.Z.json
   python3 tools/deposit_receipt.py check \
     /absolute/path/deposit-receipt-vX.Y.Z.json \
     /absolute/path/vdw-rabung-bounds-vX.Y.Z.tar.gz \
     /absolute/path/downloaded-draft.tar.gz
   ```

   All three artifact paths must be absolute.  The receipt output is a new JSON
   file outside the repository; the tool rejects an in-repository destination
   and succeeds only after streaming byte-for-byte equality.
6. Publish the tag and archive only after the draft upload matches the local
   archive. The post-tag receipt is published alongside the release, but is
   deliberately outside the payload whose bytes it attests and is not embedded
   evidence for the `doi-tag-archive-freeze` gate.

`tools/freeze_release.py create` is therefore the commit boundary, not an action
performed after a supposedly complete public release: the release-form status is
staged so the transaction can validate it, and becomes a committed assertion only
with the manifest that a successful transaction produced.
`tools/build_release_archive.py` deterministically renders and rechecks the outer
container from the clean `HEAD` tree, and `tools/deposit_receipt.py` binds it to
the separately downloaded draft copy without entering the payload. The final
container and external deposit receipt do not yet exist and remain release work.
Likewise, byte-identical PDF
rebuilding is presently an intra-environment check: a long-term claim requires
the TeX/font toolchain to be pinned or fully recorded. Public visibility is the
last step, not evidence that the earlier steps passed.
