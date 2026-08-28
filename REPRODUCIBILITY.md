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

A fresh full criterion/oracle sweep through `p < 10000` is archived under
`results/cpu/`.  Its 20,170 cases and 190 stronger finite checks have zero
disagreements, but its record explicitly remains preliminary because the
worktree was not the final clean release candidate. A replay from the exact
final-candidate commit, with durable raw outputs and environment metadata, is
therefore still required before that candidate is tagged and published.

## 2. Read-only recovery on the campaign PC

Do not rerun the 515-chunk search first. Preserve the historical state before
changing or cleaning the source checkout. From a separate output directory:

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

The recovery gate requires the complete 515-row checkpoint/campaign evidence,
raw or derived per-chunk artifacts, the missing journal case for chunk 7
resolved from checkpoint evidence, historical transition outputs, and the
sampled CPU-check evidence described by the manuscript. Every imported object
must be hashed and mapped; do not reconstruct unavailable historical metadata.

## 3. Targeted release-candidate calculations

After the candidate source is committed and the worktree is clean:

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

Then complete the remaining release-candidate evidence:

1. build the CPU executables from that same exact commit and preserve their
   command, environment, source, and binary identities;
2. create exactly one directory per canonical claim under
   `results/claims/<claim-id>/`;
3. preserve two `scan_gpu --verify1` runs, two `rabung_criterion -q` runs, and
   one `verify_claim` run for each of 13 claims;
4. additionally preserve a Montgomery-free `highp_witness` run for each of the
   two claims that requires one;
5. validate the resulting 67-or-more recorded executions with
   `tools/claim_audit.py validate-set results/claims`;
6. compare the ordered scanner and independent CPU prime streams on all 515
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

The ready-to-send CPU-only operator procedure is in
`replication/README.md`. Each of four distinct operators receives one frozen
claim. The runner requires a clean committed checkout, a persistent operator
ID, and an explicit attestation; it builds and self-tests the verifier source
extracted from that commit, executes exactly the assigned claim, and emits a
self-verifying bundle without changing the canonical ledger or gate:

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
   independent-replication, bibliography, and rights gates that do not depend
   on final DOI metadata or a final tag. Reserving a draft archive DOI comes
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
   deposit identifiers, and byte-for-byte upload comparison in an external
   deposit receipt or release record. The implemented builder and byte-identity
   check are run with destinations outside the repository:

   ```bash
   python3 tools/build_release_archive.py build /absolute/path/vdw-rabung-bounds-vX.Y.Z.tar.gz
   python3 tools/build_release_archive.py check /absolute/path/vdw-rabung-bounds-vX.Y.Z.tar.gz
   ```

   After uploading the draft, download it to a distinct external file and
   create, then recheck, the external receipt:

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
