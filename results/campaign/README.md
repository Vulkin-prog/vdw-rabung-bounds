# Campaign recovery

This directory contains the authenticated recovery of the 515-chunk campaign
archive.  The retained payload comprises the authoritative checkpoint, the
campaign journal, 498 per-chunk histograms for chunks 18--515, and 15 other
auxiliary artifacts.  The unavailable original per-chunk scanner streams for
chunks 1--17 are not reconstructed; the separately preserved aggregate re-scan
in `results/redo17/redo_17chunks_v2.txt` covers that interval instead.

The recovery path is deliberately split into discovery, human selection,
byte-exact import, deterministic derivation, and validation. None of these
commands launches the scanner or writes to the historical checkout.

First create the read-only inventory on the campaign PC, with a new output
directory outside the source checkout:

```bash
./scripts/inventory_pc.sh \
  --public-campaign-scope \
  /absolute/path/to/vdw-gpu-starter \
  /absolute/new/path/pc-inventory
```

The mandatory public-campaign mode inventories every filesystem object below
`results/campaign/`, and nothing elsewhere. Its candidate list and its ignored,
untracked, and porcelain-v2 Git path streams are all restricted to that prefix;
the authenticated v2 metadata records the exact scope. Validation fails if an
out-of-scope path is inserted, even when the inventory checksums are recomputed.
This prevents excluded project names, sizes, mtimes, and hashes from entering a
future public release merely because they happened to share words such as
`prime`, `scan`, or `witness`.

Authenticate the inventory and create a complete review ledger:

```bash
python3 tools/campaign_recovery.py validate-inventory /path/to/pc-inventory
python3 tools/campaign_recovery.py propose-selection \
  /path/to/pc-inventory \
  --output /path/to/campaign-selection.json
```

The proposal selects nothing. A reviewer must change `status` to `approved`
and classify every row as either `import` or `exclude`. Every imported row
needs an allowed role, a destination below `results/campaign/raw/`, and a
reason; every exclusion also needs a reason. The only parsed roles are
`authoritative_checkpoint` and `campaign_daily`. Use `auxiliary_unparsed` for
bytes worth retaining that make no campaign claim and close no evidence gate.
Exactly one authoritative checkpoint and at least one `campaign_daily`
journal are required. Paths, sizes, hashes, and suggestions copied from the
inventory are immutable.

Run the import on the PC into another new directory. It verifies the Git
commit and tree, preflights every selected file, opens regular files through a
non-symlink descriptor chain, checks inode/size/mtime while streaming, and
compares SHA-256 before publishing each destination with an atomic
no-overwrite operation:

```bash
python3 tools/campaign_recovery.py import \
  --source /absolute/path/to/vdw-gpu-starter \
  --inventory /absolute/path/to/pc-inventory \
  --selection /absolute/path/to/campaign-selection.json \
  --output /absolute/new/path/campaign-import
```

The import also preserves all six authenticated inventory files below
`results/campaign/recovery-inventory/`. Thus the selection can be replayed by
a third party without access to the PC or the original inventory directory.
Transfer the complete resulting `results/campaign/raw/`,
`results/campaign/recovery-inventory/`, `recovery-selection.json`, and
`import-receipt.json` into this publication checkout. Also retain the frozen
`provenance/scanners/historical/*.base64` files already tracked here. Then
derive and replay the strict manifest:

```bash
python3 tools/campaign_recovery.py build
python3 tools/campaign_recovery.py check
```

The manifest contains exactly 515 ordered rows for the half-open chunks of
`[970000000,2000000000)`, binds each row to the frozen eight-revision source
map, and reparses the single shared checkpoint rather than manufacturing 515
raw files. One or more journals may jointly cover the campaign; repeated rows
from restarts are retained as distinct matches. A chunk-like line outside the
frozen grammar is rejected, and the combined journals must contain every chunk
row except chunk 7. For chunk 7, the manifest binds
`done["982000000-984000000"]`, its checksum, duration, revision `ebd54ea...`,
and every journal searched. It also decodes and re-hashes the preserved Base64
driver and verifies the causal order
`run_scan -> done -> save_ckpt -> journal`. The explicit resolution is
`checkpoint_recovers_missing_journal`. This proves checkpoint completion; it
does not reconstruct unavailable raw scanner output.

The separate ordered-prime audit is preserved in
`prime_identity_manifest.json`.  It records byte equality of the scanner and
independent CPU streams on all 515 chunks: 48,823,489 ordered primes and
535,628,154 stream bytes.  Aggregate counts or the recovery manifest alone
would not replace that stronger check.
