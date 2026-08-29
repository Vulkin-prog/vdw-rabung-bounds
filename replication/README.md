# CPU-only external replication kit

This kit is for the four cross-machine certificate rechecks frozen in
`publication/external-replication.json`. One operator runs one assigned claim;
the final set therefore contains four one-claim bundles from four distinct
persistent operator IDs. The kit does not update the canonical ledger, close
the publication gate, or assert that an incomplete/failed capture passed.

These executions test reproducibility on separately administered hardware and
software environments. Because they run the same verifier source, they are not
independent software validations. Algorithmic separation instead comes from
the distinct verifier, finite oracle, CPU walk, and non-Montgomery witness
paths documented in the paper.

## Operator procedure

Use a machine administered independently of the author. The verifier is
CPU-only, but the largest assigned run allocates roughly 3.5 GB for its colour
array; allow comfortable memory headroom and expect the check to be
long-running.

| Slot | Frozen claim ID | `(p, r, k)` | Expected strict bound |
|---:|---|---|---:|
| 1 | `w2_k25_p1138900957` | `(1138900957, 2, 25)` | `27333622969` |
| 2 | `w3_k17_p1961601427` | `(1961601427, 3, 17)` | `31385622833` |
| 3 | `w2_k27_p3459826103` | `(3459826103, 2, 27)` | `89955478679` |
| 4 | `w2_k28_p3476732783` | `(3476732783, 2, 28)` | `93871785142` |

The coordinator assigns each slot to a different operator. Operators should
not exchange bundles or IDs after starting a run.

1. Obtain the candidate repository and check out the exact candidate commit.
2. Agree a persistent, non-secret operator ID with the coordinator. Fill in a
   copy of `replication/operator-attestation.txt.example`, saved **outside** the
   Git checkout. Its single `Operator ID:` line must match the command, and its
   `Candidate Git commit:` line must contain the full checked-out `HEAD`. Do not
   use the unedited example.
3. Ensure the checkout is clean, then run from its root, also writing the
   package outside the checkout:

   ```bash
   git status --short
   python3 tools/external_replication.py run \
     --claim-id w2_k25_p1138900957 \
     --operator-id operator-01 \
     --attestation /absolute/path/operator-attestation.txt \
     --output /absolute/path/replication-package
   ```

The runner refuses a dirty checkout. It extracts `tools/verify_claim.cpp`, the
claim catalogue, and the frozen protocol from `HEAD`, compiles that committed
source, runs its ten-case selftest, and invokes the resulting binary exactly
once for the assigned frozen claim. The claim ID and all numerical parameters
are checked against hard-coded protocol values as well as the committed claim
catalogue.

The package contains the committed verifier source and binary, build logs,
verbatim attestation, selftest evidence, claim stdout/stderr, exit code, hashes,
exact argv, timing, and a compiler/OS/CPU environment record. It also preserves
the exact committed `claim_audit.py`; its validators alone derive `ACCEPT` from
the raw stdout and exit code and reject negative stderr tokens.
`manifest.partial.json` is deliberately retained if compilation, selftest, or
capture is interrupted. Only a fully attempted one-row capture is renamed to
`manifest.json`.

## Recipient verification and import preparation

Verify the received directory against the candidate repository:

```bash
python3 tools/external_replication.py validate-bundle \
  --package /absolute/path/replication-package
```

Verification rehashes every packaged file, rejects extra files and symbolic
links, checks both source files against the recorded Git commit, rederives the
command and parser verdict, and returns nonzero unless the one row is
`ACCEPT`.

The coordinator places the four unchanged bundle directories in one otherwise
empty set directory and validates the global assignment:

```bash
python3 tools/external_replication.py validate-set \
  --set-dir /absolute/path/four-bundle-set \
  --repository-prefix results/external-replication/set-01 \
  > /tmp/external-replication-set.json
```

This fails unless the set covers every frozen claim exactly once, uses four
distinct operator IDs, targets one Git commit, and every bundle validates and
accepts. The emitted rows are ordered by the frozen claim list.

For review of an individual bundle, a one-row fragment can also be rendered:

```bash
python3 tools/external_replication.py ledger-fragment \
  --package /absolute/path/replication-package \
  --repository-prefix results/external-replication/operator-01 \
  > /tmp/operator-01-ledger-fragment.json
```

Both fragment forms use repository-relative paths and retain the operator ID.
They refuse non-accepting evidence. They still do not edit
`publication/external-replication.json` or `STATUS.json`: copying the unchanged
bundle set, importing its reviewed rows, and closing the gate remain explicit
release actions.
