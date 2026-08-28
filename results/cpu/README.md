# CPU staging evidence

`rabung-p10000.json` records a fresh, CPU-only replay of the complete
criterion/oracle sweep used in the manuscript.  The raw standard streams and
the compiler identity are committed beside it and are covered by hashes in the
record.

This is deliberately **staging evidence**, not the final release-tag gate.  The
record binds the exact source bytes used, but those bytes were an uncommitted
correction relative to the recorded `HEAD` and other concurrent repository
preparation also made the worktree dirty.  The final gate must therefore repeat
the command from a clean checkout of the release tag and replace or supersede
this record with tag-bound evidence.

Replay from the repository root:

```bash
tmp_dir=$(mktemp -d)
g++ -O2 -std=c++17 tools/rabung_criterion.cpp -o "$tmp_dir/rabung_criterion"
"$tmp_dir/rabung_criterion" 10000
```

Expected summary: 190 strong cases with zero inconsistencies, then 20,170
criterion/oracle cases, 4,499 accepted by the criterion, and zero mismatches.

The same directory also contains a preliminary execution of the stand-alone
verifier for `w2_k25_p1138900957`.  It accepted the strict bound
`W(2,25) > 27333622969` while using about 1.12 GiB.  Its progress stream is
stored as base64 so carriage-return progress records remain byte-exact.  This
run was neither made from a clean final commit nor administered by an external
operator, so it closes neither the claim-manifest gate nor the independent
replication gate.
