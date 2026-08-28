# CPU staging evidence

`rabung-p10000.json` records a fresh, CPU-only replay of the complete
criterion/oracle sweep used in the manuscript.  The raw standard streams and
the compiler identity are committed beside it and are covered by hashes in the
record.

This is deliberately **staging evidence**, not the final release-tag gate.  The
record binds a clean committed worktree and the exact source and binary bytes
used.  It also records the tree-identical commit published in the PR history,
so the source state remains resolvable from a fresh clone.  The final gate must
nevertheless repeat the command from a clean checkout of the release candidate
and preserve evidence bound to that final commit.

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
`W(2,25) > 27333622969`.  Its progress stream is stored as base64 so
carriage-return progress records remain byte-exact.  This clean committed run
still predates the final release candidate and was not administered by an
external operator, so it closes neither the claim-manifest gate nor the
independent-replication gate.
