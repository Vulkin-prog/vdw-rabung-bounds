# Claim evidence — deferred, with a fail-closed capture protocol

This directory is a layout placeholder, not claim evidence. The final package
must contain exactly one `results/claims/<claim-id>/manifest.json` plus its
referenced raw streams for each ID in `audit/claims.json`. Until
`tools/claim_audit.py validate-set results/claims --repository-root .` accepts
the complete set and the corresponding status gate is marked `passed`, no
large certificate should be described as reproduced by this repository.

## Machine-independent plan

The execution plan can be inspected without CUDA, binaries, or a clean
worktree:

```console
python3 scripts/capture_claim_evidence.py plan
# equivalent: python3 scripts/capture_claim_evidence.py capture --dry-run
```

It must report 13 claims and exactly 67 required executions: for every claim,
two independent process invocations of `scan_gpu --verify1`, two of
`rabung_criterion -q`, and one of `verify_claim`; the two claims explicitly
marked in `audit/claims.json` each add one Montgomery-free `highp_witness` run
with the frozen sample count 20,000.

## Capture on the qualified PC

Commit the release-candidate sources first and start from a clean worktree.
The simplest path builds all four programs using fixed compiler arguments:

```console
python3 scripts/capture_claim_evidence.py capture --build
```

The CUDA command targets `sm_120` and matches the scanner qualification build.
Every compiler invocation and version, source hash, preserved binary hash,
process argument vector, raw stdout, raw stderr, and integer exit code is
recorded. All manifest paths are canonical and repository-relative.

Already-qualified binaries can instead be supplied, but only with attested
metadata:

```console
python3 scripts/capture_claim_evidence.py capture \
  --binary-dir build/qualified-claim-binaries \
  --build-metadata build/qualified-claim-binaries/build-metadata.json
```

`build-metadata.json` is strict JSON of the following form. The four binary
maps must have exactly the keys shown; the source map must match the eight
release-protocol files at the current commit byte for byte.

```json
{
  "schema": "vdw-claim-build-input/v1",
  "git_commit": "<40 lowercase hex characters>",
  "sources_sha256": {"<repository-relative source>": "<sha256>"},
  "binaries_sha256": {
    "scan_gpu": "<sha256>",
    "rabung_criterion": "<sha256>",
    "verify_claim": "<sha256>",
    "highp_witness": "<sha256>"
  },
  "compile_commands": {
    "scan_gpu": ["<exact>", "<argv>"],
    "rabung_criterion": ["<exact>", "<argv>"],
    "verify_claim": ["<exact>", "<argv>"],
    "highp_witness": ["<exact>", "<argv>"]
  },
  "compiler_versions": {
    "<compiler>": "{\"command\":\"<compiler>\",\"resolved_path\":\"<build-machine path>\",\"sha256\":\"<compiler sha256>\",\"version\":\"<complete version output>\"}"
  }
}
```

The values of `compiler_versions` are canonical JSON strings because the
accepted claim-manifest schema exposes a string at that location. They bind
each compiler command to its resolved build-machine path, SHA-256, and complete
version output; supplied metadata lacking any of those four fields is rejected.
The compiler set is exactly `nvcc`, `g++`, and `gcc`; the source set, four
binary paths, binary-to-compile-command mapping, compiler argv, and each
run-stage-to-binary mapping are closed rather than extensible. In every run,
`argv[0]` is the exact repository-relative path of the binary hashed by the
manifest and the remaining arguments are frozen by the claim and stage.

All JSON inputs are parsed fail-closed: duplicate object keys, UTF-8 BOMs,
`NaN`/infinities, non-finite numeric spellings, malformed UTF-8, and trailing
syntax are rejected. Raw stream identities use canonical filenames and exact
byte counts and SHA-256 hashes; absolute, ambiguous, escaping, or symlinked
paths are invalid.

Capture is transactional. Raw streams are first written below ignored
`build/` staging; each is immediately parsed by `tools/claim_audit.py`. A
timeout, nonzero exit, negative token, malformed or merely printed `ACCEPT`,
digest disagreement, missing repeat, changed source, changed `HEAD`, or dirty
worktree rejects the session. The script publishes nothing into this directory
unless all 13 manifests validate together. It also refuses to overwrite any
existing evidence set.

Before the atomic publication step, the same staging transaction derives and
then verifies byte-for-byte these three canonical views of the validated set:

- `validated-claims.json` — the machine-readable 13-row audit table;
- `validated-claims.md` — the Markdown table for review;
- `validated-claims.tex` — the TeX table for manuscript inclusion.

`validate-set` requires those three files to equal a fresh rendering from the
13 validated manifests. They are therefore derived evidence, never manually
maintained placeholders.
