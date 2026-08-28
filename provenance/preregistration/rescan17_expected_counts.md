# Pre-run independent counts for the 17-chunk re-scan

This focused provenance record replaces a dependency on the excluded internal
`paper2/audit_log.md`. It preserves only the values needed by the public
aggregate re-scan audit.

Source identity:

- repository: `Vulkin-prog/vdw-gpu-starter`
- commit: `30e8b83df3c04cc06026983245c0db2cdabc52f2`
- source path: `paper2/audit_log.md`
- source Git blob: `554c858947f7eed46f0542cfe0c541eaafeb8c09`
- source lines: 783–790 in that immutable blob
- timing statement in source: the totals were recorded for comparison while
  the replacement 17-chunk GPU run was still in progress

Registered interval and counts:

- interval: `[970000000, 1004000000)`
- total primes / `r=2`: `1641614`
- `r=3`: `821005`
- `r=4`: `820559`
- `r=5`: `410333`
- `r=6`: `821005`
- `r=7`: `273695`
- `r=8`: `410485`
- `r=9`: `273955`

This excerpt establishes provenance of the registered expected counts. The
actual transcript comparison is performed by `tools/rescan17_audit.py`; it
does not establish per-chunk or ordered-prime identity.
