# Third-party material status

No third-party source tree, binary, PDF, HTML capture, archived result table,
or prime-count data file is included in this preparation repository.
`external/` is excluded by the machine-checked publication scope.

The paper uses factual bibliographic metadata and source locators.  The audited
locators, immutable versions, and observed hashes are recorded in
`publication/bibliography-audit.json`.  Numerical baseline provenance is
recorded separately in `publication/baseline-provenance.json`.  In particular:

- Daniel Monroe's author-owned projects-page revision is identified by commit
  `825778cca5e669cbf60140e35170113603010076`; the observed HTML SHA-256 is
  `9ac30412b14f1e7f9f890fdb0d53cafc9e1ab5591fe10c59b71bcb7f53b5a23c`.
- The archived BOINC phase-2 table is cited by its Internet Archive locator and
  upstream hash, but the table itself is not redistributed here.
- Tomás Oliveira e Silva's prime-count table is cited by a byte-specific
  archival locator and SHA-256
  `0b1ee293cbdf18a4e1b0bc9c8e02a00d71cff166811623b7317615c871c89b06`;
  the data file itself is not redistributed here.
- Monroe's upstream code tally is identified by source-repository commit, Git
  blob, and SHA-256, but is not copied into this repository.

The historical scanner and campaign-driver sources under
`provenance/scanners/` originate in the author's pinned private source
repository.  They are original project material, not third-party imports, and
remain subject to the outbound licence decision in `RIGHTS-STATUS.md`.

If any verbatim third-party object is proposed for the final package, record
its author, source URL, capture date, exact SHA-256, observed licence,
modifications, and redistribution decision here before adding the file.
