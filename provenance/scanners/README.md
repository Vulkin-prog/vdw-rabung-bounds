# Historical campaign sources

The 515 chunks were executed across eight Git revisions, four distinct
`scan_gpu.cu` blobs, and seven distinct `campaign.py` driver blobs. All eleven
historical source blobs are stored here as Base64 so their original bytes are
preserved even when a text transport normalizes decomposed Unicode codepoints.
The Base64 payload is the preservation object; a visually similar decoded file
with a different Git blob identity is not an acceptable substitute.

Validate the payloads without writing decoded files:

```bash
python3 tools/materialize_historical_sources.py --check
```

Materialize exact decoded sources into a separate directory when needed:

```bash
python3 tools/materialize_historical_sources.py --output-dir /tmp/vdw-historical
```

`campaign-source-map.json` binds every revision to both the scanner and driver
blob. It does not claim that historical binaries can be rebuilt identically;
compiler and binary identities were not preserved for all revisions.
