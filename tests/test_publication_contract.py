import contextlib
import hashlib
import importlib.util
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "check_publication_contract", ROOT / "tools" / "check_publication_contract.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def minimal_scope(allowed_paths=None):
    return {
        "allowed_paths": sorted(allowed_paths or ["publication/scope.json"]),
        "schema": "vdw-export-scope/v1",
        "included_scientific_scope": "test fixture",
        "source_policy": "explicit_allowlist",
        "forbidden_prefixes": ["paper2/", "wc/"],
        "forbidden_exact_paths": ["paper/tex/appendix_wc.tex"],
        "forbidden_name_fragments": [".pyc", "__pycache__"],
        "excluded_topics": ["paper 2", "cyclic W_c"],
    }


def minimal_status(overrides=None):
    overrides = overrides or {}
    gates = []
    for gate_id in MODULE.REQUIRED_GATES:
        gates.append({
            "id": gate_id,
            "status": overrides.get(gate_id, "open"),
            "evidence": [f"fixture/{gate_id}.txt"],
            "note": "fixture gate",
        })
    return {
        "schema": "vdw-publication-status/v1",
        "artifact": "fixture",
        "repository_state": "private_preparation",
        "citable_release": False,
        "source": {
            "repository": "owner/source",
            "commit": "1" * 40,
            "commit_date_utc": "2026-01-01T00:00:00Z",
            "export_policy": "explicit_allowlist",
        },
        "allowed_gate_statuses": sorted(MODULE.ALLOWED_GATE_STATUSES),
        "release_gates": gates,
    }


def make_minimal_repository(root: Path, status=None) -> None:
    write_json(root / "STATUS.json", status or minimal_status())
    write_json(root / "publication" / "scope.json", minimal_scope())
    write_json(
        root / "publication" / "external-replication.json",
        {
            "schema": "vdw-external-replication/v1",
            "status": "pending",
            "claim_ids": list(MODULE.EXPECTED_EXTERNAL_CLAIM_ORDER),
            "required_fields_per_claim": ["claim_id"],
            "replications": [],
        },
    )
    (root / "release").mkdir(parents=True, exist_ok=True)
    (root / "release" / "zenodo-metadata.json.in").write_text(
        '{"version": "@@VERSION@@"}\n', encoding="utf-8"
    )
    (root / "CITATION.cff").write_text(
        "cff-version: 1.2.0\ntitle: fixture\n", encoding="utf-8"
    )
    allowed = MODULE.exported_paths(root)
    write_json(root / "publication" / "scope.json", minimal_scope(allowed))


def artifact_identity(root: Path, relative: str) -> dict:
    data = (root / relative).read_bytes()
    return {
        "path": relative,
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
    }


def write_artifact(root: Path, relative: str, data: bytes) -> dict:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return artifact_identity(root, relative)


def passed_gate(gate_id: str) -> dict[str, dict]:
    return {gate_id: {"status": "passed"}}


def make_prime_identity_manifest(root: Path, campaign: dict) -> dict:
    scanner_source = write_artifact(root, "src/scan_gpu.cu", b"scanner source\n")
    independent_source = write_artifact(
        root, "tools/prime_coverage.c", b"independent source\n"
    )
    scanner_binary = write_artifact(
        root, "results/campaign/prime-identity/bin/scanner", b"scanner executable\n"
    )
    independent_binary = write_artifact(
        root,
        "results/campaign/prime-identity/bin/independent",
        b"independent executable\n",
    )
    (root / scanner_binary["path"]).chmod(0o755)
    (root / independent_binary["path"]).chmod(0o755)
    quotient, remainder = divmod(
        MODULE.CAMPAIGN_PRIME_COUNT, MODULE.CAMPAIGN_CHUNK_COUNT
    )
    chunks = []
    stream_bytes = 0
    for chunk_id in range(1, MODULE.CAMPAIGN_CHUNK_COUNT + 1):
        lower, upper = MODULE._expected_chunk(chunk_id)
        count = quotient + (1 if chunk_id <= remainder else 0)
        stdout_bytes = 1000 + chunk_id
        stdout_sha256 = hashlib.sha256(f"stream {chunk_id}\n".encode()).hexdigest()
        common = {
            "exit_code": 0,
            "stderr_bytes": 0,
            "stderr_sha256": MODULE.EMPTY_SHA256,
            "stdout_bytes": stdout_bytes,
            "stdout_sha256": stdout_sha256,
        }
        chunks.append({
            "byte_equal": True,
            "chunk_id": chunk_id,
            "count": count,
            "independent": {
                **common,
                "argv": [independent_binary["path"], "--dump-primes", str(lower), str(upper)],
            },
            "lower_inclusive": lower,
            "scanner": {
                **common,
                "argv": [scanner_binary["path"], "--dump-primes", str(lower), str(upper)],
            },
            "upper_exclusive": upper,
        })
        stream_bytes += stdout_bytes
    manifest = {
        "campaign_manifest": artifact_identity(
            root, "results/campaign/campaign_manifest.json"
        ),
        "chunks": chunks,
        "executables": {
            "independent": {
                "binary": independent_binary,
                "source": independent_source,
            },
            "scanner": {"binary": scanner_binary, "source": scanner_source},
        },
        "interval": MODULE._expected_interval(),
        "schema": MODULE.PRIME_IDENTITY_SCHEMA,
        "totals": {
            "all_byte_equal": True,
            "chunk_count": MODULE.CAMPAIGN_CHUNK_COUNT,
            "prime_count": MODULE.CAMPAIGN_PRIME_COUNT,
            "stream_bytes": stream_bytes,
        },
    }
    write_json(root / "results/campaign/prime_identity_manifest.json", manifest)
    return manifest


def make_cuda_manifest(root: Path) -> dict:
    source_data = {
        "scripts/validate_cuda.sh": b"#!/usr/bin/env bash\nexit 0\n",
        "src/scan_gpu.cu": b"// CUDA scanner fixture\n",
        "tests/gpu/test_scan_sm120.sh": b"#!/usr/bin/env bash\nexit 0\n",
    }
    for relative, data in source_data.items():
        write_artifact(root, relative, data)
    (root / "scripts/validate_cuda.sh").chmod(0o755)
    (root / "tests/gpu/test_scan_sm120.sh").chmod(0o755)
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.name", "fixture"], check=True)
    subprocess.run(
        ["git", "-C", str(root), "config", "user.email", "fixture@example.invalid"],
        check=True,
    )
    subprocess.run(["git", "-C", str(root), "add", "."], check=True)
    subprocess.run(["git", "-C", str(root), "commit", "-qm", "qualification source"], check=True)
    commit = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD"], text=True
    ).strip()
    tree = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD^{tree}"], text=True
    ).strip()

    prefix = "results/release/cuda-qualification/"
    binary = write_artifact(root, prefix + "scan_gpu", b"qualified binary\n")
    (root / binary["path"]).chmod(0o755)
    environment_files = {
        "nvcc-version.txt": b"Cuda compilation tools, release 12.8\n",
        "cuobjdump-version.txt": b"cuobjdump release 12.8\n",
        "gpu-devices.csv": b"0, GPU fixture, GPU-uuid, 12.0, 570.00, 32768\n",
        "kernel.txt": b"Linux fixture\n",
        "nvidia-smi-L.txt": b"GPU 0: GPU fixture (UUID: GPU-uuid)\n",
        "os-release.txt": b"NAME=Fixture\n",
    }
    environment_identities = {
        name: write_artifact(root, prefix + name, data)
        for name, data in environment_files.items()
    }
    stdout = write_artifact(
        root, prefix + "qualification.stdout", b"SCAN_SM120_REGRESSION_OK\n"
    )
    stderr = write_artifact(root, prefix + "qualification.stderr", b"")
    log_identities = [
        write_artifact(root, prefix + "git-commit.txt", (commit + "\n").encode()),
        write_artifact(
            root,
            prefix + "command.txt",
            b"bash tests/gpu/test_scan_sm120.sh\n",
        ),
        write_artifact(root, prefix + "source-sha256.txt", b"source identities\n"),
        write_artifact(root, prefix + "logs/scan.log", b"build log\n"),
    ]
    manifest = {
        "build": {
            "binaries": [binary],
            "command_argv": ["bash", "tests/gpu/test_scan_sm120.sh"],
            "git_commit": commit,
            "git_tree": tree,
            "sources": [artifact_identity(root, path) for path in sorted(source_data)],
            "worktree_clean_before_build": True,
        },
        "environment": {
            "compiler": {
                "identity": "nvcc release 12.8",
                "version_log": environment_identities["nvcc-version.txt"],
            },
            "cuda": {
                "cuobjdump_identity": "cuobjdump release 12.8",
                "cuobjdump_version_log": environment_identities["cuobjdump-version.txt"],
                "version": "12.8",
            },
            "driver": {
                "device_query": environment_identities["gpu-devices.csv"],
                "versions": ["570.00"],
            },
            "gpu": [{
                "compute_capability": "12.0",
                "index": "0",
                "memory_mib": "32768",
                "name": "GPU fixture",
                "uuid": "GPU-uuid",
            }],
            "kernel_log": environment_identities["kernel.txt"],
            "nvidia_smi_inventory": environment_identities["nvidia-smi-L.txt"],
            "os_release": environment_identities["os-release.txt"],
        },
        "finished_utc": "2026-08-28T12:00:01Z",
        "logs": log_identities,
        "qualification": "PASS",
        "schema": MODULE.CUDA_EVIDENCE_SCHEMA,
        "started_utc": "2026-08-28T12:00:00Z",
        "tests": [{
            "command_argv": ["bash", "tests/gpu/test_scan_sm120.sh"],
            "exit_code": 0,
            "id": "scan-sm120-regression",
            "stderr": stderr,
            "stdout": stdout,
            "success_marker": "SCAN_SM120_REGRESSION_OK",
            "success_marker_count": 1,
            "verdict": "PASS",
            "working_directory": ".",
        }],
    }
    write_json(root / prefix / "manifest.json", manifest)
    return manifest


# Use the real recovery producer so contract and producer share one canonical
# campaign schema.
def make_campaign_manifest(root: Path) -> dict:
    import shutil

    from tests.test_campaign_recovery import RecoveryFixture

    fixture = RecoveryFixture(root.parent / f"{root.name}-campaign-recovery")
    inventory = fixture.make_inventory()
    fixture.approve_selection(inventory)
    fixture.import_evidence()
    document, _ = fixture.build()
    shutil.copytree(fixture.publication, root, dirs_exist_ok=True)
    write_artifact(
        root,
        "tools/campaign_recovery.py",
        (ROOT / "tools/campaign_recovery.py").read_bytes(),
    )
    source_map = json.loads(
        (ROOT / "provenance/scanners/campaign-source-map.json").read_text(encoding="utf-8")
    )
    for row in source_map["artifacts"].values():
        write_artifact(root, row["encoded_path"], (ROOT / row["encoded_path"]).read_bytes())
    return document


class PublicationContractTest(unittest.TestCase):
    def test_current_repository_is_an_honest_staging_package(self):
        report = MODULE.audit_repository(ROOT, "staging")
        self.assertEqual(report["errors"], [])
        self.assertEqual(report["verdict"], "BLOCKED")
        codes = {item["code"] for item in report["blockers"]}
        self.assertIn("gate.claim-manifests-13", codes)
        self.assertIn("gate.campaign-archive-515", codes)
        self.assertIn("gate.external-replication-4", codes)

    def test_staging_and_report_accept_incompleteness_but_release_fails(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            make_minimal_repository(root)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(MODULE.main(["--root", str(root), "--mode", "staging"]), 0)
                self.assertEqual(MODULE.main(["--root", str(root), "--mode", "report"]), 0)
                self.assertEqual(MODULE.main(["--root", str(root), "--mode", "release"]), 1)

    def test_forbidden_export_path_is_a_structural_error(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            make_minimal_repository(root)
            forbidden = root / "paper2" / "private-review.txt"
            forbidden.parent.mkdir(parents=True)
            forbidden.write_text("not for export\n", encoding="utf-8")
            report = MODULE.audit_repository(root, "staging")
            errors = {item["code"] for item in report["errors"]}
            self.assertIn("scope.forbidden_path", errors)

    def test_scope_allowlist_rejects_innocent_new_and_stale_paths(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            make_minimal_repository(root)
            (root / "meeting-notes.txt").write_text("unreviewed\n", encoding="utf-8")
            report = MODULE.audit_repository(root, "staging")
            self.assertIn(
                "scope.allowlist_mismatch",
                {item["code"] for item in report["errors"]},
            )

            scope = minimal_scope(MODULE.exported_paths(root))
            scope["allowed_paths"].append("approved-but-missing.txt")
            scope["allowed_paths"].sort()
            write_json(root / "publication" / "scope.json", scope)
            report = MODULE.audit_repository(root, "staging")
            self.assertIn(
                "scope.allowlist_mismatch",
                {item["code"] for item in report["errors"]},
            )

    def test_bibliography_audit_is_bound_to_tex_and_bibtex(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "paper" / "tex").mkdir(parents=True)
            for source in sorted((ROOT / "paper" / "tex").glob("*.tex")):
                (root / "paper" / "tex" / source.name).write_bytes(source.read_bytes())
            (root / "paper" / "references.bib").write_bytes(
                (ROOT / "paper" / "references.bib").read_bytes()
            )
            audit = json.loads(
                (ROOT / "publication" / "bibliography-audit.json").read_text(
                    encoding="utf-8"
                )
            )
            findings = MODULE.Findings()
            MODULE.validate_bibliography_bindings(root, audit, findings)
            self.assertEqual(findings.errors, [])

            with (root / "paper" / "tex" / "main.tex").open("a", encoding="utf-8") as stream:
                stream.write("\\cite{MissingPrimarySource}\n")
            with (root / "paper" / "references.bib").open("a", encoding="utf-8") as stream:
                stream.write("\n@misc{UncitedExtra, title={extra}}\n")
            findings = MODULE.Findings()
            MODULE.validate_bibliography_bindings(root, audit, findings)
            codes = {item["code"] for item in findings.errors}
            self.assertIn("bibliography.tex_ledger", codes)
            self.assertIn("bibliography.bib_ledger", codes)

    def test_source_import_rehashes_imported_derived_and_new_targets(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "src").mkdir(parents=True)
            imported = root / "src" / "imported.py"
            derived = root / "src" / "derived.py"
            new = root / "new.txt"
            imported.write_bytes(b"print('exact')\n")
            derived.write_bytes(b"print('after adaptation')\n")
            new.write_bytes(b"created for publication\n")

            def identity(path: str, data: bytes):
                return {
                    "path": path,
                    "git_blob_sha1": hashlib.sha1(
                        f"blob {len(data)}\0".encode("ascii") + data
                    ).hexdigest(),
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "size": len(data),
                }

            imported_identity = identity("src/imported.py", imported.read_bytes())
            derived_target = identity("src/derived.py", derived.read_bytes())
            derived_source = identity("src/derived.py", b"print('before adaptation')\n")
            new_identity = identity("new.txt", new.read_bytes())
            files = [
                {
                    **new_identity,
                    "classification": "new",
                    "rationale": "publication-only fixture",
                },
                {
                    **derived_target,
                    "classification": "derived",
                    "rationale": "adapted fixture",
                    "source": derived_source,
                },
                {
                    **imported_identity,
                    "classification": "imported",
                    "source": dict(imported_identity),
                },
            ]
            write_json(
                root / "publication" / "source-import.json",
                {
                    "schema": "vdw-source-import/v1",
                    "source": {"repository": "owner/source", "commit": "1" * 40},
                    "files": files,
                    "inventory": {
                        "excluded_directory_names": [
                            ".git", ".pytest_cache", "__pycache__", "build", "dist"
                        ],
                        "excluded_paths": ["MANIFEST.sha256", "publication/source-import.json"],
                    },
                    "omitted_source_files": [],
                    "summary": {
                        "imported": 1,
                        "derived": 1,
                        "new": 1,
                        "omitted_source": 0,
                        "total_present": 3,
                    },
                },
            )
            status = minimal_status()
            findings = MODULE.Findings()
            MODULE.validate_source_import(root, status, minimal_scope(), findings)
            self.assertEqual(findings.errors, [])

            imported.write_bytes(imported.read_bytes() + b"# tampered\n")
            findings = MODULE.Findings()
            MODULE.validate_source_import(root, status, minimal_scope(), findings)
            codes = {item["code"] for item in findings.errors}
            self.assertIn("source_import.hash_mismatch", codes)
            self.assertIn("source_import.target_blob_mismatch", codes)

    def test_source_import_classification_controls_nested_source_identity(self):
        findings = MODULE.Findings()
        target = {
            "path": "x.txt",
            "git_blob_sha1": "1" * 40,
            "sha256": "2" * 64,
            "size": 1,
        }
        # Exercise the exact row-shape policy without needing a full fixture:
        # new has no source, while imported/derived must have one.
        identity_fields = {"git_blob_sha1", "path", "sha256", "size"}
        new_fields = set(identity_fields) | {"classification", "rationale"}
        imported_fields = set(identity_fields) | {"classification", "source"}
        self.assertEqual(
            set({**target, "classification": "new", "rationale": "fixture"}),
            new_fields,
        )
        self.assertEqual(
            set({**target, "classification": "imported", "source": dict(target)}),
            imported_fields,
        )

        # A malformed nested source blob is rejected independently of target
        # bytes; derived files are not required to equal that source identity.
        malformed = dict(target)
        malformed["git_blob_sha1"] = "not-a-blob"
        self.assertIsNone(
            MODULE._source_import_identity(
                malformed, context="derived.source", findings=findings
            )
        )
        self.assertIn("source_import.blob", {item["code"] for item in findings.errors})

    def test_gate_marked_passed_without_evidence_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            status = minimal_status({"ordered-prime-identity-515": "passed"})
            make_minimal_repository(root, status)
            report = MODULE.audit_repository(root, "staging")
            errors = {item["code"] for item in report["errors"]}
            self.assertIn("gate.evidence_missing", errors)
            self.assertIn("prime_identity.missing", errors)

    def test_campaign_manifest_rehashes_515_exact_contiguous_chunks(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            manifest = make_campaign_manifest(root)
            findings = MODULE.Findings()
            MODULE.validate_campaign_evidence(
                root, passed_gate("campaign-archive-515"), findings
            )
            self.assertEqual(findings.errors, [])

            # A count of 515 must not hide a duplicate, a range overlap, an
            # incoherent total, or a tampered referenced object.
            manifest["chunks"][7]["chunk_id"] = 7
            manifest["chunks"][8]["lower_inclusive"] -= 2
            manifest["totals"]["chunk_count"] = 514
            (root / manifest["checkpoint"]["path"]).write_bytes(b"tampered checkpoint\n")
            (root / "provenance/scanners/historical/campaign_ebd54ea.py.base64").write_bytes(
                b"YmFk\n"
            )
            manifest["chunk_7_checkpoint_evidence"]["resolution"] = "journal_assumed"
            manifest["chunk_7_checkpoint_evidence"]["checkpoint_record_sha256"] = "0" * 64
            write_json(root / "results/campaign/campaign_manifest.json", manifest)
            findings = MODULE.Findings()
            MODULE.validate_campaign_evidence(
                root, passed_gate("campaign-archive-515"), findings
            )
            codes = {item["code"] for item in findings.errors}
            self.assertIn("campaign.chunk_duplicate", codes)
            self.assertIn("campaign.chunk_ids", codes)
            self.assertIn("campaign.chunk_range", codes)
            self.assertIn("campaign.checkpoint_artifact.hash_mismatch", codes)
            self.assertIn("campaign.chunk7_driver_hash", codes)
            self.assertIn("campaign.totals", codes)
            self.assertIn("campaign.chunk7", codes)
            self.assertIn("campaign.authoritative_reject", codes)

    def test_campaign_schema_and_artifact_paths_are_closed(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            manifest = make_campaign_manifest(root)
            manifest["unexpected"] = "not permitted"
            write_json(root / "results/campaign/campaign_manifest.json", manifest)
            findings = MODULE.Findings()
            MODULE.validate_campaign_evidence(
                root, passed_gate("campaign-archive-515"), findings
            )
            self.assertIn("campaign.shape", {item["code"] for item in findings.errors})

    def test_prime_identity_binds_campaign_two_binaries_sources_and_byte_streams(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            campaign = make_campaign_manifest(root)
            manifest = make_prime_identity_manifest(root, campaign)
            findings = MODULE.Findings()
            MODULE.validate_prime_identity(
                root,
                passed_gate("ordered-prime-identity-515"),
                findings,
                campaign,
            )
            self.assertEqual(findings.errors, [])

            manifest["chunks"][0]["independent"]["stdout_sha256"] = "f" * 64
            manifest["chunks"][1]["lower_inclusive"] += 2
            manifest["totals"]["prime_count"] -= 1
            binary_path = manifest["executables"]["scanner"]["binary"]["path"]
            (root / binary_path).write_bytes(b"tampered scanner\n")
            write_json(
                root / "results/campaign/prime_identity_manifest.json", manifest
            )
            findings = MODULE.Findings()
            MODULE.validate_prime_identity(
                root,
                passed_gate("ordered-prime-identity-515"),
                findings,
                campaign,
            )
            codes = {item["code"] for item in findings.errors}
            self.assertIn("prime_identity.stream_mismatch", codes)
            self.assertIn("prime_identity.chunk_range", codes)
            self.assertIn("prime_identity.campaign_range", codes)
            self.assertIn("prime_identity.binary.hash_mismatch", codes)
            self.assertIn("prime_identity.totals", codes)
            self.assertIn("prime_identity.known_total", codes)

    def test_prime_identity_rejects_legacy_or_open_schema(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            campaign = make_campaign_manifest(root)
            manifest = make_prime_identity_manifest(root, campaign)
            manifest["schema"] = "vdw-prime-identity/v1"
            manifest["executables"]["scanner"]["source"]["extra"] = True
            write_json(
                root / "results/campaign/prime_identity_manifest.json", manifest
            )
            findings = MODULE.Findings()
            MODULE.validate_prime_identity(
                root,
                passed_gate("ordered-prime-identity-515"),
                findings,
                campaign,
            )
            codes = {item["code"] for item in findings.errors}
            self.assertIn("prime_identity.schema", codes)
            self.assertIn("prime_identity.source.shape", codes)

            manifest["schema"] = MODULE.PRIME_IDENTITY_SCHEMA
            manifest["executables"]["scanner"]["source"].pop("extra")
            manifest["unexpected"] = True
            write_json(
                root / "results/campaign/prime_identity_manifest.json", manifest
            )
            findings = MODULE.Findings()
            MODULE.validate_prime_identity(
                root,
                passed_gate("ordered-prime-identity-515"),
                findings,
                campaign,
            )
            self.assertIn(
                "prime_identity.shape", {item["code"] for item in findings.errors}
            )

    def test_cuda_manifest_rehashes_every_output_and_binds_commit_sources(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            manifest = make_cuda_manifest(root)
            findings = MODULE.Findings()
            MODULE.validate_cuda_evidence(
                root, passed_gate("cuda-release-qualification"), findings
            )
            self.assertEqual(findings.errors, [])

            log = manifest["logs"][0]
            (root / log["path"]).write_bytes(b"tampered log\n")
            manifest["build"]["git_tree"] = "f" * 40
            manifest["tests"][0]["success_marker_count"] = 2
            write_json(
                root / "results/release/cuda-qualification/manifest.json", manifest
            )
            findings = MODULE.Findings()
            MODULE.validate_cuda_evidence(
                root, passed_gate("cuda-release-qualification"), findings
            )
            codes = {item["code"] for item in findings.errors}
            self.assertIn("cuda.log.hash_mismatch", codes)
            self.assertIn("cuda.tree_mismatch", codes)
            self.assertIn("cuda.success_marker", codes)

    def test_cuda_manifest_rejects_extra_schema_fields_and_unsigned_logs(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            manifest = make_cuda_manifest(root)
            manifest["unexpected"] = True
            write_json(
                root / "results/release/cuda-qualification/manifest.json", manifest
            )
            findings = MODULE.Findings()
            MODULE.validate_cuda_evidence(
                root, passed_gate("cuda-release-qualification"), findings
            )
            self.assertIn("cuda.shape", {item["code"] for item in findings.errors})

            manifest.pop("unexpected")
            write_artifact(
                root,
                "results/release/cuda-qualification/logs/unlisted.log",
                b"not in manifest\n",
            )
            write_json(
                root / "results/release/cuda-qualification/manifest.json", manifest
            )
            findings = MODULE.Findings()
            MODULE.validate_cuda_evidence(
                root, passed_gate("cuda-release-qualification"), findings
            )
            self.assertIn(
                "cuda.artifact_coverage", {item["code"] for item in findings.errors}
            )

    def test_external_replication_requires_four_stable_distinct_operator_ids(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_artifact(
                root,
                "tools/external_replication.py",
                (ROOT / "tools/external_replication.py").read_bytes(),
            )
            rows = []
            for index, claim_id in enumerate(MODULE.EXPECTED_EXTERNAL_CLAIM_ORDER):
                verifier = write_artifact(
                    root,
                    f"results/external-replication/operator-{index}/verify_claim",
                    f"verifier {index}\n".encode(),
                )
                stdout = write_artifact(
                    root,
                    f"results/external-replication/operator-{index}/stdout.txt",
                    b"PASS\n",
                )
                stderr = write_artifact(
                    root,
                    f"results/external-replication/operator-{index}/stderr.txt",
                    b"",
                )
                rows.append({
                    "candidate_git_commit": "1" * 40,
                    "claim_id": claim_id,
                    "command_argv": [verifier["path"], claim_id],
                    "environment": {"host": f"external-{index}"},
                    "exit_code": 0,
                    "operator_attestation": f"Operator ID: same-operator\nClaim: {claim_id}\n",
                    "operator_id": "same-operator",
                    "stderr_path": stderr["path"],
                    "stderr_sha256": stderr["sha256"],
                    "stdout_path": stdout["path"],
                    "stdout_sha256": stdout["sha256"],
                    "verdict": "PASS",
                    "verifier_path": verifier["path"],
                    "verifier_sha256": verifier["sha256"],
                })
            ledger = {
                "claim_ids": list(MODULE.EXPECTED_EXTERNAL_CLAIM_ORDER),
                "replications": rows,
                "required_fields_per_claim": list(MODULE.EXTERNAL_REQUIRED_FIELDS),
                "schema": "vdw-external-replication/v1",
                "status": "passed",
            }
            write_json(root / "publication/external-replication.json", ledger)
            findings = MODULE.Findings()
            MODULE.validate_external_evidence(
                root, passed_gate("external-replication-4"), findings
            )
            self.assertIn(
                "external.operator_id_distinct",
                {item["code"] for item in findings.errors},
            )
            self.assertIn(
                "external.authoritative_reject",
                {item["code"] for item in findings.errors},
            )

            ledger["replications"][0]["operator_id"] = "bad id"
            write_json(root / "publication/external-replication.json", ledger)
            findings = MODULE.Findings()
            MODULE.validate_external_evidence(
                root, passed_gate("external-replication-4"), findings
            )
            self.assertIn("external.operator_id", {item["code"] for item in findings.errors})

    def test_duplicate_json_keys_fail_closed(self):
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "duplicate.json"
            path.write_text('{"a": 1, "a": 2}\n', encoding="utf-8")
            with self.assertRaises(MODULE.ContractDataError):
                MODULE.load_json(path)

    def test_passed_doi_gate_calls_authoritative_structural_freeze(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "tools").mkdir(parents=True)
            (root / "release").mkdir()
            (root / "paper").mkdir()
            (root / "tools" / "freeze_release.py").write_text(
                "import sys\nprint('fixture freeze rejection', file=sys.stderr)\nraise SystemExit(3)\n",
                encoding="utf-8",
            )
            for relative in (
                "MANIFEST.sha256",
                "paper/main.pdf",
                "release/zenodo-metadata.json",
            ):
                (root / relative).write_bytes(b"fixture\n")
            (root / "CITATION.cff").write_text(
                "version: 1.0.0\ndate-released: 2026-08-28\ndoi: 10.1/test\n",
                encoding="utf-8",
            )
            findings = MODULE.Findings()
            MODULE.validate_release_metadata(
                root,
                {"doi-tag-archive-freeze": {"status": "passed"}},
                findings,
            )
            self.assertIn(
                "release.freeze_authoritative",
                {item["code"] for item in findings.errors},
            )


if __name__ == "__main__":
    unittest.main()
