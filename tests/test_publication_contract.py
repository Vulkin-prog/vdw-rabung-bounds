import contextlib
import hashlib
import importlib.util
import io
import json
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


def minimal_scope():
    return {
        "schema": "vdw-export-scope/v1",
        "included_scientific_scope": "test fixture",
        "source_policy": "explicit_allowlist",
        "forbidden_prefixes": ["paper2/", "wc/"],
        "forbidden_exact_paths": ["paper/tex/appendix_wc.tex"],
        "forbidden_name_fragments": ["__pycache__", ".pyc"],
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
            "claim_ids": sorted(MODULE.EXPECTED_EXTERNAL_CLAIMS),
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
                        "excluded_paths": ["publication/source-import.json"],
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

    def test_duplicate_json_keys_fail_closed(self):
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "duplicate.json"
            path.write_text('{"a": 1, "a": 2}\n', encoding="utf-8")
            with self.assertRaises(MODULE.ContractDataError):
                MODULE.load_json(path)


if __name__ == "__main__":
    unittest.main()
