import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEX = ROOT / "paper" / "tex"


class ManuscriptClaimRegressionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sources = "\n".join(
            path.read_text(encoding="utf-8")
            for path in sorted(TEX.glob("*.tex"))
        )

    def test_false_priority_phrases_are_absent(self):
        lowered = self.sources.lower()
        for forbidden in (
            "clean records",
            "from any method",
            "three independent implementations",
            "first publicly checkable confirmation",
            "conjecturally final",
            "[repository url to be inserted at submission]",
            "release manifests are not yet populated",
            "release manifest pending",
            "committed before",
            "b7afe3a79de1",
        ):
            self.assertNotIn(forbidden, lowered)

    def test_current_narrative_has_no_stale_capture_status(self):
        current_narrative_paths = (
            ROOT / "REPRODUCIBILITY.md",
        )
        combined = "\n".join(
            path.read_text(encoding="utf-8") for path in current_narrative_paths
        ).lower()
        self.assertNotIn("release manifest pending", combined)
        self.assertNotIn("b7afe3a79de1ff17c2051caadb6a3bf7", combined)

    def test_capture_time_claim_credit_remains_bound_to_the_manifests(self):
        evidence_readme = (
            ROOT / "results" / "claims" / "README.md"
        ).read_text(encoding="utf-8")
        self.assertIn("capture-time suffix", evidence_readme)
        self.assertIn("`release manifest pending`", evidence_readme)
        registry = json.loads(
            (ROOT / "audit" / "claims.json").read_text(encoding="utf-8")
        )
        monroe_claims = [
            claim for claim in registry["claims"]
            if claim["origin"].startswith("monroe_phase2_archive")
        ]
        self.assertEqual(len(monroe_claims), 4)
        for claim in monroe_claims:
            manifest = json.loads(
                (
                    ROOT / "results" / "claims" / claim["id"] / "manifest.json"
                ).read_text(encoding="utf-8")
            )
            self.assertEqual(manifest["claim"], claim)
            self.assertTrue(
                claim["priority_credit"].endswith("; release manifest pending")
            )

    def test_corrected_recurrence_bounds_are_present(self):
        table = (TEX / "generated_bounds_table.tex").read_text(encoding="utf-8")
        self.assertIn(r"22 & $1\,999\,999\,927$ & $41\,999\,998\,468$ & $49\,058\,715\,046$", table)
        self.assertIn(r"24 & $1\,999\,999\,927$ & $45\,999\,998\,322$ & $1\,082\,646\,556\,499$", table)
        self.assertIn(r"25 & $1\,999\,999\,927$ & $47\,999\,998\,249$ & $1\,082\,646\,556\,499$", table)
        self.assertIn(r"W(3,28) &> 2\,159\,051\,058\,266", self.sources)

    def test_priority_audit_language_is_conservative(self):
        lowered = self.sources.lower()
        self.assertIn("no earlier public source was located", lowered)
        self.assertIn("does not establish global priority", lowered)
        self.assertIn("excluded from the numerical registry", lowered)
        self.assertNotIn("priority remains monroe's", lowered)

    def test_bounds_table_is_generated_not_retyped(self):
        bounds = (TEX / "sec4_bounds.tex").read_text(encoding="utf-8")
        self.assertIn(r"\input{generated_bounds_table}", bounds)
        self.assertNotIn(r"41\,999\,998\,468", bounds)

    def test_validated_claim_table_is_optional_and_copied_by_builder(self):
        bounds = (TEX / "sec4_bounds.tex").read_text(encoding="utf-8")
        self.assertIn(r"\IfFileExists{generated_validated_claims.tex}", bounds)
        appendix = (TEX / "appendix_certificates.tex").read_text(encoding="utf-8")
        self.assertIn(r"\input{generated_validated_claims}", appendix)
        self.assertIn(r"\ref{s:certificate-evidence}", bounds)
        self.assertIn("Validated-claim table unavailable in this build", bounds)
        self.assertNotIn("Pending validated-claim table", bounds)
        self.assertNotIn("staging build", bounds)
        builder = (ROOT / "scripts" / "build_paper.sh").read_text(encoding="utf-8")
        self.assertIn("results/claims/validated-claims.tex", builder)
        self.assertIn("tools/claim_audit.py", builder)
        self.assertIn('validate-set "$REPOSITORY_ROOT/results/claims"', builder)
        self.assertIn('--repository-root "$REPOSITORY_ROOT"', builder)
        self.assertIn('"$build_dir/tex/generated_validated_claims.tex"', builder)
        self.assertLess(
            builder.index('validate-set "$REPOSITORY_ROOT/results/claims"'),
            builder.index('cp -- "$validated_claims_table"'),
        )

    def test_narrative_contract_and_section_order(self):
        main = (TEX / "main.tex").read_text(encoding="utf-8")
        self.assertIn(
            r"\title{Succinct Rabung certificates and recurrence-closed\\"
            "\n"
            r"lower bounds for van der Waerden numbers}",
            main,
        )
        ordered_inputs = (
            r"\input{sec1_intro}",
            r"\input{sec4_bounds}",
            r"\input{sec2_method}",
            r"\input{sec3_campaign}",
            r"\input{sec6_conclusion}",
            r"\input{sec7_data}",
            r"\appendix",
            r"\input{sec6_prereg}",
            r"\input{sec5_density}",
            r"\input{appendix_density}",
        )
        positions = [main.index(item) for item in ordered_inputs]
        self.assertEqual(positions, sorted(positions))
        self.assertTrue((TEX / "sec6_conclusion.tex").is_file())
        self.assertTrue((TEX / "appendix_density.tex").is_file())
        method = (TEX / "sec2_method.tex").read_text(encoding="utf-8")
        self.assertLess(
            method.index(r"\input{appendix_bstar}"),
            method.index(r"\subsection{Finite oracle audit"),
        )

    def test_discovery_proof_and_ai_boundaries_are_explicit(self):
        campaign = (TEX / "sec3_campaign.tex").read_text(encoding="utf-8")
        disclosure = (TEX / "sec8_disclosure.tex").read_text(encoding="utf-8")
        self.assertIn("No lower bound follows from a scanner verdict alone", campaign)
        self.assertIn("all original\ncomputational code for the project", disclosure)
        self.assertIn("sole exception", disclosure)
        self.assertIn("pre-existing code recovered from Daniel Monroe", disclosure)
        for obsolete in (
            "stand-alone independent verifier",
            "principal independent checks",
            "independent verifier on the four headline",
            "historical independent checks",
        ):
            self.assertNotIn(obsolete, self.sources)


if __name__ == "__main__":
    unittest.main()
