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
        ):
            self.assertNotIn(forbidden, lowered)

    def test_corrected_recurrence_bounds_are_present(self):
        table = (TEX / "generated_bounds_table.tex").read_text(encoding="utf-8")
        self.assertIn(r"22 & $1\,999\,999\,927$ & $41\,999\,998\,468$ & $49\,058\,715\,046$", table)
        self.assertIn(r"25 & $1\,999\,999\,927$ & $47\,999\,998\,249$ & $628\,673\,328\,287$", table)
        self.assertIn(r"W(3,28) &> 2\,159\,051\,058\,266", self.sources)

    def test_bounds_table_is_generated_not_retyped(self):
        bounds = (TEX / "sec4_bounds.tex").read_text(encoding="utf-8")
        self.assertIn(r"\input{generated_bounds_table}", bounds)
        self.assertNotIn(r"41\,999\,998\,468", bounds)

    def test_validated_claim_table_is_optional_and_copied_by_builder(self):
        bounds = (TEX / "sec4_bounds.tex").read_text(encoding="utf-8")
        self.assertIn(r"\IfFileExists{generated_validated_claims.tex}", bounds)
        self.assertIn(r"\input{generated_validated_claims}", bounds)
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
            r"\input{sec6_prereg}",
            r"\input{sec5_density}",
            r"\input{sec6_conclusion}",
            r"\input{sec7_data}",
            r"\input{appendix_bstar}",
            r"\input{appendix_density}",
        )
        positions = [main.index(item) for item in ordered_inputs]
        self.assertEqual(positions, sorted(positions))
        self.assertTrue((TEX / "sec6_conclusion.tex").is_file())
        self.assertTrue((TEX / "appendix_density.tex").is_file())

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
