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


if __name__ == "__main__":
    unittest.main()
