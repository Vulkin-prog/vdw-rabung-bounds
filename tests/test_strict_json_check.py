import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "strict_json_check", ROOT / "tools" / "strict_json_check.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class StrictJSONTest(unittest.TestCase):
    def load_bytes(self, data: bytes):
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "value.json"
            path.write_bytes(data)
            return MODULE.load_strict(path)

    def test_normal_json_is_accepted(self):
        self.assertEqual(self.load_bytes(b'{"a": [1, 2.5, true]}\n'), {"a": [1, 2.5, True]})

    def test_duplicate_and_nonfinite_values_are_rejected(self):
        for raw in (b'{"a": 1, "a": 2}\n', b'{"a": NaN}\n', b'{"a": Infinity}\n'):
            with self.subTest(raw=raw):
                with self.assertRaises(MODULE.StrictJSONError):
                    self.load_bytes(raw)

    def test_bom_surrogate_and_large_integer_are_rejected(self):
        for raw in (
            b'\xef\xbb\xbf{}\n',
            b'{"a": "\\ud800"}\n',
            b'{"a": 18446744073709551616}\n',
        ):
            with self.subTest(raw=raw):
                with self.assertRaises((MODULE.StrictJSONError, UnicodeDecodeError)):
                    self.load_bytes(raw)

    def test_exact_mathematical_integer_can_be_opted_in(self):
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "closure.json"
            path.write_bytes(b'{"bound": 326367112801923710186}\n')
            value = MODULE.load_strict(path, allow_arbitrary_integers=True)
        self.assertEqual(value["bound"], 326367112801923710186)


if __name__ == "__main__":
    unittest.main()
