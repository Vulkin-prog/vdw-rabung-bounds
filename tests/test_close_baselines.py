#!/usr/bin/env python3
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "close_baselines", ROOT / "tools" / "close_baselines.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ClosureTests(unittest.TestCase):
    def setUp(self):
        self.result, self.nodes, self.winners, _ = MODULE.closure()

    def winner(self, colors, length):
        return self.nodes[self.winners[("ordinary", colors, length)]]

    def test_direct_claim_arithmetic(self):
        claims = MODULE.load_json(MODULE.CLAIMS_PATH)["claims"]
        for claim in claims:
            self.assertEqual(
                claim["lower_bound"],
                (claim["length"] - 1) * claim["prime"] + 1,
                claim["id"],
            )

    def test_corrected_three_color_bounds(self):
        expected = {
            17: 31385622833,
            18: 33999912468,
            19: 35999998687,
            20: 37999998614,
            21: 39999998541,
            22: 49058715046,
            23: 142741265701,
            24: 252542143876,
            25: 628673328287,
            26: 1221912599848,
            27: 2068976009617,
            28: 2159051058266,
        }
        for length, bound in expected.items():
            self.assertEqual(self.winner(3, length)["lower_bound"], bound)

    def test_priority_switch_occurs_at_22(self):
        for length in range(17, 22):
            self.assertEqual(self.winner(3, length)["method"], "direct_rabung")
        for length in range(22, 29):
            self.assertEqual(self.winner(3, length)["method"], "bct2018")

    def test_bct_nodes_use_largest_prime_not_exceeding_length(self):
        for node in self.nodes.values():
            if node["method"] != "bct2018":
                continue
            expected_q = max(MODULE.primes_up_to(node["length"]))
            self.assertEqual(node["parameters"]["prime_q"], expected_q, node["id"])

    def test_xu_published_w4_7_example_has_no_off_by_one(self):
        # WR(2,7)>617 and W(2,7)>3703 give W(4,7)>617*3703.
        self.assertEqual(MODULE.xu_strict_bound(617, 3703), 2_284_751)

    def test_xu_nodes_store_the_strict_product(self):
        for node in self.nodes.values():
            if node["method"] != "xu2013":
                continue
            ring_parent, ordinary_parent = (
                self.nodes[parent] for parent in node["parents"]
            )
            self.assertEqual(
                node["lower_bound"],
                ring_parent["lower_bound"] * ordinary_parent["lower_bound"],
                node["id"],
            )
            self.assertGreaterEqual(node["parameters"]["t"], 2, node["id"])
            self.assertEqual(
                node["parameters"]["least_prime_factor_n"],
                MODULE.least_prime_factor(node["parameters"]["n"]),
                node["id"],
            )
            self.assertGreater(
                node["parameters"]["least_prime_factor_n"],
                node["length"],
                node["id"],
            )

    def test_least_prime_factor(self):
        self.assertEqual(MODULE.least_prime_factor(2), 2)
        self.assertEqual(MODULE.least_prime_factor(49), 7)
        self.assertEqual(MODULE.least_prime_factor(617), 617)

    def test_registered_ring_witnesses_meet_xu_precondition(self):
        baselines = MODULE.load_json(MODULE.BASELINES_PATH)
        claims = {
            claim["id"]: claim
            for claim in MODULE.load_json(MODULE.CLAIMS_PATH)["claims"]
        }
        for seed in baselines["ring_seeds"]:
            if "claim_id" in seed:
                claim = claims[seed["claim_id"]]
                witness = claim["prime"]
                length = claim["length"]
                label = claim["id"]
            else:
                witness = seed["lower_bound"]
                length = seed["length"]
                label = seed["id"]
            self.assertGreaterEqual(witness, 5, label)
            self.assertGreater(MODULE.least_prime_factor(witness), length, label)


if __name__ == "__main__":
    unittest.main()
