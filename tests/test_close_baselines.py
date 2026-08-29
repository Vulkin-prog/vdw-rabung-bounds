#!/usr/bin/env python3
import importlib.util
import json
import math
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
            24: 1082646556499,
            25: 1082646556499,
            26: 1221912599848,
            27: 2068976009617,
            28: 2159051058266,
        }
        for length, bound in expected.items():
            self.assertEqual(self.winner(3, length)["lower_bound"], bound)

    def test_winning_method_switches_are_explicit(self):
        for length in range(17, 22):
            self.assertEqual(self.winner(3, length)["method"], "direct_rabung")
        for length in (22, 23, 26, 27, 28):
            self.assertEqual(self.winner(3, length)["method"], "bct2018")
        self.assertEqual(self.winner(3, 24)["method"], "published_seed")
        self.assertEqual(self.winner(3, 25)["method"], "length_monotonicity")

    def test_berlekamp_specialization_and_length_monotonicity(self):
        expected = 23 * (3**23 - 1) // 2
        self.assertEqual(expected, 1_082_646_556_499)
        at_24 = self.winner(3, 24)
        at_25 = self.winner(3, 25)
        self.assertEqual(at_24["source"], "berlekamp1968")
        self.assertEqual(at_24["lower_bound"], expected)
        self.assertEqual(at_25["parents"], [at_24["id"]])
        self.assertEqual(at_25["lower_bound"], expected)

    def test_all_registered_berlekamp_specializations_are_exact(self):
        baselines = MODULE.load_json(MODULE.BASELINES_PATH)
        seeds = [
            seed for seed in baselines["ordinary_seeds"]
            if seed.get("source") == "berlekamp1968"
        ]
        self.assertEqual([seed["length"] for seed in seeds], list(range(12, 29)))
        for seed in seeds:
            parameters = seed["parameters"]
            t = parameters["berlekamp_t"]
            denominator = parameters["condition_denominator"]
            self.assertEqual(t, seed["length"] - 1, seed["id"])
            self.assertEqual(
                seed["lower_bound"],
                t * (3**t - 1) // denominator,
                seed["id"],
            )
            self.assertEqual(
                denominator,
                MODULE.berlekamp_condition_denominator(t, 3),
                seed["id"],
            )

    def test_pre_range_berlekamp_bound_is_not_truncated(self):
        earlier = [
            (MODULE.berlekamp_strict_bound(t, 3), t)
            for t in range(2, 11)
        ]
        self.assertEqual(max(earlier), (7_651, 7))
        self.assertLess(max(earlier)[0], 974_303)
        at_12 = [
            node for node in self.nodes.values()
            if node["kind"] == "ordinary"
            and node["colors"] == 3
            and node["length"] == 12
            and node["source"] == "berlekamp1968"
        ]
        self.assertEqual(len(at_12), 1)
        self.assertEqual(at_12[0]["lower_bound"], 974_303)

    def test_prewindow_three_color_priority_seeds_are_exact_and_dominated(self):
        expected = {
            "rabung_lotts_w3_12": (12, 7_194_013, 79_134_144),
            "monroe_v1_w3_13": (13, 20_940_193, 251_282_317),
            "monroe_v1_w3_14": (14, 51_481_237, 669_256_082),
            "monroe_v1_w3_15": (15, 160_782_877, 2_250_960_279),
            "monroe_v1_w3_16": (16, 478_698_307, 7_180_474_606),
            "monroe_v4_w3_16": (16, 612_400_081, 9_186_001_216),
        }
        baselines = MODULE.load_json(MODULE.BASELINES_PATH)
        by_id = {
            seed["id"]: seed
            for seed in baselines["ordinary_seeds"]
            if seed.get("id") in expected
        }
        self.assertEqual(set(by_id), set(expected))
        for seed_id, (length, prime, bound) in expected.items():
            seed = by_id[seed_id]
            self.assertEqual(seed["parameters"]["rabung_prime"], prime)
            self.assertEqual(seed["lower_bound"], (length - 1) * prime + 1)
            self.assertEqual(seed["lower_bound"], bound)
            self.assertEqual(MODULE.least_prime_factor(prime), prime)

        for length, bound, source in (
            (12, 79_134_144, "rabunglotts2012"),
            (13, 251_282_317, "monroe2016v1"),
            (14, 669_256_082, "monroe2016v1"),
            (15, 2_250_960_279, "monroe2016v1"),
            (16, 9_186_001_216, "monroe2017v4"),
        ):
            winner = self.winner(3, length)
            self.assertEqual(winner["lower_bound"], bound)
            self.assertEqual(winner["source"], source)
        self.assertGreater(self.winner(3, 17)["lower_bound"], 9_186_001_216)

    def test_registered_cfs_specializations_are_exact_and_dominated(self):
        baselines = MODULE.load_json(MODULE.BASELINES_PATH)
        seeds = [
            seed for seed in baselines["ordinary_seeds"]
            if seed.get("source") == "cfs2026"
        ]
        self.assertEqual([seed["length"] for seed in seeds], list(range(17, 29)))
        for seed in seeds:
            factors = seed["parameters"]["distinct_primes"]
            self.assertEqual(len(factors), len(set(factors)), seed["id"])
            self.assertEqual(sum(factors), seed["length"] - 1, seed["id"])
            self.assertEqual(
                seed["lower_bound"],
                (seed["length"] - 1) * math.prod(2**p - 1 for p in factors),
                seed["id"],
            )
            maximal_bound, maximal_factors = MODULE.cfs_max_product_specialization(
                seed["length"]
            )
            self.assertEqual(seed["lower_bound"], maximal_bound, seed["id"])
            self.assertEqual(tuple(factors), maximal_factors, seed["id"])
            self.assertGreater(
                self.winner(2, seed["length"])["lower_bound"],
                seed["lower_bound"],
            )

    def test_registered_gasarch_haeupler_family_is_exact_and_dominated(self):
        baselines = MODULE.load_json(MODULE.BASELINES_PATH)
        seeds = [
            seed for seed in baselines["ordinary_seeds"]
            if seed.get("source") == "gasarch2011"
        ]
        self.assertEqual([seed["length"] for seed in seeds], list(range(17, 29)))
        for seed in seeds:
            self.assertEqual(
                seed["lower_bound"],
                MODULE.gasarch_haeupler_strict_bound(seed["length"], 3),
                seed["id"],
            )
            self.assertGreater(
                self.winner(3, seed["length"])["lower_bound"],
                seed["lower_bound"],
                seed["id"],
            )

    def test_liang_rows_keep_original_priority_provenance(self):
        baselines = MODULE.load_json(MODULE.BASELINES_PATH)
        for key in ("ordinary_seeds", "ring_seeds"):
            liang = [
                seed for seed in baselines[key]
                if seed.get("source") == "liang2012"
            ]
            expected_lengths = (
                list(range(12, 24))
                if key == "ordinary_seeds"
                else list(range(13, 24))
            )
            self.assertEqual([seed["length"] for seed in liang], expected_lengths)
            monroe = [
                seed for seed in baselines[key]
                if seed.get("colors") == 2
                and seed.get("source") in {"monroe2016v1", "monroe2017v4"}
            ]
            self.assertEqual([seed["length"] for seed in monroe], list(range(21, 26)))
            by_length = {seed["length"]: seed["source"] for seed in monroe}
            for length in range(21, 24):
                self.assertEqual(by_length[length], "monroe2016v1")
            for length in range(24, 26):
                self.assertEqual(by_length[length], "monroe2017v4")

        ordinary = {
            seed["length"]: seed["lower_bound"]
            for seed in baselines["ordinary_seeds"]
            if seed.get("source") == "liang2012"
        }
        ring = {
            seed["length"]: seed["lower_bound"]
            for seed in baselines["ring_seeds"]
            if seed.get("source") == "liang2012"
        }
        self.assertEqual(set(ordinary), set(range(12, 24)))
        self.assertEqual(set(ring), set(range(13, 24)))
        self.assertEqual(ordinary[12], 2 * (12 - 1) * 29_033 + 1)
        for length in ring:
            self.assertEqual(ordinary[length], (length - 1) * ring[length] + 1)

    def test_unverified_landman_statement_is_not_a_seed(self):
        baselines = MODULE.load_json(MODULE.BASELINES_PATH)
        self.assertNotIn("landman", json.dumps(baselines).lower())

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
            self.assertGreaterEqual(node["parameters"]["t"], 1, node["id"])
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

    def test_xu_t_one_specializations_are_included_and_dominated(self):
        t_one = [
            node for node in self.nodes.values()
            if node["method"] == "xu2013" and node["parameters"]["t"] == 1
        ]
        self.assertTrue(t_one)
        for node in t_one:
            ring_parent, ordinary_parent = (
                self.nodes[parent] for parent in node["parents"]
            )
            self.assertEqual(ordinary_parent["colors"], 1, node["id"])
            self.assertEqual(
                node["lower_bound"],
                ring_parent["lower_bound"] * (node["length"] - 1),
                node["id"],
            )
            self.assertGreaterEqual(
                self.winner(node["colors"], node["length"])["lower_bound"],
                node["lower_bound"],
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
