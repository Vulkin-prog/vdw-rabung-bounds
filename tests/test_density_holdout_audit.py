#!/usr/bin/env python3
import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "density_holdout_audit", ROOT / "tools" / "density_holdout_audit.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class DensityHoldoutAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.events, cls.digests = MODULE.load_events()
        cls.report, cls.rows = MODULE.build_report()

    def assertClose(self, actual, expected, tolerance=1.0e-10):
        self.assertAlmostEqual(actual, expected, delta=tolerance)

    def test_versioned_event_identity_and_validation(self):
        self.assertEqual(len(self.events), 1859)
        self.assertEqual(self.events[0], 970019599)
        self.assertEqual(self.events[-1], 1961601427)
        self.assertEqual(
            self.digests["git_blob_sha1"],
            "9bb530be18006a6c992d107ee092ffbe2aaafeb4",
        )
        self.assertEqual(
            self.digests["sha256"],
            "fee301d24213e021e276de09d33ba59b0d65f1ee8c4650359d0425e4bc6a0c32",
        )

    def test_training_holdout_and_disjoint_counts(self):
        campaign = self.report["campaign"]
        self.assertEqual(campaign["training_observed"], 1727)
        self.assertEqual(campaign["holdout_chunk_count"], 335)
        self.assertEqual(campaign["holdout_observed"], 132)
        self.assertEqual(
            [increment["observed"] for increment in self.report["increments"]],
            [90, 20, 16, 6],
        )

    def test_full_boundary_increment_means(self):
        expected = (
            (68.35059885449490, 80.26472432872380, 122.19858988596982),
            (18.74983594528852, 24.04420378521979, 57.06260099209342),
            (12.57912881161113, 18.58951825419927, 88.86671194608586),
            (2.807210288159953, 5.820887119232712, 90.04054630086986),
        )
        for increment, wanted in zip(self.report["increments"], expected):
            actual = (
                increment["mu_bare"],
                increment["mu_decaying"],
                increment["mu_constant_floor"],
            )
            for value, target in zip(actual, wanted):
                self.assertClose(value, target)

        totals = self.report["totals"]
        self.assertClose(totals["mu_bare"], 102.48677389955450)
        self.assertClose(totals["mu_decaying"], 128.71933348737556)
        self.assertClose(totals["mu_constant_floor"], 358.16844912501900)

    def test_simpson_panel_convergence_at_increment_boundaries(self):
        for chunk in (181, 250, 251, 300, 301, 400, 401, 515):
            coarse = MODULE.integrate_chunk(chunk, panels=16)
            retained = MODULE.integrate_chunk(chunk, panels=32)
            for left, right in zip(coarse, retained):
                self.assertClose(left, right, tolerance=1.0e-12)

    def test_fixed_model_diagnostics(self):
        diagnostics = self.report["diagnostics_for_frozen_decaying_model"]
        self.assertClose(diagnostics["pearson"]["statistic"], 324.1541417302614)
        self.assertClose(
            diagnostics["pearson"]["fixed_model_scale_statistic_over_chunk_count"],
            0.9676243036724221,
        )
        self.assertClose(
            diagnostics["poisson_deviance"]["statistic"], 210.45603652290296
        )
        ljung_box = diagnostics["ljung_box_pearson_residuals"]
        self.assertClose(ljung_box["statistic"], 7.173825561964949)
        self.assertClose(ljung_box["conditional_chi_square_p_value"], 0.845915785995608)

    def test_block_scales_include_last_partial_block(self):
        expected = {
            5: (67, 5, 0.8079350408565844),
            10: (34, 5, 0.9608290265329785),
            20: (17, 15, 1.0499165913960606),
            25: (14, 10, 0.9346386431752917),
            50: (7, 35, 0.47302776123198764),
        }
        blocks = self.report["diagnostics_for_frozen_decaying_model"]["block_pearson"]
        for block in blocks:
            count, last_length, scale = expected[block["block_length"]]
            self.assertEqual(block["block_count"], count)
            self.assertEqual(block["last_block_length"], last_length)
            self.assertClose(block["scale_statistic_over_block_count"], scale)

    def test_nb2_boundary_is_not_an_optimizer_epsilon(self):
        nb2 = self.report["diagnostics_for_frozen_decaying_model"]["nb2_sensitivity"]
        self.assertEqual(nb2["status"], "Poisson boundary")
        self.assertEqual(nb2["alpha_hat"], 0.0)
        self.assertClose(nb2["score_at_alpha_zero"], -6.477800585088103)
        self.assertLess(
            nb2["profile_grid"]["best_log_likelihood_delta_from_poisson"], 0.0
        )

    def test_moving_block_bootstrap_is_seeded_and_reproducible(self):
        bootstrap = self.report["diagnostics_for_frozen_decaying_model"][
            "moving_block_log_score_sensitivity"
        ]
        self.assertEqual(bootstrap["seed"], 20260803)
        self.assertEqual(bootstrap["replicates"], 20000)
        bare = bootstrap["summaries"]["decaying_minus_bare"]
        floor = bootstrap["summaries"]["decaying_minus_constant_floor"]
        self.assertClose(bare["observed_mean"], 0.011849376013381888)
        self.assertClose(bare["percentile_95_interval"][0], -0.005087245865772968)
        self.assertClose(bare["percentile_95_interval"][1], 0.02957376137421048)
        self.assertClose(bare["bootstrap_probability_nonpositive"], 0.092)
        self.assertClose(floor["observed_mean"], 0.40231724302045624)
        self.assertGreater(floor["percentile_95_interval"][0], 0.0)
        self.assertEqual(floor["bootstrap_probability_nonpositive"], 0.0)

    def test_operational_and_theoretical_lambda_sensitivity_is_recorded(self):
        models = self.report["models"]
        self.assertEqual(models["operational_lambda"], "p/3^17")
        self.assertEqual(models["natural_theoretical_lambda"], "(p-1)/3^17")
        sensitivity = models["formula_sensitivity"]
        self.assertLess(sensitivity["maximum_absolute_total_difference"], 9.0e-7)
        self.assertEqual(sensitivity["printed_table_effect"], "none at two decimal places")

    def test_generated_artifacts_are_current(self):
        expected = {
            MODULE.OUT_JSON: MODULE.render_json(self.report),
            MODULE.OUT_CSV: MODULE.render_csv(self.rows),
            MODULE.OUT_TEX: MODULE.render_tex(self.report),
        }
        for path, content in expected.items():
            self.assertTrue(path.exists(), path)
            self.assertEqual(path.read_text(encoding="utf-8"), content, path)


if __name__ == "__main__":
    unittest.main()
