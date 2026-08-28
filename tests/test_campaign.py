#!/usr/bin/env python3
import importlib.util
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("campaign", ROOT / "src" / "campaign.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class CampaignBaselineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.baselines = MODULE.load_closed_baselines()

    def complete_agg(self):
        return {
            target:{"criterion":"AB","count":0,"count_a":0}
            for target in MODULE.canonical_campaign_config(
                100,300,100,"results/test-campaign"
            )["targets"]
        }

    def test_direct_champion_can_be_below_general_record(self):
        result = MODULE.classify_bound(self.baselines, 3, 22, 42_000_000_000)
        self.assertTrue(result["direct_rabung_family_champion"])
        self.assertFalse(result["general_record_candidate"])
        self.assertEqual(result["direct_rabung_baseline"]["lower_bound"], 41_999_998_468)
        self.assertEqual(result["general_closed_baseline"]["lower_bound"], 49_058_715_046)

    def test_general_record_candidate_beats_closed_winner(self):
        result = MODULE.classify_bound(self.baselines, 3, 22, 50_000_000_000)
        self.assertTrue(result["direct_rabung_family_champion"])
        self.assertTrue(result["general_record_candidate"])

    def test_dominated_bound_is_not_recorded(self):
        self.assertIsNone(MODULE.candidate_record(
            self.baselines, 3, 22, 2_000_000_000, 41_999_998_468, "test"
        ))

    def test_legacy_a_only_checkpoint_is_rejected(self):
        config=MODULE.canonical_campaign_config(100,300,100,"results/test-campaign")
        legacy={
            "done":{"100-200":{"criterion":"A","checksum":1}},
            "agg":{"3,17":{"criterion":"A","count":2}},
            "campaign_config":config,
        }
        with self.assertRaises(RuntimeError):
            MODULE.validate_resume_checkpoint(legacy,config)

    def test_ab_checkpoint_is_resume_compatible(self):
        config=MODULE.canonical_campaign_config(100,300,100,"results/test-campaign")
        current={
            "done":{"100-200":{"criterion":"AB","checksum":1,"checksum_ab":2}},
            "agg":self.complete_agg(),
            "campaign_config":config,
        }
        MODULE.validate_resume_checkpoint(current,config)

    def test_checkpoint_geometry_mismatch_is_rejected(self):
        config=MODULE.canonical_campaign_config(100,300,100,"results/test-campaign")
        wrong=MODULE.canonical_campaign_config(100,400,100,"results/test-campaign")
        current={
            "done":{"100-200":{"criterion":"AB","checksum":1,"checksum_ab":2}},
            "agg":self.complete_agg(),
            "campaign_config":config,
        }
        with self.assertRaises(RuntimeError):
            MODULE.validate_resume_checkpoint(current,wrong)

    def test_noncanonical_done_range_is_rejected(self):
        config=MODULE.canonical_campaign_config(100,400,100,"results/test-campaign")
        current={
            "done":{"200-300":{"criterion":"AB","checksum":1,"checksum_ab":2}},
            "agg":self.complete_agg(),
            "campaign_config":config,
        }
        with self.assertRaises(RuntimeError):
            MODULE.validate_resume_checkpoint(current,config)

    def test_aggregate_and_done_presence_must_agree(self):
        config=MODULE.canonical_campaign_config(100,300,100,"results/test-campaign")
        with self.assertRaises(RuntimeError):
            MODULE.validate_resume_checkpoint({
                "done":{},"agg":self.complete_agg(),"campaign_config":config,
            },config)
        with self.assertRaises(RuntimeError):
            MODULE.validate_resume_checkpoint({
                "done":{"100-200":{"criterion":"AB","checksum":1,"checksum_ab":2}},
                "agg":{},"campaign_config":config,
            },config)

    def test_unbound_nonempty_checkpoint_is_rejected(self):
        config=MODULE.canonical_campaign_config(100,300,100,"results/test-campaign")
        current={
            "done":{"100-200":{"criterion":"AB","checksum":1,"checksum_ab":2}},
            "agg":{"3,17":{"criterion":"AB","count":1,"count_a":2}},
        }
        with self.assertRaises(RuntimeError):
            MODULE.validate_resume_checkpoint(current,config)

    def test_smoke_and_dry_runs_use_separate_default_output(self):
        self.assertEqual(
            MODULE.resolve_output_path(None,False,1_000_000,1_020_000,10_000),
            "results/campaign-dry",
        )
        self.assertEqual(
            MODULE.resolve_output_path(None,False,970_000_000,2_000_000_000,2_000_000),
            "results/campaign",
        )
        self.assertEqual(
            MODULE.resolve_output_path("custom",True,1,2,1),"custom",
        )


class CrosscheckParsingTests(unittest.TestCase):
    def completed(self, returncode, stdout, stderr=""):
        return subprocess.CompletedProcess([], returncode, stdout=stdout, stderr=stderr)

    def test_validate_requires_structured_positive_line(self):
        output = "\n".join([
            "=== VALIDATION DIFFERENTIELLE (3 voies) ===",
            "VERDICT : ACCORD 100% (V2a/V2b + B7 + tri + CPU concordants)  (12.3s)",
        ])
        self.assertEqual(MODULE.crosscheck_pass(self.completed(0, output), "validate"), (True, "ok"))
        self.assertFalse(MODULE.crosscheck_pass(self.completed(0, "ACCORD 100"), "validate")[0])

    def test_scanner_success_literals_match_fail_closed_consumers(self):
        source = (ROOT / "src" / "scan_gpu.cu").read_text(encoding="utf-8")
        self.assertIn(
            'ok?"ACCORD 100% (V2a/V2b + B7 + tri + CPU concordants)"',
            source,
        )
        self.assertIn('nf==0?"100%":"ECHEC"', source)
        self.assertIn(
            'allok?"ACCORD 100% (V2a=B7=CPU, double-run identique)"',
            source,
        )
        self.assertNotIn('ACCORD 100%%', source)
        self.assertNotIn('nf==0?"100%%":"ECHEC"', source)

    def test_positive_text_does_not_override_nonzero_returncode(self):
        output = "VERDICT : ACCORD 100% (V2a/V2b + B7 + tri + CPU concordants)  (1.0s)"
        self.assertFalse(MODULE.crosscheck_pass(self.completed(1, output), "validate")[0])

    def test_xcheck_rejects_negative_output(self):
        success = (
            "XCHECK [1800000000,1802000000] 6 prem. : 12 comp. ; "
            "V2a/Jacobi vs CPU desaccords=0 -> ACCORD (moteur campagne OK) ; B7plein WARN=1"
        )
        self.assertEqual(MODULE.crosscheck_pass(self.completed(0, success), "xcheck"), (True, "ok"))
        self.assertFalse(MODULE.crosscheck_pass(
            self.completed(0, "FAIL detail\n" + success), "xcheck"
        )[0])


class ScanParsingTests(unittest.TestCase):
    def valid_output(self, lo=1_000_000, hi=1_010_000):
        lines=[f"# SCAN [{lo},{hi}] : 0 premiers"]
        for r,k in sorted(MODULE.CAMPAIGN_TARGETS):
            lines.append(
                f"TARGET r={r} k={k} A_count=0 A_max_p=0 A_bound=0 "
                "AB_count=0 AB_max_p=0 AB_bound=0 Bstar_reject=0"
            )
        lines += ["CHECKSUM_A 1469598103934665603", "CHECKSUM_AB 1469598103934665603"]
        for r,k in sorted(MODULE.CAMPAIGN_TARGETS):
            lines.append(f"COLQ r={r} k={k} cnt_AB=0 : 0 0 0 0 0 0")
        for r in range(2,10):
            lines.append(f"HISTO r={r} :"+" 0"*64)
            lines.append(f"TOP r={r} :")
        return "\n".join(lines)+"\n"

    def test_complete_structured_output_accepts(self):
        parsed=MODULE.parse_scan_output(self.valid_output(),"",1_000_000,1_010_000)
        self.assertEqual(set(parsed[0]),MODULE.CAMPAIGN_TARGETS)
        self.assertEqual(parsed[1],1469598103934665603)

    def test_empty_or_partial_output_is_rejected(self):
        with self.assertRaises(RuntimeError):
            MODULE.parse_scan_output("","",1_000_000,1_010_000)
        partial="\n".join(self.valid_output().splitlines()[:-1])+"\n"
        with self.assertRaises(RuntimeError):
            MODULE.parse_scan_output(partial,"",1_000_000,1_010_000)

    def test_negative_stderr_is_rejected(self):
        with self.assertRaises(RuntimeError):
            MODULE.parse_scan_output(
                self.valid_output(),"FAIL: GPU comparison disagreed",1_000_000,1_010_000
            )

    def test_duplicate_target_is_rejected(self):
        output=self.valid_output()
        duplicate=next(line for line in output.splitlines() if line.startswith("TARGET"))
        with self.assertRaises(RuntimeError):
            MODULE.parse_scan_output(output+duplicate+"\n","",1_000_000,1_010_000)

    def test_inconsistent_target_arithmetic_is_rejected(self):
        output=self.valid_output().replace(
            "TARGET r=3 k=17 A_count=0 A_max_p=0 A_bound=0",
            "TARGET r=3 k=17 A_count=0 A_max_p=1000003 A_bound=16000049",
        )
        with self.assertRaises(RuntimeError):
            MODULE.parse_scan_output(output,"",1_000_000,1_010_000)

    def test_missing_histo_or_top_is_rejected(self):
        lines=self.valid_output().splitlines()
        truncated="\n".join(line for line in lines if line!="TOP r=9 :")+"\n"
        with self.assertRaises(RuntimeError):
            MODULE.parse_scan_output(truncated,"",1_000_000,1_010_000)

    def test_histo_top_cardinality_mismatch_is_rejected(self):
        output=self.valid_output().replace(
            "HISTO r=2 :"+" 0"*64,
            "HISTO r=2 : 0 1"+" 0"*62,
        )
        with self.assertRaises(RuntimeError):
            MODULE.parse_scan_output(output,"",1_000_000,1_010_000)

    def test_top_must_contain_the_largest_histo_bins(self):
        hist=[0]*64; hist[1]=20; hist[10]=1
        top=" ".join(f"{1_000_101+2*i}:1" for i in range(20))
        output=self.valid_output().replace(
            "# SCAN [1000000,1010000] : 0 premiers",
            "# SCAN [1000000,1010000] : 21 premiers",
        ).replace(
            "HISTO r=2 :"+" 0"*64,
            "HISTO r=2 : "+" ".join(map(str,hist)),
        ).replace("TOP r=2 :",f"TOP r=2 : {top}")
        with self.assertRaises(RuntimeError):
            MODULE.parse_scan_output(output,"",1_000_000,1_010_000)

    def test_target_a_count_must_equal_histo_cumulative_count(self):
        output=self.valid_output().replace(
            "# SCAN [1000000,1010000] : 0 premiers",
            "# SCAN [1000000,1010000] : 1 premiers",
        ).replace(
            "TARGET r=3 k=18 A_count=0 A_max_p=0 A_bound=0 "
            "AB_count=0 AB_max_p=0 AB_bound=0 Bstar_reject=0",
            "TARGET r=3 k=18 A_count=1 A_max_p=1000003 A_bound=17000052 "
            "AB_count=0 AB_max_p=0 AB_bound=0 Bstar_reject=1",
        )
        with self.assertRaises(RuntimeError):
            MODULE.parse_scan_output(output,"",1_000_000,1_010_000)


if __name__ == "__main__":
    unittest.main()
