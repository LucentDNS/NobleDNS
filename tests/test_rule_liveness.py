import hashlib
import importlib.util
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "nobledns_liveness", Path(__file__).parents[1] / "tools" / "audit_rule_liveness.py"
)
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)

NOW = datetime(2026, 11, 12, 12, 0, tzinfo=timezone.utc)


def observation(host="ads.example.com", day="2026-11-10", resolver="r1",
                operator="cloudflare", vantage="us-west", qtype="A",
                rcode="NXDOMAIN", answers=None, sinkhole_ref=None):
    row = {
        "hostname": host,
        "observed_at_utc": f"{day}T12:00:00Z",
        "resolver": resolver,
        "resolver_operator": operator,
        "vantage": vantage,
        "qtype": qtype,
        "rcode": rcode,
        "answers": answers or [],
    }
    if sinkhole_ref:
        row["sinkhole_evidence_reference"] = sinkhole_ref
    return row


def stable_nxdomain_observations():
    result = []
    resolvers = [
        ("cf1", "cloudflare"),
        ("gg1", "google"),
        ("q91", "quad9"),
    ]
    for day in ("2026-11-01", "2026-11-05", "2026-11-10"):
        for resolver, operator in resolvers:
            for vantage in ("us-west", "cn-lanzhou"):
                for qtype in ("A", "AAAA"):
                    result.append(observation(
                        day=day, resolver=resolver, operator=operator,
                        vantage=vantage, qtype=qtype,
                    ))
    return result


class RuleLivenessTests(unittest.TestCase):
    def test_stable_nxdomain_requires_multi_resolver_multi_vantage_and_time(self):
        rows = mod.validate_observations({
            "schema_version": 1,
            "observations": stable_nxdomain_observations(),
        })
        status, metrics = mod.classify(rows, NOW, 30)
        self.assertEqual(status, "stable_nxdomain_candidate_manual_review")
        self.assertEqual(len(metrics["resolver_operators"]), 3)
        self.assertEqual(len(metrics["vantages"]), 2)
        self.assertEqual(metrics["complete_resolver_vantage_pairs"], 6)
        self.assertEqual(metrics["observation_span_days"], 9.0)

    def test_nxdomain_from_one_resolver_is_not_a_dead_domain_finding(self):
        rows = mod.validate_observations({
            "schema_version": 1,
            "observations": [
                observation(day="2026-11-01", qtype="A"),
                observation(day="2026-11-10", qtype="AAAA"),
            ],
        })
        status, _ = mod.classify(rows, NOW, 30)
        self.assertEqual(status, "insufficient_nxdomain_evidence")

    def test_nxdomain_short_window_is_not_stable(self):
        rows = mod.validate_observations({
            "schema_version": 1,
            "observations": [
                observation(day="2026-11-08", resolver="r1", operator="cloudflare", vantage="us"),
                observation(day="2026-11-10", resolver="r1", operator="cloudflare", vantage="us", qtype="AAAA"),
                observation(day="2026-11-08", resolver="r2", operator="google", vantage="cn"),
                observation(day="2026-11-10", resolver="r2", operator="google", vantage="cn", qtype="AAAA"),
                observation(day="2026-11-08", resolver="r3", operator="quad9", vantage="cn"),
                observation(day="2026-11-10", resolver="r3", operator="quad9", vantage="cn", qtype="AAAA"),
            ],
        })
        status, _ = mod.classify(rows, NOW, 30)
        self.assertEqual(status, "insufficient_nxdomain_evidence")

    def test_positive_answer_means_active_not_dead(self):
        rows = mod.validate_observations({
            "schema_version": 1,
            "observations": [observation(rcode="NOERROR", answers=["203.0.113.10"])],
        })
        status, _ = mod.classify(rows, NOW, 30)
        self.assertEqual(status, "active_dns_answer_observed")

    def test_mixed_positive_and_nxdomain_is_not_stable(self):
        rows = mod.validate_observations({
            "schema_version": 1,
            "observations": [
                observation(rcode="NXDOMAIN"),
                observation(resolver="r2", operator="google", vantage="cn",
                            rcode="NOERROR", answers=["203.0.113.10"]),
            ],
        })
        status, _ = mod.classify(rows, NOW, 30)
        self.assertEqual(status, "mixed_or_split_horizon")

    def test_nodata_is_not_nxdomain(self):
        rows = mod.validate_observations({
            "schema_version": 1,
            "observations": [observation(rcode="NOERROR", answers=[])],
        })
        status, _ = mod.classify(rows, NOW, 30)
        self.assertEqual(status, "nodata_or_no_address")

    def test_sinkhole_requires_separate_evidence_and_is_not_dead(self):
        rows = mod.validate_observations({
            "schema_version": 1,
            "observations": [observation(
                rcode="NOERROR", answers=["192.0.2.1"],
                sinkhole_ref="https://example.org/sinkhole-evidence",
            )],
        })
        status, _ = mod.classify(rows, NOW, 30)
        self.assertEqual(status, "sinkhole_observed_manual_review")

    def test_old_observations_are_not_used(self):
        rows = mod.validate_observations({
            "schema_version": 1,
            "observations": [observation(day="2026-09-01")],
        })
        status, metrics = mod.classify(rows, NOW, 30)
        self.assertEqual(status, "stale_or_missing_observations")
        self.assertEqual(metrics["fresh_observations"], 0)

    def test_audit_never_removes_rules_and_includes_source_provenance(self):
        rules = {"ads.example.com": {"||ads.example.com^"}}
        observations = mod.validate_observations({
            "schema_version": 1,
            "observations": stable_nxdomain_observations(),
        })
        report = mod.audit(
            rules, observations, {"ads.example.com": {"adguard_dns", "hagezi_normal"}},
            NOW, 30,
        )
        self.assertEqual(report["stable_nxdomain_candidates"], 1)
        self.assertEqual(report["automatic_removals"], 0)
        self.assertEqual(report["results"][0]["action"], "manual_review_only")
        self.assertEqual(
            report["results"][0]["source_keys"], ["adguard_dns", "hagezi_normal"]
        )

    def test_source_snapshot_hash_is_verified(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            data = b"||ads.example.com^\n"
            (root / "adguard.txt").write_bytes(data)
            (root / "sources-manifest.json").write_text(json.dumps({
                "adguard_dns": {
                    "filename": "adguard.txt",
                    "sha256": hashlib.sha256(data).hexdigest(),
                }
            }), encoding="utf-8")
            provenance = mod.load_source_provenance(root)
            self.assertEqual(provenance["ads.example.com"], {"adguard_dns"})

    def test_nxdomain_cannot_contain_answers(self):
        with self.assertRaisesRegex(ValueError, "cannot have answers"):
            mod.validate_observations({
                "schema_version": 1,
                "observations": [observation(answers=["203.0.113.1"])],
            })

    def test_duplicate_observation_is_rejected(self):
        row = observation()
        with self.assertRaisesRegex(ValueError, "duplicate observation"):
            mod.validate_observations({
                "schema_version": 1,
                "observations": [row, row],
            })


    def test_future_observations_are_rejected(self):
        row = observation(day="2026-11-13")
        with self.assertRaisesRegex(ValueError, "in the future"):
            mod.validate_observations(
                {"schema_version": 1, "observations": [row]}, NOW
            )

    def test_a_record_requires_ipv4_address(self):
        row = observation(rcode="NOERROR", answers=["2001:db8::1"], qtype="A")
        with self.assertRaisesRegex(ValueError, "family does not match"):
            mod.validate_observations(
                {"schema_version": 1, "observations": [row]}, NOW
            )

    def test_aaaa_record_requires_ipv6_address(self):
        row = observation(rcode="NOERROR", answers=["192.0.2.10"], qtype="AAAA")
        with self.assertRaisesRegex(ValueError, "family does not match"):
            mod.validate_observations(
                {"schema_version": 1, "observations": [row]}, NOW
            )

    def test_non_ip_answer_is_rejected(self):
        row = observation(rcode="NOERROR", answers=["edge.example.net"])
        with self.assertRaisesRegex(ValueError, "non-IP address"):
            mod.validate_observations(
                {"schema_version": 1, "observations": [row]}, NOW
            )

    def test_dns_error_cannot_contain_address_answers(self):
        row = observation(rcode="SERVFAIL", answers=["192.0.2.10"])
        with self.assertRaisesRegex(ValueError, "unless rcode is NOERROR"):
            mod.validate_observations(
                {"schema_version": 1, "observations": [row]}, NOW
            )


if __name__ == "__main__":
    unittest.main()
