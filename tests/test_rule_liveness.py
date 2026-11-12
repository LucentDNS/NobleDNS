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
        "resolver_endpoint": {
            "cloudflare": "https://cloudflare-dns.com/dns-query",
            "google": "https://dns.google/dns-query",
            "quad9": "tls://dns10.quad9.net:853",
        }.get(operator.lower(), "https://resolver.example.test/dns-query"),
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
                    row = observation(
                        day=day, resolver=resolver, operator=operator,
                        vantage=vantage, qtype=qtype,
                    )
                    row["authority_soa_zones"] = ["example.com"]
                    result.append(row)
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

    def test_quorum_without_negative_soa_is_manual_review_not_stable(self):
        rows = stable_nxdomain_observations()
        for row in rows:
            row.pop("authority_soa_zones")
        validated = mod.validate_observations({
            "schema_version": 1,
            "observations": rows,
        })
        status, metrics = mod.classify(validated, NOW, 30)
        self.assertEqual(status, "nxdomain_without_authority_soa_manual_review")
        self.assertEqual(metrics["nxdomain_observations_with_soa"], 0)

    def test_resolver_quorum_with_different_soa_zones_is_manual_review(self):
        rows = stable_nxdomain_observations()
        latest = next(row for row in rows if row["observed_at_utc"].startswith("2026-11-10"))
        latest["authority_soa_zones"] = ["ads.example.com"]
        validated = mod.validate_observations({
            "schema_version": 1,
            "observations": rows,
        })
        status, _ = mod.classify(validated, NOW, 30)
        self.assertEqual(status, "nxdomain_authority_zone_disagreement_manual_review")

    def test_multiple_soa_zones_in_one_response_are_manual_review(self):
        rows = stable_nxdomain_observations()
        latest = next(row for row in rows if row["observed_at_utc"].startswith("2026-11-10"))
        latest["authority_soa_zones"] = ["example.com", "ads.example.com"]
        validated = mod.validate_observations({
            "schema_version": 1,
            "observations": rows,
        })
        status, _ = mod.classify(validated, NOW, 30)
        self.assertEqual(status, "nxdomain_authority_zone_disagreement_manual_review")

    def test_unrelated_soa_zone_is_rejected(self):
        row = observation()
        row["authority_soa_zones"] = ["unrelated.example.net"]
        with self.assertRaisesRegex(ValueError, "unrelated SOA authority zone"):
            mod.validate_observations(
                {"schema_version": 1, "observations": [row]}, NOW
            )

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

    def test_operator_name_case_variants_do_not_fake_independent_providers(self):
        rows = stable_nxdomain_observations()
        labels = {"cf1": "cloudflare", "gg1": "CloudFlare", "q91": "CLOUDFLARE"}
        for row in rows:
            row["resolver_operator"] = labels[row["resolver"]]
        validated = mod.validate_observations({
            "schema_version": 1,
            "observations": rows,
        })
        status, metrics = mod.classify(validated, NOW, 30)
        self.assertEqual(status, "insufficient_nxdomain_evidence")
        self.assertEqual(metrics["resolver_operators"], ["cloudflare"])

    def test_old_nxdomain_from_one_pair_cannot_extend_recent_quorum_span(self):
        rows = stable_nxdomain_observations()
        rows = [
            row for row in rows
            if row["observed_at_utc"].startswith("2026-11-10")
            or (
                row["resolver"] == "cf1"
                and row["vantage"] == "us-west"
                and row["observed_at_utc"].startswith("2026-11-01")
            )
        ]
        validated = mod.validate_observations({
            "schema_version": 1,
            "observations": rows,
        })
        status, metrics = mod.classify(validated, NOW, 30)
        self.assertEqual(status, "insufficient_nxdomain_evidence")
        self.assertEqual(metrics["complete_resolver_vantage_pairs"], 6)
        self.assertEqual(metrics["pairs_with_seven_day_complete_history"], 1)
        self.assertEqual(metrics["observation_span_days"], 9.0)

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
        with self.assertRaisesRegex(ValueError, "cannot have address answers"):
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


    def test_cname_chain_is_not_misclassified_as_dead_domain(self):
        row = observation(rcode="NXDOMAIN")
        row["cname_chain"] = ["edge.example.net"]
        row["dnssec_ad"] = True
        row["resolver_endpoint"] = "https://dns.google/dns-query"
        rows = mod.validate_observations(
            {"schema_version": 1, "observations": [row]}, NOW
        )
        status, _ = mod.classify(rows, NOW, 30)
        self.assertEqual(status, "cname_chain_observed_manual_review")

    def test_same_endpoint_host_cannot_claim_multiple_resolver_operators(self):
        first = observation(resolver="cf", operator="cloudflare")
        second = observation(resolver="other", operator="impostor", qtype="AAAA")
        second["resolver_endpoint"] = "https://cloudflare-dns.com/dns-query"
        with self.assertRaisesRegex(ValueError, "claimed by multiple operators"):
            mod.validate_observations({
                "schema_version": 1,
                "observations": [first, second],
            }, NOW)

    def test_resolver_id_cannot_change_endpoint(self):
        first = observation(resolver="same-id", operator="cloudflare", qtype="A")
        second = observation(resolver="same-id", operator="cloudflare", qtype="AAAA")
        second["resolver_endpoint"] = "https://alternate-cloudflare.example/dns-query"
        with self.assertRaisesRegex(ValueError, "maps to multiple operators or endpoints"):
            mod.validate_observations({
                "schema_version": 1,
                "observations": [first, second],
            }, NOW)

    def test_invalid_cname_target_is_rejected(self):
        row = observation()
        row["cname_chain"] = ["*.example.net"]
        with self.assertRaisesRegex(ValueError, "invalid CNAME target"):
            mod.validate_observations(
                {"schema_version": 1, "observations": [row]}, NOW
            )

    def test_dnssec_flag_must_be_boolean(self):
        row = observation()
        row["dnssec_ad"] = "true"
        with self.assertRaisesRegex(ValueError, "dnssec_ad must be a boolean"):
            mod.validate_observations(
                {"schema_version": 1, "observations": [row]}, NOW
            )


    def test_resolver_endpoint_rejects_invalid_doh_and_dot_shapes(self):
        for endpoint in (
            "https://dns.example.test",
            "tls://dns.example.test:853/dns-query",
            "tls://dns.example.test:99999",
        ):
            with self.subTest(endpoint=endpoint):
                row = observation()
                row["resolver_endpoint"] = endpoint
                with self.assertRaisesRegex(ValueError, "resolver_endpoint"):
                    mod.validate_observations(
                        {"schema_version": 1, "observations": [row]}, NOW
                    )

    def test_resolver_endpoint_must_be_safe_tls_url(self):
        row = observation()
        row["resolver_endpoint"] = "https://user:pass@dns.example.test/dns-query"
        with self.assertRaisesRegex(ValueError, "safe HTTPS DoH or pathless TLS DoT endpoint"):
            mod.validate_observations(
                {"schema_version": 1, "observations": [row]}, NOW
            )


if __name__ == "__main__":
    unittest.main()
