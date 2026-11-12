import importlib.util
import json
import struct
import tempfile
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "nobledns_collector", Path(__file__).parents[1] / "tools" / "collect_dns_liveness.py"
)
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


def response(host="ads.example.com", qtype="A", answer=None, rcode=0, cname=None, soa=False):
    query_id = 0x1234
    question = mod.encode_qname(host) + struct.pack("!HH", mod.QTYPE[qtype], 1)
    records = b""
    answer_count = 0
    if answer is not None:
        raw = __import__("ipaddress").ip_address(answer).packed
        records = b"\xc0\x0c" + struct.pack("!HHIH", mod.QTYPE[qtype], 1, 120, len(raw)) + raw
        answer_count = 1
    elif cname is not None:
        raw = mod.encode_qname(cname)
        records = b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 120, len(raw)) + raw
        answer_count = 1
    authority = b""
    authority_count = 0
    if soa:
        owner = mod.encode_qname("example.com")
        mname = mod.encode_qname("ns1.example.com")
        rname = mod.encode_qname("hostmaster.example.com")
        soa_data = mname + rname + struct.pack("!IIIII", 1, 3600, 600, 86400, 300)
        authority = owner + struct.pack("!HHIH", 6, 1, 300, len(soa_data)) + soa_data
        authority_count = 1
    flags = 0x8180 | rcode
    return struct.pack("!HHHHHH", query_id, flags, 1, answer_count, authority_count, 0) + question + records + authority


def response_records(records, host="ads.example.com", qtype="A"):
    query_id = 0x1234
    question = mod.encode_qname(host) + struct.pack("!HH", mod.QTYPE[qtype], 1)
    encoded = b""
    for owner, rrtype, value in records:
        if rrtype in (1, 28):
            raw = __import__("ipaddress").ip_address(value).packed
        else:
            raw = mod.encode_qname(value)
        encoded += (
            mod.encode_qname(owner)
            + struct.pack("!HHIH", rrtype, 1, 60, len(raw))
            + raw
        )
    return struct.pack("!HHHHHH", query_id, 0x8180, 1, len(records), 0, 0) + question + encoded


class DNSLivenessCollectorTests(unittest.TestCase):
    def test_build_query_sets_dnssec_ok_edns_flag(self):
        query_id, packet = mod.build_query("ads.example.com", "A", 0x1234)
        self.assertEqual(query_id, 0x1234)
        self.assertEqual(struct.unpack("!H", packet[:2])[0], 0x1234)
        self.assertIn(b"\x00\x00\x29", packet)
        self.assertIn(b"\x00\x00\x80\x00", packet)

    def test_parse_a_answer(self):
        parsed = mod.parse_response(response(answer="192.0.2.8"), 0x1234, "A", "ads.example.com")
        self.assertEqual(parsed["rcode"], "NOERROR")
        self.assertEqual(parsed["answers"], ["192.0.2.8"])

    def test_parse_aaaa_answer(self):
        parsed = mod.parse_response(
            response(qtype="AAAA", answer="2001:db8::8"), 0x1234, "AAAA", "ads.example.com"
        )
        self.assertEqual(parsed["answers"], ["2001:db8::8"])

    def test_follow_only_cname_chain_reachable_from_query(self):
        packet = response_records([
            ("ads.example.com", 5, "edge.example.net"),
            ("edge.example.net", 1, "192.0.2.22"),
        ])
        parsed = mod.parse_response(packet, 0x1234, "A", "ads.example.com")
        self.assertEqual(parsed["cname_chain"], ["edge.example.net"])
        self.assertEqual(parsed["answers"], ["192.0.2.22"])

    def test_reject_conflicting_cname_targets(self):
        packet = response_records([
            ("ads.example.com", 5, "edge-a.example.net"),
            ("ads.example.com", 5, "edge-b.example.net"),
        ])
        with self.assertRaisesRegex(ValueError, "conflicting CNAME targets"):
            mod.parse_response(packet, 0x1234, "A", "ads.example.com")

    def test_reject_cname_and_address_data_at_same_owner(self):
        packet = response_records([
            ("ads.example.com", 5, "edge.example.net"),
            ("ads.example.com", 1, "192.0.2.23"),
        ])
        with self.assertRaisesRegex(ValueError, "both CNAME and address data"):
            mod.parse_response(packet, 0x1234, "A", "ads.example.com")

    def test_ignore_unrelated_address_records_in_answer_section(self):
        packet = response_records([
            ("other.example.com", 1, "192.0.2.99"),
        ])
        parsed = mod.parse_response(packet, 0x1234, "A", "ads.example.com")
        self.assertEqual(parsed["answers"], [])

    def test_parse_cname_without_address(self):
        parsed = mod.parse_response(
            response(cname="edge.example.net"), 0x1234, "A", "ads.example.com"
        )
        self.assertEqual(parsed["cname_chain"], ["edge.example.net"])
        self.assertEqual(parsed["answers"], [])

    def test_parse_nxdomain_negative_soa_authority(self):
        parsed = mod.parse_response(
            response(rcode=3, soa=True), 0x1234, "A", "ads.example.com"
        )
        self.assertEqual(parsed["rcode"], "NXDOMAIN")
        self.assertEqual(parsed["authority_soa_zones"], ["example.com"])

    def test_reject_response_for_wrong_hostname(self):
        with self.assertRaisesRegex(ValueError, "question does not match"):
            mod.parse_response(response(host="other.example.com"), 0x1234, "A", "ads.example.com")

    def test_resolver_config_requires_three_unique_operators_and_matching_transport(self):
        config = json.loads(
            (Path(__file__).parents[1] / "tools" / "dns-liveness-resolvers.example.json").read_text()
        )
        self.assertEqual(len(mod.validate_config(config)), 4)
        broken = json.loads(json.dumps(config))
        broken["resolvers"][2]["endpoint"] = "https://dns10.quad9.net/dns-query"
        with self.assertRaisesRegex(ValueError, "scheme/path"):
            mod.validate_config(broken)

    def test_duplicate_operator_is_rejected(self):
        config = {
            "schema_version": 1,
            "resolvers": [
                {"id": "a", "operator": "Same", "transport": "doh", "endpoint": "https://a.example/dns-query"},
                {"id": "b", "operator": "same", "transport": "dot", "endpoint": "tls://b.example:853"},
                {"id": "c", "operator": "Other", "transport": "dot", "endpoint": "tls://c.example:853"},
            ],
        }
        with self.assertRaisesRegex(ValueError, "must be unique"):
            mod.validate_config(config)

    def test_duplicate_resolver_endpoint_host_is_rejected(self):
        config = {
            "schema_version": 1,
            "resolvers": [
                {"id": "a", "operator": "One", "transport": "doh", "endpoint": "https://dns.example.test/dns-query"},
                {"id": "b", "operator": "Two", "transport": "doh", "endpoint": "https://dns.example.test/resolve"},
                {"id": "c", "operator": "Three", "transport": "dot", "endpoint": "tls://third.example.test:853"},
            ],
        }
        with self.assertRaisesRegex(ValueError, "endpoint hosts must be unique"):
            mod.validate_config(config)

    def test_sample_is_deduplicated_and_capped(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.txt"
            path.write_text("# comment\nads.example.com\nADS.EXAMPLE.COM\n", encoding="utf-8")
            self.assertEqual(mod.load_sample(path, 1), ["ads.example.com"])
            path.write_text("one.example.com\ntwo.example.com\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "exceeds"):
                mod.load_sample(path, 1)


if __name__ == "__main__":
    unittest.main()
