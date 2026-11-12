#!/usr/bin/env python3
"""Collect a small, explicit DNS liveness sample over DNS-over-HTTPS/TLS (RFC 8484).

This tool never reads the subscription automatically. It only queries hostnames
listed in an operator-supplied sample file and emits minimized DNS observations.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import secrets
import socket
import ssl
import struct
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import ProxyHandler, Request, build_opener

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import update as builder

QTYPE = {"A": 1, "AAAA": 28}
RCODE = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}


def encode_qname(hostname: str) -> bytes:
    labels = hostname.rstrip(".").split(".")
    encoded = bytearray()
    for label in labels:
        raw = label.encode("ascii")
        if not raw or len(raw) > 63:
            raise ValueError(f"invalid DNS label in {hostname}")
        encoded.append(len(raw))
        encoded.extend(raw)
    encoded.append(0)
    return bytes(encoded)


def build_query(hostname: str, qtype: str, query_id: int | None = None) -> tuple[int, bytes]:
    if qtype not in QTYPE:
        raise ValueError("qtype must be A or AAAA")
    query_id = secrets.randbelow(65536) if query_id is None else query_id
    if not 0 <= query_id <= 65535:
        raise ValueError("query ID out of range")
    header = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 1)
    question = encode_qname(hostname) + struct.pack("!HH", QTYPE[qtype], 1)
    # EDNS(0), UDP payload size 1232, DNSSEC OK bit set.
    opt = b"\x00" + struct.pack("!HHIH", 41, 1232, 0x00008000, 0)
    return query_id, header + question + opt


def decode_name(packet: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    cursor = offset
    consumed: int | None = None
    jumps = 0
    while True:
        if cursor >= len(packet):
            raise ValueError("truncated DNS name")
        length = packet[cursor]
        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(packet):
                raise ValueError("truncated DNS compression pointer")
            pointer = ((length & 0x3F) << 8) | packet[cursor + 1]
            if pointer >= len(packet):
                raise ValueError("DNS compression pointer out of bounds")
            if consumed is None:
                consumed = cursor + 2
            cursor = pointer
            jumps += 1
            if jumps > 32:
                raise ValueError("DNS compression pointer loop")
            continue
        if length & 0xC0:
            raise ValueError("unsupported DNS label encoding")
        cursor += 1
        if length == 0:
            if consumed is None:
                consumed = cursor
            break
        if length > 63 or cursor + length > len(packet):
            raise ValueError("invalid or truncated DNS label")
        try:
            labels.append(packet[cursor:cursor + length].decode("ascii").lower())
        except UnicodeDecodeError as exc:
            raise ValueError("non-ASCII label in DNS response") from exc
        cursor += length
    return ".".join(labels), consumed


def parse_response(packet: bytes, query_id: int, qtype: str, hostname: str) -> dict:
    if len(packet) < 12:
        raise ValueError("DNS response shorter than header")
    ident, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", packet[:12])
    if ident != query_id:
        raise ValueError("DNS response ID mismatch")
    if not flags & 0x8000:
        raise ValueError("packet is not a DNS response")
    if flags & 0x0200:
        return {"rcode": "OTHER", "answers": [], "cname_chain": [], "authority_soa_zones": [], "dnssec_ad": bool(flags & 0x0020)}
    if qdcount != 1:
        raise ValueError("DNS response must contain exactly one question")
    offset = 12
    question_name, offset = decode_name(packet, offset)
    if offset + 4 > len(packet):
        raise ValueError("truncated DNS question")
    question_type, question_class = struct.unpack("!HH", packet[offset:offset + 4])
    offset += 4
    if question_name != hostname or question_class != 1 or question_type != QTYPE[qtype]:
        raise ValueError("DNS response question does not match request")

    addresses: list[str] = []
    cnames: list[str] = []
    authority_soa_zones: list[str] = []
    total_records = ancount + nscount + arcount
    if total_records > 4096:
        raise ValueError("DNS response has an unreasonable record count")
    for index in range(total_records):
        owner, offset = decode_name(packet, offset)
        if offset + 10 > len(packet):
            raise ValueError("truncated DNS resource record")
        rrtype, rrclass, _ttl, rdlength = struct.unpack("!HHIH", packet[offset:offset + 10])
        offset += 10
        end = offset + rdlength
        if end > len(packet):
            raise ValueError("truncated DNS resource data")
        # Only answer-section A/AAAA and CNAME records are evidence for this sample.
        if index < ancount and rrclass == 1:
            if rrtype == QTYPE[qtype]:
                expected_len = 4 if qtype == "A" else 16
                if rdlength != expected_len:
                    raise ValueError("address record has invalid length")
                addresses.append(str(ipaddress.ip_address(packet[offset:end])))
            elif rrtype == 5:
                cname, consumed = decode_name(packet, offset)
                if consumed != end:
                    raise ValueError("CNAME name does not exactly fill its resource data")
                valid, reason = builder.valid_domain(cname)
                if not valid:
                    raise ValueError(f"invalid CNAME target: {reason}")
                cnames.append(cname)
        elif ancount <= index < ancount + nscount and rrclass == 1 and rrtype == 6:
            mname, soa_offset = decode_name(packet, offset)
            rname, soa_offset = decode_name(packet, soa_offset)
            if soa_offset + 20 != end:
                raise ValueError("SOA record has malformed resource data")
            valid, reason = builder.valid_domain(owner)
            if not valid:
                raise ValueError(f"invalid SOA owner: {reason}")
            if hostname == owner or hostname.endswith("." + owner):
                authority_soa_zones.append(owner)
        offset = end

    rcode_num = flags & 0x000F
    return {
        "rcode": RCODE.get(rcode_num, "OTHER"),
        "answers": addresses,
        "cname_chain": list(dict.fromkeys(cnames)),
        "authority_soa_zones": list(dict.fromkeys(authority_soa_zones)),
        "dnssec_ad": bool(flags & 0x0020),
    }


def validate_config(document: object) -> list[dict]:
    if not isinstance(document, dict) or set(document) != {"schema_version", "resolvers"}:
        raise ValueError("resolver config must contain exactly schema_version and resolvers")
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise ValueError("resolver config schema_version must be integer 1")
    resolvers = document["resolvers"]
    if not isinstance(resolvers, list) or len(resolvers) < 3 or len(resolvers) > 10:
        raise ValueError("configure between 3 and 10 independent DNS resolvers")
    seen_ids: set[str] = set()
    seen_operators: set[str] = set()
    for index, resolver in enumerate(resolvers):
        if not isinstance(resolver, dict) or set(resolver) != {"id", "operator", "transport", "endpoint"}:
            raise ValueError(f"resolver[{index}] must contain exactly id, operator, transport and endpoint")
        for field in ("id", "operator", "endpoint"):
            if not isinstance(resolver[field], str) or not resolver[field].strip():
                raise ValueError(f"resolver[{index}].{field} must be a non-empty string")
        if resolver["id"] in seen_ids or resolver["operator"].lower() in seen_operators:
            raise ValueError("resolver IDs and operator names must be unique")
        seen_ids.add(resolver["id"])
        seen_operators.add(resolver["operator"].lower())
        transport = resolver["transport"]
        parsed = urlsplit(resolver["endpoint"])
        valid_doh = transport == "doh" and parsed.scheme == "https" and bool(parsed.path)
        valid_dot = transport == "dot" and parsed.scheme == "tls" and parsed.path in {"", "/"}
        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError(f"resolver[{index}].endpoint has an invalid port") from exc
        if (
            not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or not (valid_doh or valid_dot)
            or (port is not None and not 1 <= port <= 65535)
        ):
            raise ValueError(f"resolver[{index}] endpoint scheme/path/port does not match doh or dot transport")
    return resolvers


def query_doh(endpoint: str, hostname: str, qtype: str, timeout: int) -> dict:
    query_id, payload = build_query(hostname, qtype)
    request = Request(
        endpoint,
        data=payload,
        method="POST",
        headers={
            "Accept": "application/dns-message",
            "Content-Type": "application/dns-message",
            "User-Agent": "NobleDNS-Liveness-Audit/1.0",
        },
    )
    try:
        # Bypass ambient HTTP proxy settings: a proxy would invalidate resolver identity.
        opener = build_opener(ProxyHandler({}))
        with opener.open(request, timeout=timeout) as response:
            if response.status != 200 or response.headers.get_content_type() != "application/dns-message":
                return {"rcode": "OTHER", "answers": [], "cname_chain": [], "authority_soa_zones": [], "dnssec_ad": False}
            body = response.read(65536)
        return parse_response(body, query_id, qtype, hostname)
    except (TimeoutError, socket.timeout):
        return {"rcode": "TIMEOUT", "answers": [], "cname_chain": [], "authority_soa_zones": [], "dnssec_ad": False}
    except (HTTPError, URLError, OSError, ValueError):
        return {"rcode": "OTHER", "answers": [], "cname_chain": [], "authority_soa_zones": [], "dnssec_ad": False}


def _recv_exact(connection: ssl.SSLSocket, length: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < length:
        part = connection.recv(length - len(chunks))
        if not part:
            raise OSError("unexpected EOF on DNS-over-TLS connection")
        chunks.extend(part)
    return bytes(chunks)


def query_dot(endpoint: str, hostname: str, qtype: str, timeout: int) -> dict:
    query_id, payload = build_query(hostname, qtype)
    parsed = urlsplit(endpoint)
    port = parsed.port or 853
    try:
        with socket.create_connection((parsed.hostname, port), timeout=timeout) as raw:
            raw.settimeout(timeout)
            with ssl.create_default_context().wrap_socket(raw, server_hostname=parsed.hostname) as tls:
                tls.sendall(struct.pack("!H", len(payload)) + payload)
                response_length = struct.unpack("!H", _recv_exact(tls, 2))[0]
                if response_length < 12:
                    raise ValueError("DNS-over-TLS response is too short")
                response = _recv_exact(tls, response_length)
        return parse_response(response, query_id, qtype, hostname)
    except (TimeoutError, socket.timeout):
        return {"rcode": "TIMEOUT", "answers": [], "cname_chain": [], "authority_soa_zones": [], "dnssec_ad": False}
    except (OSError, ssl.SSLError, ValueError):
        return {"rcode": "OTHER", "answers": [], "cname_chain": [], "authority_soa_zones": [], "dnssec_ad": False}


def query_resolver(resolver: dict, hostname: str, qtype: str, timeout: int) -> dict:
    if resolver["transport"] == "doh":
        return query_doh(resolver["endpoint"], hostname, qtype, timeout)
    return query_dot(resolver["endpoint"], hostname, qtype, timeout)


def load_sample(path: Path, max_hostnames: int) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for line_number, raw in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        host = raw.strip().lower().rstrip(".")
        if not host or host.startswith(("#", "!")):
            continue
        valid, reason = builder.valid_domain(host)
        if not valid:
            raise ValueError(f"{path}:{line_number}: invalid hostname: {reason}")
        if host in seen:
            continue
        seen.add(host)
        result.append(host)
        if len(result) > max_hostnames:
            raise ValueError(f"sample exceeds --max-hostnames={max_hostnames}; split it into smaller batches")
    if not result:
        raise ValueError("sample file contains no hostnames")
    return result


def collect(hostnames: list[str], resolvers: list[dict], vantage: str,
            timeout: int, delay: float) -> dict:
    observations = []
    for resolver in resolvers:
        for hostname in hostnames:
            for qtype in ("A", "AAAA"):
                result = query_resolver(resolver, hostname, qtype, timeout)
                observations.append({
                    "hostname": hostname,
                    "observed_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                    "resolver": resolver["id"],
                    "resolver_operator": resolver["operator"],
                    "resolver_endpoint": resolver["endpoint"],
                    "vantage": vantage,
                    "qtype": qtype,
                    "rcode": result["rcode"],
                    "answers": result["answers"],
                    "cname_chain": result["cname_chain"],
                    "authority_soa_zones": result["authority_soa_zones"],
                    "dnssec_ad": result["dnssec_ad"],
                })
                time.sleep(delay)
    return {"schema_version": 1, "observations": observations}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample", required=True, type=Path, help="Explicit newline-separated hostname sample")
    parser.add_argument("--resolvers", required=True, type=Path, help="Resolver configuration JSON")
    parser.add_argument("--vantage", required=True, help="Operator-assigned vantage label; verify location independently")
    parser.add_argument("--output", required=True, type=Path, help="Output observation JSON")
    parser.add_argument("--max-hostnames", type=int, default=20)
    parser.add_argument("--timeout", type=int, default=8)
    parser.add_argument("--delay", type=float, default=0.5, help="Delay between requests in seconds")
    args = parser.parse_args()
    if not args.vantage.strip():
        parser.error("--vantage cannot be empty")
    if not 1 <= args.max_hostnames <= 50:
        parser.error("--max-hostnames must be between 1 and 50")
    if not 2 <= args.timeout <= 20:
        parser.error("--timeout must be between 2 and 20 seconds")
    if not 0.2 <= args.delay <= 5:
        parser.error("--delay must be between 0.2 and 5 seconds")
    try:
        resolvers = validate_config(json.loads(args.resolvers.read_text(encoding="utf-8")))
        hostnames = load_sample(args.sample, args.max_hostnames)
        document = collect(hostnames, resolvers, args.vantage.strip(), args.timeout, args.delay)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"DNS LIVENESS COLLECTION FAILED: {exc}", file=sys.stderr)
        return 1
    print(
        f"Collected {len(hostnames)} hostnames from {len(resolvers)} resolver operators "
        f"at vantage {args.vantage!r}; {len(document['observations'])} observations written."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
