import socket
import time
import struct
import random

ROOT_SERVERS = [
    "198.41.0.4",
    "199.9.14.201",
    "192.33.4.12",
    "199.7.91.13",
    "192.203.230.10",
    "192.5.5.241",
    "192.112.36.4",
    "198.97.190.53",
    "192.36.148.17",
    "192.58.128.30",
    "193.0.14.129",
    "199.7.83.42",
    "202.12.27.33",
]

DNS_PORT = 53
CLASS_IN = 1

TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
TYPE_AAAA = 28

TYPE_NAME = {
    TYPE_A: "A",
    TYPE_NS: "NS",
    TYPE_CNAME: "CNAME",
    TYPE_AAAA: "AAAA",
}


def encode_qname(domain: str) -> bytes:
    domain = domain.strip(".")
    out = bytearray()
    for label in domain.split("."):
        if len(label) > 63:
            raise ValueError("label too long")
        out.append(len(label))
        out.extend(label.encode("ascii"))
    out.append(0)
    return bytes(out)


def build_dns_request(domain="wikipedia.org", qtype=TYPE_A):
    """
    DNS header (12 bytes) + question section.
    We use RD=0 so we can follow referrals ourselves.
    Returns (txid, payload_bytes).
    """
    txid = random.randint(0, 0xFFFF)

    flags = 0x0000

    qdcount = 1
    ancount = 0
    nscount = 0
    arcount = 0

    header = struct.pack("!HHHHHH", txid, flags, qdcount, ancount, nscount, arcount)
    question = encode_qname(domain) + struct.pack("!HH", qtype, CLASS_IN)

    return txid, header + question


def send_dns_request(sock, server_ip, payload, timeout_s=10.0):
    """
    Uses UDP sendto() and returns start_time so we can compute RTT.
    """
    sock.settimeout(timeout_s)
    start_time = time.perf_counter()
    sock.sendto(payload, (server_ip, DNS_PORT))
    return start_time


def receive_dns_response(sock, start_time):
    """
    Uses recvfrom() to get response bytes and calculates RTT (ms).
    Returns (rtt_ms, response_bytes).
    """
    resp, _ = sock.recvfrom(4096)
    end_time = time.perf_counter()
    rtt_ms = (end_time - start_time) * 1000.0
    return rtt_ms, resp


def extract_dns_records(response_bytes):
    """
    Parses:
      - header
      - question section (skipped)
      - answers / authority / additional RRs
    Returns dict with parsed fields + RR lists.
    """
    if len(response_bytes) < 12:
        raise ValueError("DNS response too short")

    txid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", response_bytes[:12])

    aa = (flags >> 10) & 0x1
    rcode = flags & 0xF

    def decode_name(offset):
        labels = []
        jumped = False
        original_next = offset

        while True:
            if offset >= len(response_bytes):
                raise ValueError("decode_name out of bounds")

            length = response_bytes[offset]

            if (length & 0xC0) == 0xC0:
                if offset + 1 >= len(response_bytes):
                    raise ValueError("truncated pointer")
                ptr = ((length & 0x3F) << 8) | response_bytes[offset + 1]
                if not jumped:
                    original_next = offset + 2
                    jumped = True
                offset = ptr
                continue

            if length == 0:
                offset += 1
                if not jumped:
                    original_next = offset
                break

            offset += 1
            if offset + length > len(response_bytes):
                raise ValueError("truncated label")
            labels.append(response_bytes[offset:offset + length].decode("ascii", errors="replace"))
            offset += length
            if not jumped:
                original_next = offset

        return ".".join(labels), original_next

    offset = 12

    for _ in range(qd):
        _, offset = decode_name(offset)
        offset += 4
        if offset > len(response_bytes):
            raise ValueError("truncated question section")

    def parse_rr_section(count, offset):
        records = []
        for _ in range(count):
            name, offset = decode_name(offset)
            if offset + 10 > len(response_bytes):
                raise ValueError("truncated RR header")

            rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", response_bytes[offset:offset + 10])
            offset += 10

            if offset + rdlen > len(response_bytes):
                raise ValueError("truncated RDATA")

            rdata_offset = offset
            rdata = response_bytes[offset:offset + rdlen]
            offset += rdlen

            if rtype == TYPE_A and rdlen == 4:
                rdata_val = socket.inet_ntop(socket.AF_INET, rdata)
            elif rtype == TYPE_AAAA and rdlen == 16:
                rdata_val = socket.inet_ntop(socket.AF_INET6, rdata)
            elif rtype in (TYPE_NS, TYPE_CNAME):
                rdata_val, _ = decode_name(rdata_offset)
            else:
                rdata_val = "0x" + rdata.hex()

            records.append({
                "name": name,
                "type": rtype,
                "type_name": TYPE_NAME.get(rtype, str(rtype)),
                "class": rclass,
                "ttl": ttl,
                "rdata": rdata_val,
            })
        return records, offset

    answers, offset = parse_rr_section(an, offset)
    authority, offset = parse_rr_section(ns, offset)
    additional, offset = parse_rr_section(ar, offset)

    return {
        "txid": txid,
        "flags": flags,
        "rcode": rcode,
        "aa": aa,
        "answers": answers,
        "authority": authority,
        "additional": additional,
    }


def display_dns_output(server_ip, rtt_ms, parsed):
    print(f"Server: {server_ip} RTT={rtt_ms:.2f} ms rcode={parsed['rcode']} aa={parsed['aa']}")
    print("Answers:")
    for rr in parsed["answers"]:
        print(" ", rr)
    print("Authority:")
    for rr in parsed["authority"]:
        print(" ", rr)
    print("Additional:")
    for rr in parsed["additional"]:
        print(" ", rr)
