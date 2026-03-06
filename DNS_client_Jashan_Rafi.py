import socket
import time
import struct
import random

ROOT_SERVERS = [
    "198.41.0.4",      # a.root-servers.net
    "199.9.14.201",    # b.root-servers.net
    "192.33.4.12",     # c.root-servers.net
    "199.7.91.13",     # d.root-servers.net
    "192.203.230.10",  # e.root-servers.net
    "192.5.5.241",     # f.root-servers.net
    "192.112.36.4",    # g.root-servers.net
    "198.97.190.53",   # h.root-servers.net
    "192.36.148.17",   # i.root-servers.net
    "192.58.128.30",   # j.root-servers.net
    "193.0.14.129",    # k.root-servers.net
    "199.7.83.42",     # l.root-servers.net
    "202.12.27.33",    # m.root-servers.net
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


# -------------------------
# helpers (you need these to parse real DNS packets)
# -------------------------
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


def decode_name(msg: bytes, offset: int):
    """
    Decode a DNS name, handling compression pointers (0xC0xx).
    Returns (name, next_offset_in_original_stream).
    """
    labels = []
    jumped = False
    original_next = offset

    while True:
        if offset >= len(msg):
            raise ValueError("decode_name out of bounds")

        length = msg[offset]

        # compression pointer
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(msg):
                raise ValueError("truncated pointer")
            ptr = ((length & 0x3F) << 8) | msg[offset + 1]
            if not jumped:
                original_next = offset + 2
                jumped = True
            offset = ptr
            continue

        # end
        if length == 0:
            offset += 1
            if not jumped:
                original_next = offset
            break

        offset += 1
        if offset + length > len(msg):
            raise ValueError("truncated label")
        labels.append(msg[offset:offset + length].decode("ascii", errors="replace"))
        offset += length
        if not jumped:
            original_next = offset

    return ".".join(labels), original_next


# -------------------------
# Build the DNS request payload from scratch
# -------------------------
def build_dns_request(domain="wikipedia.org", qtype=TYPE_A):
    """
    DNS header (12 bytes) + question section.
    We use RD=0 so we can follow referrals ourselves.
    Returns (txid, payload_bytes).
    """
    txid = random.randint(0, 0xFFFF)

    # flags: QR=0, OPCODE=0, AA=0, TC=0, RD=0, RA=0, Z=0, RCODE=0
    flags = 0x0000

    qdcount = 1
    ancount = 0
    nscount = 0
    arcount = 0

    header = struct.pack("!HHHHHH", txid, flags, qdcount, ancount, nscount, arcount)
    question = encode_qname(domain) + struct.pack("!HH", qtype, CLASS_IN)

    return txid, header + question


# -------------------------
# Send the DNS request
# -------------------------
def send_dns_request(sock, server_ip, payload, timeout_s=10.0):
    """
    Uses UDP sendto() and returns start_time so we can compute RTT.
    """
    sock.settimeout(timeout_s)
    start_time = time.perf_counter()
    sock.sendto(payload, (server_ip, DNS_PORT))
    return start_time


# -------------------------
# Receive and unpack the response from the resolver
# -------------------------
def receive_dns_response(sock, start_time):
    """
    Uses recvfrom() to get response bytes and calculates RTT (ms).
    Returns (rtt_ms, response_bytes).
    """
    resp, _ = sock.recvfrom(4096)
    end_time = time.perf_counter()
    rtt_ms = (end_time - start_time) * 1000.0
    return rtt_ms, resp


# -------------------------
# Extract the DNS records
# -------------------------
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

    offset = 12

    # Skip question section
    for _ in range(qd):
        _, offset = decode_name(response_bytes, offset)
        offset += 4  # QTYPE + QCLASS
        if offset > len(response_bytes):
            raise ValueError("truncated question section")

    def parse_rr_section(count, offset):
        records = []
        for _ in range(count):
            name, offset = decode_name(response_bytes, offset)
            if offset + 10 > len(response_bytes):
                raise ValueError("truncated RR header")

            rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", response_bytes[offset:offset + 10])
            offset += 10

            if offset + rdlen > len(response_bytes):
                raise ValueError("truncated RDATA")

            rdata_offset = offset
            rdata = response_bytes[offset:offset + rdlen]
            offset += rdlen

            # decode common RDATA formats
            if rtype == TYPE_A and rdlen == 4:
                rdata_val = socket.inet_ntop(socket.AF_INET, rdata)
            elif rtype == TYPE_AAAA and rdlen == 16:
                rdata_val = socket.inet_ntop(socket.AF_INET6, rdata)
            elif rtype in (TYPE_NS, TYPE_CNAME):
                rdata_val, _ = decode_name(response_bytes, rdata_offset)
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


# -------------------------
# OPTIONAL: quick test harness (remove if your assignment forbids)
# -------------------------
if __name__ == "__main__":
    domain = "wikipedia.org"
    server_ip = random.choice(ROOT_SERVERS)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        txid, payload = build_dns_request(domain, TYPE_A)
        start = send_dns_request(sock, server_ip, payload)
        rtt_ms, resp = receive_dns_response(sock, start)
        parsed = extract_dns_records(resp)

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

    except socket.timeout:
        print("Timed out")
    finally:
        sock.close()