"""Helpers for rule2pcap build scripts.

Copy this file next to build.py in the output directory, so the build stays
standalone. build.py adds its own directory to sys.path, because the build
runs with python -I, which leaves the script's directory off the path.

Sections:
  payloads     esc, dns_messages, http_date, http_message, inert_pe
  flowsynth    flow_line, event_line, compile_synth
  post-process restamp, reply_gap, randomize_isns, teardown, set_ip_fields,
               rebuild (for Flowsynth output; set_ip_fields goes last)
  scapy        Host, frame, tcp_session, udp_exchange, icmp_echo
  tls          mint_cert, mint_chain, tls_flights
"""

import datetime
import struct
import subprocess
import sys

from scapy.all import ICMP, IP, TCP, UDP, Ether, IPv6, Raw

SEQ_MOD = 2**32
# Ephemeral (client) port ranges: Windows, and Linux's default.
WINDOWS_PORTS = (49152, 65535)
LINUX_PORTS = (32768, 60999)


# ---------------------------------------------------------------- payloads


def esc(data: bytes) -> str:
    """Escape bytes for a Flowsynth content string.

    Flowsynth tokenises with shlex and only understands \\xHH escapes, so
    anything outside plain ASCII text becomes \\xHH.
    """
    ok = set(
        b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 /.:,=-_()*&?%"
    )
    return "".join(chr(c) if c in ok else f"\\x{c:02x}" for c in data)


QTYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16, "AAAA": 28}


def dns_messages(txid, name, addr=None, ttl=300, qtype="A", rcode=0):
    """A DNS query and its response, as UDP payloads.

    qtype "A" or "AAAA" with addr gives one answer record. addr=None gives
    an empty answer: NODATA with rcode=0, or NXDOMAIN with rcode=3.
    """
    import ipaddress

    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    question = qname + struct.pack(">HH", QTYPES[qtype], 1)
    query = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0) + question
    answers = b""
    if addr is not None:
        rdata = ipaddress.ip_address(addr).packed
        answers = (
            struct.pack(">HHHIH", 0xC00C, QTYPES[qtype], 1, ttl, len(rdata)) + rdata
        )
    flags = 0x8180 | (rcode & 0xF)
    reply = (
        struct.pack(">HHHHHH", txid, flags, 1, 1 if answers else 0, 0, 0)
        + question
        + answers
    )
    return query, reply


def http_date(dt):
    return dt.strftime("%a, %d %b %Y %H:%M:%S GMT")


def http_message(start_line, headers, body=b""):
    """An HTTP/1.x message from a start line and (name, value) pairs.

    Content-Length is added when there's a body and no length header.
    """
    lines = [start_line] + [f"{k}: {v}" for k, v in headers]
    if body and not any(
        k.lower() in ("content-length", "transfer-encoding") for k, _ in headers
    ):
        lines.append(f"Content-Length: {len(body)}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


def inert_pe(size=4096, e_lfanew=0x80, rng=None, dll=False):
    """Bytes shaped like a Windows PE file that can't run.

    A standard DOS header (the usual MZ field values and stub, so it looks
    like a linker's output and base64 of it starts "TVqQAAMAAAAEAAAA//8AALgA"),
    the PE signature at e_lfanew, an i386 COFF header with one .text section
    header and no optional header, then filler. There's no optional header,
    entry point or code, so no loader will run it. Filler is seeded random
    bytes when rng is given, zeros otherwise.
    """
    dos = struct.pack(
        "<2s13H8s2H20sI",
        b"MZ",
        0x0090,  # e_cblp
        0x0003,  # e_cp
        0,  # e_crlc
        0x0004,  # e_cparhdr
        0,  # e_minalloc
        0xFFFF,  # e_maxalloc
        0,  # e_ss
        0x00B8,  # e_sp
        0,  # e_csum
        0,  # e_ip
        0,  # e_cs
        0x0040,  # e_lfarlc
        0,  # e_ovno
        bytes(8),  # e_res
        0,  # e_oemid
        0,  # e_oeminfo
        bytes(20),  # e_res2
        e_lfanew,
    )
    dos += b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21"
    dos += b"This program cannot be run in DOS mode.\r\r\n$"
    dos = dos[:e_lfanew].ljust(e_lfanew, b"\0")
    characteristics = 0x0102 | (0x2000 if dll else 0)  # executable, 32-bit (+DLL)
    coff = struct.pack(
        "<4sHHIIIHH", b"PE\0\0", 0x014C, 1, 0x5E2A1C00, 0, 0, 0, characteristics
    )
    text = struct.pack(
        "<8sIIIIIIHHI",
        b".text\0\0\0",
        0x1000,  # virtual size
        0x1000,  # virtual address
        0x200,  # raw size
        0x400,  # raw pointer
        0,
        0,
        0,
        0,
        0x60000020,  # code, execute, read
    )
    body = dos + coff + text
    filler = size - len(body)
    if filler > 0:
        body += (
            bytes(rng.randrange(256) for _ in range(filler)) if rng else bytes(filler)
        )
    return body


# --------------------------------------------------------------- flowsynth


def flow_line(name, proto, src, sport, dst, dport, src_mac, dst_mac):
    """A Flowsynth flow declaration with fixed MACs (never Flowsynth's own)."""
    init = "tcp.initialize; " if proto == "tcp" else ""
    return f"flow {name} {proto} {src}:{sport} > {dst}:{dport} ( {init}src_mac:{src_mac}; dst_mac:{dst_mac}; );\n"


def event_line(name, direction, data):
    """A Flowsynth event: direction ">" (to server) or "<" (to client)."""
    return f'{name} {direction} ( content:"{esc(data)}"; );\n'


def compile_synth(synth, pcap):
    subprocess.run(
        [sys.executable, "-m", "flowsynth", "-f", "pcap", "-w", pcap, synth],
        check=True,
        stdout=subprocess.DEVNULL,
    )


# ------------------------------------------------------------ post-process


def l3(p):
    return p[IP] if IP in p else p[IPv6]


def payload_len(p):
    """Application payload length of a TCP or UDP packet."""
    ip = l3(p)
    if TCP in p:
        if IP in p:
            return ip.len - ip.ihl * 4 - p[TCP].dataofs * 4
        return ip.plen - p[TCP].dataofs * 4
    if UDP in p:
        return p[UDP].len - 8
    return len(bytes(ip.payload))


tcp_payload_len = payload_len


def endpoints(p):
    """((src ip, src port), (dst ip, dst port)); ports are None for ICMP."""
    for proto in (TCP, UDP):
        if proto in p:
            return (l3(p).src, p[proto].sport), (l3(p).dst, p[proto].dport)
    return (l3(p).src, None), (l3(p).dst, None)


def rebuild(q, when=None):
    """Recompute lengths and checksums after editing a packet."""
    when = q.time if when is None else when
    if IP in q:
        del q[IP].len, q[IP].chksum
    else:
        del q[IPv6].plen
    for proto in (TCP, UDP, ICMP):
        if proto in q:
            del q[proto].chksum
    q = q.__class__(bytes(q))
    q.time = when
    return q


def reply_gap(p, prev, remote, rng, rtt=(0.035, 0.060), local=(0.0002, 0.0008)):
    """A plausible gap before packet p, seen from a capture point.

    remote: the set of IPs on the far side of the WAN from the capture
    point. A packet from a remote host that answers a local one arrives an
    RTT later; everything else (back-to-back segments of one flight, local
    replies) is sub-millisecond. If the capture point is near the server
    (an inbound attack), the remote set is the outside client.
    """
    src = l3(p).src
    if prev is not None and src in remote and l3(prev).src not in remote:
        return rng.uniform(*rtt)
    return rng.uniform(*local)


def restamp(pkts, start, gap):
    """Replace Flowsynth's wall-clock stamps.

    gap(packet, new_flow, prev) returns the seconds since the previous
    packet; new_flow is True for the first packet of a flow and prev is the
    previous packet in the capture (None for the first). The first packet
    is stamped exactly at start.
    """
    seen, prev = set(), None
    t = start.timestamp() if isinstance(start, datetime.datetime) else start
    for p in pkts:
        key = frozenset(endpoints(p))
        if prev is not None:
            t += gap(p, key not in seen, prev)
        seen.add(key)
        p.time = t
        prev = p


def randomize_isns(pkts, rng):
    """Give each TCP flow seeded random ISNs.

    Flowsynth 1.4's tcp.initialize starts every flow at ISN 10 (client) and
    100 (server), which no real stack does.
    """
    offsets, out = {}, []
    for p in pkts:
        if TCP not in p:
            out.append(p)
            continue
        src, dst = endpoints(p)
        key = frozenset((src, dst))
        for side in (src, dst):
            offsets.setdefault((key, side), rng.randrange(SEQ_MOD))
        q = p.copy()
        q[TCP].seq = (q[TCP].seq + offsets[(key, src)]) % SEQ_MOD
        if q[TCP].flags.A:
            q[TCP].ack = (q[TCP].ack + offsets[(key, dst)]) % SEQ_MOD
        out.append(rebuild(q, p.time))
    return out


def teardown(pkts, closer="server", idle=0.2, rtt=0.045, capture="client"):
    """Add a FIN, ACK, FIN, ACK close to every TCP flow that has none.

    Flowsynth 1.4 emits no teardown. Without one, data at the end of a flow
    is inspected only when the flow times out, after rules that ran earlier.

    closer is "server" or "client". capture is where the capture point is:
    "client" (the default, e.g. an inside host calling out) or "server"
    (e.g. an inbound attack seen on the server's LAN). A packet from the far
    side that answers one from the near side shows up an RTT later. The new
    packets copy their IP header from earlier ones: run set_ip_fields()
    afterwards so IP IDs stay unique.
    """
    flows = {}
    for p in pkts:
        if TCP in p:
            flows.setdefault(frozenset(endpoints(p)), []).append(p)
    added = []
    for flow in flows.values():
        if any(p[TCP].flags.F or p[TCP].flags.R for p in flow):
            continue
        client = endpoints(flow[0])[0]
        last, nxt = {}, {}
        for p in flow:
            side = endpoints(p)[0]
            last[side] = p
            nxt[side] = (
                p[TCP].seq + payload_len(p) + (1 if p[TCP].flags.S else 0)
            ) % SEQ_MOD
        server = next((s for s in last if s != client), None)
        if server is None:
            continue
        a, b = (server, client) if closer == "server" else (client, server)
        far = server if capture == "client" else client
        t = max(float(p.time) for p in flow) + idle
        steps = (
            (a, "FA", nxt[a], nxt[b], 0),
            (b, "A", nxt[b], nxt[a] + 1, rtt if b == far else 0.0003),
            (b, "FA", nxt[b], nxt[a] + 1, 0.0002),
            (a, "A", nxt[a] + 1, nxt[b] + 1, rtt if a == far else 0.0003),
        )
        for side, flags, seq, ack, dt in steps:
            q = last[side].copy()
            q[TCP].flags, q[TCP].seq, q[TCP].ack = flags, seq % SEQ_MOD, ack % SEQ_MOD
            q[TCP].remove_payload()
            t += dt
            added.append(rebuild(q, t))
    return sorted(list(pkts) + added, key=lambda p: float(p.time))


def set_ip_fields(pkts, rng, ttl=None, df=True):
    """Set per-host TTLs and realistic IPv4 IDs, then fix checksums.

    Flowsynth stamps TTL 64 and IP ID 1 on every packet. ttl maps source
    IP -> TTL as seen at the capture point (local Windows 128, local Linux
    64, a remote host a few hops lower, e.g. 52 or 116). IDs start at a
    seeded random value per host and count up per packet, as Windows and
    most embedded stacks do. Run this last, after teardown().
    """
    ttl = ttl or {}
    next_id = {}
    out = []
    for p in pkts:
        if IP not in p:
            out.append(p)
            continue
        q = p.copy()
        src = q[IP].src
        if src in ttl:
            q[IP].ttl = ttl[src]
        if src not in next_id:
            next_id[src] = rng.randrange(1, 65536)
        q[IP].id = next_id[src]
        next_id[src] = (next_id[src] % 65535) + 1
        if df:
            q[IP].flags = "DF"
        out.append(rebuild(q, p.time))
    return out


# ------------------------------------------------------------------- scapy


class Host:
    """An endpoint as seen from the capture point.

    For a remote host, mac is the local gateway's MAC and ttl is what
    arrives after a few hops (e.g. 64 - 12 = 52, or 128 - 10 = 118).
    """

    def __init__(self, ip, mac, ttl=64, window=64240):
        self.ip, self.mac, self.ttl, self.window = ip, mac, ttl, window


def frame(src, dst, l4, rng):
    return (
        Ether(src=src.mac, dst=dst.mac)
        / IP(src=src.ip, dst=dst.ip, ttl=src.ttl, id=rng.randrange(65536), flags="DF")
        / l4
    )


def tcp_session(
    t,
    client,
    server,
    sport,
    dport,
    messages,
    rng,
    rtt=0.045,
    mss=1460,
    closer="client",
    near="client",
):
    """One whole TCP connection; returns (packets, end time).

    messages is a list of (">" or "<", bytes). near says which end the
    capture point sits next to: "client" (an outbound connection seen from
    the LAN) or "server" (an inbound connection to a local server). A
    packet from the far end that answers the near end arrives `rtt` later;
    everything else is sub-millisecond. Data is segmented at the MSS and
    each message is ACKed. A message bigger than the receiver's window is
    sent in flights, each ACKed before the next: the window in a SYN isn't
    scaled, so a peer that has sent only its SYN offers just `window`
    bytes. The connection ends with a FIN close started by `closer`, or
    closer=None to leave it open.
    """
    out = []
    far = "<" if near == "client" else ">"
    seq = {">": rng.randrange(SEQ_MOD), "<": rng.randrange(SEQ_MOD)}
    copts = [
        ("MSS", mss),
        ("NOP", None),
        ("WScale", 8),
        ("NOP", None),
        ("NOP", None),
        ("SAckOK", b""),
    ]
    sopts = [
        ("MSS", mss),
        ("NOP", None),
        ("NOP", None),
        ("SAckOK", b""),
        ("NOP", None),
        ("WScale", 7),
    ]
    last = [None]
    wscale = {">": 8, "<": 7}  # from copts and sopts
    scaled = {">": False, "<": False}  # has that side sent a non-SYN packet

    def window(side):
        """Bytes the side is offering to receive."""
        host = client if side == ">" else server
        return host.window << wscale[side] if scaled[side] else host.window

    def send(at, frm, flags, data=b"", options=None):
        back = "<" if frm == ">" else ">"
        src, dst = (client, server) if frm == ">" else (server, client)
        s, d = (sport, dport) if frm == ">" else (dport, sport)
        tcp = TCP(
            sport=s,
            dport=d,
            flags=flags,
            seq=seq[frm] % SEQ_MOD,
            window=src.window,
            options=options or [],
        )
        tcp.ack = seq[back] % SEQ_MOD if "A" in flags else 0
        p = frame(src, dst, tcp / Raw(data) if data else tcp, rng)
        p.time = at
        out.append(p)
        seq[frm] += len(data) + (1 if "S" in flags or "F" in flags else 0)
        last[0] = frm
        scaled[frm] = scaled[frm] or "S" not in flags

    def step(frm):
        """Delay before a packet from frm: an RTT if it answers across the WAN."""
        if last[0] is not None and frm == far and last[0] != far:
            return rtt
        return 0.0003

    send(t, ">", "S", options=copts)
    t += step("<")
    send(t, "<", "SA", options=sopts)
    t += step(">")
    send(t, ">", "A")
    for frm, data in messages:
        back = "<" if frm == ">" else ">"
        t += step(frm)
        flight = 0
        for i in range(0, len(data), mss):
            segment = data[i : i + mss]
            if flight and flight + len(segment) > window(back):
                # window full: wait for the receiver's ACK
                t += step(back)
                send(t, back, "A")
                t += step(frm)
                flight = 0
            send(t, frm, "PA", segment)
            flight += len(segment)
            t += 0.00004
        t += step(back)
        send(t, back, "A")
    if closer:
        first = ">" if closer == "client" else "<"
        second = "<" if first == ">" else ">"
        t += 0.2
        send(t, first, "FA")
        t += step(second)
        send(t, second, "A")
        t += 0.0002
        send(t, second, "FA")
        t += step(first)
        send(t, first, "A")
    return out, t


def udp_exchange(t, client, server, sport, dport, request, reply, rng, rtt=0.045):
    q = frame(client, server, UDP(sport=sport, dport=dport) / Raw(request), rng)
    q.time = t
    r = frame(server, client, UDP(sport=dport, dport=sport) / Raw(reply), rng)
    r.time = t + rtt
    return [q, r], t + rtt


def icmp_echo(t, src, dst, ident, seq, payload, rng, rtt=0.045):
    q = frame(src, dst, ICMP(type=8, id=ident, seq=seq) / Raw(payload), rng)
    q.time = t
    r = frame(dst, src, ICMP(type=0, id=ident, seq=seq) / Raw(payload), rng)
    r.time = t + rtt
    return [q, r], t + rtt


# --------------------------------------------------------------------- tls


def _name(pairs, printable):
    """An x509.Name from (field, value) pairs, in order.

    printable=True encodes values as PrintableString (DER tag 0x13), as Java,
    many malware kits and most public CAs do; OpenSSL defaults to UTF8String
    (0x0c). Uses cryptography's private _ASN1Type; if a future release moves
    it, values fall back to the default encoding.
    """
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    try:
        from cryptography.x509.name import _ASN1Type

        printable_type = _ASN1Type.PrintableString
    except ImportError:  # pragma: no cover - depends on cryptography version
        printable_type = None
    oids = {
        "C": NameOID.COUNTRY_NAME,
        "ST": NameOID.STATE_OR_PROVINCE_NAME,
        "L": NameOID.LOCALITY_NAME,
        "O": NameOID.ORGANIZATION_NAME,
        "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
        "CN": NameOID.COMMON_NAME,
        "emailAddress": NameOID.EMAIL_ADDRESS,
    }
    attrs = []
    for k, v in pairs:
        if printable and printable_type is not None and k != "emailAddress":
            attrs.append(x509.NameAttribute(oids[k], v, printable_type))
        else:
            attrs.append(x509.NameAttribute(oids[k], v))
    return x509.Name(attrs)


def _write_key(key, path):
    from cryptography.hazmat.primitives import serialization

    with open(path, "wb") as f:
        f.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )


def mint_cert(
    subject, not_before, days, serial, cert_path, key_path, issuer=None, printable=True
):
    """Write a self-signed RSA-2048 cert and key as PEM.

    subject/issuer: list of (field, value) pairs in order, e.g.
    [("C", "US"), ("O", "Example"), ("CN", "a.example")]. issuer only sets
    the issuer name; the cert is still signed with its own key. For a cert
    "issued" by a public CA, use mint_chain(), which also sends the
    intermediate the way a real server does.

    The key is random, so a build should mint once and reuse the files.
    Needs the cryptography package.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(subject, printable))
        .issuer_name(_name(issuer or subject, printable))
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(not_before)
        .not_valid_after(not_before + datetime.timedelta(days=days))
        .sign(key, hashes.SHA256())
    )
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    _write_key(key, key_path)
    return cert.fingerprint(hashes.SHA1()).hex()


def mint_chain(
    ca_subject,
    ca_issuer,
    ca_not_before,
    ca_days,
    leaf_subject,
    leaf_sans,
    leaf_not_before,
    leaf_days,
    serials,
    chain_path,
    key_path,
    printable=True,
):
    """Write a leaf cert issued by a stand-in intermediate CA, as a chain.

    Copy the real intermediate's subject, issuer and validity from crt.sh
    (ca_subject, ca_issuer, ca_not_before, ca_days); its key and signature
    are minted here, so the chain won't validate. The leaf is a DV-style
    server cert: subject, subjectAltName DNS names, serverAuth.

    chain_path gets leaf then intermediate, which is what a server sends and
    what tls_flights() loads; key_path gets the leaf key. serials is
    (intermediate serial, leaf serial); public CAs use random serials of
    about 128 bits. The days arguments may be fractional: a notAfter of
    23:59:59, as many CAs use, is days - 1/86400. Needs the cryptography
    package.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = _name(ca_subject, printable)
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(_name(ca_issuer, printable))
        .public_key(ca_key.public_key())
        .serial_number(serials[0])
        .not_valid_before(ca_not_before)
        .not_valid_after(ca_not_before + datetime.timedelta(days=ca_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    leaf = (
        x509.CertificateBuilder()
        .subject_name(_name(leaf_subject, printable))
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(serials[1])
        .not_valid_before(leaf_not_before)
        .not_valid_after(leaf_not_before + datetime.timedelta(days=leaf_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in leaf_sans]),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    with open(chain_path, "wb") as f:
        f.write(leaf.public_bytes(serialization.Encoding.PEM))
        f.write(ca.public_bytes(serialization.Encoding.PEM))
    _write_key(leaf_key, key_path)
    return leaf.fingerprint(hashes.SHA1()).hex()


def tls_flights(
    cert_path, key_path, exchanges, keylog_path, sni=None, max_version="TLSv1_2"
):
    """Run a real TLS handshake plus application data in memory.

    cert_path may hold a chain (leaf first), as mint_chain() writes.
    exchanges is a list of (request bytes, response bytes). Returns a list
    of (">" or "<", record bytes) in wire order. The randoms can't be
    seeded, so callers should cache the result (see build_tls.py) and keep
    the NSS key log, which lets Wireshark decrypt the capture.
    """
    import ssl

    version = getattr(ssl.TLSVersion, max_version)
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(cert_path, key_path)
    sctx.maximum_version = version
    sctx.options |= ssl.OP_NO_TICKET
    cctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    cctx.check_hostname, cctx.verify_mode = False, ssl.CERT_NONE
    cctx.maximum_version = version
    cctx.keylog_filename = keylog_path

    c_in, c_out, s_in, s_out = (ssl.MemoryBIO() for _ in range(4))
    cli = cctx.wrap_bio(c_in, c_out, server_side=False, server_hostname=sni)
    srv = sctx.wrap_bio(s_in, s_out, server_side=True)
    flights = []

    def pump(src_out, dst_in, direction):
        data = src_out.read()
        if data:
            flights.append((direction, data))
            dst_in.write(data)

    done = [False, False]
    while not all(done):
        for i, side in enumerate((cli, srv)):
            if not done[i]:
                try:
                    side.do_handshake()
                    done[i] = True
                except ssl.SSLWantReadError:
                    pass
        pump(c_out, s_in, ">")
        pump(s_out, c_in, "<")
    # either side may be empty: a beacon with no reply, or a server that
    # speaks first
    for request, response in exchanges:
        if request:
            cli.write(request)
            pump(c_out, s_in, ">")
            srv.read(1 << 20)
        if response:
            srv.write(response)
            pump(s_out, c_in, "<")
            cli.read(1 << 20)
    return flights
