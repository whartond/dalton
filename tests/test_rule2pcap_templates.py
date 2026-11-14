"""The skill's build templates must run, rebuild byte-for-byte, and lint clean."""

import hashlib
import importlib.util
import shutil
import subprocess
import sys

import pytest

from tests.rule2pcap_scripts import SCRIPTS, load

pl = load("pcap_lint")
TEMPLATES = SCRIPTS.parent / "templates"


def build(tmp_path, template):
    shutil.copy(TEMPLATES / template, tmp_path / "build.py")
    shutil.copy(TEMPLATES / "pcapkit.py", tmp_path / "pcapkit.py")
    out = subprocess.run(
        [sys.executable, "-I", "build.py"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert out.returncode == 0, out.stderr
    return out.stdout.strip().splitlines()[-1]


@pytest.mark.parametrize(
    "template",
    [
        "build_flowsynth.py",
        "build_scapy.py",
        pytest.param(
            "build_tls.py",
            marks=pytest.mark.skipif(
                importlib.util.find_spec("cryptography") is None,
                reason="cryptography not installed",
            ),
        ),
    ],
)
def test_template_builds_reproducibly_and_lints_clean(tmp_path, template):
    pcap = build(tmp_path, template)
    first = hashlib.sha256(open(pcap, "rb").read()).hexdigest()
    pcap = build(tmp_path, template)
    assert hashlib.sha256(open(pcap, "rb").read()).hexdigest() == first
    result = pl.lint(pcap)
    assert [f for f in result["findings"] if f["level"] != "info"] == []
    tcp_flows = [f for f in result["summary"]["flows"] if f["proto"] == "tcp"]
    assert tcp_flows and all(f["handshake"] and f["teardown"] for f in tcp_flows)
    assert not (tmp_path / "__pycache__").exists()


def test_every_demo_rule_parses():
    rf = load("rule_facts")
    result = rf.facts_for_text((TEMPLATES / "demo.rules").read_text())
    assert len(result["rules"]) == 5
    assert all(n["level"] != "error" for r in result["rules"] for n in r["notes"])


def test_eval_rules_parse_cleanly():
    import json
    import re

    rf = load("rule_facts")
    evals = json.loads((SCRIPTS.parent / "evals" / "evals.json").read_text())
    sids = []
    for case in evals["evals"]:
        rules = re.findall(r"alert .*?rev:1;\)", case["prompt"])
        assert rules, case["id"]
        result = rf.facts_for_text("\n".join(rules))
        assert not [n for n in result["notes"] if n["level"] != "info"], case["id"]
        sids += [r["sid"] for r in result["rules"]]
    assert len(sids) == len(set(sids))


def pcapkit():
    sys.path.insert(0, str(TEMPLATES))
    try:
        import pcapkit as pk
    finally:
        sys.path.pop(0)
    return pk


def test_inert_pe_looks_like_a_linker_built_pe():
    import base64
    import random
    import struct

    pk = pcapkit()
    pe = pk.inert_pe(4096, rng=random.Random(1), dll=True)
    assert base64.b64encode(pe).startswith(b"TVqQAAMAAAAEAAAA//8AALgA")
    e_lfanew = struct.unpack("<I", pe[60:64])[0]
    assert pe[e_lfanew : e_lfanew + 4] == b"PE\0\0"
    (sections,) = struct.unpack("<H", pe[e_lfanew + 6 : e_lfanew + 8])
    (characteristics,) = struct.unpack("<H", pe[e_lfanew + 22 : e_lfanew + 24])
    assert sections == 1 and characteristics & 0x2000
    assert pe[e_lfanew + 24 : e_lfanew + 29] == b".text"
    assert len(pe) == 4096


def test_dns_messages_aaaa_and_nxdomain():
    from scapy.layers.dns import DNS

    pk = pcapkit()
    _, reply = pk.dns_messages(7, "a.example", "2001:db8::5", qtype="AAAA")
    dns = DNS(reply)
    assert dns.ancount == 1 and dns.an[0].rdata == "2001:db8::5"
    _, reply = pk.dns_messages(7, "nope.example", rcode=3)
    dns = DNS(reply)
    assert dns.rcode == 3 and dns.ancount == 0


def test_set_ip_fields_and_reply_gap():
    import random

    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether

    pk = pcapkit()
    rng = random.Random(3)
    pkts = [
        Ether() / IP(src="10.0.0.1", dst="203.0.113.9", id=1) / TCP(),
        Ether() / IP(src="203.0.113.9", dst="10.0.0.1", id=1) / TCP(),
        Ether() / IP(src="10.0.0.1", dst="203.0.113.9", id=1) / TCP(),
    ]
    for i, p in enumerate(pkts):
        p.time = 100 + i
    out = pk.set_ip_fields(pkts, rng, ttl={"10.0.0.1": 128, "203.0.113.9": 52})
    assert [p[IP].ttl for p in out] == [128, 52, 128]
    assert out[2][IP].id == out[0][IP].id + 1
    for p in out:
        clone = p[IP].copy()
        clone.chksum = None
        assert IP(bytes(clone)).chksum == p[IP].chksum
    remote = {"203.0.113.9"}
    assert pk.reply_gap(out[1], out[0], remote, rng) >= 0.035  # remote answers local
    assert pk.reply_gap(out[2], out[1], remote, rng) < 0.001  # local is fast


@pytest.mark.skipif(
    importlib.util.find_spec("cryptography") is None,
    reason="cryptography not installed",
)
def test_mint_chain_writes_leaf_then_intermediate(tmp_path):
    import datetime

    from cryptography import x509

    pk = pcapkit()
    when = datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc)
    pk.mint_chain(
        [("C", "AT"), ("O", "ZeroSSL"), ("CN", "ZeroSSL RSA Domain Secure Site CA")],
        [("C", "US"), ("O", "The USERTRUST Network"), ("CN", "USERTrust RSA")],
        when,
        3650,
        [("CN", "portal.example.net")],
        ["portal.example.net"],
        when,
        90,
        (11, 22),
        str(tmp_path / "chain.pem"),
        str(tmp_path / "leaf.key"),
    )
    leaf, ca = x509.load_pem_x509_certificates((tmp_path / "chain.pem").read_bytes())
    assert leaf.issuer == ca.subject
    assert "ZeroSSL" in leaf.issuer.rfc4514_string()
    assert leaf.serial_number == 22 and ca.serial_number == 11


@pytest.mark.parametrize("tls", ["TLSv1_2", "TLSv1_3"])
@pytest.mark.parametrize(
    "exchanges", [[(b"beacon", b"")], [(b"", b"hello")], [(b"a", b"b"), (b"", b"c")]]
)
def test_tls_flights_with_an_empty_side(tmp_path, tls, exchanges):
    import datetime

    pk = pcapkit()
    when = datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc)
    cert, key = str(tmp_path / "c.pem"), str(tmp_path / "k.pem")
    pk.mint_cert([("CN", "a.example")], when, 30, 1, cert, key)
    flights = pk.tls_flights(
        cert, key, exchanges, str(tmp_path / "keys.log"), max_version=tls
    )
    assert flights and {d for d, _ in flights} == {">", "<"}
