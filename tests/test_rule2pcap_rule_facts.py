import json

import pytest

from tests.rule2pcap_scripts import load

rf = load("rule_facts")


def facts(text):
    return rf.facts_for_text(text)


def codes(notes):
    return {n["code"] for n in notes}


def test_decode_content_mixes_text_hex_and_escapes():
    assert rf.decode_content('"GET |20 2f|a\\;b\\"c"') == b'GET  /a;b"c'


def test_printable_round_trips_through_rule_syntax():
    data = b'ab;"|\r\n'
    assert rf.printable(data) == "ab|3b 22 7c 0d 0a|"
    assert rf.decode_content(rf.printable(data)) == data


def test_split_options_keeps_escaped_and_quoted_semicolons():
    opts = rf.split_options(
        'msg:"a; b"; content:"x\\;y"; nocase; pcre:"/a;b/i"; sid:5;'
    )
    assert opts == [
        ("msg", '"a; b"'),
        ("content", '"x\\;y"'),
        ("nocase", None),
        ("pcre", '"/a;b/i"'),
        ("sid", "5"),
    ]


def test_header_with_spaced_address_list():
    rule = rf.parse_rule(
        "alert tcp [10.0.0.1, 10.0.0.2] any -> $EXTERNAL_NET [80, 8080] "
        '(msg:"x"; sid:1;)'
    )
    assert rule["src"] == "[10.0.0.1, 10.0.0.2]"
    assert rule["dport"] == "[80, 8080]"


def test_not_a_rule():
    assert rf.parse_rule("include foo.rules") is None
    assert facts("# just a comment\n")["notes"][0]["code"] == "no-rules"


def test_sticky_buffers_and_legacy_modifiers():
    result = facts(
        'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"t"; '
        'flow:established,to_server; http.method; content:"POST"; '
        'http.uri; content:"/gate.php"; startswith; nocase; '
        'content:"ua"; http_user_agent; sid:10; rev:2;)'
    )
    rule = result["rules"][0]
    assert rule["sid"] == 10 and rule["rev"] == 2
    assert [(c["buffer"], c["printable"]) for c in rule["contents"]] == [
        ("http.method", "POST"),
        ("http.uri", "/gate.php"),
        ("http.user_agent", "ua"),
    ]
    assert rule["contents"][1]["modifiers"] == {"startswith": True, "nocase": True}
    assert rule["roles"]["client"] == "$HOME_NET any"
    assert rule["roles"]["server"] == "$EXTERNAL_NET any"


def test_negated_content_and_hex_bytes():
    rule = facts('alert tcp any any -> any any (content:!"|00 01|ab"; sid:3;)')[
        "rules"
    ][0]
    content = rule["contents"][0]
    assert content["negated"] is True
    assert content["bytes_hex"] == "00016162"


def test_flowbit_without_setter_is_flagged():
    result = facts(
        "alert http any any -> any any (flow:to_client; "
        'flowbits:isset,a.b; content:"x"; sid:2;)'
    )
    assert "no-setter" in codes(result["notes"])


def test_flowbit_setter_in_file_satisfies_isset():
    result = facts(
        "alert http any any -> any any (flow:to_server; "
        "flowbits:set,a.b; flowbits:noalert; sid:1;)\n"
        "alert http any any -> any any (flow:to_client; "
        "flowbits:isset,a.b|c.d; sid:2;)\n"
        "alert http any any -> any any (flowbits:set,c.d; sid:3;)\n"
    )
    assert "no-setter" not in codes(result["notes"])
    assert "noalert" in codes(result["rules"][0]["notes"])


def test_threshold_and_ips_only_notes():
    rule = facts(
        "alert tls $HOME_NET any -> $EXTERNAL_NET any (flow:established,to_client; "
        'ssl_state:server_hello; content:"|04|"; offset:2; depth:1; '
        "threshold:type both,track by_dst,count 100,seconds 2; sid:4;)"
    )["rules"][0]
    assert rule["threshold"] == {
        "type": "both",
        "track": "by_dst",
        "count": "100",
        "seconds": "2",
    }
    assert {"threshold", "ips-only"} <= codes(rule["notes"])
    assert rule["roles"]["server"] == "$HOME_NET any"


def test_header_fields_external_deps_drop_and_no_sid():
    rule = facts(
        'drop icmp any any -> any any (itype:0; dataset:isset,x; content:"a";)'
    )["rules"][0]
    assert {"header-fields", "external-dependency", "drop-action", "no-sid"} <= codes(
        rule["notes"]
    )


def test_non_ascii_rule_is_an_error():
    result = facts('alert tcp any any -> any any (content:"café"; sid:9;)')
    assert "non-ascii" in codes(result["rules"][0]["notes"])


def test_leads_from_references_metadata_and_msg():
    rule = facts(
        'alert http any any -> any any (msg:"Exploit CVE-2021-44228 attempt"; '
        "reference:cve,2014-6271; reference:url,example.com/a; "
        "reference:md5,d41d8cd98f00b204e9800998ecf8427e; "
        "metadata:cve 2016-0800, malware_family Foo; sid:7;)"
    )["rules"][0]
    leads = rule["leads"]
    assert leads["cves"] == ["CVE-2014-6271", "CVE-2016-0800", "CVE-2021-44228"]
    assert leads["cve_urls"][0] == "https://nvd.nist.gov/vuln/detail/CVE-2014-6271"
    assert leads["urls"] == ["https://example.com/a"]
    assert leads["hashes"] == ["d41d8cd98f00b204e9800998ecf8427e"]
    assert leads["families"] == ["Foo"]


def test_port_vars_and_disabled_rules_and_continuations():
    result = facts(
        "# alert tcp any any -> any any (sid:1;)\n"
        "alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS \\\n"
        '  (msg:"x"; sid:2;)\n'
    )
    assert len(result["rules"]) == 1
    assert result["rules"][0]["port_vars"] == {"HTTP_PORTS": "80"}
    assert result["rules"][0]["address_vars"] == ["EXTERNAL_NET", "HOME_NET"]
    assert "disabled" in codes(result["notes"])


@pytest.mark.parametrize(
    "text, exit_code",
    [
        ('alert tcp any any -> any any (content:"a"; sid:1;)', 0),
        ("not a rule", 1),
    ],
)
def test_main_exit_codes(tmp_path, capsys, text, exit_code):
    path = tmp_path / "x.rules"
    path.write_text(text)
    assert rf.main([str(path)]) == exit_code
    json.loads(capsys.readouterr().out)


def test_main_help_and_usage(capsys):
    assert rf.main(["--help"]) == 0
    assert "Usage:" in capsys.readouterr().out
    assert rf.main([]) == 2
    assert "Usage:" in capsys.readouterr().err


def test_content_value_is_unquoted_and_suggested_dir():
    rule = facts(
        'alert tcp any any -> any any (msg:"Big Bad: Thing!"; content:"ab"; sid:42;)'
    )["rules"][0]
    assert rule["contents"][0]["value"] == "ab"
    assert rule["suggested_dir"] == "42-big-bad-thing"


def test_min_version_no_content_and_byte_notes():
    rule = facts(
        "alert smtp any any -> any any (flow:to_server; smtp.mail_from; "
        'content:"x"; sid:1;)'
    )["rules"][0]
    assert "min-version" in codes(rule["notes"])
    rule = facts(
        "alert tcp any any -> any any (flow:to_server; byte_test:2,>,40000,4; sid:2;)"
    )["rules"][0]
    notes = {n["code"]: n["message"] for n in rule["notes"]}
    assert "no-content" in notes
    assert "reads 2 bytes (big-endian) at offset 4" in notes["byte_test"]
    rule = facts(
        'alert http any any -> any any (file.data; content:"MZ"; startswith; '
        "byte_jump:4,58,relative,little; sid:3;)"
    )["rules"][0]
    notes = {n["code"]: n["message"] for n in rule["notes"]}
    assert (
        "little-endian" in notes["byte_jump"]
        and "after the previous" in notes["byte_jump"]
    )


def test_roles_basis_echoes_the_rules_keyword():
    rule = facts(
        'alert tls any any -> any any (flow:established,from_server; content:"x"; sid:4;)'
    )["rules"][0]
    assert rule["roles"]["basis"] == "flow from_server"
