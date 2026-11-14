import email.parser
import email.policy
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from tests.rule2pcap_scripts import load

dc = load("dalton_client")

CONF = '%YAML 1.1\n---\nvars:\n  address-groups:\n    HOME_NET: "[10.0.0.0/8]"\nstream:\n  inline: auto\n'
EVE = "\n".join(
    json.dumps(e)
    for e in (
        {
            "event_type": "alert",
            "pcap_cnt": 4,
            "src_ip": "203.0.113.5",
            "src_port": 80,
            "dest_ip": "10.0.0.5",
            "dest_port": 49152,
            "app_proto": "http",
            "alert": {"signature_id": 1000001, "signature": "TEST one"},
        },
        {"event_type": "anomaly", "anomaly": {"type": "stream", "event": "X"}},
        {"event_type": "flow"},
    )
)


class FakeDalton:
    """Just enough of Dalton's controller API to drive the client."""

    def __init__(self):
        self.mode = "ok"
        self.submissions = []
        self.job_tech = {}
        state = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def reply(self, code, body=b"", ctype="text/plain", headers=None):
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(body if isinstance(body, bytes) else body.encode())

            def guard(self):
                if state.mode == "401":
                    self.reply(401, b'{"error": "Authentication required."}')
                    return False
                if state.mode == "setuser":
                    self.reply(302, headers={"Location": "/dalton/setuser"})
                    return False
                return True

            def do_GET(self):
                if not self.guard():
                    return
                path = self.path
                if path.startswith("/dalton/controller_api/get-current-sensors/"):
                    techs = ["suricata/8.0.6/ctf", "suricata/8.0.6", "suricata/7.0.17"]
                    self.reply(200, json.dumps({"sensor_tech": techs}))
                elif path.startswith("/dalton/controller_api/get-prod-rulesets/"):
                    self.reply(200, json.dumps({"prod-rulesets": ["/r/ET.rules"]}))
                elif path.startswith("/dalton/controller_api/request_engine_conf"):
                    self.reply(200, CONF.replace("\n", "\r\n"))
                elif path.startswith("/dalton/controller_api/job_status_code/"):
                    jid = path.rstrip("/").split("/")[-1]
                    timed_out = state.mode == "timeout-old" and (
                        state.job_tech.get(jid) == "suricata/7.0.17"
                    )
                    self.reply(200, "4" if timed_out else "2")
                elif path.startswith("/dalton/controller_api/v2/"):
                    parts = path.rstrip("/").split("/")
                    key, jid = parts[-1], parts[-2]
                    tech = state.job_tech.get(jid, "")
                    error = ""
                    if state.mode == "rule-error" or (
                        state.mode == "old-engine-gap" and tech == "suricata/7.0.17"
                    ):
                        error = (
                            "Error message(s) found in IDS output.\n\n"
                            "Error: detect-parse: unknown rule keyword 'depthh'.\n\n"
                            'Error: detect: error parsing signature "alert ..." at line 1\n'
                        )
                    fast = (
                        "11/14/2026-01:02:03.000000  [**] [1:1000001:1] TEST one [**] "
                        "[Classification: (null)] [Priority: 3] {TCP} "
                        "203.0.113.5:80 -> 10.0.0.5:49152\n"
                    )
                    ids = "Suricata version 8.0.6 RELEASE\n"
                    if state.mode == "ids-only-error":
                        # Suricata's own format, which the agent's error filter misses
                        ids += (
                            "E: detect-parse: unknown rule keyword 'depthh'.\n"
                            'E: detect: error parsing signature "alert ..." at line 1\n'
                        )
                    data = {"eve": EVE, "alert": fast, "error": error, "ids": ids}.get(
                        key
                    )
                    body = {"error": data is None, "error_msg": None, "data": data}
                    self.reply(200, json.dumps(body), "application/json")
                else:
                    self.reply(404)

            def do_POST(self):
                if not self.guard():
                    return
                length = int(self.headers["Content-Length"])
                raw = self.rfile.read(length)
                msg = email.parser.BytesParser(policy=email.policy.HTTP).parsebytes(
                    b"Content-Type: "
                    + self.headers["Content-Type"].encode()
                    + b"\r\n\r\n"
                    + raw
                )
                form = {}
                for part in msg.iter_parts():
                    name = part.get_param("name", header="content-disposition")
                    form[name] = part.get_payload(decode=True)
                state.submissions.append(form)
                if state.mode == "error":
                    self.reply(
                        200,
                        "<html><ul><li>You must specify a PCAP file.</li></ul></html>",
                    )
                elif b"teapotJob" in b"".join(k.encode() for k in form):
                    jid = f"teapot_{len(state.submissions):016x}"
                    state.job_tech[jid] = form["sensor_tech"].decode()
                    self.reply(200, jid)
                else:
                    jid = f"{len(state.submissions):016x}"
                    state.job_tech[jid] = form["sensor_tech"].decode()
                    self.reply(302, headers={"Location": f"/dalton/job/{jid}"})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def dalton():
    fake = FakeDalton()
    yield fake
    fake.close()


@pytest.fixture
def files(tmp_path):
    pcap = tmp_path / "x.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1fake")
    rules = tmp_path / "test.rules"
    rules.write_text(
        'alert http any any -> any any (msg:"set"; flowbits:set,a; flowbits:noalert; sid:1000000;)\n'
        '# alert http any any -> any any (msg:"off"; sid:999;)\n'
        'alert http any any -> any any (msg:"TEST one"; flowbits:isset,a; sid:1000001;)\n'
    )
    return pcap, rules


def run(capsys, argv):
    code = dc.main(argv)
    return code, json.loads(capsys.readouterr().out)


def test_parse_headers():
    assert dc.parse_headers("X-Key: abc\nbogus\nX-Other:  d e ") == {
        "X-Key": "abc",
        "X-Other": "d e",
    }


def test_default_techs_prefers_stock_config_once_per_version():
    sensors = [
        "suricata/8.0.6/ctf",
        "suricata/8.0.6",
        "suricata/8.0.6",
        "suricata/6.0.1/x",
    ]
    assert dc.default_techs(sensors) == ["suricata/8.0.6", "suricata/6.0.1/x"]


def test_alerting_sids_skips_noalert_and_comments(files):
    _, rules = files
    assert dc.alerting_sids(rules.read_text()) == ["1000001"]


def test_summarise_eve_and_fast_fallback():
    fired, anomalies = dc.summarise(dc.parse_eve(EVE))
    assert fired["1000001"]["count"] == 1
    assert fired["1000001"]["first"]["pcap_cnt"] == 4
    assert anomalies == {"stream:X": 1}
    fast = (
        "11/14/2026-01:02:03.000000  [**] [1:42:3] TEST fast [**] [Classification: x]"
    )
    fired, _ = dc.summarise([], fast)
    assert fired == {"42": {"count": 1, "msg": "TEST fast", "first": None}}


def test_apply_sets_edits_nested_keys():
    out = dc.apply_sets(
        CONF,
        [
            "stream.inline=true",
            "vars.address-groups.HOME_NET=[192.168.0.0/16]",
            "new.key=1",
        ],
    )
    assert "inline: 'true'" in out or "inline: true" in out
    assert (
        "HOME_NET: '[192.168.0.0/16]'" in out or 'HOME_NET: "[192.168.0.0/16]"' in out
    )
    assert "new:\n  key:" in out


def test_preflight_reports_sensors(dalton, capsys):
    _, report = run(capsys, ["preflight", "--url", dalton.url])
    assert report["dalton"]["auth"] == "ok"
    assert report["dalton"]["prod_rulesets"] == ["/r/ET.rules"]
    assert report["ready"]["dalton"] is True


@pytest.mark.parametrize("mode", ["401", "setuser"])
def test_preflight_reports_auth_required(dalton, capsys, mode):
    dalton.mode = mode
    code, report = run(capsys, ["preflight", "--url", dalton.url])
    assert code == 1
    assert report["dalton"]["auth"] == "required"
    assert report["ready"]["dalton"] is False


def test_preflight_unreachable(capsys):
    code, report = run(capsys, ["preflight", "--url", "http://127.0.0.1:9"])
    assert code == 1
    assert report["dalton"]["reachable"] is False


def test_test_runs_one_job_per_version_and_passes(dalton, files, capsys):
    pcap, rules = files
    code, report = run(
        capsys,
        [
            "test",
            "--url",
            dalton.url,
            "--pcap",
            str(pcap),
            "--rules",
            str(rules),
            "--set",
            "stream.inline=true",
        ],
    )
    assert code == 0 and report["pass"] is True
    assert report["expect"] == ["1000001"]
    assert [r["tech"] for r in report["results"]] == [
        "suricata/8.0.6",
        "suricata/7.0.17",
    ]
    first = report["results"][0]
    assert first["job_url"] == f"{dalton.url}/dalton/job/{first['jid']}"
    assert first["anomalies"] == {"stream:X": 1}
    sub = dalton.submissions[0]
    assert sub["sensor_tech"] == b"suricata/8.0.6"
    assert sub["coverage-pcap0"] == pcap.read_bytes()
    assert (
        b"inline: " in sub["custom_engineconf"]
        and b"auto" not in sub["custom_engineconf"]
    )
    assert sub["optionEveLog"] == b"on"


def test_test_fails_when_expected_sid_missing(dalton, files, capsys):
    pcap, rules = files
    code, report = run(
        capsys,
        [
            "test",
            "--url",
            dalton.url,
            "--pcap",
            str(pcap),
            "--rules",
            str(rules),
            "--expect-sid",
            "5",
            "--engine-tech",
            "suricata/7.0.17",
            "--teapot",
        ],
    )
    assert code == 1 and report["pass"] is False
    assert report["results"][0]["jid"].startswith("teapot_")
    assert report["results"][0]["expected_fired"] == {"5": False}


def test_submission_error_page_is_reported(dalton, files, capsys):
    pcap, rules = files
    dalton.mode = "error"
    code, report = run(
        capsys,
        ["test", "--url", dalton.url, "--pcap", str(pcap), "--rules", str(rules)],
    )
    assert code == 2
    assert "You must specify a PCAP file." in report["error"]


def test_docker_dry_run_prints_commands_and_runs_nothing(files, capsys, tmp_path):
    pcap, rules = files
    code, report = run(
        capsys,
        [
            "test",
            "--runner",
            "docker",
            "--dry-run",
            "--image",
            "suricata-current:latest",
            "--pcap",
            str(pcap),
            "--rules",
            str(rules),
            "--set",
            "stream.inline=true",
        ],
    )
    assert code == 0 and report["dry_run"] is True
    (cmd,) = report["commands"]
    assert cmd.startswith("docker run --rm --name rule2pcap-")
    assert " --network none " in cmd
    # nothing was created: the paths are placeholders for a real run's temp dir
    assert "rule2pcap-XXXXXXXX" in cmd and "rule2pcap-XXXXXXXX" in report["note"]
    assert f"{pcap}:/in/x.pcap:ro" in cmd
    assert "--runmode single" in cmd and "--set stream.inline=true" in cmd
    # the time limit is enforced inside the container, so it always ends normally
    assert "timeout 600 suricata -k none" in cmd
    if hasattr(os, "getuid"):
        assert f"chown -R {os.getuid()}:{os.getgid()} /out" in cmd


def test_tiny_pcap_is_a_clean_single_packet(tmp_path):
    path = tmp_path / "v.pcap"
    dc.tiny_pcap(str(path))
    result = load("pcap_lint").lint(str(path))
    assert result["summary"]["packets"] == 1
    assert [f for f in result["findings"] if f["level"] == "error"] == []


@pytest.mark.parametrize("mode, valid", [("ok", True), ("rule-error", False)])
def test_validate_reports_rule_errors(dalton, files, capsys, mode, valid):
    _, rules = files
    dalton.mode = mode
    code, report = run(capsys, ["validate", "--url", dalton.url, "--rules", str(rules)])
    assert report["valid"] is valid and code == (0 if valid else 1)
    first = report["results"][0]
    assert first["loaded"] is valid
    assert len(first["rule_errors"]) == (0 if valid else 2)
    assert dalton.submissions[0]["coverage-pcap0"][:4] == b"\xd4\xc3\xb2\xa1"


def test_engine_that_cannot_load_the_rule_is_reported_not_failed(dalton, files, capsys):
    pcap, rules = files
    dalton.mode = "rule-error"
    code, report = run(
        capsys,
        ["test", "--url", dalton.url, "--pcap", str(pcap), "--rules", str(rules)],
    )
    # every engine rejected the rules: nothing to judge, so not a pass
    assert code == 1 and report["pass"] is False
    assert report["not_loaded"] == ["suricata/8.0.6", "suricata/7.0.17"]


def test_test_reports_alert_lines_and_pkt_src(dalton, files, capsys):
    pcap, rules = files
    _, report = run(
        capsys,
        ["test", "--url", dalton.url, "--pcap", str(pcap), "--rules", str(rules)],
    )
    first = report["results"][0]
    assert first["alert_lines"][0].endswith("203.0.113.5:80 -> 10.0.0.5:49152")
    assert "pkt_src" in first["fired"]["1000001"]["first"]


def test_older_engine_missing_a_keyword_is_a_version_gap(dalton, files, capsys):
    pcap, rules = files
    dalton.mode = "old-engine-gap"
    code, report = run(capsys, ["validate", "--url", dalton.url, "--rules", str(rules)])
    assert code == 0 and report["valid"] is True
    assert report["needs_newer_engine"] is True
    assert report["loaded_on"] == ["suricata/8.0.6"]
    assert report["not_loaded"] == ["suricata/7.0.17"]
    assert report["results"][1]["unknown_keywords"] == ["depthh"]
    code, report = run(
        capsys,
        ["test", "--url", dalton.url, "--pcap", str(pcap), "--rules", str(rules)],
    )
    assert code == 0 and report["pass"] is True
    assert report["results"][1]["expected_fired"] is None


def test_preflight_lists_the_engines_test_will_use(dalton, capsys):
    _, report = run(capsys, ["preflight", "--url", dalton.url])
    assert report["dalton"]["engines"] == ["suricata/8.0.6", "suricata/7.0.17"]


def test_validate_finds_errors_only_in_engine_output(dalton, files, capsys):
    _, rules = files
    dalton.mode = "ids-only-error"
    code, report = run(capsys, ["validate", "--url", dalton.url, "--rules", str(rules)])
    assert code == 1 and report["valid"] is False
    for result in report["results"]:
        assert result["unknown_keywords"] == ["depthh"]
        assert result["rule_errors"][0].startswith("E: detect-parse")


def test_unfinished_job_is_not_run_and_fails(dalton, files, capsys):
    pcap, rules = files
    dalton.mode = "timeout-old"
    code, report = run(
        capsys,
        ["test", "--url", dalton.url, "--pcap", str(pcap), "--rules", str(rules)],
    )
    assert code == 2 and report["pass"] is False
    assert report["not_run"] == ["suricata/7.0.17"] and report["not_loaded"] == []


def test_nothing_to_check_fails(dalton, files, capsys, tmp_path):
    pcap, _ = files
    rules = tmp_path / "noalert.rules"
    rules.write_text(
        'alert tcp any any -> any any (msg:"set"; flowbits:set,x; noalert; sid:5;)\n'
    )
    code, report = run(
        capsys,
        ["test", "--url", dalton.url, "--pcap", str(pcap), "--rules", str(rules)],
    )
    assert code == 1 and report["pass"] is False and "no sids" in report["error"]
