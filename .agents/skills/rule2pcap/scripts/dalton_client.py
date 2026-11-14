#!/usr/bin/env python3
"""Check the environment for rule2pcap, and test a pcap against rules.

Subcommands:

  preflight   Is Dalton reachable, which engines are online, which prod
              rulesets exist, is the build venv complete, and are local
              engine images available for the docker fallback.

  validate    Load a rules file in each engine (with a one-packet pcap)
              and report what the engine rejects. Same runner options as
              test.

  test        Run a pcap and a rules file and report which sids fired.
              --runner dalton (default) submits one Dalton job per engine.
              --runner docker runs local engine images directly; only use it
              after the user has agreed, and show them --dry-run first.

Output is JSON on stdout. Exit codes: 0 ok/pass, 1 not ready/fail,
2 usage or infrastructure error.

Environment:
  DALTON_URL      Dalton base URL (default http://localhost)
  DALTON_USER     username cookie, for Dalton instances with auth_prefix set
  DALTON_HEADERS  extra request headers, "Name: value", one per line; for
                  deployments that sit behind an auth proxy or use API keys

Standard library only, except that --set on the Dalton runner needs
ruamel.yaml (in requirements.txt) to edit the engine config.
"""

import argparse
import http.cookiejar
import io
import json
import os
import re
import shlex
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

STAT_INVALID, STAT_QUEUED, STAT_RUNNING, STAT_DONE = -1, 0, 1, 2
STAT_INTERRUPTED, STAT_TIMEOUT = 3, 4
STATUS_NAMES = {
    STAT_INVALID: "invalid",
    STAT_QUEUED: "queued",
    STAT_RUNNING: "running",
    STAT_DONE: "done",
    STAT_INTERRUPTED: "interrupted",
    STAT_TIMEOUT: "timeout",
}
JID_RE = re.compile(r"^(teapot_)?[0-9a-zA-Z]{6,64}$")
SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REQUIREMENTS = os.path.join(SKILL_DIR, "requirements.txt")
# Engines the runners know how to drive. Snort or another engine slots in by
# adding its name here and a command builder in docker_command().
ENGINES = ("suricata",)


class DaltonError(Exception):
    """A Dalton call failed in a way the user needs to hear about."""


class AuthRequired(DaltonError):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def parse_headers(text):
    headers = {}
    for line in (text or "").splitlines():
        if ":" in line:
            name, value = line.split(":", 1)
            if name.strip():
                headers[name.strip()] = value.strip()
    return headers


def encode_multipart(fields, files):
    """Encode form fields and files as multipart/form-data."""
    boundary = uuid.uuid4().hex
    buf = io.BytesIO()
    for name, value in fields:
        buf.write(f"--{boundary}\r\n".encode())
        buf.write(f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode())
        buf.write(str(value).encode("utf-8"))
        buf.write(b"\r\n")
    for name, filename, data in files:
        buf.write(f"--{boundary}\r\n".encode())
        buf.write(
            f'Content-Disposition: form-data; name="{name}"; '
            f'filename="{filename}"\r\n'.encode()
        )
        buf.write(b"Content-Type: application/octet-stream\r\n\r\n")
        buf.write(data)
        buf.write(b"\r\n")
    buf.write(f"--{boundary}--\r\n".encode())
    return buf.getvalue(), f"multipart/form-data; boundary={boundary}"


class Dalton:
    def __init__(self, url, headers=None, user=None, timeout=30, opener=None):
        self.url = url.rstrip("/")
        self.headers = dict(headers or {})
        self.timeout = timeout
        if user:
            self.headers["Cookie"] = f"dalton_user={user}"
        self.opener = opener or urllib.request.build_opener(
            _NoRedirect, urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
        )

    def request(self, method, path, body=None, content_type=None):
        """Return (status, headers, body bytes). Redirects are not followed."""
        req = urllib.request.Request(self.url + path, data=body, method=method)
        for name, value in self.headers.items():
            req.add_header(name, value)
        if content_type:
            req.add_header("Content-Type", content_type)
        try:
            with self.opener.open(req, timeout=self.timeout) as resp:
                return resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers or {}), exc.read() or b""
        except (urllib.error.URLError, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            raise DaltonError(f"cannot reach Dalton at {self.url}: {reason}") from exc

    def get_json(self, path):
        status, headers, body = self.request("GET", path)
        self._check_auth(status, headers, body)
        if status != 200:
            raise DaltonError(f"GET {path} returned HTTP {status}")
        try:
            return json.loads(body)
        except ValueError as exc:
            raise DaltonError(f"GET {path} did not return JSON") from exc

    def get_text(self, path):
        status, headers, body = self.request("GET", path)
        self._check_auth(status, headers, body)
        if status != 200:
            raise DaltonError(f"GET {path} returned HTTP {status}")
        return body.decode("utf-8", errors="replace")

    def _check_auth(self, status, headers, body):
        location = headers.get("Location", "") or headers.get("location", "")
        if status in (301, 302, 303, 307) and "setuser" in location:
            raise AuthRequired(
                "Dalton requires a username (auth_prefix is set); export "
                "DALTON_USER with the expected prefix"
            )
        if status in (401, 403):
            hint = headers.get("WWW-Authenticate") or headers.get("www-authenticate")
            raise AuthRequired(
                f"Dalton returned HTTP {status}; this deployment needs "
                "credentials. Ask the user which header it expects and export "
                "it, e.g. DALTON_HEADERS='X-Api-Key: <value>' (one 'Name: "
                "value' per line for several)"
                + (f". Server hint: {hint}" if hint else "")
            )

    def sensors(self, engine):
        data = self.get_json(f"/dalton/controller_api/get-current-sensors/{engine}")
        return data.get("sensor_tech", [])

    def prod_rulesets(self, engine):
        path = f"/dalton/controller_api/get-prod-rulesets/{engine}"
        return self.get_json(path).get("prod-rulesets", [])

    def engine_conf(self, tech):
        query = urllib.parse.urlencode({"sensor": tech})
        text = self.get_text(f"/dalton/controller_api/request_engine_conf?{query}")
        if text.lstrip().startswith("# No suitable") or text.lstrip().startswith(
            "# Unable"
        ):
            raise DaltonError(f"Dalton has no engine config for {tech}: {text.strip()}")
        return text.replace("\r\n", "\n")

    def submit(
        self,
        tech,
        pcap_path,
        rules_text,
        conf_text,
        prod_ruleset=None,
        teapot=False,
        dump_buffers=False,
        external_net_any=False,
        other_logs=False,
        socket_control=False,
    ):
        fields = [
            ("sensor_tech", tech),
            ("optionCustomRuleset", "on"),
            ("custom_ruleset", rules_text),
            ("custom_engineconf", conf_text),
            ("optionEveLog", "on"),
        ]
        if prod_ruleset:
            fields += [("optionProdRuleset", "on"), ("prod_ruleset", prod_ruleset)]
        if teapot:
            fields.append(("teapotJob", "1"))
        if dump_buffers:
            fields.append(("optionDumpBuffers", "on"))
        if external_net_any:
            fields.append(("overrideExternalNet", "on"))
        if other_logs:
            fields.append(("optionOtherLogs", "on"))
        if socket_control:
            fields.append(("optionUseSC", "on"))
        with open(pcap_path, "rb") as fh:
            files = [("coverage-pcap0", os.path.basename(pcap_path), fh.read())]
        body, ctype = encode_multipart(fields, files)
        status, headers, resp = self.request(
            "POST", "/dalton/coverage/summary", body, ctype
        )
        self._check_auth(status, headers, resp)
        location = headers.get("Location", "") or headers.get("location", "")
        m = re.search(r"/dalton/job/([^/?#]+)", location)
        if status in (302, 303) and m:
            return m.group(1)
        text = resp.decode("utf-8", errors="replace").strip()
        if status == 200 and JID_RE.match(text):
            return text
        raise DaltonError(f"job submission failed: {html_error(text) or status}")

    def status(self, jid):
        text = self.get_text(f"/dalton/controller_api/job_status_code/{jid}")
        try:
            return int(text.strip())
        except ValueError:
            return STAT_INVALID

    def wait(self, jid, timeout=600, interval=2.0):
        deadline = time.monotonic() + timeout
        while True:
            code = self.status(jid)
            if code not in (STAT_QUEUED, STAT_RUNNING):
                return code
            if time.monotonic() > deadline:
                return STAT_TIMEOUT
            time.sleep(interval)

    def job_data(self, jid, key):
        data = self.get_json(f"/dalton/controller_api/v2/{jid}/{key}")
        if data.get("error"):
            return None
        return data.get("data")

    def job_url(self, jid):
        return f"{self.url}/dalton/job/{jid}"


def html_error(text):
    """Pull the message out of Dalton's HTML error page."""
    items = re.findall(r"<li[^>]*>(.*?)</li>", text, flags=re.S | re.I)
    if not items:
        items = re.findall(r"<p[^>]*>(.*?)</p>", text, flags=re.S | re.I)
    clean = [re.sub(r"<[^>]+>", "", i).strip() for i in items]
    return " ".join(c for c in clean if c)[:500]


def apply_sets(conf_text, sets):
    """Apply key.path=value overrides to a Suricata YAML config."""
    if not sets:
        return conf_text
    try:
        from ruamel.yaml import YAML
    except ImportError as exc:
        raise DaltonError(
            "--set with the Dalton runner needs ruamel.yaml; install "
            f"{REQUIREMENTS} into the venv"
        ) from exc
    yaml = YAML()
    yaml.version = (1, 1)
    yaml.preserve_quotes = True
    config = yaml.load(conf_text)
    for item in sets:
        key, _, value = item.partition("=")
        node = config
        parts = key.split(".")
        for part in parts[:-1]:
            if part not in node or node[part] is None:
                node[part] = {}
            node = node[part]
            if not hasattr(node, "keys"):
                raise DaltonError(f"--set {key}: '{part}' is not a mapping")
        node[parts[-1]] = value
    out = io.StringIO()
    yaml.dump(config, out)
    return out.getvalue()


def parse_eve(text):
    events = []
    for line in (text or "").splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                events.append(json.loads(line))
            except ValueError:
                continue
    return events


FAST_RE = re.compile(r"\[\*\*\]\s*\[(\d+):(\d+):(\d+)\]\s*(.*?)\s*\[\*\*\]")


def summarise(events, fast_text=None):
    """Count alerts per sid, and anomaly events, from eve (or fast.log)."""
    fired, anomalies = {}, {}
    for ev in events:
        etype = ev.get("event_type")
        if etype == "alert":
            alert = ev.get("alert", {})
            sid = str(alert.get("signature_id"))
            entry = fired.setdefault(
                sid,
                {"count": 0, "msg": alert.get("signature"), "first": None},
            )
            entry["count"] += 1
            if entry["first"] is None:
                entry["first"] = {
                    "pcap_cnt": ev.get("pcap_cnt"),
                    "src": f"{ev.get('src_ip')}:{ev.get('src_port')}",
                    "dst": f"{ev.get('dest_ip')}:{ev.get('dest_port')}",
                    "app_proto": ev.get("app_proto"),
                    # "stream (flow timeout)" etc. when pcap_cnt is null
                    "pkt_src": ev.get("pkt_src"),
                }
        elif etype == "anomaly":
            a = ev.get("anomaly", {})
            key = f"{a.get('type')}:{a.get('event') or a.get('code')}"
            anomalies[key] = anomalies.get(key, 0) + 1
    if not events and fast_text:
        for m in FAST_RE.finditer(fast_text):
            entry = fired.setdefault(
                m.group(2), {"count": 0, "msg": m.group(4), "first": None}
            )
            entry["count"] += 1
    return fired, anomalies


def verdict(fired, expect):
    return {sid: sid in fired for sid in expect}


def alert_lines(fast_text, limit=20):
    """The engine's own fast.log alert lines, for the write-up."""
    lines = [x.strip() for x in (fast_text or "").splitlines() if "[**]" in x]
    return lines[:limit]


def alerting_sids(rules_text):
    """Sids of rules that should alert: not commented out, not noalert."""
    sids = []
    for line in rules_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if re.search(r"flowbits\s*:\s*noalert\s*;", line) or re.search(
            r"(^|[;(\s])noalert\s*;", line
        ):
            continue
        m = re.search(r"(?:^|[;(\s])sid\s*:\s*(\d+)\s*;", line)
        if m:
            sids.append(m.group(1))
    return sids


def default_techs(sensors):
    """One tech per engine version, preferring the stock config.

    Dalton lists a tech once per agent, and agents running a custom config
    show up as engine/version/config. Those are kept only when no stock
    agent runs that version.
    """
    chosen = {}
    for tech in sensors:
        parts = tech.split("/")
        version = "/".join(parts[:2])
        if version not in chosen or len(parts) == 2:
            chosen[version] = tech
    return list(chosen.values())


def run_dalton(args, rules_text, expect):
    client = client_from_env(args)
    techs = args.engine_tech or default_techs(client.sensors(args.engine))
    if not techs:
        raise DaltonError(f"no {args.engine} agents are online in Dalton")
    jobs = []
    for tech in techs:
        conf = apply_sets(client.engine_conf(tech), args.set)
        jid = client.submit(
            tech,
            args.pcap,
            rules_text,
            conf,
            prod_ruleset=args.prod_ruleset,
            teapot=args.teapot,
            dump_buffers=args.dump_buffers,
            external_net_any=args.external_net_any,
            other_logs=args.other_logs,
            socket_control=args.socket_control,
        )
        jobs.append((tech, jid))
    results = []
    for tech, jid in jobs:
        code = client.wait(jid, timeout=args.timeout)
        result = {
            "tech": tech,
            "jid": jid,
            "job_url": client.job_url(jid),
            "status": STATUS_NAMES.get(code, str(code)),
        }
        if code == STAT_DONE:
            eve = client.job_data(jid, "eve")
            fast = client.job_data(jid, "alert")
            fired, anomalies = summarise(parse_eve(eve), fast)
            result.update(
                fired=fired,
                alert_lines=alert_lines(fast),
                anomalies=anomalies,
                expected_fired=verdict(fired, expect),
                errors=(client.job_data(jid, "error") or "").strip()[-4000:],
            )
        results.append(result)
    return {"runner": "dalton", "url": client.url, "results": results}


def client_from_env(args):
    headers = parse_headers(os.environ.get("DALTON_HEADERS"))
    headers.update(parse_headers("\n".join(getattr(args, "header", None) or [])))
    return Dalton(
        getattr(args, "url", None) or os.environ.get("DALTON_URL", "http://localhost"),
        headers=headers,
        user=os.environ.get("DALTON_USER"),
    )


def docker_images(engine="suricata"):
    """Local images that look like engine images, e.g. suricata-current:latest."""
    if not shutil.which("docker"):
        return None
    try:
        out = subprocess.run(
            ["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"],
            capture_output=True,
            text=True,
            timeout=15,
            check=True,
        ).stdout
    except (subprocess.SubprocessError, OSError):
        return None
    pattern = re.compile(rf"(^|/){re.escape(engine)}[-_:]", re.I)
    return sorted({i for i in out.split() if pattern.search(i) and "<none>" not in i})


def docker_command(image, pcap, rules_file, log_dir, sets, engine="suricata"):
    """The docker command that runs one engine image over the pcap.

    The engine runs as the image's own user (its config is not readable by
    others), then hands the log files back to the caller's uid so they can
    be read and deleted without root.
    """
    if engine != "suricata":
        raise DaltonError(f"the docker runner does not support {engine} yet")
    pcap_abs, rules_abs = os.path.abspath(pcap), os.path.abspath(rules_file)
    pcap_in = f"/in/{os.path.basename(pcap_abs)}"
    engine_cmd = ["suricata", "-k", "none", "--runmode", "single"]
    engine_cmd += ["-S", "/rules/test.rules", "-r", pcap_in, "-l", "/out"]
    for item in sets or []:
        engine_cmd += ["--set", item]
    owner = f"{os.getuid()}:{os.getgid()}" if hasattr(os, "getuid") else None
    script = shlex.join(engine_cmd) + "; rc=$?"
    if owner:
        script += f"; chown -R {owner} /out"
    script += "; exit $rc"
    return [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "-v",
        f"{pcap_abs}:{pcap_in}:ro",
        "-v",
        f"{rules_abs}:/rules/test.rules:ro",
        "-v",
        f"{os.path.abspath(log_dir)}:/out",
        "--entrypoint",
        "sh",
        image,
        "-c",
        script,
    ]


def run_docker(args, rules_text, expect):
    images = args.image or docker_images(args.engine) or []
    if not images:
        raise DaltonError(f"no local {args.engine} images found; pass --image")
    keep = args.keep_logs
    base = keep or tempfile.mkdtemp(prefix="rule2pcap-")
    os.makedirs(base, exist_ok=True)
    rules_file = os.path.join(base, "test.rules")
    with open(rules_file, "w", encoding="utf-8") as fh:
        fh.write(rules_text)
    plans = []
    for image in images:
        log_dir = os.path.join(base, re.sub(r"[^A-Za-z0-9_.-]", "_", image))
        os.makedirs(log_dir, exist_ok=True)
        plans.append(
            (
                image,
                log_dir,
                docker_command(image, args.pcap, rules_file, log_dir, args.set),
            )
        )
    if args.dry_run:
        if not keep:
            shutil.rmtree(base, ignore_errors=True)
        return {
            "runner": "docker",
            "dry_run": True,
            "commands": [shlex.join(cmd) for _, _, cmd in plans],
        }
    results = []
    try:
        for image, log_dir, cmd in plans:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=args.timeout
            )
            output = proc.stdout + proc.stderr
            version = re.search(r"Suricata version (\S+)", output)
            eve = read_file(os.path.join(log_dir, "eve.json"))
            fast = read_file(os.path.join(log_dir, "fast.log"))
            fired, anomalies = summarise(parse_eve(eve), fast)
            errors = "\n".join(
                line
                for line in output.splitlines()
                if re.search(r"(^|[\s\]])(Error|E):|\berror\b", line)
            )
            results.append(
                {
                    "image": image,
                    "tech": f"suricata/{version.group(1)}" if version else None,
                    "status": "done" if proc.returncode == 0 else "failed",
                    "exit_code": proc.returncode,
                    "fired": fired,
                    "alert_lines": alert_lines(fast),
                    "anomalies": anomalies,
                    "expected_fired": verdict(fired, expect),
                    "errors": errors[-4000:],
                    "logs": log_dir if keep else None,
                }
            )
    finally:
        if not keep:
            shutil.rmtree(base, ignore_errors=True)
    return {"runner": "docker", "results": results}


def read_file(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def check_python(python):
    """Which pinned packages the build interpreter has, and at what version."""
    pins = {}
    try:
        with open(REQUIREMENTS, encoding="utf-8") as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                if "==" in line:
                    name, version = line.split("==", 1)
                    pins[name.strip()] = version.strip()
    except OSError:
        pass
    code = (
        "import importlib.metadata as m, json, sys\n"
        "out = {'python': sys.version.split()[0], 'packages': {}}\n"
        f"for name in {sorted(pins)!r}:\n"
        "    try:\n"
        "        out['packages'][name] = m.version(name)\n"
        "    except m.PackageNotFoundError:\n"
        "        out['packages'][name] = None\n"
        "print(json.dumps(out))\n"
    )
    try:
        proc = subprocess.run(
            [python, "-I", "-c", code], capture_output=True, text=True, timeout=30
        )
        info = json.loads(proc.stdout)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        return {"python": python, "ok": False, "error": str(exc)}
    problems = []
    for name, want in pins.items():
        have = info["packages"].get(name)
        if have is None:
            problems.append(f"{name} missing (want {want})")
        elif have != want:
            problems.append(f"{name} {have} installed, {want} pinned")
    major, minor = (int(x) for x in info["python"].split(".")[:2])
    if (major, minor) < (3, 10):
        problems.append(f"Python {info['python']} is too old; need 3.10+")
    info.update(
        interpreter=python,
        ok=not any("missing" in p or "too old" in p for p in problems),
        problems=problems,
        fix=f"{python} -m pip install -r {REQUIREMENTS}" if problems else None,
    )
    return info


def ip_checksum(header):
    total = sum(struct.unpack(f"!{len(header) // 2}H", header))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def tiny_pcap(path):
    """Write a one-packet pcap (a UDP datagram between documentation hosts).

    validate runs rules against it only to see whether the engine loads
    them; an empty pcap makes Suricata log pcap errors as well.
    """
    payload = b"rule2pcap rule validation"
    udp = struct.pack("!HHHH", 40000, 9, 8 + len(payload), 0) + payload
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(udp),
        1,
        0,
        64,
        17,
        0,
        bytes([192, 0, 2, 1]),
        bytes([192, 0, 2, 2]),
    )
    ip = ip[:10] + struct.pack("!H", ip_checksum(ip)) + ip[12:]
    eth = bytes.fromhex("0200000000020200000000010800")
    frame = eth + ip + udp
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        fh.write(struct.pack("<IIII", 1700000000, 0, len(frame), len(frame)))
        fh.write(frame)


RULE_ERROR_RE = re.compile(r"(Error|E):.*(signature|rule|keyword|parse|option)", re.I)


def cmd_validate(args):
    """Load the rules in each engine and report what the engine rejects."""
    tmp = tempfile.mkdtemp(prefix="rule2pcap-validate-")
    try:
        args.pcap = os.path.join(tmp, "validate.pcap")
        tiny_pcap(args.pcap)
        args.expect_sid = []
        with open(args.rules, encoding="utf-8") as fh:
            rules_text = fh.read()
        if args.runner == "docker":
            report = run_docker(args, rules_text, [])
        else:
            report = run_dalton(args, rules_text, [])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if report.get("dry_run"):
        print(json.dumps(report, indent=2))
        return 0
    mark_rule_errors(report)
    for result in report["results"]:
        for key in ("fired", "anomalies", "expected_fired", "alert_lines"):
            result.pop(key, None)
        unknown = []
        for line in result["rule_errors"]:
            m = re.search(r"unknown rule keyword '([^']+)'", line)
            if m:
                unknown.append(m.group(1))
        result["unknown_keywords"] = unknown
    loaded = [r for r in report["results"] if r["loaded"]]
    failed = [r for r in report["results"] if not r["loaded"]]

    # Version gap: an engine fails only because it lacks keywords that
    # another engine accepts (e.g. Suricata 8 additions on Suricata 7).
    def version_gap(r):
        if not r["unknown_keywords"] or not loaded:
            return False
        parse_lines = [x for x in r["rule_errors"] if "unknown rule keyword" not in x]
        return all("error parsing signature" in x for x in parse_lines)

    report["loaded_on"] = [r["tech"] or r.get("image") for r in loaded]
    report["not_loaded"] = [r["tech"] or r.get("image") for r in failed]
    report["needs_newer_engine"] = bool(failed) and all(version_gap(r) for r in failed)
    report["valid"] = bool(loaded) and (not failed or report["needs_newer_engine"])
    print(json.dumps(report, indent=2))
    return 0 if report["valid"] else 1


def cmd_preflight(args):
    report = {"dalton": {}, "docker": {}, "build_env": check_python(args.python)}
    client = client_from_env(args)
    d = report["dalton"]
    d["url"] = client.url
    try:
        d["sensors"] = client.sensors(args.engine)
        d["engines"] = default_techs(d["sensors"])
        d["engines_note"] = (
            "test and validate use 'engines': one agent per version, stock "
            "config preferred. 'sensors' lists every agent; a third path "
            "part (e.g. suricata/8.0.6/ctf) is an agent running a custom "
            "config, used only when passed with --engine-tech"
        )
        d["reachable"], d["auth"] = True, "ok"
        try:
            d["prod_rulesets"] = client.prod_rulesets(args.engine)
        except DaltonError as exc:
            d["prod_rulesets"], d["prod_rulesets_error"] = [], str(exc)
    except AuthRequired as exc:
        d.update(reachable=True, auth="required", error=str(exc), sensors=[])
    except DaltonError as exc:
        d.update(reachable=False, error=str(exc), sensors=[])
    images = docker_images(args.engine)
    report["docker"] = {"available": images is not None, "images": images or []}
    report["ready"] = {
        "dalton": bool(d.get("sensors")),
        "docker_fallback": bool(images),
        "build_env": report["build_env"].get("ok", False),
    }
    print(json.dumps(report, indent=2))
    return 0 if report["ready"]["dalton"] and report["ready"]["build_env"] else 1


def cmd_test(args):
    with open(args.rules, encoding="utf-8") as fh:
        rules_text = fh.read()
    expect = [str(s) for s in args.expect_sid] or alerting_sids(rules_text)
    if args.runner == "docker":
        report = run_docker(args, rules_text, expect)
    else:
        report = run_dalton(args, rules_text, expect)
    if report.get("dry_run"):
        print(json.dumps(report, indent=2))
        return 0
    report["expect"] = expect
    mark_rule_errors(report)
    loaded = [r for r in report["results"] if r["loaded"]]
    # An engine that can't load the rule (e.g. a keyword newer than that
    # version) says nothing about the pcap. Report it, judge the rest.
    report["not_loaded"] = [
        r["tech"] or r.get("image") for r in report["results"] if not r["loaded"]
    ]
    for r in report["results"]:
        if not r["loaded"] and "expected_fired" in r:
            r["expected_fired"] = None  # couldn't load the rule: nothing to judge
    report["pass"] = bool(loaded) and all(
        r.get("status") == "done" and all(r.get("expected_fired", {}).values())
        for r in loaded
    )
    print(json.dumps(report, indent=2))
    return 0 if report["pass"] else 1


def mark_rule_errors(report):
    """Add rule_errors and loaded to each result."""
    for result in report["results"]:
        lines = [x.strip() for x in (result.get("errors") or "").splitlines()]
        result["rule_errors"] = [x for x in lines if RULE_ERROR_RE.search(x)]
        result["loaded"] = result.get("status") == "done" and not result["rule_errors"]


def build_parser():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def common(p):
        p.add_argument("--url", help="Dalton base URL (default $DALTON_URL)")
        p.add_argument(
            "--header",
            action="append",
            help='extra request header "Name: value" (repeatable). Visible '
            "in the process list: put secrets in DALTON_HEADERS instead",
        )
        p.add_argument("--engine", default="suricata", choices=ENGINES)

    pre = sub.add_parser("preflight", help="check Dalton, docker and the venv")
    common(pre)
    pre.add_argument(
        "--python",
        default=sys.executable,
        help="interpreter the build scripts will use (default: this one)",
    )
    pre.set_defaults(func=cmd_preflight)

    test = sub.add_parser("test", help="run a pcap against rules")
    common(test)
    test.add_argument("--pcap", required=True)
    runner_options(test)
    test.set_defaults(func=cmd_test)

    validate = sub.add_parser(
        "validate", help="load the rules in each engine and report errors"
    )
    common(validate)
    runner_options(validate)
    validate.set_defaults(func=cmd_validate)
    return parser


def runner_options(test):
    test.add_argument("--rules", required=True)
    test.add_argument("--runner", choices=("dalton", "docker"), default="dalton")
    test.add_argument(
        "--expect-sid",
        action="append",
        default=[],
        help="sid that must fire (repeatable; default: every alerting rule)",
    )
    test.add_argument(
        "--engine-tech",
        action="append",
        help="Dalton engine, e.g. suricata/8.0.6 (default: all online)",
    )
    test.add_argument(
        "--set",
        action="append",
        default=[],
        help="engine config override key.path=value (repeatable)",
    )
    test.add_argument("--prod-ruleset", help="also load this Dalton prod ruleset")
    test.add_argument("--teapot", action="store_true", help="short-lived job")
    test.add_argument("--dump-buffers", action="store_true")
    test.add_argument("--external-net-any", action="store_true")
    test.add_argument("--other-logs", action="store_true")
    test.add_argument(
        "--socket-control",
        action="store_true",
        help="run through the agent's single-threaded Suricata socket daemon",
    )
    test.add_argument("--timeout", type=int, default=600)
    test.add_argument("--image", action="append", help="docker runner: image")
    test.add_argument("--keep-logs", help="docker runner: keep engine logs here")
    test.add_argument(
        "--dry-run",
        action="store_true",
        help="docker runner: print the commands without running them",
    )


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except DaltonError as exc:
        print(json.dumps({"error": str(exc)}, indent=2))
        return 2


if __name__ == "__main__":
    sys.exit(main())
