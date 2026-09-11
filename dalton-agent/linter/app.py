import csv
import io
import os
import re
import subprocess
import tempfile

import guard
from flask import Flask, jsonify, request
from legacy_keywords import LEGACY_KEYWORD_ALIASES
from suricatals.langserver import LangServer

SURICATA_BINARY = "suricata"


def _get_engine_version():
    out = subprocess.run(
        [SURICATA_BINARY, "-V"], capture_output=True, text=True, check=True
    ).stdout
    match = re.search(r"version\s+([\d.]+)", out)
    return match.group(1) if match else out.strip()


def _get_keywords():
    """Parse `suricata --list-keywords=csv` and add back the legacy
    sticky-buffer spellings current engines still accept but no longer
    advertise. Keywords come from Suricata itself, not from any
    third-party database - see legacy_keywords.py for why."""
    out = subprocess.run(
        [SURICATA_BINARY, "--list-keywords=csv"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    reader = csv.DictReader(io.StringIO(out), delimiter=";")
    by_name = {}
    for row in reader:
        name = row["name"]
        by_name[name] = {
            "name": name,
            "description": row["description"],
            "app_layer": row["app layer"],
            "features": row["features"],
            "documentation": row["documentation"],
        }

    keywords = list(by_name.values())
    for legacy_name, modern_name in LEGACY_KEYWORD_ALIASES.items():
        modern = by_name.get(modern_name)
        if modern is None:
            # The engine this container was built against doesn't have the
            # modern keyword under the name we expect - skip rather than
            # offer a completion for something that would fail to parse.
            continue
        keywords.append(
            {
                "name": legacy_name,
                "description": f"{modern['description']} (legacy name for '{modern_name}')",
                "app_layer": modern["app_layer"],
                "features": modern["features"],
                "documentation": modern["documentation"],
                "legacy_for": modern_name,
            }
        )
    return keywords


ENGINE_VERSION = _get_engine_version()
KEYWORDS = _get_keywords()

# Constructed once per gunicorn worker at import time; this runs
# `suricata -V` once, not per-request - benchmark the service, not the
# `suricata-language-server --batch-file` CLI, which pays that cost (plus
# re-importing pygls and the Docker SDK) on every single invocation.
_lang_server = LangServer(
    settings={
        "suricata_binary": SURICATA_BINARY,
        "max_lines": 500,
        "docker_mode": False,
    },
    batch_mode=True,
)

app = Flask(__name__)


def _guard_rejection_diagnostic(rejection):
    return {
        "range": {
            "start": {"line": rejection.line, "character": 0},
            "end": {"line": rejection.line, "character": 1},
        },
        "message": rejection.message,
        "source": "Dalton Rule Guard",
        "severity": 1,  # LSP Error
        "content": "",
        "sid": 0,
    }


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "engine_version": ENGINE_VERSION})


@app.route("/keywords", methods=["GET"])
def keywords():
    return jsonify({"engine_version": ENGINE_VERSION, "keywords": KEYWORDS})


@app.route("/check", methods=["POST"])
def check():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        data = {}
    rules = data.get("rules") or ""
    if not isinstance(rules, str):
        # Without this a JSON object or list reaches .strip() and 500s.
        return jsonify({"error": "'rules' must be a string"}), 400
    engine_analysis = bool(data.get("engine_analysis", False))

    try:
        guard.check_rule_buffer(rules)
    except guard.GuardRejection as rejection:
        return jsonify(
            {
                "engine_version": ENGINE_VERSION,
                "diagnostics": [_guard_rejection_diagnostic(rejection)],
            }
        )

    # An empty, isolated working directory: any relative path a rule names
    # (e.g. a lua: target the guard didn't already reject) resolves to
    # nothing, rather than something real on the container's filesystem.
    with tempfile.TemporaryDirectory() as tmpdir:
        rule_path = os.path.join(tmpdir, "dalton.rules")
        with open(rule_path, "w", encoding="utf-8") as f:
            f.write(rules)
        _, _, diags = _lang_server.analyse_file(
            rule_path, engine_analysis=engine_analysis
        )

    messages = [m for m in (d.to_message() for d in diags) if m is not None]
    return jsonify({"engine_version": ENGINE_VERSION, "diagnostics": messages})
