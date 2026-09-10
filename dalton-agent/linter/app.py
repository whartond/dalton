import csv
import io
import re
import subprocess

from flask import Flask, jsonify
from legacy_keywords import LEGACY_KEYWORD_ALIASES

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

app = Flask(__name__)


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "engine_version": ENGINE_VERSION})


@app.route("/keywords", methods=["GET"])
def keywords():
    return jsonify({"engine_version": ENGINE_VERSION, "keywords": KEYWORDS})
