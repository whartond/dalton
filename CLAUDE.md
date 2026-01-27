# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Dalton is a web-based system for running network packet captures (pcaps) against IDS sensors (Suricata, Snort, Zeek). It consists of:

- **Controller** (`app/dalton.py`): Flask web application that manages job submission, queuing, and results display
- **Agents** (`dalton-agent/dalton-agent.py`): Run on IDS sensors, poll the controller for jobs, execute them locally, and return results
- **Flowsynth WebUI** (`app/flowsynth.py`): Wizard interface for creating custom pcaps

## Build and Run Commands

```bash
# Start all containers (controller + agents)
./start-dalton.sh
# or equivalently:
docker compose build && docker compose up -d

# Access the web UI at http://localhost/dalton/
```

## Development Commands

```bash
# Create virtualenv and install dependencies
make venv

# Run tests
make test

# Run a single test file
.venv/bin/pytest tests/test_dalton.py

# Run a specific test
.venv/bin/pytest tests/test_dalton.py::TestClassName::test_method_name

# Lint code
make lint

# Auto-fix lint issues
make fix

# Run coverage
make coverage

# Lint Dockerfiles
make hadolint

# Bump version (patch/minor/major)
make bumpversion BUMPPART=patch
```

## Architecture

### Controller-Agent Communication
- Redis manages job queues (one per sensor type/version), results storage, and active agent tracking
- Agents poll the controller every ~1 second for pending jobs
- Jobs are queued by engine type and version (e.g., `suricata/7.0.14`)
- Results are stored in Redis with configurable expiration (default 5 days, teapot jobs 62 minutes)

### Key Flask Blueprints
- `dalton_blueprint` (`/dalton/`): Main IDS job interface
- `flowsynth_blueprint` (`/flowsynth/`): Pcap generation wizard

### Configuration Files
- `dalton.conf`: Controller settings (Redis, paths, timeouts)
- `dalton-agent/dalton-agent.conf`: Agent settings (controller URL, engine paths)
- `.env`: Docker environment variables (ports, proxy settings, debug flags)

### Storage Paths (in container)
- `/opt/dalton/jobs`: Job zip files
- `/opt/dalton/rulesets/{suricata,snort,zeek}`: Ruleset files (`.rules`)
- `/opt/dalton/app/static/engine-configs/{suricata,snort}`: Engine config templates

### API Endpoints
- Job results: `GET /dalton/controller_api/v2/<jobid>/<key>`
- Raw results: `GET /dalton/controller_api/v2/<jobid>/<key>/raw`
- Sensor list: `GET /dalton/controller_api/get-current-sensors/<engine>`
- Job submission: `POST /dalton/coverage/summary`

## Adding New Sensor Versions

Edit `docker-compose.yml` and copy an existing agent specification, changing the version:

```yaml
agent-suricata-X.Y.Z:
  build:
    context: ./dalton-agent
    dockerfile: Dockerfiles/Dockerfile_suricata
    args:
      - SURI_VERSION=X.Y.Z
  image: suricata-X.Y.Z:latest
  container_name: suricata-X.Y.Z
```

For Suricata 4.x with Rust support, add `- ENABLE_RUST=--enable-rust` to args.

## Frontend Notes

- Uses Bootstrap 2.3.2 with jQuery 3.7.1
- Bootstrap JS has been patched for jQuery 3.x compatibility (`.delegate()` → `.on()`, `href="#"` selector handling)
- Templates use Jinja2, located in `app/templates/dalton/` and `app/templates/pcapwg/`
