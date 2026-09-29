#!/usr/bin/env bash
# Run tests/integration against production through the edge, QA tenant only.
# From your Mac:  bash scripts/qa/run_integration.sh
# Needs on Main: scripts/qa/infra.sh + scripts/qa/seed.py done once, and a
# Python env with pytest + httpx (/tmp/wt/venv is the one used so far).
set -euo pipefail
HERE=$(cd "$(dirname "$0")/../.." && pwd)
PY=${QA_PYTHON:-/tmp/wt/venv/bin/python}
ssh -o ConnectTimeout=10 root@178.104.53.123 'rm -rf /tmp/qa-it && mkdir -p /tmp/qa-it'
rsync -a "$HERE/tests/integration/" root@178.104.53.123:/tmp/qa-it/
ssh -o ConnectTimeout=10 -o ServerAliveInterval=15 root@178.104.53.123 \
  "cd /tmp/qa-it && timeout 900 $PY -m pytest . -q --no-header -p no:cacheprovider -W ignore::DeprecationWarning -rfEs"
