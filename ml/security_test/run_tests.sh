#!/usr/bin/env bash
# Measure the Gen 3 model's detection with 3 standard WAF-testing tools, on a
# LOCAL harness only. Defensive evaluation of your own model — never point this
# at the production VPS or any host you do not own.
#
#   TOOLS=~/.cache/wafprobe/tools bash ml/security_test/run_tests.sh
#
# Expects the harness already running on $TARGET (see waf_test_harness.py) and
# the tools present: $TOOLS/gotestwaf, $TOOLS/nuclei, $TOOLS/sqlmap/sqlmap.py.
set -uo pipefail
TARGET="${TARGET:-http://127.0.0.1:8088}"
TOOLS="${TOOLS:-$HOME/.cache/wafprobe/tools}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$HERE/reports"; mkdir -p "$OUT/gotestwaf"
RL="${RL:-25}"   # requests/sec cap — keep the local box responsive

echo "== target $TARGET"; curl -s "$TARGET/healthz"; echo

# 1) GoTestWAF — purpose-built WAF efficacy benchmark (its own malicious + benign corpus).
if [ -x "$TOOLS/gotestwaf" ]; then
  echo "== [1/3] GoTestWAF"
  "$TOOLS/gotestwaf" --url "$TARGET" --blockStatusCodes 403 --passStatusCodes 200 \
    --workers 8 --reportPath "$OUT/gotestwaf" --reportName gtw --reportFormat json \
    --noEmailReport --skipWAFIdentification 2>&1 | tail -20
fi

# 2) Nuclei — scanner templates (CVE, exposed panels, config files). Shows the
#    no-payload probe gap (e.g. /wp-admin) the model is known to miss.
if [ -x "$TOOLS/nuclei" ]; then
  echo "== [2/3] Nuclei"
  "$TOOLS/nuclei" -u "$TARGET" -tags panel,exposure,misconfig -rl "$RL" -jsonl \
    -o "$OUT/nuclei.jsonl" -stats -silent 2>&1 | tail -15
fi

# 3) sqlmap — one endpoint, tamper scripts, to see if the model still catches
#    obfuscated SQLi. --batch = no prompts; scoped to the local harness.
if [ -f "$TOOLS/sqlmap/sqlmap.py" ]; then
  echo "== [3/3] sqlmap"
  python3 "$TOOLS/sqlmap/sqlmap.py" -u "$TARGET/item?id=1" --batch --level 3 --risk 2 \
    --tamper=space2comment,between,charencode --technique=BEU \
    --output-dir="$OUT/sqlmap" 2>&1 | tail -15
fi

echo "== done — reports in $OUT"
