#!/usr/bin/env bash
# open-appsec WAF Comparison against our systems, all on local Docker containers.
# Plan and rules: ml/security_test/BENCHMARK_PLAN_OPENAPPSEC.md
#
#   bash ml/security_test/openappsec/run_benchmark.sh --systems K,A --fast --workers 16
#   bash ml/security_test/openappsec/run_benchmark.sh --systems B,C,D --workers 32
#
# Systems (letters as in the plan, section 5):
#   K  CRS 4.20.0 image defaults (calibration against the published "OWASP CRS 4.20.0" row)
#   A  CRS 3.3.8 (owasp/modsecurity-crs:nginx, what production runs), PL1, inbound anomaly 5
#   B  A + ML harness behind it, ML blocks at score >= 0.99
#   C  A + ML harness behind it, ML threshold from the model card
#   D  ML harness alone (no CRS), threshold from the model card
#
# Environment:
#   MODEL       ONNX model for B/C/D, relative to the repo (default ml/models/gen3/gen3_f_noopenappsec.onnx)
#               must be the model trained WITHOUT OpenAppSec (plan section 3)
#   RESULTS     tool results dir with results/datasets (default ~/waf-bench/results); the tool
#               downloads the datasets (~1.2 GB zip, ~7 GB extracted) there on first run
#
# Only local containers are targeted; nothing here touches the production VPS.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SYSTEMS="K,A"; FAST=""; WORKERS=16
while [ $# -gt 0 ]; do
  case "$1" in
    --systems) SYSTEMS="$2"; shift 2 ;;
    --fast) FAST="--fast"; shift ;;
    --workers) WORKERS="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
MODEL="${MODEL:-ml/models/gen3/gen3_f_noopenappsec.onnx}"
RESULTS="${RESULTS:-$HOME/waf-bench/results}"
NET=oa-net
CRS4=owasp/modsecurity-crs:4.20.0-nginx-202511100111
CRS3=owasp/modsecurity-crs:nginx
TOOL=ghcr.io/openappsec/waf-comparison-project:latest
HARNESS_IMG=waf-gen3-harness:local
mkdir -p "$RESULTS" "$RESULTS/harness-logs"

need_ml=0
case ",$SYSTEMS," in *,B,*|*,C,*|*,D,*) need_ml=1 ;; esac
if [ $need_ml = 1 ]; then
  [ -f "$REPO/$MODEL" ] || { echo "model not found: $REPO/$MODEL (see plan, step 3)" >&2; exit 1; }
  if ! docker image inspect $HARNESS_IMG >/dev/null 2>&1; then
    echo "== building ML harness image"
    docker build -q -t $HARNESS_IMG -f "$REPO/ml/security_test/openappsec/Dockerfile.harness" "$REPO" >/dev/null
  else
    echo "== ML harness image $HARNESS_IMG already exists, reusing"
  fi
fi

echo "== cleaning old containers"
docker rm -f oa-tool oa-stub oa-K oa-A oa-B oa-C oa-D oa-ml-B oa-ml-C oa-ml-D >/dev/null 2>&1 || true
docker network rm $NET >/dev/null 2>&1 || true
docker network create $NET >/dev/null
docker run -d --name oa-stub --network $NET traefik/whoami >/dev/null

ml_harness() {  # name threshold-or-empty
  local name=$1 thr=$2
  docker run -d --name "$name" --network $NET -v "$REPO:/app" -v "$RESULTS/harness-logs:/logs" \
    -e WAF_GEN3_ONNX_PATH="/app/$MODEL" ${thr:+-e WAF_TEST_THRESHOLD=$thr} \
    -e WAF_TEST_LOG="/logs/$name.jsonl" $HARNESS_IMG >/dev/null
}
crs3() {  # name backend
  docker run -d --name "$1" --network $NET -e BACKEND="$2" \
    -e PARANOIA=1 -e ANOMALY_INBOUND=5 -e ANOMALY_OUTBOUND=4 $CRS3 >/dev/null
}

ARGS=()
IFS=, read -ra LIST <<< "$SYSTEMS"
for s in "${LIST[@]}"; do
  case "$s" in
    K) docker run -d --name oa-K --network $NET -e BACKEND=http://oa-stub:80 $CRS4 >/dev/null
       ARGS+=(--waf-name="K_CRS-4.20.0_default" --waf-url="http://oa-K:8080") ;;
    A) crs3 oa-A http://oa-stub:80
       ARGS+=(--waf-name="A_CRS-3.3.8_PL1_a5" --waf-url="http://oa-A:8080") ;;
    B) ml_harness oa-ml-B 0.99; crs3 oa-B http://oa-ml-B:8088
       ARGS+=(--waf-name="B_CRS-3.3.8+ML@0.99" --waf-url="http://oa-B:8080") ;;
    C) ml_harness oa-ml-C ""; crs3 oa-C http://oa-ml-C:8088
       ARGS+=(--waf-name="C_CRS-3.3.8+ML@card" --waf-url="http://oa-C:8080") ;;
    D) ml_harness oa-ml-D ""
       ARGS+=(--waf-name="D_ML-only@card" --waf-url="http://oa-ml-D:8088") ;;
    *) echo "unknown system: $s" >&2; exit 2 ;;
  esac
done

echo "== waiting for targets (benign must be 200, XSS must be 403)"
probe() { docker run --rm --network $NET curlimages/curl:latest -s -o /dev/null -w "%{http_code}" "$1" 2>/dev/null || echo 000; }
for ((i=1; i<${#ARGS[@]}; i+=2)); do
  url="${ARGS[$i]#--waf-url=}"
  for _ in $(seq 1 90); do [ "$(probe "$url/")" = 200 ] && break; sleep 2; done
  b=$(probe "$url/"); x=$(probe "$url/?a=%3Cscript%3Ealert(1)%3C/script%3E")
  echo "   $url benign=$b xss=$x"
  [ "$b" = 200 ] && [ "$x" = 403 ] || { echo "target not ready: $url" >&2; exit 1; }
done

echo "== running the open-appsec tool ($SYSTEMS, workers=$WORKERS ${FAST:-full})"
start=$(date +%s)
docker run --rm --name oa-tool --network $NET -v "$RESULTS:/app/results" $TOOL \
  --fresh-run $FAST --max-workers "$WORKERS" "${ARGS[@]}"
echo "ELAPSED_SEC $(( $(date +%s) - start ))"

echo "== rates (status 0 = timeout, dropped from the rates by the tool; report the count)"
if command -v python3 >/dev/null 2>&1 && python3 -c "import duckdb" >/dev/null 2>&1; then
  python3 "$REPO/ml/security_test/openappsec/summarize_db.py" "$RESULTS/db/waf_comparison.duckdb" \
    | tee "$RESULTS/summary-$(date +%Y%m%d-%H%M%S).txt"
else
  docker run --rm -v "$RESULTS:/r" -v "$REPO/ml/security_test/openappsec:/s:ro" python:3.12-slim \
    sh -c "pip install -q duckdb >/dev/null 2>&1 && python /s/summarize_db.py /r/db/waf_comparison.duckdb" \
    | tee "$RESULTS/summary-$(date +%Y%m%d-%H%M%S).txt"
fi
echo "== report: $RESULTS/waf-comparison-report.pdf"
