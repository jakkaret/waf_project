#!/usr/bin/env python3
"""
WAF decision endpoint for measuring the Gen 3 model's detection on a LOCAL test host.

This is a DEFENSIVE test rig: it fronts a fake origin, scores every incoming
request with the Gen 3 model exactly as ml_api would, and answers 403 when the
model flags an attack and 200 otherwise. Point a WAF-efficacy tool (GoTestWAF,
Nuclei, sqlmap) at it and its "blocked" count becomes the model's detection rate,
its benign requests becoming the false-positive rate. Nothing here attacks anything.

Run against localhost only, on your own machine, never the production VPS.

    WAF_GEN3_ONNX_PATH=ml/models/gen3/gen3_f_model.onnx \
      PYTHONPATH=. uvicorn ml.security_test.waf_test_harness:app --host 127.0.0.1 --port 8088

Every decision is appended as JSON to $WAF_TEST_LOG (default security_test/decisions.jsonl)
so the run can be audited request by request.
"""

import json
import os
import time

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from ml.ml_api import load_gen3_model

MODEL, ERR = load_gen3_model()
THRESHOLD = float(os.environ.get("WAF_TEST_THRESHOLD", MODEL.threshold if MODEL else 0.5))
LOG_PATH = os.environ.get("WAF_TEST_LOG", os.path.join(os.path.dirname(__file__), "decisions.jsonl"))
app = FastAPI(title="WAF Gen 3 detection test harness")


@app.get("/healthz")
def healthz():
    return {"model_loaded": MODEL is not None, "runtime": getattr(MODEL, "runtime", None),
            "threshold": THRESHOLD, "error": ERR}


@app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"])
async def gate(full_path: str, request: Request):
    """Score the request; 403 = model flags an attack, 200 = allowed through to the (stub) origin."""
    raw = await request.body()
    try:
        body = raw.decode("utf-8", "replace")
    except Exception:
        body = ""
    url = request.url.path + (("?" + request.url.query) if request.url.query else "")
    if MODEL is None:
        return PlainTextResponse("model unavailable", status_code=503)
    try:
        score = MODEL.score_request(method=request.method, url=url, body=body)
    except Exception as exc:
        # Fail open, and record it, so a scoring crash never looks like a block.
        score = 0.0
        _log(request.method, url, len(raw), None, f"{type(exc).__name__}: {exc}")
        return PlainTextResponse("origin ok", status_code=200)
    blocked = score >= THRESHOLD
    _log(request.method, url, len(raw), score, None)
    if blocked:
        return JSONResponse({"blocked": True, "score": round(score, 4)}, status_code=403)
    return PlainTextResponse("origin ok", status_code=200)


def _log(method, url, body_len, score, error):
    rec = {"t": round(time.time(), 3), "method": method, "url": url[:800], "body_len": body_len,
           "score": score, "blocked": bool(score is not None and score >= THRESHOLD), "error": error}
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:
        pass
