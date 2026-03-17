"""
app.py - LLMGuard Flask Backend
OWASP LLM Top 10 Red-Teaming Tool

Endpoints:
  GET  /                    → Web UI
  GET  /api/categories      → Available OWASP categories + payload counts
  POST /api/scan            → SSE stream: runs payloads against a target LLM
  GET  /api/payloads        → Full payload library metadata
"""

import json
import logging
import os
import time
import uuid
from typing import Generator

import requests
from dotenv import load_dotenv
from flask import Flask, Response, jsonify, render_template, request, stream_with_context

from scanner import (
    ALL_PAYLOADS,
    OWASPCategory,
    analyze_response,
    get_all_categories,
    get_payloads_by_category,
)

load_dotenv()

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("llmguard")

# Simple in-memory rate limiter: {ip: [timestamp, ...]}
_rate_limit_store: dict[str, list[float]] = {}
RATE_LIMIT_MAX = int(os.getenv("RATE_LIMIT_MAX", "10"))   # requests per window
RATE_LIMIT_WINDOW = int(os.getenv("RATE_LIMIT_WINDOW", "60"))  # seconds


def _check_rate_limit(ip: str) -> bool:
    """Return True if request is allowed, False if rate-limited."""
    now = time.time()
    window_start = now - RATE_LIMIT_WINDOW
    timestamps = [t for t in _rate_limit_store.get(ip, []) if t > window_start]
    if len(timestamps) >= RATE_LIMIT_MAX:
        return False
    timestamps.append(now)
    _rate_limit_store[ip] = timestamps
    return True


# ---------------------------------------------------------------------------
# LLM Client helpers
# ---------------------------------------------------------------------------

REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "30"))  # seconds


def _call_openai(prompt: str, api_key: str, model: str, system_prompt: str = "") -> str:
    """Send a prompt to an OpenAI-compatible endpoint and return the text reply."""
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    messages = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": prompt})
    body = {
        "model": model,
        "messages": messages,
        "max_tokens": 1024,
        "temperature": 0.7,
    }
    resp = requests.post(
        "https://api.openai.com/v1/chat/completions",
        headers=headers,
        json=body,
        timeout=REQUEST_TIMEOUT,
    )
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]["content"]


def _call_anthropic(prompt: str, api_key: str, model: str, system_prompt: str = "") -> str:
    """Send a prompt to the Anthropic Messages API and return the text reply."""
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "Content-Type": "application/json",
    }
    body: dict = {
        "model": model,
        "max_tokens": 1024,
        "messages": [{"role": "user", "content": prompt}],
    }
    if system_prompt:
        body["system"] = system_prompt
    resp = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers=headers,
        json=body,
        timeout=REQUEST_TIMEOUT,
    )
    resp.raise_for_status()
    return resp.json()["content"][0]["text"]


def _dispatch(prompt: str, provider: str, api_key: str, model: str, system_prompt: str = "") -> str:
    """Route the prompt to the correct provider and return the reply text."""
    if provider == "openai":
        return _call_openai(prompt, api_key, model, system_prompt)
    elif provider == "anthropic":
        return _call_anthropic(prompt, api_key, model, system_prompt)
    else:
        raise ValueError(f"Unknown provider: {provider!r}")


# ---------------------------------------------------------------------------
# SSE helpers
# ---------------------------------------------------------------------------

def _sse_event(event: str, data: dict) -> str:
    """Format a Server-Sent Events message."""
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


def _scan_generator(
    scan_id: str,
    provider: str,
    api_key: str,
    model: str,
    category_ids: list[str],
    delay: float,
    system_prompt: str = "",
) -> Generator[str, None, None]:
    """
    Generator that yields SSE events as each payload is executed.
    Yields:
      - 'scan_start'   – metadata about the scan run
      - 'result'       – one event per payload with result details
      - 'scan_end'     – summary statistics
      - 'error'        – if a fatal error occurs
    """
    # Collect payloads for the requested categories
    payloads = []
    for cat_id in category_ids:
        try:
            cat = OWASPCategory(cat_id)
            payloads.extend(get_payloads_by_category(cat))
        except ValueError:
            logger.warning("Unknown category requested: %s", cat_id)

    if not payloads:
        yield _sse_event("error", {"message": "No payloads matched the selected categories."})
        return

    yield _sse_event("scan_start", {
        "scan_id": scan_id,
        "provider": provider,
        "model": model,
        "total_payloads": len(payloads),
        "timestamp": time.time(),
    })

    # Tally for the final summary
    stats = {"VULNERABLE": 0, "PARTIAL": 0, "RESISTANT": 0, "REVIEW": 0, "ERROR": 0}
    severity_counts: dict[str, dict[str, int]] = {}

    for idx, payload in enumerate(payloads, start=1):
        try:
            logger.info("[%s] Running %s (%d/%d)", scan_id, payload.id, idx, len(payloads))
            start_ts = time.time()
            response_text = _dispatch(payload.prompt, provider, api_key, model, system_prompt)
            elapsed = round(time.time() - start_ts, 2)

            analysis = analyze_response(payload, response_text)
            status = analysis["status"]

            stats[status] = stats.get(status, 0) + 1

            # Track severity breakdown
            sev = payload.severity.value
            if sev not in severity_counts:
                severity_counts[sev] = {"VULNERABLE": 0, "PARTIAL": 0, "RESISTANT": 0, "REVIEW": 0}
            severity_counts[sev][status] = severity_counts[sev].get(status, 0) + 1

            yield _sse_event("result", {
                "index": idx,
                "total": len(payloads),
                "payload": payload.to_dict(),
                "response_preview": response_text[:500],
                "analysis": analysis,
                "elapsed_ms": int(elapsed * 1000),
                "timestamp": time.time(),
            })

        except requests.exceptions.Timeout:
            stats["ERROR"] += 1
            yield _sse_event("result", {
                "index": idx,
                "total": len(payloads),
                "payload": payload.to_dict(),
                "response_preview": "",
                "analysis": {"status": "ERROR", "confidence": 0, "error": "Request timed out"},
                "elapsed_ms": REQUEST_TIMEOUT * 1000,
                "timestamp": time.time(),
            })
        except requests.exceptions.HTTPError as exc:
            stats["ERROR"] += 1
            err_body = exc.response.text[:200] if exc.response else str(exc)
            yield _sse_event("result", {
                "index": idx,
                "total": len(payloads),
                "payload": payload.to_dict(),
                "response_preview": "",
                "analysis": {"status": "ERROR", "confidence": 0, "error": f"HTTP {exc.response.status_code}: {err_body}"},
                "elapsed_ms": 0,
                "timestamp": time.time(),
            })
        except Exception as exc:
            stats["ERROR"] += 1
            logger.exception("Unexpected error on payload %s", payload.id)
            yield _sse_event("result", {
                "index": idx,
                "total": len(payloads),
                "payload": payload.to_dict(),
                "response_preview": "",
                "analysis": {"status": "ERROR", "confidence": 0, "error": str(exc)},
                "elapsed_ms": 0,
                "timestamp": time.time(),
            })

        # Polite delay between requests to avoid triggering provider rate limits
        if idx < len(payloads) and delay > 0:
            time.sleep(delay)

    # Compute overall risk score (0–100)
    vuln_weight = stats["VULNERABLE"] * 3 + stats["PARTIAL"] * 1
    max_weight = len(payloads) * 3
    risk_score = round((vuln_weight / max_weight) * 100) if max_weight else 0

    yield _sse_event("scan_end", {
        "scan_id": scan_id,
        "stats": stats,
        "severity_counts": severity_counts,
        "risk_score": risk_score,
        "total_payloads": len(payloads),
        "timestamp": time.time(),
    })


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/health")
def api_health():
    """Liveness probe for GCP Cloud Run / load balancers."""
    return jsonify({"status": "ok", "version": "1.0.0"}), 200


@app.route("/api/keys-status")
def api_keys_status():
    """Return which API keys are configured (without exposing them)."""
    claude_key = os.getenv("CLAUDE_API_KEY", "").strip()
    openai_key = os.getenv("OPENAI_API_KEY", "").strip()
    return jsonify({
        "claude_available": bool(claude_key),
        "openai_available": bool(openai_key),
        "default_provider": "anthropic" if claude_key else "openai" if openai_key else None,
    })


@app.route("/api/categories")
def api_categories():
    """Return all OWASP LLM Top 10 categories with payload metadata."""
    return jsonify(get_all_categories())


@app.route("/api/payloads")
def api_payloads():
    """Return the full payload library (metadata only, no execution)."""
    category_filter = request.args.get("category")
    payloads = ALL_PAYLOADS
    if category_filter:
        payloads = [p for p in payloads if p.category.value == category_filter]
    return jsonify([p.to_dict() for p in payloads])


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """
    Stream scan results as Server-Sent Events.

    Expected JSON body:
    {
      "provider":    "anthropic" | "openai",
      "api_key":     "<user-supplied key>" (optional; uses .env if omitted),
      "model":       "claude-sonnet-4-6" | "gpt-4o" | etc.,
      "categories":  ["LLM01", "LLM06", ...],   // optional; omit for all
      "delay":       1.0                          // seconds between requests (optional)
    }
    """
    ip = request.remote_addr
    if not _check_rate_limit(ip):
        return jsonify({"error": "Rate limit exceeded. Please wait before scanning again."}), 429

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Request body must be JSON."}), 400

    provider = data.get("provider", "").strip().lower()
    api_key = data.get("api_key", "").strip()
    model = data.get("model", "").strip()
    system_prompt = data.get("system_prompt", "").strip()
    categories = data.get("categories", [cat.value for cat in OWASPCategory])
    delay = float(data.get("delay", 1.0))

    # Validate required fields
    if provider not in ("openai", "anthropic"):
        return jsonify({"error": "provider must be 'openai' or 'anthropic'."}), 400
    
    # If no API key provided, try to use one from .env
    if not api_key:
        if provider == "anthropic":
            api_key = os.getenv("CLAUDE_API_KEY", "").strip()
        elif provider == "openai":
            api_key = os.getenv("OPENAI_API_KEY", "").strip()
    
    if not api_key:
        return jsonify({"error": f"api_key is required (or set {provider.upper()}_API_KEY in .env)."}), 400
    if not model:
        return jsonify({"error": "model is required."}), 400
    if not isinstance(categories, list) or not categories:
        return jsonify({"error": "categories must be a non-empty list."}), 400

    # Clamp delay to a sane range
    delay = max(0.0, min(delay, 10.0))

    scan_id = str(uuid.uuid4())[:8]
    logger.info("Scan %s started — provider=%s model=%s categories=%s", scan_id, provider, model, categories)

    return Response(
        stream_with_context(_scan_generator(scan_id, provider, api_key, model, categories, delay, system_prompt)),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",   # Disable Nginx buffering
            "Access-Control-Allow-Origin": "*",
        },
    )


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(500)
def internal_error(e):
    logger.exception("Internal server error")
    return jsonify({"error": "Internal server error"}), 500


# ---------------------------------------------------------------------------
# Dev entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="0.0.0.0", port=port, debug=debug, threaded=True)
