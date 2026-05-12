#!/usr/bin/env bash
# ============================================================================
# benchmark-backends.sh — head-to-head Ollama vs LocalAI on the same model.
#
# Methodology (mirrors scripts/benchmark-localai.sh):
#   1. Cold-load prime (4 tokens, response discarded) — makes the model resident
#   2. Warm timed pass — measures wall time + parses usage.completion_tokens
#   3. tok/s = completion_tokens / wall_seconds
#
# Both backends are reached from inside the `devsecops-agent` container, which
# already sits on `devsecops-net` and has Python + httpx. This avoids depending
# on curl being present in the ollama image (it isn't) while keeping identical
# mechanism for both backends — so the comparison stays apples-to-apples.
#
# Usage:
#   scripts/benchmark-backends.sh              # default qwen2.5-coder
#   scripts/benchmark-backends.sh -v           # also print response bodies
# ============================================================================
set -euo pipefail

VERBOSE=false
[[ "${1:-}" == "-v" || "${1:-}" == "--also-print-response" ]] && VERBOSE=true

# Embedded Python runner — receives backend URL + model + verbose flag,
# prints "<tokens>|<seconds>|<first_120_chars_of_response>" on success.
read -r -d '' PY_RUNNER <<'PY' || true
import json, sys, time, httpx

base_url, model, verbose = sys.argv[1], sys.argv[2], sys.argv[3] == "true"
prompt = (
    "Write a 60-word paragraph summarising the OWASP Top 10 risks "
    "for a PHP web application. Keep it factual."
)

with httpx.Client(timeout=900.0) as c:
    # Cold prime — 4 tokens, discarded.
    c.post(f"{base_url}/v1/chat/completions", json={
        "model": model,
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": 4,
    })
    # Warm timed pass.
    start = time.monotonic()
    r = c.post(f"{base_url}/v1/chat/completions", json={
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 80,
        "temperature": 0.1,
    })
    secs = time.monotonic() - start

r.raise_for_status()
data = r.json()
tokens = (data.get("usage") or {}).get("completion_tokens", 0)
body = (data.get("choices") or [{}])[0].get("message", {}).get("content", "")
print(f"{tokens}|{secs:.3f}|{body if verbose else body[:120]}")
PY

bench() {
  local label="$1" base_url="$2" model="$3"
  echo "▶ $label ($model) — priming + warm pass..." >&2
  local out tokens secs body tps
  if ! out=$(docker exec -i devsecops-agent python -c "$PY_RUNNER" "$base_url" "$model" "$VERBOSE" 2>&1); then
    printf '| %-7s | %-22s | %6s | %8s | %5s |\n' "$label" "$model" "err" "err" "err"
    echo "── $label error ──" >&2
    echo "$out" >&2
    return
  fi
  tokens=${out%%|*}; rest=${out#*|}
  secs=${rest%%|*}; body=${rest#*|}
  tps=$(awk -v t="$tokens" -v s="$secs" 'BEGIN{printf "%.2f", t/s}')
  printf '| %-7s | %-22s | %6d | %8s | %5s |\n' "$label" "$model" "$tokens" "$secs" "$tps"
  if [[ "$VERBOSE" == "true" ]]; then
    echo "── $label response ──" >&2
    echo "$body" >&2
    echo "" >&2
  fi
}

echo
echo "| Backend | Model                  | Tokens | Wall (s) | tok/s |"
echo "|---------|------------------------|-------:|---------:|------:|"
bench "Ollama"  "http://ollama:11434"  "qwen2.5-coder:7b"
bench "LocalAI" "http://localai:8080"  "qwen2.5-coder-7b"
echo
