#!/usr/bin/env bash
# ============================================================================
# Measure warm-token-per-second on every chat model installed in LocalAI.
#
# Output: a Markdown table you can paste into agent/app/routers/chat.py
# under LOCALAI_MODEL_META["<model>"]["speed_tps"].
#
# Each model is queried twice:
#   1st call → cold load (discarded — populates RAM)
#   2nd call → measured (warm)
#
# Usage:
#   bash scripts/benchmark-localai.sh                     # all models
#   bash scripts/benchmark-localai.sh phi-4 gemma-3-4b-it # specific models
#
# Notes:
#   - Skips mmproj-*.gguf (vision projectors, not chat models)
#   - Each warm pass generates 80 tokens — keeps the run under ~5 min total
# ============================================================================
set -euo pipefail

LOCALAI_URL="${LOCALAI_URL:-http://localhost:8081}"
PROMPT='Write a 60-word paragraph summarising the OWASP Top 10 risks for a PHP web application. Keep it factual.'
MAX_TOKENS=80

# Resolve target model list
if [[ $# -gt 0 ]]; then
  MODELS=("$@")
else
  mapfile -t MODELS < <(
    curl -fsS "${LOCALAI_URL}/v1/models" \
      | python3 -c "
import sys,json
d=json.load(sys.stdin)
for m in d.get('data',[]):
  mid=m.get('id','')
  if mid and 'mmproj' not in mid.lower() and not mid.endswith('.gguf'):
    print(mid)
"
  )
fi

if [[ ${#MODELS[@]} -eq 0 ]]; then
  echo "No chat models found in LocalAI."
  exit 1
fi

echo "Benchmarking ${#MODELS[@]} model(s) — ~30-60s per model (warm pass only)…"
echo

# Markdown header
printf '| Model | Warm tok/s | Tokens | Wall time (s) |\n'
printf '|-------|------------|--------|----------------|\n'

for model in "${MODELS[@]}"; do
  # ── Cold load (discarded) ──────────────────────────────────────────────
  curl -sS -o /dev/null -X POST "${LOCALAI_URL}/v1/chat/completions" \
    -H "Content-Type: application/json" \
    -d "{\"model\":\"${model}\",\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}],\"max_tokens\":4}" \
    || { printf '| %s | err | — | — |\n' "$model"; continue; }

  # ── Warm pass (measured) ───────────────────────────────────────────────
  payload=$(python3 -c "
import json
print(json.dumps({
  'model': '${model}',
  'messages': [{'role': 'user', 'content': '''${PROMPT}'''}],
  'max_tokens': ${MAX_TOKENS},
  'temperature': 0.1,
}))
")

  start=$(date +%s.%N)
  response=$(curl -sS -X POST "${LOCALAI_URL}/v1/chat/completions" \
    -H "Content-Type: application/json" -d "$payload" || echo '{}')
  end=$(date +%s.%N)

  tokens=$(echo "$response" | python3 -c "
import sys,json
try:
  d=json.load(sys.stdin)
  print(d.get('usage',{}).get('completion_tokens', 0))
except Exception:
  print(0)
")

  wall=$(python3 -c "print(round(${end} - ${start}, 2))")
  if [[ "$tokens" -gt 0 && $(python3 -c "print(1 if ${wall}>0 else 0)") == "1" ]]; then
    tps=$(python3 -c "print(round(${tokens} / ${wall}, 1))")
  else
    tps='err'
  fi

  printf '| `%s` | **%s** | %s | %s |\n' "$model" "$tps" "$tokens" "$wall"
done

echo
echo "Paste the numbers into agent/app/routers/chat.py LOCALAI_MODEL_META[<model>]['speed_tps']."
