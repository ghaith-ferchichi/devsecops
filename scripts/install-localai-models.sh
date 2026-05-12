#!/usr/bin/env bash
# ============================================================================
# Install the test model set into the LocalAI sandbox.
# Idempotent — re-running is safe (LocalAI skips already-installed models).
#
# Required: LocalAI sandbox running on http://localhost:8081
#   docker compose -f docker-compose.localai.yml up -d
#
# Usage:
#   bash scripts/install-localai-models.sh          # all 4 models
#   bash scripts/install-localai-models.sh qwen7    # just qwen2.5-coder:7b
# ============================================================================
set -euo pipefail

LOCALAI_URL="${LOCALAI_URL:-http://localhost:8081}"

# Wait for LocalAI to be ready
echo "→ Waiting for LocalAI at ${LOCALAI_URL}…"
for i in $(seq 1 60); do
  if curl -fsS "${LOCALAI_URL}/readyz" >/dev/null 2>&1; then
    echo "  LocalAI is ready."
    break
  fi
  sleep 2
done

# Model set — verified against LocalAI v3.0.0 gallery (May 2026)
#   Gallery IDs come from `curl http://localhost:8081/models/available`.
#
# Installed by default:
#   gemma3      Google instruction-tuned 12B (~8 GB Q4)
#   gemma3-4b   Google instruction-tuned 4B  (~3 GB Q4, fast smoke test)
#   qwen3coder  Qwen3-Coder MoE 30B/3B-active (~18 GB, modern coder)
#
# Direct HuggingFace GGUFs (e.g. qwen2.5-coder, phi-4) are NOT included here
# because LocalAI v3.0.0 /models/apply requires a gallery-style YAML config
# alongside the GGUF. To install them, write a YAML in localai/config/ and
# mount it — see comments at the bottom of this file for an example.
declare -A MODELS=(
  [gemma3-4b]="gemma-3-4b-it"
  [gemma3]="gemma-3-12b-it"
  [qwen3coder]="qwen3-coder-30b-a3b-instruct"
)

install_model() {
  local key="$1"
  if [[ ! -v MODELS[$key] ]]; then
    echo "✗ Unknown model key: ${key}"
    echo "  Available: ${!MODELS[*]}"
    return 1
  fi
  local model_id="${MODELS[$key]}"
  echo
  echo "──────────────────────────────────────────────────"
  echo "→ Installing ${key} → ${model_id}"
  echo "──────────────────────────────────────────────────"
  curl -fsS -X POST "${LOCALAI_URL}/models/apply" \
    -H "Content-Type: application/json" \
    -d "{\"id\": \"${model_id}\"}" \
    | python3 -m json.tool || echo "  (request accepted — download runs async)"
  # Serialize to avoid overloading the install worker
  sleep 5
}

# Either install the one model requested, or all of them
if [[ $# -gt 0 ]]; then
  for key in "$@"; do
    install_model "$key" || exit 1
  done
else
  for key in gemma3-4b gemma3 qwen3coder; do
    install_model "$key" || true
  done
fi

# ────────────────────────────────────────────────────────────────────────
# Manual HuggingFace install (Phi-4, Qwen2.5-Coder, etc.)
# ────────────────────────────────────────────────────────────────────────
# LocalAI v3.0.0 /models/apply does not accept bare GGUF URLs.
# To install a HuggingFace GGUF that is not in the gallery, write a small
# YAML in localai/config/ then restart the container. Example for Phi-4:
#
#   # /opt/devsecops/localai/config/phi-4.yaml
#   name: phi-4
#   parameters:
#     model: huggingface://bartowski/phi-4-GGUF/phi-4-Q4_K_M.gguf
#   context_size: 8192
#   threads: 12
#
# Then:
#   docker compose -f docker-compose.localai.yml restart localai
#   curl http://localhost:8081/v1/models   # phi-4 should appear
# ────────────────────────────────────────────────────────────────────────

echo
echo "──────────────────────────────────────────────────"
echo "→ Download jobs (may take 20-40 min total on first run):"
echo "──────────────────────────────────────────────────"
curl -fsS "${LOCALAI_URL}/models/jobs" | python3 -m json.tool || true

echo
echo "→ Currently installed models:"
curl -fsS "${LOCALAI_URL}/v1/models" | python3 -m json.tool || true

echo
echo "Done. Track progress with:"
echo "  watch -n 5 'curl -s ${LOCALAI_URL}/models/jobs | python3 -m json.tool'"
