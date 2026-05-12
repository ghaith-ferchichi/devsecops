from prometheus_client import Counter, Gauge, Histogram, Info

agent_reviews_total = Counter(
    "agent_reviews_total", "Total PR reviews", ["risk_score", "verdict"]
)

agent_llm_duration = Histogram(
    "agent_llm_duration_seconds", "LLM call duration", ["model", "node"],
    buckets=[5, 10, 30, 60, 120, 180, 300],
)

agent_scan_duration = Histogram(
    "agent_scan_duration_seconds", "Scanner duration", ["scanner"],
    buckets=[5, 10, 30, 60, 120, 300],
)

agent_errors_total = Counter(
    "agent_errors_total", "Pipeline errors by stage", ["stage"]
)

agent_pipeline_duration = Histogram(
    "agent_pipeline_duration_seconds", "Total pipeline duration",
    buckets=[30, 60, 120, 180, 300, 600],
)

agent_cache_hits = Counter(
    "agent_cache_hits_total", "Redis cache hits"
)

# Ollama connectivity (1 = reachable, 0 = unreachable — set by 30s poller)
ollama_reachable = Gauge(
    "ollama_reachable", "1 if Ollama API is reachable, 0 if not"
)

# Ollama model metrics (polled every 30s from /api/ps)
ollama_model_loaded = Gauge(
    "ollama_model_loaded", "Whether a model is currently loaded in Ollama", ["model"]
)
ollama_model_size_bytes = Gauge(
    "ollama_model_size_bytes", "Size of loaded model in bytes", ["model"]
)
ollama_model_vram_bytes = Gauge(
    "ollama_model_vram_bytes", "VRAM used by loaded model in bytes", ["model"]
)
ollama_models_loaded_total = Gauge(
    "ollama_models_loaded_total", "Total number of models currently loaded in Ollama"
)

# LocalAI sandbox connectivity (1 = reachable, 0 = unreachable — set by 30s poller)
localai_reachable = Gauge(
    "localai_reachable", "1 if LocalAI sandbox API is reachable, 0 if not"
)
localai_models_total = Gauge(
    "localai_models_total", "Number of models installed in LocalAI sandbox"
)
localai_health_check_latency_seconds = Gauge(
    "localai_health_check_latency_seconds",
    "Latency of the last /readyz probe against LocalAI (seconds)",
)
# Per-model presence — 1 if the model is installed in LocalAI, 0 once removed.
# The 30s poller sets this from /v1/models and zeroes labels that disappear.
localai_model_installed = Gauge(
    "localai_model_installed",
    "1 if the model is installed in LocalAI sandbox",
    ["model"],
)
# On-disk size in GB (sourced from LOCALAI_MODEL_META catalog in app.routers.chat).
# Zero for models not in the catalog (we don't probe LocalAI's filesystem).
localai_model_size_gb = Gauge(
    "localai_model_size_gb",
    "On-disk size of LocalAI model in gigabytes (from catalog)",
    ["model"],
)

# ── Chat backend A/B telemetry (Ollama vs LocalAI) ───────────────────────
# These wrap /chat/stream and let Grafana compare backend latency / throughput
# without touching the production PR-review path.
chat_requests_total = Counter(
    "chat_requests_total",
    "Chat streaming requests by backend / model / status",
    ["backend", "model", "status"],
)
chat_request_seconds = Histogram(
    "chat_request_seconds",
    "End-to-end duration of /chat/stream calls",
    ["backend", "model"],
    buckets=[1, 2, 5, 10, 20, 40, 80, 160, 320, 600],
)
chat_first_token_seconds = Histogram(
    "chat_first_token_seconds",
    "Time to first generated token (cold-load + prompt eval)",
    ["backend", "model"],
    buckets=[0.5, 1, 2, 5, 10, 20, 40, 80, 160, 320],
)
chat_tokens_streamed_total = Counter(
    "chat_tokens_streamed_total",
    "Tokens streamed back to the chat UI (one chunk ≈ one token)",
    ["backend", "model"],
)

# Disk usage — scraped by Prometheus alert rules (no node-exporter needed)
agent_disk_used_percent = Gauge(
    "agent_disk_used_percent", "Root filesystem used percentage (0-100)"
)
agent_disk_free_gb = Gauge(
    "agent_disk_free_gb", "Root filesystem free space in GB"
)

# ── Per-container metrics (docker-stats poller) ──────────────────────────
# We poll the docker socket every 30s rather than running cAdvisor — Docker
# on this host uses the containerd snapshotter which breaks cAdvisor's
# layer-DB integration. The poller lives in app/main.py.
container_running = Gauge(
    "container_running",
    "1 if the container is running, 0 if stopped/missing",
    ["name", "image"],
)
container_memory_bytes = Gauge(
    "container_memory_bytes",
    "Container memory usage in bytes (RSS+cache)",
    ["name", "image"],
)
container_memory_limit_bytes = Gauge(
    "container_memory_limit_bytes",
    "Container memory limit in bytes (0 if unbounded)",
    ["name", "image"],
)
container_cpu_percent = Gauge(
    "container_cpu_percent",
    "Container CPU usage as percent of one core (100 = one full core)",
    ["name", "image"],
)
container_network_rx_bytes = Gauge(
    "container_network_rx_bytes",
    "Bytes received by the container since start (sum of all interfaces)",
    ["name"],
)
container_network_tx_bytes = Gauge(
    "container_network_tx_bytes",
    "Bytes transmitted by the container since start (sum of all interfaces)",
    ["name"],
)
