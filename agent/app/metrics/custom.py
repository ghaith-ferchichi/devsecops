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

# Disk usage — scraped by Prometheus alert rules (no node-exporter needed)
agent_disk_used_percent = Gauge(
    "agent_disk_used_percent", "Root filesystem used percentage (0-100)"
)
agent_disk_free_gb = Gauge(
    "agent_disk_free_gb", "Root filesystem free space in GB"
)
