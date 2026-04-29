import time
from functools import lru_cache

import httpx
import structlog
from langchain_ollama import ChatOllama

from app.config import get_settings

log = structlog.get_logger().bind(service="llm")

# Circuit breaker state
_failure_count = 0
_circuit_open_until = 0.0
_FAILURE_THRESHOLD = 3
_COOLDOWN_SECONDS = 300


@lru_cache
def get_fast_llm() -> ChatOllama:
    """7B model for classification — fast, JSON-forced."""
    s = get_settings()
    return ChatOllama(
        base_url=s.ollama_base_url,
        model=s.ollama_model_fast,
        temperature=0.0,
        num_ctx=4096,          # classify prompt is short — 4K is enough
        num_predict=512,
        format="json",
        keep_alive="10m",
        request_timeout=float(s.ollama_timeout),
    )


@lru_cache
def get_deep_llm() -> ChatOllama:
    """14B model for deep security analysis — SAST output + diff can be large."""
    s = get_settings()
    return ChatOllama(
        base_url=s.ollama_base_url,
        model=s.ollama_model_deep,
        temperature=0.1,
        num_ctx=8192,          # scan data + PR diff easily exceeds 4K
        num_predict=1500,
        keep_alive="10m",
        request_timeout=float(s.ollama_timeout),
    )


@lru_cache
def get_combined_llm() -> ChatOllama:
    """14B model for combined security + code-quality review — larger context window."""
    s = get_settings()
    return ChatOllama(
        base_url=s.ollama_base_url,
        model=s.ollama_model_deep,
        temperature=0.1,
        num_ctx=12288,         # scan results + diff + annotated diff
        num_predict=2500,
        keep_alive="10m",
        request_timeout=float(s.ollama_timeout),
    )


@lru_cache
def get_review_llm() -> ChatOllama:
    """14B model for code-quality review — balanced speed/accuracy, JSON output."""
    s = get_settings()
    return ChatOllama(
        base_url=s.ollama_base_url,
        model=s.ollama_model_review,
        temperature=0.1,
        num_ctx=8192,          # diff + inline comment context needs room
        num_predict=2048,
        format="json",
        keep_alive="10m",
        request_timeout=float(s.ollama_timeout),
    )


def is_circuit_open() -> bool:
    """Check if the LLM circuit breaker is open (too many failures)."""
    if _failure_count >= _FAILURE_THRESHOLD and time.time() < _circuit_open_until:
        return True
    return False


def record_llm_failure():
    """Record an LLM call failure. Opens circuit after threshold."""
    global _failure_count, _circuit_open_until
    _failure_count += 1
    if _failure_count >= _FAILURE_THRESHOLD:
        _circuit_open_until = time.time() + _COOLDOWN_SECONDS
        log.warning("circuit_breaker_open", cooldown=_COOLDOWN_SECONDS)


def record_llm_success():
    """Record a successful LLM call. Resets circuit breaker."""
    global _failure_count
    _failure_count = 0


async def check_ollama_health() -> bool:
    """Check if Ollama is reachable."""
    try:
        async with httpx.AsyncClient(timeout=5) as c:
            r = await c.get(f"{get_settings().ollama_base_url}/api/tags")
            return r.status_code == 200
    except Exception:
        return False
