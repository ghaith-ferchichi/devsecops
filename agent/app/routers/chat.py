"""
Chat router — ops assistant endpoints.

GET  /chat/models   → list available Ollama models
POST /chat/stream   → SSE streaming ReAct chat
GET  /ui            → serve the chat HTML
"""
from __future__ import annotations

import asyncio
import json
import re
import time as _time
from pathlib import Path
from typing import AsyncIterator

import httpx
import structlog
from fastapi import APIRouter
from fastapi.responses import HTMLResponse, StreamingResponse
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langchain_ollama import ChatOllama
from pydantic import BaseModel

from app.workflows.ops_assistant.graph import SYSTEM_PROMPT, TOOL_MAP

log = structlog.get_logger().bind(service="chat")
router = APIRouter(tags=["chat"])

_UI_PATH = Path(__file__).parent.parent / "static" / "index.html"

# Matches a fenced code block wrapping JSON
_FENCE_RE = re.compile(r'^```(?:json)?\s*([\s\S]*?)\s*```\s*$')
# Matches a JSON tool call anywhere in text (last occurrence wins)
_EMBEDDED_TC_RE = re.compile(
    r'\{[^{}]*"name"\s*:\s*"([^"]+)"[^{}]*"arguments"\s*:\s*(\{[^{}]*\})[^{}]*\}',
    re.DOTALL,
)


# ───────────────────────────────────────────────────────────
# Request / response models
# ───────────────────────────────────────────────────────────

class ChatMessage(BaseModel):
    role: str        # "user" | "assistant"
    content: str     # plain text for user; for assistant may be JSON segment array


class ChatRequest(BaseModel):
    message: str
    model: str = "qwen2.5-coder:7b"    # 7b default: ~2× faster than 14b on CPU
    history: list[ChatMessage] = []


# ───────────────────────────────────────────────────────────
# Helpers
# ───────────────────────────────────────────────────────────

def _sse(data: dict) -> str:
    return f"data: {json.dumps(data)}\n\n"


def _try_parse_json_tc(t: str) -> dict | None:
    """Try to JSON-parse a string as a tool call dict."""
    try:
        d = json.loads(t)
        if isinstance(d, dict) and "name" in d and "arguments" in d:
            return d
    except Exception:
        pass
    return None


def _extract_tool_call(text: str) -> tuple[dict | None, str]:
    """Find a tool call anywhere in text.

    Returns (tool_call_dict, pre_text) where pre_text is the
    human-readable text that appeared before the tool call (may be empty).
    Handles:
      - Pure JSON:              {"name": "...", "arguments": {...}}
      - Fenced JSON:            ```json\\n{...}\\n```
      - Text then JSON:         "Let's try:\\n{"name": ...}"
      - Text then fenced JSON:  "Oops, correcting:\\n```json\\n{...}\\n```"
    """
    t = text.strip()

    # 1. Whole response is a fenced block
    m = _FENCE_RE.match(t)
    if m:
        tc = _try_parse_json_tc(m.group(1).strip())
        if tc:
            return tc, ""

    # 2. Whole response is plain JSON
    tc = _try_parse_json_tc(t)
    if tc:
        return tc, ""

    # 3. Tool call embedded somewhere in text — find the LAST occurrence
    #    so that explanatory text before it becomes pre_text
    for match in reversed(list(_EMBEDDED_TC_RE.finditer(text))):
        candidate = match.group(0)
        tc = _try_parse_json_tc(candidate)
        if tc:
            pre = text[:match.start()].strip()
            return tc, pre

    # 4. Fenced block embedded in text
    for fm in re.finditer(r'```(?:json)?\s*([\s\S]*?)\s*```', text):
        tc = _try_parse_json_tc(fm.group(1).strip())
        if tc:
            pre = text[:fm.start()].strip()
            return tc, pre

    return None, text


def _looks_like_tool_call(text: str) -> bool:
    """Quick heuristic on first non-whitespace chars — suppress token streaming."""
    t = text.lstrip()
    return t.startswith("{") or t.startswith("```")


def _flatten_history(history: list[ChatMessage]) -> list:
    """Convert ChatMessage history to LangChain message objects."""
    msgs = []
    for msg in history[-16:]:     # keep last 16 turns
        if msg.role == "user":
            msgs.append(HumanMessage(content=msg.content))
        else:
            # assistant content may be a JSON segment array — flatten to plain text
            content = msg.content
            try:
                segs = json.loads(content)
                if isinstance(segs, list):
                    text_parts = []
                    tool_names = []
                    for s in segs:
                        if s.get("type") == "text":
                            text_parts.append(s["content"])
                        elif s.get("type") == "thinking":
                            pass  # skip raw tool-call JSON from history
                        elif s.get("type") == "tool":
                            tool_names.append(s["name"])
                    # Summarise tool usage without a mimicable format
                    if tool_names:
                        tools_used = ", ".join(f"`{n}`" for n in tool_names)
                        summary = f"(In a previous step I used: {tools_used} to gather data.)"
                        content = summary + ("\n\n" + "\n\n".join(text_parts) if text_parts else "")
                    else:
                        content = "\n\n".join(text_parts)
            except Exception:
                pass
            msgs.append(AIMessage(content=content))
    return msgs


# ── Tool result cache ────────────────────────────────────────
# Avoids re-running identical tool calls within a short window.
# Keyed by "tool_name:sorted_json_args" → (result_str, timestamp).
_TOOL_CACHE: dict[str, tuple[str, float]] = {}

# Per-tool TTL (seconds). 0 = never cache (write ops, highly volatile).
_TOOL_TTL: dict[str, int] = {
    "vps_status":              20,
    "disk_usage":              60,
    "container_stats":         10,
    "list_containers":         20,
    "list_images":            120,
    "prometheus_alerts":       30,
    "query_prometheus":        20,
    "query_prometheus_range": 120,
    "ollama_status":           20,
    "redis_info":              30,
    "jenkins_status":          30,
    "network_stats":           15,
    "system_net_io":           15,
    "query_database":          60,
    "list_scan_artifacts":     60,
}


def _run_tool(name: str, arguments: dict) -> str:
    """Invoke a tool synchronously and return its string result (cached)."""
    tool = TOOL_MAP.get(name)
    if tool is None:
        available = ", ".join(TOOL_MAP.keys())
        return f"Error: unknown tool '{name}'. Available: {available}"

    ttl = _TOOL_TTL.get(name, 0)
    cache_key = f"{name}:{json.dumps(arguments, sort_keys=True)}"

    if ttl > 0:
        cached = _TOOL_CACHE.get(cache_key)
        if cached:
            result, ts = cached
            if _time.time() - ts < ttl:
                return result   # serve from cache

    try:
        result = str(tool.invoke(arguments))
    except Exception as exc:
        return f"Tool error: {exc}"

    if ttl > 0:
        _TOOL_CACHE[cache_key] = (result, _time.time())
    return result


# ───────────────────────────────────────────────────────────
# Custom ReAct streaming loop
# ───────────────────────────────────────────────────────────

async def _unload_other_models(keep: str) -> None:
    """Unload any Ollama models that aren't the one we're about to use.

    Ollama only loads one model at a time on CPU; unloading prevents OOM when
    switching between models (e.g. 32b → 14b, each requiring 10–20 GB of RAM).
    """
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get("http://ollama:11434/api/ps")
            loaded = resp.json().get("models", [])
            for m in loaded:
                name = m.get("name", "")
                if name and name != keep:
                    await client.post(
                        "http://ollama:11434/api/generate",
                        json={"model": name, "keep_alive": 0},
                        timeout=30,
                    )
                    log.info("ollama_model_unloaded", model=name)
    except Exception as exc:
        log.warning("ollama_unload_failed", error=str(exc))


async def _stream_react(req: ChatRequest) -> AsyncIterator[str]:
    # Larger models need more time: ~2 tok/s for 32B, ~6 tok/s for 14B on CPU
    request_timeout = 900.0   # 15 min — covers cold-load + generation for any model

    # Signal immediately so the UI shows activity during model cold-start
    yield _sse({"type": "status", "content": f"Loading {req.model}…"})

    # Free RAM used by other loaded models before loading the requested one
    await _unload_other_models(keep=req.model)

    # Context: prompt ~1,900 tok + history + tool observations (each 100-500 tok).
    # 6144 gives ~4,200 tok free — enough for 6 tool observations + final answer.
    # 32b verbosely generates so keeps a larger window.
    _num_ctx = 16384 if "32b" in req.model else 6144

    # 800 tokens: tool call JSON ~80 tok, monitoring answers rarely exceed 700 tok.
    # Higher than before so complex multi-container/metric answers don't get cut off
    # mid-sentence (cut-off answers cause the model to fill the rest from memory).
    _num_predict = 800

    llm = ChatOllama(
        base_url="http://ollama:11434",
        model=req.model,
        temperature=0.0,   # deterministic — eliminates "creative" metric invention
        num_ctx=_num_ctx,
        num_predict=_num_predict,
        keep_alive="10m",
        request_timeout=request_timeout,
    )

    # Build message history with system prompt
    messages: list = [SystemMessage(content=SYSTEM_PROMPT)]
    messages += _flatten_history(req.history)
    messages.append(HumanMessage(content=req.message))

    max_steps = 8      # max tool calls before forcing final answer
    tool_call_count = 0
    called_tool_sigs: set[str] = set()   # dedup: "name:sorted_args_json"
    called_tool_names: list[str] = []    # ordered list for status messages

    # Keywords that signal the question requires live system data.
    # If the model tries to answer on step 0 without calling a tool for these,
    # we intercept and force a tool call.
    _LIVE_DATA_KW = {
        # Resource metrics — these always need live data
        "cpu", "ram", "memory", "disk", "network", "bandwidth", "load",
        "usage", "uptime", "free", "used", "available",
        # System entities
        "container", "containers", "process", "processes",
        "ollama", "redis", "jenkins", "prometheus", "grafana", "victoriametrics",
        # Operational concepts
        "running", "status", "health", "error", "errors",
        "log", "logs", "metric", "metrics", "alert", "alerts",
        "review", "reviews", "scan", "artifact", "database",
        # Time-relative triggers
        "current", "now", "live", "today", "latest", "real-time",
        # Action verbs that imply live inspection
        "show me", "how much", "how many", "how is",
        "check", "inspect", "monitor",
    }

    def _needs_tool(msg: str) -> bool:
        lower = msg.lower()
        return any(kw in lower for kw in _LIVE_DATA_KW)

    try:
        for step in range(max_steps):
            accumulated = ""
            thinking_buf = ""    # tokens emitted as thinking (tool-call building)
            is_tool_call: bool | None = None

            # ── Stream LLM response ──────────────────────────────────
            async for chunk in llm.astream(messages):
                tok = chunk.content
                if not tok:
                    continue
                accumulated += tok

                # Decide on first meaningful chars: tool call or text?
                if is_tool_call is None and accumulated.strip():
                    is_tool_call = _looks_like_tool_call(accumulated)
                    if is_tool_call:
                        # Announce that the model is reasoning about a tool
                        yield _sse({"type": "thinking_start", "step": step + 1})

                if is_tool_call is True:
                    # Stream raw tokens as "thinking" so the user sees the model deciding
                    thinking_buf += tok
                    yield _sse({"type": "thinking_token", "content": tok})
                else:
                    yield _sse({"type": "token", "content": tok})

            # Close thinking block before we resolve the call
            if is_tool_call is True:
                yield _sse({"type": "thinking_end"})

            # ── Check for tool call (anywhere in response) ───────────
            tool_call, pre_text = _extract_tool_call(accumulated)

            if tool_call:
                name = tool_call["name"]
                args = tool_call.get("arguments", {})

                # ── Dedup guard: hard-stop repeated tool+args ────────────
                sig = f"{name}:{json.dumps(args, sort_keys=True)}"
                if sig in called_tool_sigs:
                    already = ", ".join(f"`{t}`" for t in called_tool_names)
                    messages.append(AIMessage(content=accumulated))
                    messages.append(HumanMessage(content=(
                        f"STOP — you already called `{name}` with the same arguments.\n"
                        f"Data already collected this turn: {already}.\n"
                        f"Do NOT call any more tools. Write your complete final answer "
                        f"in Markdown now, using all the [OBSERVATION] data above."
                    )))
                    continue   # let the model write its final answer

                called_tool_sigs.add(sig)
                called_tool_names.append(name)
                tool_call_count += 1

                # If model added plain-text explanation before the JSON call,
                # surface it as a normal token (not as thinking)
                if pre_text:
                    if is_tool_call is False:
                        yield _sse({"type": "replace_text", "content": pre_text})
                    else:
                        yield _sse({"type": "token", "content": pre_text})

                yield _sse({
                    "type": "tool_start",
                    "name": name,
                    "args": args,
                    "step": tool_call_count,
                })

                result = await asyncio.get_event_loop().run_in_executor(
                    None, _run_tool, name, args
                )

                yield _sse({"type": "tool_end", "name": name, "content": result})

                messages.append(AIMessage(content=accumulated))

                already = ", ".join(f"`{t}`" for t in called_tool_names)
                remaining = max_steps - tool_call_count
                messages.append(HumanMessage(content=(
                    f"[OBSERVATION: {name}]\n{result}\n[/OBSERVATION]\n\n"
                    f"Tools called this turn: {already}. Steps remaining: {remaining}.\n"
                    f"RULES FOR YOUR NEXT RESPONSE:\n"
                    f"• Every number, percentage, status, name, and timestamp you write "
                    f"MUST appear verbatim in one of the [OBSERVATION] blocks above.\n"
                    f"• NEVER invent, estimate, or recall values from training data.\n"
                    f"• If you need more data, call exactly one more tool (not one already called).\n"
                    f"• If you have all required data, write your complete Markdown answer now."
                )))
                continue   # next ReAct step

            # ── No-tool guard (step 0 only) ──────────────────────────
            # If the model skipped all tools and answered directly on the
            # first step, and the question involves live system data,
            # intercept and force it to call a tool first.
            if step == 0 and tool_call_count == 0 and _needs_tool(req.message):
                messages.append(AIMessage(content=accumulated))
                messages.append(HumanMessage(content=(
                    "STOP. You answered from your training data without calling any tool.\n"
                    "This VPS has live state that changes every second — your training data "
                    "does NOT reflect current CPU, RAM, disk, container status, logs, or metrics.\n"
                    "DO NOT repeat that answer. Call the correct tool NOW to get real data, "
                    "then write your answer using ONLY the [OBSERVATION] content returned."
                )))
                yield _sse({"type": "thinking_start", "step": step + 1})
                continue   # force another LLM step to call a tool

            # ── Final answer ─────────────────────────────────────────
            # If we wrongly suppressed tokens, flush now
            if is_tool_call is True and not tool_call:
                yield _sse({"type": "token", "content": accumulated})
            break

    except Exception as exc:
        log.exception("chat_react_error", error=str(exc))
        yield _sse({"type": "error", "content": str(exc)})

    yield _sse({"type": "done"})


# ───────────────────────────────────────────────────────────
# Routes
# ───────────────────────────────────────────────────────────

@router.get("/chat/models")
async def get_models():
    """Return all models available in Ollama, annotated with benchmark metadata."""

    # Benchmarked on this VPS (12-core Haswell, CPU-only) against real system prompt.
    # accuracy = correct tool selected on 5-question test suite with full system prompt.
    MODEL_META: dict[str, dict] = {
        "qwen2.5-coder:7b": {
            "tag": "recommended",
            "label": "Recommended",
            "speed_tps": 5.1,
            "accuracy": 80,
            "note": "Best balance — 80 % tool accuracy, ~5 tok/s warm",
        },
        "qwen2.5-coder:14b": {
            "tag": "deep",
            "label": "Deep analysis",
            "speed_tps": 3.2,
            "accuracy": 80,
            "note": "PR review pipeline — same accuracy as 7b but 2× slower",
        },
        "llama3.2:3b": {
            "tag": "experimental",
            "label": "Experimental",
            "speed_tps": 8.0,
            "accuracy": 0,
            "note": "Fast but collapses under full system prompt — PARSE_FAIL on all tests",
        },
        "granite3.1-dense:2b": {
            "tag": "incompatible",
            "label": "Incompatible",
            "speed_tps": 8.5,
            "accuracy": 0,
            "note": "Uses IBM tool format — 0 % accuracy with our JSON schema",
        },
    }

    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get("http://ollama:11434/api/tags")
            models = resp.json().get("models", [])
            return {
                "models": [
                    {
                        "name":     m["name"],
                        "size_gb":  round(m.get("size", 0) / 1e9, 1),
                        **MODEL_META.get(m["name"], {
                            "tag": "untested", "label": "Untested",
                            "speed_tps": None, "accuracy": None, "note": "Not benchmarked",
                        }),
                    }
                    for m in models
                ]
            }
    except Exception as exc:
        return {"models": [], "error": str(exc)}


@router.post("/chat/stream")
async def chat_stream(req: ChatRequest):
    """Stream chat responses as Server-Sent Events."""
    return StreamingResponse(
        _stream_react(req),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@router.get("/ui", response_class=HTMLResponse)
async def chat_ui():
    """Serve the chat interface."""
    return HTMLResponse(content=_UI_PATH.read_text(encoding="utf-8"))
