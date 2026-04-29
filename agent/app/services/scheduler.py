"""
Autonomous background scheduler.

Tasks:
  • disk_guard      — every 30 min: update disk metrics, alert + auto-clean if critical
  • health_digest   — daily at 09:00 UTC: post VPS health summary to Slack
"""
from __future__ import annotations

import asyncio
import shutil
from datetime import datetime, timezone, timedelta

import httpx
import structlog

from app.services import slack_api

log = structlog.get_logger().bind(service="scheduler")

_DISK_INTERVAL   = 30 * 60   # 30 minutes
_DIGEST_HOUR_UTC = 9          # 09:00 UTC daily


# ─────────────────────────────────────────────────────────────────────────────
# Disk guard
# ─────────────────────────────────────────────────────────────────────────────

async def _disk_guard_loop() -> None:
    while True:
        try:
            await _check_disk()
        except Exception as exc:
            log.error("disk_guard_error", error=str(exc))
        await asyncio.sleep(_DISK_INTERVAL)


async def _check_disk() -> None:
    from app.metrics.custom import agent_disk_used_percent, agent_disk_free_gb

    usage = shutil.disk_usage("/")
    pct   = usage.used / usage.total * 100
    free_gb = usage.free / 1024 ** 3

    agent_disk_used_percent.set(pct)
    agent_disk_free_gb.set(free_gb)

    log.info("disk_guard_check", used_pct=round(pct, 1), free_gb=round(free_gb, 1))

    if pct >= 90:
        log.warning("disk_critical", used_pct=round(pct, 1))
        cleaned = await _prune_build_cache()
        await slack_api.send_notification(
            text=(
                f"🔴 *BTE Agent — Disk CRITICAL* ({pct:.1f}% used, {free_gb:.1f} GB free)\n"
                f"Auto-cleanup: {cleaned}"
            )
        )
    elif pct >= 80:
        log.warning("disk_warning", used_pct=round(pct, 1))
        await slack_api.send_notification(
            text=(
                f"🟡 *BTE Agent — Disk Warning* ({pct:.1f}% used, {free_gb:.1f} GB free)\n"
                f"Consider cleaning unused models or artifacts."
            )
        )


async def _prune_build_cache() -> str:
    """Docker builder prune — safe, recoverable. Returns human-readable result."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "docker", "builder", "prune", "-f",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
        if proc.returncode == 0:
            out = stdout.decode().strip().splitlines()
            total_line = next((l for l in out if "Total" in l), "cache pruned")
            log.info("build_cache_pruned", result=total_line)
            return f"Docker build cache pruned ({total_line})"
        return "prune failed (non-zero exit)"
    except Exception as exc:
        log.error("prune_error", error=str(exc))
        return f"prune error: {exc}"


# ─────────────────────────────────────────────────────────────────────────────
# Daily health digest
# ─────────────────────────────────────────────────────────────────────────────

async def _health_digest_loop() -> None:
    """Fire at 09:00 UTC every day."""
    while True:
        now   = datetime.now(timezone.utc)
        next9 = now.replace(hour=_DIGEST_HOUR_UTC, minute=0, second=0, microsecond=0)
        if next9 <= now:
            next9 += timedelta(days=1)
        wait  = (next9 - now).total_seconds()
        log.info("digest_next_run", at=next9.isoformat(), wait_seconds=int(wait))
        await asyncio.sleep(wait)

        try:
            await _post_health_digest()
        except Exception as exc:
            log.error("digest_error", error=str(exc))


async def _post_health_digest() -> None:
    """Collect VPS state and post a structured Slack digest."""
    log.info("posting_health_digest")

    # Disk
    usage   = shutil.disk_usage("/")
    disk_pct = usage.used / usage.total * 100
    free_gb  = usage.free / 1024 ** 3
    disk_icon = "🔴" if disk_pct >= 90 else ("🟡" if disk_pct >= 80 else "🟢")

    # Containers
    container_lines = await _get_container_states()

    # Ollama
    ollama_status = await _get_ollama_status()

    # Prometheus alerts
    active_alerts = await _get_active_alerts()

    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"📊 BTE VPS Daily Digest — {date_str}"}
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*{disk_icon} Disk*\n{disk_pct:.1f}% used · {free_gb:.1f} GB free"},
                {"type": "mrkdwn", "text": f"*🤖 Ollama*\n{ollama_status}"},
            ]
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*🐳 Containers*\n{container_lines}"}
        },
    ]

    if active_alerts:
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*🚨 Active Alerts*\n{active_alerts}"}
        })
    else:
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": "✅ *No active alerts*"}
        })

    blocks.append({"type": "divider"})

    await slack_api.send_notification(
        text=f"BTE VPS Daily Digest — {date_str}",
        blocks=blocks,
    )
    log.info("health_digest_posted")


async def _get_container_states() -> str:
    try:
        proc = await asyncio.create_subprocess_exec(
            "docker", "ps", "--format", "{{.Names}}\t{{.Status}}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
        lines = stdout.decode().strip().splitlines()
        parts = []
        for line in lines:
            name, _, status = line.partition("\t")
            icon = "🟢" if "healthy" in status.lower() or "up" in status.lower() else "🔴"
            parts.append(f"{icon} `{name}` — {status}")
        return "\n".join(parts) if parts else "No containers found"
    except Exception as exc:
        return f"Error: {exc}"


async def _get_ollama_status() -> str:
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get("http://ollama:11434/api/ps")
            models = resp.json().get("models", [])
            if models:
                names = ", ".join(m.get("name", "?") for m in models)
                return f"{names} loaded"
            return "idle (no model loaded)"
    except Exception:
        return "unreachable"


async def _get_active_alerts() -> str:
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get("http://prometheus:9090/api/v1/alerts")
            alerts = resp.json().get("data", {}).get("alerts", [])
            firing = [a for a in alerts if a.get("state") == "firing"]
            if not firing:
                return ""
            return "\n".join(
                f"• {a['labels'].get('alertname','?')} ({a['labels'].get('severity','?')})"
                for a in firing[:5]
            )
    except Exception:
        return ""


# ─────────────────────────────────────────────────────────────────────────────
# Entry point — called from main.py lifespan
# ─────────────────────────────────────────────────────────────────────────────

def start_scheduler() -> list[asyncio.Task]:
    """Start all background tasks. Returns tasks so they can be cancelled on shutdown."""
    tasks = [
        asyncio.create_task(_disk_guard_loop(),   name="disk_guard"),
        asyncio.create_task(_health_digest_loop(), name="health_digest"),
    ]
    log.info("scheduler_started", tasks=[t.get_name() for t in tasks])
    return tasks
