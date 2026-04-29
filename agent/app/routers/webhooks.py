import json
from urllib.parse import parse_qs
from uuid import uuid4

import structlog
from fastapi import APIRouter, BackgroundTasks, HTTPException, Request

from app.config import get_settings
from app.engine.dispatcher import dispatch_event
from app.services.github_api import validate_webhook_signature
from app.services import slack_api

log = structlog.get_logger().bind(service="webhooks")
router = APIRouter(tags=["webhooks"])


@router.post("/webhooks/github", status_code=202)
async def github_webhook(request: Request, background_tasks: BackgroundTasks):
    """Receive GitHub webhook events, validate HMAC, and dispatch to workflow engine."""
    settings = get_settings()
    body = await request.body()
    signature = request.headers.get("X-Hub-Signature-256", "")

    # 1. Validate HMAC
    if not await validate_webhook_signature(body, signature, settings.github_webhook_secret):
        log.warning("webhook_invalid_signature")
        raise HTTPException(status_code=403, detail="Invalid signature")

    if not body:
        raise HTTPException(status_code=400, detail="Empty request body")

    # GitHub can send webhooks as JSON or as form-encoded (payload= field)
    content_type = request.headers.get("Content-Type", "")
    try:
        if "application/x-www-form-urlencoded" in content_type:
            form = parse_qs(body.decode())
            raw = form.get("payload", [None])[0]
            if not raw:
                raise HTTPException(status_code=400, detail="Missing payload field in form body")
            payload = json.loads(raw)
        else:
            payload = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    event_type = request.headers.get("X-GitHub-Event", "")
    log.info("webhook_received", github_event=event_type, action=payload.get("action", ""))

    # Filter — only handle pull_request opened/synchronize
    if event_type != "pull_request":
        return {"message": "event ignored", "event": event_type}

    action = payload.get("action", "")
    if action not in ("opened", "synchronize"):
        return {"message": "action ignored", "action": action}

    # Dispatch to workflow engine
    task_id = str(uuid4())
    background_tasks.add_task(dispatch_event, "pull_request", payload, task_id)

    log.info("webhook_dispatched", task_id=task_id, pr=payload.get("number"))
    return {"message": "processing", "task_id": task_id}


@router.post("/webhooks/alertmanager", status_code=200)
async def alertmanager_webhook(request: Request, background_tasks: BackgroundTasks):
    """Receive Prometheus AlertManager alerts and route to Slack with LLM triage."""
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    alerts = payload.get("alerts", [])
    if not alerts:
        return {"message": "no alerts"}

    log.info("alertmanager_webhook_received", count=len(alerts))
    background_tasks.add_task(_handle_alerts, alerts, payload.get("groupLabels", {}))
    return {"message": "received", "count": len(alerts)}


async def _handle_alerts(alerts: list, group_labels: dict) -> None:
    """Format and send alerts to Slack, auto-remediating where safe."""
    firing = [a for a in alerts if a.get("status") == "firing"]
    resolved = [a for a in alerts if a.get("status") == "resolved"]

    # Auto-remediation for disk critical (safe: prune build cache only)
    for alert in firing:
        name = alert.get("labels", {}).get("alertname", "")
        if name in ("DiskCritical", "AgentDiskCritical"):
            await _auto_clean_disk()

    # Format Slack blocks
    blocks = _build_alert_blocks(firing, resolved)
    if blocks:
        await slack_api.send_notification(blocks=blocks, text=_alert_summary(firing, resolved))

    log.info("alerts_dispatched", firing=len(firing), resolved=len(resolved))


def _alert_summary(firing: list, resolved: list) -> str:
    parts = []
    if firing:
        parts.append(f"{len(firing)} alert(s) firing")
    if resolved:
        parts.append(f"{len(resolved)} resolved")
    return "BTE Security Agent — " + ", ".join(parts)


def _build_alert_blocks(firing: list, resolved: list) -> list:
    blocks = []

    if firing:
        blocks.append({
            "type": "header",
            "text": {"type": "plain_text", "text": f"🚨 {len(firing)} Alert(s) Firing — BTE VPS"}
        })
        for alert in firing[:5]:
            labels = alert.get("labels", {})
            ann = alert.get("annotations", {})
            severity = labels.get("severity", "unknown").upper()
            icon = {"CRITICAL": "🔴", "WARNING": "🟡", "INFO": "🔵"}.get(severity, "⚪")
            blocks.append({
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*{icon} {labels.get('alertname', 'Unknown')}*"},
                    {"type": "mrkdwn", "text": f"*Severity:* {severity}"},
                    {"type": "mrkdwn", "text": ann.get("description", ann.get("summary", "No details"))},
                ]
            })
        blocks.append({"type": "divider"})

    if resolved:
        names = ", ".join(
            a.get("labels", {}).get("alertname", "?") for a in resolved[:3]
        )
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"✅ *Resolved:* {names}"}
        })

    return blocks


async def _auto_clean_disk() -> None:
    """Prune Docker build cache when disk hits critical — safe, no data loss."""
    import asyncio
    log.warning("auto_disk_cleanup_triggered")
    try:
        proc = await asyncio.create_subprocess_exec(
            "docker", "builder", "prune", "-f",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
        if proc.returncode == 0:
            log.info("auto_disk_cleanup_success")
            await slack_api.send_notification(
                text="🧹 *BTE Agent Auto-Cleanup* — Docker build cache pruned automatically (disk critical)."
            )
        else:
            log.error("auto_disk_cleanup_failed", stderr=stderr.decode()[:200])
    except Exception as exc:
        log.error("auto_disk_cleanup_error", error=str(exc))
