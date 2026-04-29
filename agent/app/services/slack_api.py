import structlog

from app.config import get_settings

log = structlog.get_logger().bind(service="slack_api")


async def send_notification(
    channel: str | None = None, text: str = "", blocks: list | None = None
) -> None:
    """Send a Slack notification. No-op if SLACK_BOT_TOKEN is not set."""
    settings = get_settings()
    if not settings.slack_bot_token:
        log.warning("slack_not_configured", action="send_notification")
        return

    target_channel = channel or settings.slack_channel_id

    try:
        from slack_sdk.web.async_client import AsyncWebClient

        client = AsyncWebClient(token=settings.slack_bot_token)
        await client.chat_postMessage(
            channel=target_channel,
            text=text,
            blocks=blocks,
        )
        log.info("slack_notification_sent", channel=target_channel)
    except Exception as e:
        log.error("slack_notification_failed", error=str(e))


async def request_approval(
    channel: str | None = None, pr_info: dict | None = None, findings: list | None = None
) -> None:
    """Post a Slack Block Kit message with Approve/Reject buttons."""
    settings = get_settings()
    if not settings.slack_bot_token:
        log.warning("slack_not_configured", action="request_approval")
        return

    target_channel = channel or settings.slack_channel_id
    pr_info = pr_info or {}
    findings = findings or []

    findings_text = "\n".join(
        f"• {f}" for f in findings[:3]
    ) or "No critical findings."

    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "SECURITY AI AGENT — Approval Required",
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*PR:* {pr_info.get('title', 'N/A')}"},
                {"type": "mrkdwn", "text": f"*Author:* {pr_info.get('author', 'N/A')}"},
                {"type": "mrkdwn", "text": f"*Risk:* {pr_info.get('risk_score', 'N/A')}"},
                {"type": "mrkdwn", "text": f"*URL:* {pr_info.get('url', 'N/A')}"},
            ],
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Top Findings:*\n{findings_text}",
            },
        },
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Approve"},
                    "style": "primary",
                    "action_id": "security_approve",
                    "value": str(pr_info.get("pr_number", "")),
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Reject"},
                    "style": "danger",
                    "action_id": "security_reject",
                    "value": str(pr_info.get("pr_number", "")),
                },
            ],
        },
    ]

    try:
        from slack_sdk.web.async_client import AsyncWebClient

        client = AsyncWebClient(token=settings.slack_bot_token)
        await client.chat_postMessage(
            channel=target_channel,
            text=f"SECURITY AI AGENT — Approval needed for PR #{pr_info.get('pr_number', '?')}",
            blocks=blocks,
        )
        log.info("approval_request_sent", channel=target_channel, pr=pr_info.get("pr_number"))
    except Exception as e:
        log.error("approval_request_failed", error=str(e))
