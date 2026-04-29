import json

import structlog
from fastapi import APIRouter, Request

from app.config import get_settings
from app.engine.registry import WORKFLOW_REGISTRY

log = structlog.get_logger().bind(service="callbacks")
router = APIRouter(tags=["callbacks"])


@router.post("/callbacks/slack")
async def slack_callback(request: Request):
    """Handle Slack interactive message callbacks to resume paused graphs."""
    body = await request.body()
    payload_str = (await request.form()).get("payload", "")

    if not payload_str:
        log.warning("slack_callback_empty_payload")
        return {"message": "no payload"}

    payload = json.loads(payload_str)
    actions = payload.get("actions", [])

    if not actions:
        log.warning("slack_callback_no_actions")
        return {"message": "no actions"}

    action = actions[0]
    action_id = action.get("action_id", "")
    pr_number = action.get("value", "")

    log.info("slack_callback_received", action_id=action_id, pr_number=pr_number)

    # Determine approval status from action
    if action_id == "security_approve":
        approval_status = "approved"
    elif action_id == "security_reject":
        approval_status = "rejected"
    else:
        log.warning("slack_callback_unknown_action", action_id=action_id)
        return {"message": "unknown action"}

    # Resume the paused graph
    graph = WORKFLOW_REGISTRY.get("pull_request")
    if not graph:
        log.error("slack_callback_no_graph")
        return {"message": "workflow not found"}

    thread_id = f"pull_request-{pr_number}"
    config = {"configurable": {"thread_id": thread_id}}

    try:
        await graph.ainvoke(
            {"approval_status": approval_status},
            config=config,
        )
        log.info(
            "graph_resumed",
            thread_id=thread_id,
            approval_status=approval_status,
        )
    except Exception as e:
        log.error("graph_resume_failed", error=str(e), thread_id=thread_id)
        return {"message": "resume failed", "error": str(e)}

    return {"message": "processed", "approval_status": approval_status}
