import structlog

from app.engine.registry import WORKFLOW_REGISTRY

log = structlog.get_logger().bind(service="dispatcher")


async def dispatch_event(event_type: str, payload: dict, task_id: str) -> str:
    """Look up the correct workflow graph and invoke it."""
    # Bind task_id to structlog contextvars for the entire pipeline
    structlog.contextvars.bind_contextvars(task_id=task_id)

    graph = WORKFLOW_REGISTRY.get(event_type)
    if not graph:
        log.warning("unknown_event_type", event_type=event_type, task_id=task_id)
        return "ignored"

    config = {"configurable": {"thread_id": f"{event_type}-{task_id}"}}

    log.info(
        "dispatching_event",
        event_type=event_type,
        task_id=task_id,
    )

    try:
        from app.models.github_webhooks import PullRequestWebhookPayload

        if event_type == "pull_request":
            webhook = PullRequestWebhookPayload(**payload)
            initial_state = webhook.to_initial_state(task_id=task_id)
        else:
            initial_state = {"workflow_type": event_type, "task_id": task_id, **payload}

        await graph.ainvoke(initial_state, config=config)
        log.info("workflow_completed", event_type=event_type, task_id=task_id)
        return "dispatched"
    except Exception as e:
        log.error(
            "workflow_failed",
            event_type=event_type,
            task_id=task_id,
            error=str(e),
            exc_info=True,
        )
        return "failed"
    finally:
        structlog.contextvars.unbind_contextvars("task_id")
