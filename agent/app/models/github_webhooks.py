from pydantic import BaseModel, Field


class PullRequestUser(BaseModel):
    login: str
    id: int


class PullRequestHead(BaseModel):
    ref: str
    sha: str
    label: str = ""


class PullRequestBase(BaseModel):
    ref: str
    sha: str
    label: str = ""


class PullRequestRepo(BaseModel):
    full_name: str
    clone_url: str
    html_url: str
    default_branch: str = "main"
    private: bool = False


class PullRequestData(BaseModel):
    number: int
    title: str
    body: str | None = ""
    html_url: str
    state: str = "open"
    user: PullRequestUser
    head: PullRequestHead
    base: PullRequestBase


class PullRequestWebhookPayload(BaseModel):
    action: str
    number: int
    pull_request: PullRequestData
    repository: PullRequestRepo
    sender: PullRequestUser

    def to_initial_state(self, task_id: str = "") -> dict:
        """Convert webhook payload to initial PRReviewState fields."""
        return {
            "workflow_type": "pull_request",
            "repo_full_name": self.repository.full_name,
            "trigger_ref": str(self.number),
            "current_stage": "pending",
            "error": "",
            "task_id": task_id,
            "messages": [],
            "pr_number": self.number,
            "clone_url": self.repository.clone_url,
            "head_branch": self.pull_request.head.ref,
            "head_sha": self.pull_request.head.sha,
            "base_branch": self.pull_request.base.ref,
            "pr_title": self.pull_request.title,
            "pr_body": self.pull_request.body or "",
            "pr_url": self.pull_request.html_url,
            "sender": self.sender.login,
            "repo_path": "",
            "diff": "",
            "has_dockerfile": False,
            "docker_image_tag": "",
            "pr_classification": "",
            "files_changed": [],
            "scan_results": {},
            "security_review": "",
            "risk_score": "INFO",
            "verdict": "APPROVE",
            "approval_status": "auto",
            "repo_history": [],
            "started_at": "",
        }
