from functools import lru_cache
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # GitHub
    github_token: str = ""
    github_webhook_secret: str = ""

    # Ollama — three-model setup
    ollama_base_url: str = "http://ollama:11434"
    ollama_model_fast: str = "qwen2.5-coder:7b"    # classify_node
    ollama_model_deep: str = "qwen2.5-coder:14b"   # analyze_node (security)
    ollama_model_review: str = "qwen2.5-coder:14b" # code_review_node (quality)
    ollama_timeout: int = 300

    # Slack
    slack_bot_token: str = ""
    slack_channel_id: str = ""
    slack_signing_secret: str = ""
    slack_escalation_enabled: bool = False  # requires working HTTPS callback URL

    # Jenkins
    jenkins_url: str = "http://jenkins:8080"
    jenkins_user: str = "admin"
    jenkins_api_token: str = ""

    # PostgreSQL
    postgres_host: str = "postgres"
    postgres_port: int = 5432
    postgres_user: str = "devsecops"
    postgres_password: str = ""
    postgres_db: str = "devsecops_db"

    # Redis
    redis_url: str = "redis://redis:6379/0"

    # Grafana
    grafana_password: str = ""

    # Agent
    agent_log_level: str = "INFO"
    agent_workspace: str = "/tmp/agent-workspace"
    trivy_severity: str = "CRITICAL,HIGH,MEDIUM"
    artifacts_path: str = "/opt/devsecops/artifacts"

    # Remote VPS monitoring — comma-separated list of SSH targets
    # Format: "alias:user@host:port,alias2:user@host2:22"
    # Example: "vps-prod:root@192.168.1.10:22,vps-staging:ubuntu@10.0.0.5:22"
    remote_vps_hosts: str = ""
    # Path to SSH private key inside the agent container
    remote_vps_ssh_key: str = "/run/secrets/vps_ssh_key"

    @property
    def postgres_dsn(self) -> str:
        return (
            f"postgresql://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def async_postgres_dsn(self) -> str:
        return (
            f"postgresql+psycopg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


@lru_cache
def get_settings() -> Settings:
    return Settings()
