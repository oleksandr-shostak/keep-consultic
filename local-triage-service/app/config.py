import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    api_host: str
    api_port: int
    db_dsn: str
    ollama_base_url: str
    ollama_chat_model: str
    ollama_embed_model: str
    top_k: int
    similarity_threshold: float
    llm_temperature: float
    llm_top_p: float
    llm_num_ctx: int
    request_timeout_sec: int
    api_token: str | None


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    return int(value) if value is not None and value != "" else default


def _env_float(name: str, default: float) -> float:
    value = os.getenv(name)
    return float(value) if value is not None and value != "" else default


def get_settings() -> Settings:
    return Settings(
        api_host=os.getenv("TRIAGE_API_HOST", "0.0.0.0"),
        api_port=_env_int("TRIAGE_API_PORT", 8099),
        db_dsn=os.getenv(
            "TRIAGE_DB_DSN", "postgresql://triage:triagepass@localhost:5439/triage_kb"
        ),
        ollama_base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
        ollama_chat_model=os.getenv("OLLAMA_CHAT_MODEL", "qwen2.5:7b"),
        ollama_embed_model=os.getenv("OLLAMA_EMBED_MODEL", "nomic-embed-text"),
        top_k=_env_int("TRIAGE_TOP_K", 6),
        similarity_threshold=_env_float("TRIAGE_SIMILARITY_THRESHOLD", 0.55),
        llm_temperature=_env_float("TRIAGE_LLM_TEMPERATURE", 0.0),
        llm_top_p=_env_float("TRIAGE_LLM_TOP_P", 0.2),
        llm_num_ctx=_env_int("TRIAGE_LLM_NUM_CTX", 8192),
        request_timeout_sec=_env_int("TRIAGE_REQUEST_TIMEOUT_SEC", 120),
        api_token=os.getenv("TRIAGE_API_TOKEN"),
    )
