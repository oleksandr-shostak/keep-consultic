import json
from typing import Any

import httpx

from app.config import Settings


class OllamaClient:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.client = httpx.Client(timeout=settings.request_timeout_sec)

    def close(self):
        self.client.close()

    def health(self) -> dict[str, Any]:
        response = self.client.get(f"{self.settings.ollama_base_url}/api/tags")
        response.raise_for_status()
        return response.json()

    def embed(self, text: str) -> list[float]:
        payload = {
            "model": self.settings.ollama_embed_model,
            "input": [text],
        }
        response = self.client.post(f"{self.settings.ollama_base_url}/api/embed", json=payload)
        if response.status_code == 404:
            fallback = self.client.post(
                f"{self.settings.ollama_base_url}/api/embeddings",
                json={"model": self.settings.ollama_embed_model, "prompt": text},
            )
            fallback.raise_for_status()
            body = fallback.json()
            return [float(x) for x in body["embedding"]]

        response.raise_for_status()
        body = response.json()
        embeddings = body.get("embeddings")
        if not embeddings or not embeddings[0]:
            raise RuntimeError("Ollama embedding response did not include embeddings")
        return [float(x) for x in embeddings[0]]

    def chat_json(
        self,
        system_prompt: str,
        user_payload: dict[str, Any],
        schema: dict[str, Any],
        return_debug: bool = False,
    ) -> dict[str, Any]:
        payload = {
            "model": self.settings.ollama_chat_model,
            "stream": False,
            "format": schema,
            "messages": [
                {"role": "system", "content": system_prompt},
                {
                    "role": "user",
                    "content": json.dumps(user_payload, ensure_ascii=False, indent=2),
                },
            ],
            "options": {
                "temperature": self.settings.llm_temperature,
                "top_p": self.settings.llm_top_p,
                "num_ctx": self.settings.llm_num_ctx,
            },
        }
        response = self.client.post(
            f"{self.settings.ollama_base_url}/api/chat",
            json=payload,
        )
        response.raise_for_status()
        body = response.json()
        content = ((body.get("message") or {}).get("content") or "").strip()
        if not content:
            raise RuntimeError("Ollama returned empty message content")
        try:
            parsed = json.loads(content)
            if return_debug:
                return {
                    "parsed": parsed,
                    "raw_content": content,
                    "raw_response": body,
                    "request_payload": payload,
                }
            return parsed
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Ollama JSON parse failed: {content}") from exc
