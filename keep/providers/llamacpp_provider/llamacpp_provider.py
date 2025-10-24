import dataclasses
import json
import pydantic
import re
import requests

from keep.contextmanager.contextmanager import ContextManager
from keep.exceptions.provider_exception import ProviderException
from keep.providers.base.base_provider import BaseProvider
from keep.providers.models.provider_config import ProviderConfig


@pydantic.dataclasses.dataclass
class LlamacppProviderAuthConfig:
    host: str = dataclasses.field(
        metadata={
            "required": True,
            "description": "Llama.cpp Server Host URL",
            "sensitive": False,
        },
        default="http://localhost:8080"
    )


class LlamacppProvider(BaseProvider):
    PROVIDER_DISPLAY_NAME = "Llama.cpp"
    PROVIDER_CATEGORY = ["AI"]

    def __init__(
        self, context_manager: ContextManager, provider_id: str, config: ProviderConfig
    ):
        super().__init__(context_manager, provider_id, config)

    def validate_config(self):
        self.authentication_config = LlamacppProviderAuthConfig(
            **self.config.authentication
        )

    def dispose(self):
        pass

    def validate_scopes(self) -> dict[str, bool | str]:
        scopes = {}
        return scopes

    def _query(
        self,
        prompt,
        max_tokens=1024,
    ):
        # Build the API URL for completion
        api_url = f"{self.authentication_config.host}/completion"

        # Prepare the request payload
        payload = {
            "prompt": prompt,
            "n_predict": max_tokens,
            "temperature": 0.7,
            "stop": ["\n\n"],  # Common stop sequence
            "stream": False
        }

        try:
            # Make the API request
            response = requests.post(api_url, json=payload)
            response.raise_for_status()
            content = response.json()["content"]
            
            self.logger.info(
                "Llama.cpp raw response",
                extra={"raw_content": content[:500]}  # Log first 500 chars
            )
            
            # Strip markdown code blocks if present (common in LLM responses)
            # Matches: ```json\n...\n``` or ```\n...\n```
            content_cleaned = re.sub(r'```(?:json)?\s*\n?(.*?)\n?```', r'\1', content, flags=re.DOTALL)
            content_cleaned = content_cleaned.strip()
            
            self.logger.info(
                "Llama.cpp cleaned response",
                extra={"cleaned_content": content_cleaned[:500]}
            )
            
            # Try to parse as JSON (similar to OpenAI provider behavior)
            try:
                parsed_content = json.loads(content_cleaned)
                response_content = parsed_content
                self.logger.info(
                    "Llama.cpp JSON parsed successfully",
                    extra={"parsed_keys": list(parsed_content.keys()) if isinstance(parsed_content, dict) else "not_a_dict"}
                )
            except json.JSONDecodeError as e:
                # If not valid JSON, return as-is
                response_content = content_cleaned
                self.logger.warning(
                    "Llama.cpp response is not valid JSON, returning as text",
                    extra={"json_error": str(e)}
                )
            
            result = {
                "response": response_content,
            }
            
            self.logger.info(
                "Llama.cpp final result structure",
                extra={"result": result}
            )
            
            return result

        except requests.exceptions.RequestException as e:
            raise ProviderException(f"Error calling Llama.cpp API: {str(e)}")


if __name__ == "__main__":
    import logging

    logging.basicConfig(level=logging.DEBUG, handlers=[logging.StreamHandler()])
    context_manager = ContextManager(
        tenant_id="singletenant",
        workflow_id="test",
    )

    config = ProviderConfig(
        description="Llama.cpp Provider",
        authentication={
            "host": "http://localhost:8080",  # Default Llama.cpp server host
        },
    )

    provider = LlamacppProvider(
        context_manager=context_manager,
        provider_id="llamacpp_provider",
        config=config,
    )

    print(
        provider.query(
            prompt="Here is an alert, define environment for it: Clients are panicking, nothing works. Give one word: production or dev.",
            max_tokens=10,
        )
    )