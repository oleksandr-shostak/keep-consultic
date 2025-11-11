"""
OpenAI Assistant Provider

This provider integrates with OpenAI's Assistants API, supporting:
- Stateful conversations (threads)
- File Search (knowledge retrieval)
- Code Interpreter
- Function calling
- Structured outputs

Author: Keep
"""

import json
import dataclasses
import pydantic
from typing import Optional, Dict, Any, List

from openai import OpenAI

from keep.contextmanager.contextmanager import ContextManager
from keep.exceptions.provider_exception import ProviderException
from keep.providers.base.base_provider import BaseProvider
from keep.providers.models.provider_config import ProviderConfig


@pydantic.dataclasses.dataclass
class OpenaiassistantProviderAuthConfig:
    api_key: str = dataclasses.field(
        metadata={
            "required": True,
            "description": "OpenAI Platform API Key",
            "sensitive": True,
        },
    )
    prompt_id: str | None = dataclasses.field(
        metadata={
            "required": False,
            "description": (
                "OpenAI Prompt ID (recommended). If omitted, a model must be supplied."
            ),
            "sensitive": False,
        },
        default=None,
    )
    model: str = dataclasses.field(
        metadata={
            "required": False,
            "description": "Fallback model to use when prompt_id is not supplied.",
            "sensitive": False,
        },
        default="gpt-4.1-mini",
    )
    organization_id: str | None = dataclasses.field(
        metadata={
            "required": False,
            "description": "OpenAI Platform Organization ID",
            "sensitive": False,
        },
        default=None,
    )


class OpenaiassistantProvider(BaseProvider):
    """Provider for OpenAI Responses + Prompts API"""

    PROVIDER_DISPLAY_NAME = "OpenAI Assistant"
    PROVIDER_CATEGORY = ["AI"]

    def __init__(
        self, context_manager: ContextManager, provider_id: str, config: ProviderConfig
    ):
        super().__init__(context_manager, provider_id, config)
        self.client = None

    def validate_config(self):
        """Validate provider configuration"""
        self.authentication_config = OpenaiassistantProviderAuthConfig(
            **self.config.authentication
        )

        if (
            not self.authentication_config.prompt_id
            and not self.authentication_config.model
        ):
            raise ProviderException(
                "Either prompt_id must be provided or a default model must be configured."
            )

        # Initialize OpenAI client
        self.client = OpenAI(
            api_key=self.authentication_config.api_key,
            organization=self.authentication_config.organization_id,
        )

        # If prompt configured attempt light validation via prompts.list
        if self.authentication_config.prompt_id:
            if hasattr(self.client, "prompts"):
                try:
                    prompt = self.client.prompts.retrieve(
                        self.authentication_config.prompt_id
                    )
                    self.logger.info(
                        "Successfully connected to OpenAI prompt",
                        extra={
                            "prompt_id": prompt.id,
                            "last_updated": getattr(prompt, "updated_at", None),
                        },
                    )
                except Exception as exc:
                    raise ProviderException(
                        f"Failed to retrieve prompt {self.authentication_config.prompt_id}: {exc}"
                    )
            else:
                self.logger.warning(
                    "OpenAI client does not expose prompts API; skipping prompt validation",
                    extra={"prompt_id": self.authentication_config.prompt_id},
                )

    def dispose(self):
        """Cleanup resources"""
        pass

    def validate_scopes(self) -> dict[str, bool | str]:
        """Validate API scopes/permissions"""
        scopes = {}
        
        try:
            if self.authentication_config.prompt_id:
                prompt = self.client.prompts.retrieve(
                    self.authentication_config.prompt_id
                )
                scopes["prompt_access"] = True
                scopes["prompt_version"] = prompt.version
            else:
                # When using direct model access, just test a lightweight responses.create call
                self.client.responses.create(
                    model=self.authentication_config.model,
                    input=[{"role": "user", "content": "ping"}],
                    max_output_tokens=1,
                )
                scopes["responses_access"] = True
        except Exception as exc:
            scopes["prompt_access" if self.authentication_config.prompt_id else "responses_access"] = (
                f"Failed: {exc}"
            )

        return scopes

    def _query(
        self,
        prompt: str,
        conversation_id: Optional[str] = None,
        additional_instructions: Optional[str] = None,
        parse_json: bool = True,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Query the OpenAI Assistant via the Responses API.

        Args:
            prompt: The user message to send to the assistant
            conversation_id: Optional existing conversation ID for continuing dialogue
            additional_instructions: Additional instructions for this run
            parse_json: Try to parse response as JSON
            **kwargs: Additional arguments forwarded to responses.create()

        Returns:
            Dict containing:
                - response: The assistant's response (string or dict if JSON)
                - conversation_id: The conversation ID (for continuing conversation)
                - output_items: Raw output items from the response
        """
        if not self.client:
            self.client = OpenAI(
                api_key=self.authentication_config.api_key,
                organization=self.authentication_config.organization_id,
            )

        try:

            response_kwargs: Dict[str, Any] = {
                "input": [{"role": "user", "content": prompt}],
            }

            if self.authentication_config.prompt_id:
                response_kwargs["prompt"] = {"id": self.authentication_config.prompt_id}
            else:
                response_kwargs["model"] = kwargs.pop(
                    "model", self.authentication_config.model
                )

            if conversation_id:
                response_kwargs["conversation"] = conversation_id

            if additional_instructions:
                response_kwargs["instructions"] = additional_instructions

            # Allow callers to override defaults (e.g., temperature, tools...)
            response_kwargs.update(kwargs)

            response = self.client.responses.create(**response_kwargs)

            if getattr(response, "status", "completed") != "completed":
                raise ProviderException(
                    f"Assistant response failed with status {response.status}"
                )

            conversation_reference = getattr(response, "conversation", None)
            response_conversation_id = None
            if hasattr(conversation_reference, "id"):
                response_conversation_id = conversation_reference.id
            elif isinstance(conversation_reference, dict):
                response_conversation_id = conversation_reference.get("id")

            # Extract output text/items
            output_items = list(getattr(response, "output", []) or [])
            output_text = getattr(response, "output_text", "")

            if not output_text:
                text_blocks: List[str] = []
                for item in output_items:
                    content = getattr(item, "content", None)
                    if not content and isinstance(item, dict):
                        content = item.get("content")
                    if not content:
                        continue
                    # content can be list of blocks
                    for block in content:
                        block_type = getattr(block, "type", None) or block.get("type")
                        if block_type in {"output_text", "text"}:
                            text_value = getattr(block, "text", None)
                            if hasattr(text_value, "value"):
                                text_blocks.append(text_value.value)
                            else:
                                text_blocks.append(block.get("text", ""))
                output_text = "".join(text_blocks).strip()

            raw_response = output_text
            response_parsed: Any = raw_response
            if parse_json and raw_response:
                try:
                    response_parsed = json.loads(raw_response)
                    self.logger.info("Successfully parsed response as JSON")
                except json.JSONDecodeError:
                    self.logger.debug("Response is not valid JSON, returning as text")

            return {
                "response": response_parsed,
                "conversation_id": response_conversation_id,
                "output_items": output_items,
                "raw_response": raw_response,
            }

        except Exception as e:
            if isinstance(e, ProviderException):
                raise
            raise ProviderException(f"Error querying OpenAI Assistant: {str(e)}")


if __name__ == "__main__":
    """
    Test the provider locally
    
    Usage:
        export OPENAI_API_KEY=sk-...
        export ASSISTANT_ID=asst_...
        python openaiassistant_provider.py
    """
    import os
    import logging

    logging.basicConfig(level=logging.DEBUG, handlers=[logging.StreamHandler()])
    
    context_manager = ContextManager(
        tenant_id="singletenant",
        workflow_id="test",
    )

    api_key = os.environ.get("OPENAI_API_KEY")
    prompt_id = os.environ.get("PROMPT_ID")

    if not api_key:
        print("Please set OPENAI_API_KEY environment variable")
        exit(1)

    config = ProviderConfig(
        description="OpenAI Assistant Test",
        authentication={
            "api_key": api_key,
            "prompt_id": prompt_id,
        },
    )

    provider = OpenaiassistantProvider(
        context_manager=context_manager,
        provider_id="test_assistant",
        config=config,
    )

    # Test 1: Simple query
    print("\n=== Test 1: Simple Query ===")
    result = provider.query(
        prompt="Analyze this alert: Server memory usage is at 95%. Should I be concerned?"
    )
    print(f"Response: {result['response']}")
    print(f"Conversation ID: {result['conversation_id']}")

    # Test 2: Continue conversation in same thread
    print("\n=== Test 2: Continue Conversation ===")
    result2 = provider.query(
        prompt="What specific actions should I take right now?",
        conversation_id=result["conversation_id"],
    )
    print(f"Response: {result2['response']}")

    # Test 3: With additional instructions
    print("\n=== Test 3: With Additional Instructions ===")
    result3 = provider.query(
        prompt="Analyze this: Database connection pool exhausted",
        additional_instructions="Respond in JSON format with keys: severity, action, explanation"
    )
    print(f"Response: {result3['response']}")

