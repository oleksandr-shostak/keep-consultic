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
import time
import dataclasses
import pydantic
from typing import Optional, Dict, Any, List

from openai import OpenAI

from keep.contextmanager.contextmanager import ContextManager
from keep.exceptions.provider_exception import ProviderException
from keep.providers.base.base_provider import BaseProvider
from keep.providers.models.provider_config import ProviderConfig


@pydantic.dataclasses.dataclass
class OpenaiAssistantProviderAuthConfig:
    api_key: str = dataclasses.field(
        metadata={
            "required": True,
            "description": "OpenAI Platform API Key",
            "sensitive": True,
        },
    )
    organization_id: str | None = dataclasses.field(
        metadata={
            "required": False,
            "description": "OpenAI Platform Organization ID",
            "sensitive": False,
        },
        default=None,
    )
    assistant_id: str = dataclasses.field(
        metadata={
            "required": True,
            "description": "OpenAI Assistant ID (e.g., asst_GPkwWwZeCdU68iUXSQ5wglGk)",
            "sensitive": False,
        },
    )


class OpenaiAssistantProvider(BaseProvider):
    """Provider for OpenAI Assistants API"""
    
    PROVIDER_DISPLAY_NAME = "OpenAI Assistant"
    PROVIDER_CATEGORY = ["AI"]
    
    # Maximum time to wait for assistant response (seconds)
    MAX_WAIT_TIME = 120
    POLL_INTERVAL = 1  # seconds between status checks

    def __init__(
        self, context_manager: ContextManager, provider_id: str, config: ProviderConfig
    ):
        super().__init__(context_manager, provider_id, config)
        self.client = None

    def validate_config(self):
        """Validate provider configuration"""
        self.authentication_config = OpenaiAssistantProviderAuthConfig(
            **self.config.authentication
        )
        
        # Initialize OpenAI client
        self.client = OpenAI(
            api_key=self.authentication_config.api_key,
            organization=self.authentication_config.organization_id,
        )
        
        # Verify assistant exists
        try:
            assistant = self.client.beta.assistants.retrieve(
                assistant_id=self.authentication_config.assistant_id
            )
            self.logger.info(
                "Successfully connected to OpenAI Assistant",
                extra={
                    "assistant_name": assistant.name,
                    "assistant_model": assistant.model,
                    "tools": [tool.type for tool in assistant.tools] if assistant.tools else []
                }
            )
        except Exception as e:
            raise ProviderException(
                f"Failed to retrieve assistant {self.authentication_config.assistant_id}: {str(e)}"
            )

    def dispose(self):
        """Cleanup resources"""
        pass

    def validate_scopes(self) -> dict[str, bool | str]:
        """Validate API scopes/permissions"""
        scopes = {}
        
        try:
            # Test if we can retrieve the assistant
            assistant = self.client.beta.assistants.retrieve(
                assistant_id=self.authentication_config.assistant_id
            )
            scopes["assistant_access"] = True
            scopes["assistant_name"] = assistant.name or "Unnamed"
            scopes["assistant_model"] = assistant.model
        except Exception as e:
            scopes["assistant_access"] = f"Failed: {str(e)}"
        
        return scopes

    def _query(
        self,
        prompt: str,
        thread_id: Optional[str] = None,
        max_wait_time: Optional[int] = None,
        additional_instructions: Optional[str] = None,
        parse_json: bool = True,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Query the OpenAI Assistant
        
        Args:
            prompt: The user message to send to the assistant
            thread_id: Optional existing thread ID for continuing conversation
            max_wait_time: Maximum time to wait for response (seconds)
            additional_instructions: Additional instructions for this run
            parse_json: Try to parse response as JSON
            **kwargs: Additional arguments passed to runs.create()
        
        Returns:
            Dict containing:
                - response: The assistant's response (string or dict if JSON)
                - thread_id: The thread ID (for continuing conversation)
                - run_id: The run ID
                - messages: All messages in the thread
        """
        if not self.client:
            self.client = OpenAI(
                api_key=self.authentication_config.api_key,
                organization=self.authentication_config.organization_id,
            )
        
        max_wait = max_wait_time or self.MAX_WAIT_TIME
        
        try:
            # Step 1: Create or use existing thread
            if thread_id:
                self.logger.info(f"Using existing thread: {thread_id}")
                thread = self.client.beta.threads.retrieve(thread_id=thread_id)
            else:
                self.logger.info("Creating new thread")
                thread = self.client.beta.threads.create()
            
            # Step 2: Add message to thread
            self.logger.info(f"Adding message to thread {thread.id}")
            message = self.client.beta.threads.messages.create(
                thread_id=thread.id,
                role="user",
                content=prompt
            )
            
            # Step 3: Run the assistant
            self.logger.info(
                f"Running assistant {self.authentication_config.assistant_id}",
                extra={"thread_id": thread.id}
            )
            
            run_kwargs = {
                "thread_id": thread.id,
                "assistant_id": self.authentication_config.assistant_id,
            }
            
            if additional_instructions:
                run_kwargs["additional_instructions"] = additional_instructions
            
            # Merge any additional kwargs
            run_kwargs.update(kwargs)
            
            run = self.client.beta.threads.runs.create(**run_kwargs)
            
            # Step 4: Poll for completion
            start_time = time.time()
            while True:
                elapsed = time.time() - start_time
                
                if elapsed > max_wait:
                    # Cancel the run if it's taking too long
                    try:
                        self.client.beta.threads.runs.cancel(
                            thread_id=thread.id,
                            run_id=run.id
                        )
                    except:
                        pass
                    raise ProviderException(
                        f"Assistant did not respond within {max_wait} seconds"
                    )
                
                run = self.client.beta.threads.runs.retrieve(
                    thread_id=thread.id,
                    run_id=run.id
                )
                
                self.logger.debug(
                    f"Run status: {run.status}",
                    extra={"elapsed": elapsed}
                )
                
                if run.status == "completed":
                    break
                elif run.status == "failed":
                    error_msg = f"Assistant run failed: {run.last_error}"
                    self.logger.error(error_msg)
                    raise ProviderException(error_msg)
                elif run.status == "cancelled":
                    raise ProviderException("Assistant run was cancelled")
                elif run.status == "expired":
                    raise ProviderException("Assistant run expired")
                elif run.status in ["queued", "in_progress", "requires_action"]:
                    # Handle function calling if required
                    if run.status == "requires_action":
                        self.logger.warning(
                            "Assistant requires action (function calling), but this is not yet implemented in this provider"
                        )
                    time.sleep(self.POLL_INTERVAL)
                else:
                    self.logger.warning(f"Unknown run status: {run.status}")
                    time.sleep(self.POLL_INTERVAL)
            
            # Step 5: Retrieve messages
            messages = self.client.beta.threads.messages.list(
                thread_id=thread.id,
                order="asc"
            )
            
            # Get the last assistant message
            assistant_messages = [
                msg for msg in messages.data 
                if msg.role == "assistant"
            ]
            
            if not assistant_messages:
                raise ProviderException("No response from assistant")
            
            last_message = assistant_messages[-1]
            
            # Extract text from message content
            response_text = ""
            for content_block in last_message.content:
                if content_block.type == "text":
                    response_text += content_block.text.value
            
            self.logger.info(
                "Got response from assistant",
                extra={
                    "response_length": len(response_text),
                    "thread_id": thread.id,
                    "run_id": run.id
                }
            )
            
            # Try to parse as JSON if requested
            response_parsed = response_text
            if parse_json:
                try:
                    response_parsed = json.loads(response_text)
                    self.logger.info("Successfully parsed response as JSON")
                except json.JSONDecodeError:
                    self.logger.debug("Response is not valid JSON, returning as text")
            
            # Format all messages for context
            all_messages = [
                {
                    "role": msg.role,
                    "content": msg.content[0].text.value if msg.content else "",
                    "created_at": msg.created_at
                }
                for msg in messages.data
            ]
            
            return {
                "response": response_parsed,
                "thread_id": thread.id,
                "run_id": run.id,
                "messages": all_messages,
                "raw_response": response_text,
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
    assistant_id = os.environ.get("ASSISTANT_ID")

    if not api_key or not assistant_id:
        print("Please set OPENAI_API_KEY and ASSISTANT_ID environment variables")
        exit(1)

    config = ProviderConfig(
        description="OpenAI Assistant Test",
        authentication={
            "api_key": api_key,
            "assistant_id": assistant_id,
        },
    )

    provider = OpenaiAssistantProvider(
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
    print(f"Thread ID: {result['thread_id']}")

    # Test 2: Continue conversation in same thread
    print("\n=== Test 2: Continue Conversation ===")
    result2 = provider.query(
        prompt="What specific actions should I take right now?",
        thread_id=result['thread_id']
    )
    print(f"Response: {result2['response']}")
    print(f"All messages: {len(result2['messages'])}")

    # Test 3: With additional instructions
    print("\n=== Test 3: With Additional Instructions ===")
    result3 = provider.query(
        prompt="Analyze this: Database connection pool exhausted",
        additional_instructions="Respond in JSON format with keys: severity, action, explanation"
    )
    print(f"Response: {result3['response']}")

