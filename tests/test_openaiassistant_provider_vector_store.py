from keep.contextmanager.contextmanager import ContextManager
from keep.providers.models.provider_config import ProviderConfig
from keep.providers.openaiassistant_provider.openaiassistant_provider import (
    OpenaiassistantProvider,
)


def test_openaiassistant_provider_does_not_pin_prompt_version_by_default_and_attaches_vector_store_when_configured(
    monkeypatch
):
    captured_kwargs = {}
    prompt_id = "pmpt_test123"
    vector_store_id = "vs_test123"

    class FakePrompts:
        @staticmethod
        def retrieve(prompt_id):
            return type("Prompt", (), {"id": prompt_id, "version": "5"})()

    class FakeResponses:
        @staticmethod
        def create(**kwargs):
            captured_kwargs.update(kwargs)
            return type(
                "Response",
                (),
                {
                    "status": "completed",
                    "conversation": None,
                    "output": [],
                    "output_text": '{"ok": true}',
                },
            )()

    class FakeOpenAI:
        def __init__(self, *args, **kwargs):
            self.prompts = FakePrompts()
            self.responses = FakeResponses()

    monkeypatch.setattr(
        "keep.providers.openaiassistant_provider.openaiassistant_provider.OpenAI",
        FakeOpenAI,
    )

    provider = OpenaiassistantProvider(
        context_manager=ContextManager(tenant_id="keep", workflow_id="wf"),
        provider_id="openaiassistant",
        config=ProviderConfig(
            description="test",
            authentication={
                "api_key": "test-key",
                "prompt_id": prompt_id,
                "vector_store_id": vector_store_id,
            },
        ),
    )
    provider.validate_config()
    result = provider._query(prompt="test", parse_json=False)

    assert result["response"] == '{"ok": true}'
    assert captured_kwargs["prompt"]["id"] == prompt_id
    assert "version" not in captured_kwargs["prompt"]
    assert captured_kwargs["tools"] == [
        {
            "type": "file_search",
            "vector_store_ids": [vector_store_id],
        }
    ]


def test_openaiassistant_provider_does_not_attach_vector_store_when_not_configured(
    monkeypatch,
):
    captured_kwargs = {}

    class FakePrompts:
        @staticmethod
        def retrieve(prompt_id):
            return type("Prompt", (), {"id": prompt_id, "version": "5"})()

    class FakeResponses:
        @staticmethod
        def create(**kwargs):
            captured_kwargs.update(kwargs)
            return type(
                "Response",
                (),
                {
                    "status": "completed",
                    "conversation": None,
                    "output": [],
                    "output_text": '{"ok": true}',
                },
            )()

    class FakeOpenAI:
        def __init__(self, *args, **kwargs):
            self.prompts = FakePrompts()
            self.responses = FakeResponses()

    monkeypatch.setattr(
        "keep.providers.openaiassistant_provider.openaiassistant_provider.OpenAI",
        FakeOpenAI,
    )

    provider = OpenaiassistantProvider(
        context_manager=ContextManager(tenant_id="keep", workflow_id="wf"),
        provider_id="openaiassistant",
        config=ProviderConfig(
            description="test",
            authentication={
                "api_key": "test-key",
                "prompt_id": "pmpt_test123",
            },
        ),
    )
    provider.validate_config()
    result = provider._query(prompt="test", parse_json=False)

    assert result["response"] == '{"ok": true}'
    assert "tools" not in captured_kwargs
