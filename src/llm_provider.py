"""
llm_provider.py — the thin, provider-agnostic LLM seam for `badzure generate`.

BadZure stays out of the multi-provider business by delegating to LiteLLM, whose
single OpenAI-style `completion()` call fronts 100+ providers (Anthropic, OpenAI,
Gemini, HuggingFace, Ollama/local, ...). The provider is selected purely by the
model string (e.g. `anthropic/claude-opus-4-1`, `openai/gpt-4o`, `ollama/llama3`).

We deliberately do NOT rely on each provider's native structured-output / JSON mode
(support is uneven across that breadth). Reliability comes from BadZure's own
deterministic validator + retry loop in `org_generator.py` — this layer only moves
text in and out.

`litellm` is imported LAZILY inside `generate()` so importing this module (and the
CLI) never requires the package; it's only needed when someone actually runs
`badzure generate`.
"""
import logging
from typing import Optional


class LLMError(RuntimeError):
    """Raised when the LLM call fails (transport, auth, or missing dependency)."""


class LLMProvider:
    """Wraps a single chat-completion call across any LiteLLM-supported provider."""

    def __init__(self, model: str, api_key: Optional[str] = None,
                 base_url: Optional[str] = None, temperature: float = 0.7,
                 max_tokens: int = 8000):
        if not model:
            raise LLMError("LLMProvider requires a model string.")
        self.model = model
        self.api_key = api_key
        self.base_url = base_url
        self.temperature = temperature
        self.max_tokens = max_tokens

    def generate(self, system: str, user: str) -> str:
        """Send a system + user message and return the assistant's text content."""
        try:
            import litellm  # lazy: only needed when generation actually runs
        except ImportError as e:
            raise LLMError(
                "The `litellm` package is required for `badzure generate`. "
                "Install it with: pip install litellm"
            ) from e

        kwargs = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }
        if self.api_key:
            kwargs["api_key"] = self.api_key
        if self.base_url:
            kwargs["api_base"] = self.base_url

        logging.info(f"Querying LLM ({self.model}) ...")
        try:
            response = litellm.completion(**kwargs)
        except Exception as e:  # noqa: BLE001 — surface any provider/transport error
            raise LLMError(f"LLM call failed ({self.model}): {e}") from e

        try:
            return response.choices[0].message.content or ""
        except (AttributeError, IndexError, KeyError) as e:
            raise LLMError(f"Unexpected LLM response shape: {e}") from e
