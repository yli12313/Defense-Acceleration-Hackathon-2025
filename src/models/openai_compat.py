"""
OpenAI-compatible API models for OpenSafety AI Corporation of America.
These models mirror the OpenAI/OpenRouter API specification for /v1/chat/completions.
"""

from typing import Any, Literal, Optional, Union  # noqa: I001
from pydantic import BaseModel, Field
from enum import Enum
import time
import uuid


class MessageRole(str, Enum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"
    FUNCTION = "function"


class FunctionCall(BaseModel):
    """Function call in assistant message."""

    name: str
    arguments: str  # JSON string


class ToolCall(BaseModel):
    """Tool call made by the model."""

    id: str = Field(default_factory=lambda: f"call_{uuid.uuid4().hex[:24]}")
    type: Literal["function"] = "function"
    function: FunctionCall


class ContentPart(BaseModel):
    """Multimodal content part (text or image)."""

    type: Literal["text", "image_url"]
    text: Optional[str] = None
    image_url: Optional[dict[str, str]] = None  # {"url": "...", "detail": "auto"}


class ChatMessage(BaseModel):
    """A single message in the conversation."""

    role: MessageRole
    content: Optional[Union[str, list[ContentPart]]] = None
    name: Optional[str] = None  # For function/tool messages
    tool_calls: Optional[list[ToolCall]] = None  # For assistant messages
    tool_call_id: Optional[str] = None  # For tool response messages
    function_call: Optional[FunctionCall] = None  # Legacy function calling


class FunctionDefinition(BaseModel):
    """Function definition for tools."""

    name: str
    description: Optional[str] = None
    parameters: Optional[dict[str, Any]] = None
    strict: Optional[bool] = None


class Tool(BaseModel):
    """Tool definition."""

    type: Literal["function"] = "function"
    function: FunctionDefinition


class ResponseFormat(BaseModel):
    """Response format specification."""

    type: Literal["text", "json_object", "json_schema"] = "text"
    json_schema: Optional[dict[str, Any]] = None


class StreamOptions(BaseModel):
    """Streaming options."""

    include_usage: bool = False


class ChatCompletionRequest(BaseModel):
    """
    OpenAI-compatible chat completion request.
    Mirrors OpenRouter/OpenAI API specification.
    """

    model: str = Field(
        ...,
        description="Model ID (e.g., 'openai/gpt-4o', 'anthropic/claude-3.5-sonnet')",
    )  # noqa: E501
    messages: list[ChatMessage] = Field(..., description="Conversation messages")

    # Generation parameters
    temperature: Optional[float] = Field(default=1.0, ge=0.0, le=2.0)
    top_p: Optional[float] = Field(default=1.0, ge=0.0, le=1.0)
    top_k: Optional[int] = Field(default=None, ge=0)
    frequency_penalty: Optional[float] = Field(default=0.0, ge=-2.0, le=2.0)
    presence_penalty: Optional[float] = Field(default=0.0, ge=-2.0, le=2.0)
    repetition_penalty: Optional[float] = Field(default=None, ge=0.0)

    # Output control
    max_tokens: Optional[int] = Field(default=None, ge=1)
    max_completion_tokens: Optional[int] = Field(default=None, ge=1)
    n: Optional[int] = Field(default=1, ge=1, le=128)
    stop: Optional[Union[str, list[str]]] = None

    # Streaming
    stream: Optional[bool] = False
    stream_options: Optional[StreamOptions] = None

    # Tools and functions
    tools: Optional[list[Tool]] = None
    tool_choice: Optional[Union[str, dict[str, Any]]] = (
        None  # "auto", "none", "required", or specific  # noqa: E501
    )
    parallel_tool_calls: Optional[bool] = True

    # Response format
    response_format: Optional[ResponseFormat] = None

    # Sampling
    seed: Optional[int] = None
    logprobs: Optional[bool] = None
    top_logprobs: Optional[int] = Field(default=None, ge=0, le=20)
    logit_bias: Optional[dict[str, float]] = None

    # User tracking (important for security)
    user: Optional[str] = None

    # OpenRouter-specific
    transforms: Optional[list[str]] = None
    route: Optional[str] = None
    provider: Optional[dict[str, Any]] = None


class Usage(BaseModel):
    """Token usage statistics."""

    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0

    # Extended usage info
    prompt_tokens_details: Optional[dict[str, int]] = None
    completion_tokens_details: Optional[dict[str, int]] = None


class ChoiceMessage(BaseModel):
    """Message in a completion choice."""

    role: Literal["assistant"] = "assistant"
    content: Optional[str] = None
    tool_calls: Optional[list[ToolCall]] = None
    function_call: Optional[FunctionCall] = None
    refusal: Optional[str] = None


class LogprobContent(BaseModel):
    """Logprob for a single token."""

    token: str
    logprob: float
    bytes: Optional[list[int]] = None
    top_logprobs: Optional[list[dict[str, Any]]] = None


class ChoiceLogprobs(BaseModel):
    """Logprobs for a choice."""

    content: Optional[list[LogprobContent]] = None


class Choice(BaseModel):
    """A single completion choice."""

    index: int = 0
    message: ChoiceMessage
    finish_reason: Optional[
        Literal["stop", "length", "tool_calls", "content_filter", "function_call"]
    ] = None  # noqa: E501
    logprobs: Optional[ChoiceLogprobs] = None


class ChatCompletionResponse(BaseModel):
    """
    OpenAI-compatible chat completion response.
    """

    id: str = Field(default_factory=lambda: f"chatcmpl-{uuid.uuid4().hex}")
    object: Literal["chat.completion"] = "chat.completion"
    created: int = Field(default_factory=lambda: int(time.time()))
    model: str
    choices: list[Choice]
    usage: Optional[Usage] = None
    system_fingerprint: Optional[str] = None

    # OpenSafety extensions
    x_opensafety_request_id: Optional[str] = None
    x_opensafety_threat_score: Optional[float] = None


class DeltaMessage(BaseModel):
    """Delta message for streaming."""

    role: Optional[Literal["assistant"]] = None
    content: Optional[str] = None
    tool_calls: Optional[list[dict[str, Any]]] = None
    function_call: Optional[dict[str, Any]] = None


class StreamChoice(BaseModel):
    """Choice in a streaming chunk."""

    index: int = 0
    delta: DeltaMessage
    finish_reason: Optional[str] = None
    logprobs: Optional[ChoiceLogprobs] = None


class ChatCompletionChunk(BaseModel):
    """
    Streaming chunk for chat completions (SSE).
    """

    id: str
    object: Literal["chat.completion.chunk"] = "chat.completion.chunk"
    created: int
    model: str
    choices: list[StreamChoice]
    usage: Optional[Usage] = None
    system_fingerprint: Optional[str] = None


class ModelInfo(BaseModel):
    """Model information from /v1/models."""

    id: str
    object: Literal["model"] = "model"
    created: int = 0
    owned_by: str = "openrouter"

    # Extended info
    context_length: Optional[int] = None
    pricing: Optional[dict[str, float]] = None  # prompt, completion per token
    top_provider: Optional[dict[str, Any]] = None


class ModelsResponse(BaseModel):
    """Response for /v1/models endpoint."""

    object: Literal["list"] = "list"
    data: list[ModelInfo]


class ErrorDetail(BaseModel):
    """Error detail."""

    message: str
    type: str
    param: Optional[str] = None
    code: Optional[str] = None


class ErrorResponse(BaseModel):
    """API error response."""

    error: ErrorDetail
