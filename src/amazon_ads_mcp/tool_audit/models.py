"""Data models for MCP tool token audit results."""

from pydantic import BaseModel, Field


class ToolTokenBreakdown(BaseModel):
    """Token usage breakdown for a single MCP tool definition."""

    name: str
    prefix: str
    total_tokens: int
    schema_tokens: int
    description_tokens: int
    name_tokens: int
    raw_chars: int
    description_preview: str


class GroupSummary(BaseModel):
    """Aggregated token stats for a tool prefix group."""

    prefix: str
    tool_count: int
    total_tokens: int
    avg_tokens_per_tool: float
    largest_tool: str
    largest_tool_tokens: int


class CodeModeSchemaProbeItem(BaseModel):
    """Token stats for one schema fetch in code mode."""

    tool_name: str
    total_tokens: int
    raw_chars: int
    ok: bool = True
    error: str | None = None


class CodeModeProbeReport(BaseModel):
    """Optional details from probing code mode discovery + schema fetch."""

    enabled: bool
    meta_tools: list[str] = Field(default_factory=list)
    search_tool: str | None = None
    schema_tool: str | None = None
    search_queries: list[str] = Field(default_factory=list)
    sampled_tool_count: int = 0
    sampled_tools: list[str] = Field(default_factory=list)
    schema_fetches: list[CodeModeSchemaProbeItem] = Field(default_factory=list)
    total_schema_tokens: int = 0
    avg_schema_tokens: float = 0.0


class AuditReport(BaseModel):
    """Complete tool token audit report."""

    server_url: str
    tool_count: int
    encoding: str
    mode: str
    tools: list[ToolTokenBreakdown]
    groups: list[GroupSummary]
    total_tool_tokens: int
    context_window_size: int
    context_window_percent: float
    threshold: int
    threshold_violations: list[str] = Field(default_factory=list)
    code_mode_probe: CodeModeProbeReport | None = None
