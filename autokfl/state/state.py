import operator
from typing import Annotated, Sequence, Optional
from langchain_core.messages import BaseMessage
from pydantic import BaseModel, Field

class AnalysisState(BaseModel):
    """State for kernel crash fault localization analysis"""
    
    messages: Annotated[Sequence[BaseMessage], operator.add] = Field(
        default_factory=list,
        description="Complete message history exchanged between agents"
    )
    
    message_count: int = Field(
        default=0,
        description="Total number of messages exchanged so far (for preventing infinite loops)"
    )
    
    crash_analysis: dict = Field(
        default_factory=dict,
        description=(
            "Crash Observer's analysis results. "
            "Keys: crash_location, suspicious_functions, related_variables, summary. "
            "Overwritten on each Crash Observer run."
        )
    )
    
    collected_code: dict = Field(
        default_factory=dict,
        description=(
            "Source code information collected by Code Collector. "
            "Keys: functions, call_graph, type_definitions, summary. "
            "Stored as a single dict updated on each collection run."
        )
    )
    
    bug_analysis: list[dict] = Field(
        default_factory=list,
        description=(
            "List of analysis results from Code Analyzer. "
            "Each analysis contains bug_locations (list of {file, line, score, reason}), "
            "bug_scenarios (list of scenario strings), and summary (analysis_summary). "
            "Stored as a list since multiple analyses may be performed."
        )
    )
    
    final_result: Optional[dict] = Field(
        default=None,
        description=(
            "Final fault localization result from Evidence Synthesizer. "
            "Keys: ranked_locations, root_cause, summary. "
            "None if no final result yet."
        )
    )
    
    is_complete: bool = Field(
        default=False,
        description="Whether analysis is complete. If True, workflow terminates"
    )
    
    next_agent: str = Field(
        default="CrashObserver",
        description=(
            "Name of the next agent to execute. "
            "Must be one of: 'CrashObserver', 'CodeCollector', "
            "'CodeAnalyzer', 'EvidenceSynthesizer', or 'END'"
        )
    )

    from_agent: str = Field(
        default="",
        description="Name of the agent that produced this state update (who last ran)"
    )

    request_to_agent: str = Field(
        default="",
        description="Request text to pass to the next agent (handoff message)"
    )


class InternalState(BaseModel):
    """Internal state for agent subgraph tool calling loop"""
    
    messages: Annotated[list[BaseMessage], operator.add] = Field(
        default_factory=list,
        description="Message history within the subgraph (including tool calls/results)"
    )
    round_count: int = Field(
        default=0,
        description="Number of tool-call rounds executed (incremented in tool node)"
    )
    force_final_sent: bool = Field(
        default=False,
        description="True after injecting 'must call response_model only' message (avoids re-entering force_final)"
    )