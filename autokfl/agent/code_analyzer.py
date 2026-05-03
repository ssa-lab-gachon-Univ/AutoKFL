from pydantic import BaseModel, Field
from typing import Optional
from langchain_core.messages import AIMessage
from langchain_core.language_models.chat_models import BaseChatModel
from autokfl.agent.base_agent import BaseAgent
from autokfl.prompt.prompt_ca import SYSTEM_PROMPT_WITH_TOOLS, HUMAN_PROMPT
from autokfl.prompt.prompt_ca import SYSTEM_PROMPT_LLM_ONLY
from autokfl.state.state import AnalysisState
from autokfl.agent.code_collector import CollectedFunctions, CollectedFunction, CallGraph, CallGraphEdge, TypeDefinitions, TypeDefinition

class AgentRequest(BaseModel):
    agent: str = Field(description="Agent name")
    request: str = Field(description="Request details for the next agent (e.g. which functions or code ranges to collect; avoid asking for entire file contents to save tokens).")

class BugLocation(BaseModel):
    file: str = Field(description="Source file path")
    line: int = Field(description="Line number")
    score: float = Field(ge=0.0, le=1.0, description="Confidence score 0.0-1.0")
    # pattern: str = Field(description="Bug pattern e.g. use-after-free")
    reason: str = Field(description="Reason for suspecting bug at this location")


class CodeAnalyzerResponse(BaseModel):
    """Structured response from Code Analyzer agent"""
    bug_locations: list[BugLocation] = Field(
        description="List of potential bug locations with scores. Format: [{'file': 'path', 'line': 123, 'score': 0.8, 'pattern': 'use-after-free'}]"
    )
    bug_scenarios: list[str] = Field(description="Detailed bug scenario explanations")
    analysis_summary: str = Field(default="", description="Summary of code analysis")
    next_agent: str = Field(default="EvidenceSynthesizer", description="Next agent to execute: CrashObserver, CodeCollector, EvidenceSynthesizer, or END")
    request_to_agent: Optional[AgentRequest] = Field(default=None, description="Request to another agent")

class CodeAnalyzer(BaseAgent):
    def __init__(self, llm: BaseChatModel, tools: list, llm_only: bool = True):
        super().__init__(llm, tools, CodeAnalyzerResponse)
        self.llm_only = llm_only

    @property
    def system_prompt(self):
        return SYSTEM_PROMPT_WITH_TOOLS if not self.llm_only else SYSTEM_PROMPT_LLM_ONLY

    @property
    def human_prompt(self):
        return HUMAN_PROMPT

    @property
    def name(self) -> str:
        return "CodeAnalyzer"

    def update_state(self, state: AnalysisState, response: AIMessage) -> dict:
        new_analysis = {
            "bug_locations": response.bug_locations,
            "bug_scenarios": response.bug_scenarios,
            "summary": response.analysis_summary
        }
        
        new_bug_analysis = state.bug_analysis.copy()
        new_bug_analysis.append(new_analysis)
        
        return {"bug_analysis": new_bug_analysis}
