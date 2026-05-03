from pydantic import BaseModel, Field
from typing import Optional
from autokfl.agent.base_agent import BaseAgent
from autokfl.prompt.prompt_es import SYSTEM_PROMPT_WITH_TOOLS
from autokfl.prompt.prompt_es import SYSTEM_PROMPT_LLM_ONLY
from autokfl.prompt.prompt_es import HUMAN_PROMPT
from autokfl.state.state import AnalysisState
from langchain_core.messages import AIMessage
from langchain_core.language_models.chat_models import BaseChatModel

class AgentRequest(BaseModel):
    agent: str = Field(description="Agent name")
    request: str = Field(description="Request details")

class RankedLocation(BaseModel):
    file: str = Field(description="Source file path")
    function: str = Field(description="Function name")
    line: int = Field(description="Line number")
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence score 0.0-1.0")

class EvidenceSynthesizerResponse(BaseModel):
    """Structured response from Evidence Synthesizer agent"""
    ranked_locations: list[RankedLocation] = Field(
        description="Ranked buggy code locations. Format: [{'file': 'path', 'line': 123, 'confidence': 0.9}]"
    )
    root_cause: str = Field(default="", description="Root cause explanation")
    # confidence_score: float = Field(ge=0.0, le=1.0, description="Overall confidence score (0.0 to 1.0)")
    synthesis_summary: str = Field(default="", description="Summary of evidence synthesis")
    next_agent: str = Field(default="END", description="Next agent to execute: CrashObserver, CodeCollector, CodeAnalyzer, or END (usually END if complete)")
    request_to_agent: Optional[AgentRequest] = Field(default=None, description="Request to another agent")

class EvidenceSynthesizer(BaseAgent):
    def __init__(self, llm: BaseChatModel, tools: list, llm_only: bool = True):
        super().__init__(llm, tools, EvidenceSynthesizerResponse)
        self.llm_only = llm_only
        
    @property
    def system_prompt(self):
        return SYSTEM_PROMPT_WITH_TOOLS if not self.llm_only else SYSTEM_PROMPT_LLM_ONLY

    @property
    def human_prompt(self):
        return HUMAN_PROMPT

    @property
    def name(self) -> str:
        return "EvidenceSynthesizer"

    def update_state(self, state: AnalysisState, response: AIMessage) -> dict:
        final_result = {
            "ranked_locations": response.ranked_locations,
            "root_cause": response.root_cause,
            # "confidence_score": response.confidence_score,
            "summary": response.synthesis_summary
        }
        
        return {
            "final_result": final_result,
            "is_complete": response.next_agent == "END"
        }