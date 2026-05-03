from pydantic import BaseModel, Field
from typing import Optional
from autokfl.agent.base_agent import BaseAgent
from autokfl.prompt.prompt_co import SYSTEM_PROMPT
from autokfl.prompt.prompt_co import HUMAN_PROMPT
from autokfl.state.state import AnalysisState
from langchain_core.messages import AIMessage
from langchain_core.language_models.chat_models import BaseChatModel

class AgentRequest(BaseModel):
    agent: str = Field(description="Agent name")
    request: str = Field(description="Request details")

class CrashObserverResponse(BaseModel):
    """Structured response from Crash Observer agent"""
    crash_location: str = Field(description="Function and line number where crash occurred")
    suspicious_functions: list[str] = Field(description="Ranked list of suspicious function names")
    related_variables: list[str] = Field(description="Related variable and structure names")
    reduced_faulty_code: str = Field(
        default="",
        description=(
            "Faulty (user-space) code reduced per function. For each function use exactly: "
            "'N: <signature> {', then '// <function summary and crash-related info>', then 'M: }' "
            "where N and M are the start and end line numbers in the original file. "
            "Preserve source structure; no natural-language-only summary."
        )
    )
    analysis_summary: str = Field(default="", description="Summary of crash analysis")
    next_agent: str = Field(default="CodeCollector", description="Next agent to execute: CodeCollector, CodeAnalyzer, EvidenceSynthesizer, or END")
    request_to_agent: Optional[AgentRequest] = Field(
        default=None,
        description="Request to another agent. Format: {'agent': 'AgentName', 'request': 'details'}"
    )

class CrashObserver(BaseAgent):
    def __init__(self, llm: BaseChatModel, tools: list):
        super().__init__(llm, tools, CrashObserverResponse)

    @property
    def system_prompt(self):
        return SYSTEM_PROMPT

    @property
    def human_prompt(self):
        return HUMAN_PROMPT

    @property
    def name(self) -> str:
        return "CrashObserver"

    def update_state(self, state: AnalysisState, response: AIMessage) -> dict:
        crash_analysis = {
            'crash_location': response.crash_location,
            'suspicious_functions': response.suspicious_functions,
            'related_variables': response.related_variables,
            'reduced_faulty_code': getattr(response, 'reduced_faulty_code', '') or '',
            'summary': response.analysis_summary,
        }

        return {'crash_analysis': crash_analysis}

    