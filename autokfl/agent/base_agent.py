import json
from abc import ABC, abstractmethod
from pydantic import BaseModel
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.tools import StructuredTool
from langgraph.graph import StateGraph, START, END
from autokfl.state.state import AnalysisState, InternalState
from autokfl.prompt.prompt_ca import HUMAN_PROMPT
from autokfl.prompt.prompt_es import HUMAN_PROMPT

def _json_default(obj):
    if hasattr(obj, "model_dump"):
        return obj.model_dump()
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")

class BaseAgent(ABC):
    """Base class for all fault localization agents"""
    def __init__(self, llm: BaseChatModel, tools: list, response_model: type[BaseModel], max_rounds: int = 10):
        self.tools = tools
        self.tool_map = {tool.name: tool for tool in tools}
        self.response_model = response_model
        self.max_rounds = max_rounds

        response_tool = self._response_model_to_tool(response_model)
        self.llm = llm.bind_tools(tools + [response_tool])
        self.graph = self._build_graph()

    def _response_model_to_tool(self, model: type[BaseModel]):
        schema = model.model_json_schema()
        required = schema.get('required', [])

        parts = [model.__doc__ or '']
        if required:
            parts.append(f" Required arguments: {', '.join(required)}.")
        return StructuredTool.from_function(
            name=model.__name__,
            description=' '.join(parts).strip(),
            args_schema=model,
            func=lambda **kwargs: kwargs
        )

    def _build_graph(self):
        graph = StateGraph(InternalState)

        graph.add_node('llm', self._llm_node)
        graph.add_node('tool', self._tool_node)
        graph.add_node('force_final', self._force_final_node)

        graph.add_edge(START, 'llm')
        graph.add_conditional_edges('llm', self._route_node, {
            'tool': 'tool',
            'end': END,
            'force_final': 'force_final',
        })
        graph.add_edge('tool', 'llm')
        graph.add_edge('force_final', 'llm')
        return graph.compile()

    @property
    @abstractmethod
    def system_prompt(self) -> str:
        pass

    @property
    @abstractmethod
    def human_prompt(self) -> str:
        pass

    @abstractmethod
    def update_state(self, state: AnalysisState, response: AIMessage) -> dict:
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    def _llm_node(self, state: InternalState) -> dict:
        print(f'[Agent] {self.name} LLM node invoked')
        response = self.llm.invoke(state.messages)
        return {'messages': [response]}

    def _tool_node(self, state: InternalState) -> dict:
        print(f'[Agent] {self.name} Tool node invoked')
        last_message = state.messages[-1]
        tool_results = []

        for tool_call in last_message.tool_calls:
            if tool_call['name'] == self.response_model.__name__: continue

            tool = self.tool_map[tool_call['name']]
            result = tool.invoke(tool_call['args'])
            tool_results.append(ToolMessage(
                content=str(result),
                tool_call_id=tool_call['id']
            ))
        
        return {'messages': tool_results, 'round_count': state.round_count + 1}

    def _force_final_node(self, state: InternalState) -> dict:
        """Inject skipped ToolMessages for pending tool_calls (API requires each tool_call_id to have a response), then the final instruction."""
        last_message = state.messages[-1]
        out: list = []
        if hasattr(last_message, 'tool_calls') and last_message.tool_calls:
            for tc in last_message.tool_calls:
                if tc.get('name') == self.response_model.__name__:
                    continue
                out.append(ToolMessage(
                    content="[Skipped: maximum tool rounds reached.]",
                    tool_call_id=tc['id'],
                ))
        msg = (
            f"You have reached the maximum number of tool calls ({self.max_rounds}). "
            f"You must respond only by calling the tool '{self.response_model.__name__}' with your current findings. "
            "Do not call any other tools."
        )
        out.append(HumanMessage(content=msg))
        return {'messages': out, 'force_final_sent': True}

    def _route_node(self, state: InternalState) -> str:
        print(f'[Agent] {self.name} Route node invoked')
        last_message = state.messages[-1]

        if not hasattr(last_message, 'tool_calls') or not last_message.tool_calls:
            return 'end'

        for tool_call in last_message.tool_calls:
            if tool_call['name'] == self.response_model.__name__:
                return 'end'

        if state.round_count >= self.max_rounds:
            if state.force_final_sent:
                return 'end'
            return 'force_final'
        return 'tool'

    def invoke(self, state: AnalysisState) -> dict:
        print(f'[Agent] {self.name} invoked')
        messages = state.messages

        messages = [
                SystemMessage(content=self.system_prompt.format(response_model_name=self.response_model.__name__, max_rounds=self.max_rounds)),
                *messages
            ]
        if self.name == 'CodeAnalyzer':
            analysis_from_evidence_synthesizer = json.dumps(state.final_result, indent=2, default=_json_default) \
                if state.from_agent == 'EvidenceSynthesizer' and state.final_result \
                else "(No prior analysis from Evidence Synthesizer.)"
                
            messages.append(HumanMessage(content=self.human_prompt.format(
                collected_code=json.dumps(state.collected_code, indent=2, default=_json_default),
                from_agent=state.from_agent,
                request_to_agent=state.request_to_agent,
                analysis_from_evidence_synthesizer=analysis_from_evidence_synthesizer,
                crash_analysis=json.dumps(state.crash_analysis, indent=2, default=_json_default)
            )))
        elif self.name == 'CodeCollector':
            messages.append(HumanMessage(content=self.human_prompt.format(
                crash_analysis=json.dumps(state.crash_analysis, indent=2, default=_json_default),
                from_agent=state.from_agent,
                request_to_agent=state.request_to_agent
            )))
        elif self.name == 'EvidenceSynthesizer':
            messages.append(HumanMessage(content=self.human_prompt.format(
                crash_analysis=json.dumps(state.crash_analysis, indent=2, default=_json_default),
                bug_analysis=json.dumps(state.bug_analysis, indent=2, default=_json_default),
                from_agent=state.from_agent,
                request_to_agent=state.request_to_agent
            )))
        elif state.request_to_agent:
            messages.append(HumanMessage(content=self.human_prompt.format(
                from_agent=state.from_agent,
                request_to_agent=state.request_to_agent
            )))
        internal_state = InternalState(messages=messages)

        response = self.graph.invoke(internal_state)

        parsed = self._extract_parsed_response(response['messages'])

        if parsed is None:
            raise ValueError(f'No parsed response found for agent {self.name}')

        if self.name == 'CrashObserver' and getattr(parsed, 'reduced_faulty_code', ''):
            print('[REDUCED FAULTY CODE]')
            print(parsed.reduced_faulty_code)
            exit(0)

        base_updates = {
            'messages': [AIMessage(content=self._get_summary(parsed))],
            'message_count': state.message_count + 1,
            'next_agent': parsed.next_agent,
            'from_agent': self.name,
            'request_to_agent': parsed.request_to_agent.request if parsed.request_to_agent else ""
        }

        specific_updates = self.update_state(state, parsed)
        return {**base_updates, **specific_updates}
    
    def _extract_parsed_response(self, messages: list):
        name = self.response_model.__name__
        for msg in reversed(messages):
            for tc in getattr(msg, 'tool_calls', None) or []:
                if tc.get('name') == name:
                    return self.response_model.model_validate(tc['args'])
        return None


    def _get_summary(self, parsed: BaseModel) -> str:
        for attr in ('analysis_summary', 'collection_summary', 'final_result'):
            if hasattr(parsed, attr):
                val = getattr(parsed, attr)
                return str(val) if val else ''
        return parsed.model_dump_json()