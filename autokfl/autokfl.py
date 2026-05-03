import json
import os
from langgraph.graph import StateGraph, START, END
from langchain_core.messages import HumanMessage
from langchain_openai import ChatOpenAI
from langchain_anthropic import ChatAnthropic
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.language_models.chat_models import BaseChatModel
from autokfl.codebase import Codebase
from autokfl.state.state import AnalysisState
from autokfl.agent.crash_observer import CrashObserver
from autokfl.agent.code_collector import CodeCollector
from autokfl.agent.code_analyzer import CodeAnalyzer
from autokfl.agent.evidence_synthesizer import EvidenceSynthesizer
from autokfl.prompt.prompt_co import HUMAN_PROMPT
from autokfl.tool.callstack_tool import CallstackTool
from autokfl.tool.faultycode_tool import FaultyCodeTool
from autokfl.tool.crashinfo_tool import CrashInfoTool
from autokfl.tool.infercrashtype_tool import InferCrashTypeTool
from autokfl.tool.function_tool import FunctionTool
from autokfl.tool.list_tool import ListTool
from autokfl.tool.datastruct_tool import DatastructTool
from autokfl.tool.macro_tool import MacroTool
from autokfl.tool.listfunctions_tool import ListFunctionsTool
from autokfl.tool.listdatastructs_tool import ListDatastructsTool
from autokfl.tool.listmacroexpansions_tool import ListMacroExpansionsTool
from autokfl.tool.callgraph_tool import CallGraphTool
from autokfl.tool.callers_tool import CallersTool
from autokfl.tool.callees_tool import CalleesTool
from autokfl.tool.tracedatadep_tool import TraceDataDependencyTool
from autokfl.tool.detectbugpattern_tool import DetectBugPatternTool
from autokfl.tool.trackmemoryop_tool import TrackMemoryOperationsTool
from autokfl.tool.checkbounds_tool import CheckBoundsTool
from autokfl.tool.generatecfg_tool import GenerateCFGTool
from autokfl.tool.tracetaint_tool import TraceTaintTool
from autokfl.tool.analyzepointeralias_tool import AnalyzePointerAliasingTool
from autokfl.tool.checklockorder_tool import CheckLockOrderTool
from autokfl.tool.calculateconfscore_tool import CalculateConfidenceScoreTool
from autokfl.tool.calculateevidweight_tool import CalculateEvidenceWeightTool
from autokfl.tool.verifyhypoconsist_tool import VerifyHypothesisConsistencyTool
from autokfl.tool.assessanalysiscompl_tool import AssessAnalysisCompletenessTool

class Autokfl:
    def __init__(self, workdir, model, codebase: Codebase, n_try: int = 10, llm_only: bool = True):
        self.workdir = workdir
        self.model = model
        self.n_try = n_try
        self.codebase = codebase
        
        os.chdir(workdir)

        crash_observer_tools = [CallstackTool(), FaultyCodeTool(), CrashInfoTool()]#, InferCrashTypeTool()]
        code_collector_tools = [
            # ListTool(), ListFunctionsTool(), ListDatastructsTool(), ListMacroExpansionsTool(), 
            FunctionTool(), DatastructTool(), MacroTool(), 
            CallGraphTool(), CallersTool(), CalleesTool(), TraceDataDependencyTool()
        ]
        code_analyzer_tools = [] if llm_only else [
            DetectBugPatternTool(), TrackMemoryOperationsTool(), CheckBoundsTool(),
            GenerateCFGTool(), TraceTaintTool(), AnalyzePointerAliasingTool(), CheckLockOrderTool()
        ]
        evidence_synthesizer_tools = [] if llm_only else [
            CalculateConfidenceScoreTool(), CalculateEvidenceWeightTool(), VerifyHypothesisConsistencyTool(),
            AssessAnalysisCompletenessTool()
        ]

        self.crash_observer = CrashObserver(self.set_llm(model), crash_observer_tools)
        self.code_collector = CodeCollector(self.set_llm(model), code_collector_tools)
        self.code_analyzer = CodeAnalyzer(self.set_llm(model), code_analyzer_tools, llm_only)
        self.evidence_synthesizer = EvidenceSynthesizer(self.set_llm(model), evidence_synthesizer_tools, llm_only)

        self.graph = self.build_graph()

    def set_llm(self, model: str) -> BaseChatModel:
        match model:
            case 'gpt':
                return ChatOpenAI(model='gpt-5-mini', temperature=0.0)
            case 'claude':
                return ChatAnthropic(model='claude-haiku-4-5-20251001', temperature=0.0)
            case 'gemini':
                return ChatGoogleGenerativeAI(model='gemini-3-flash-preview', temperature=0.0)
            case _:
                raise ValueError(f"Invalid model: {model}")

    def build_graph(self):
        graph = StateGraph(AnalysisState)

        graph.add_node('crash_observer', self.crash_observer.invoke)
        graph.add_node('code_collector', self.code_collector.invoke)
        graph.add_node('code_analyzer', self.code_analyzer.invoke)
        graph.add_node('evidence_synthesizer', self.evidence_synthesizer.invoke)

        graph.add_edge(START, 'crash_observer')
        NODES = ['crash_observer', 'code_collector', 'code_analyzer', 'evidence_synthesizer']

        for node in NODES:
            route_map = {name: name for name in NODES if name != node}
            route_map['end'] = END
            graph.add_conditional_edges(node, self.route_node, route_map)

        return graph.compile()

    def route_node(self, state: AnalysisState) -> str:
        print('[Global] Route node invoked')
        if state.message_count >= self.n_try:
            return 'end'

        if state.is_complete: return 'end'

        next_agent = state.next_agent

        agent_mapping = {
            "CrashObserver": "crash_observer",
            "CodeCollector": "code_collector",
            "CodeAnalyzer": "code_analyzer",
            "EvidenceSynthesizer": "evidence_synthesizer",
            "END": 'end'
        }
        
        return agent_mapping.get(next_agent, 'end')
        

    def run(self, path_callstack: str, path_faulty_code: str, path_crash_info: str):
        path_callstack = os.path.join(os.getcwd(), path_callstack)
        path_faulty_code = os.path.join(os.getcwd(), path_faulty_code)
        path_crash_info = os.path.join(os.getcwd(), path_crash_info)

        initial_state = AnalysisState(
            messages=[
                HumanMessage(HUMAN_PROMPT.format(path_callstack=path_callstack, path_faulty_code=path_faulty_code, path_crash_info=path_crash_info))
            ]
        )

        result = self.graph.invoke(initial_state)
        
        if result['final_result']:
            print('[*] Ranked locations:')
            for location in result['final_result']['ranked_locations']:
                print(f'  - {location.file} {location.function}:{location.line} ({location.confidence})')
            print('[*] Root cause:')
            print(result['final_result']['root_cause'])
            print('[*] Summary:')
            print(result['final_result']['summary'])
        else:
            print('[*] No final result found')