from pydantic import BaseModel, Field, model_validator
from typing import Optional
from autokfl.agent.base_agent import BaseAgent
from autokfl.prompt.prompt_cc import SYSTEM_PROMPT
from autokfl.prompt.prompt_cc import HUMAN_PROMPT
from autokfl.state.state import AnalysisState
from langchain_core.messages import AIMessage
from langchain_core.language_models.chat_models import BaseChatModel

class AgentRequest(BaseModel):
    agent: str = Field(description="Agent name")
    request: str = Field(description="Request details")

class CallGraphNode(BaseModel):
    """Represents a function node in the call graph"""
    function_name: str = Field(description="Name of the function")
    file_path: str = Field(description="Source file path containing the function")
    line_number: int = Field(description="Line number of the function definition")

class CallGraphEdge(BaseModel):
    """Represents a caller/callee relationship"""
    caller: str = Field(description="Caller function name")
    callee: str = Field(description="Callee function name")

class CallGraph(BaseModel):
    """Call graph structure for kernel code"""
    nodes: list[CallGraphNode] = Field(description="List of function nodes in the call graph")
    edges: list[CallGraphEdge] = Field(description="List of caller/callee relationships")

# Collected functions
class CollectedFunction(BaseModel):
    """Represents a collected function"""
    function_name: str = Field(description="Name of the function")
    file_path: str = Field(description="Source file path containing the function")
    line_number: int = Field(description="Line number of the function definition")
    source_code: str = Field(description="Source code of the function")

class CollectedFunctions(BaseModel):
    """Collection of collected functions"""
    functions: list[CollectedFunction] = Field(description="List of collected functions")

# Type definitions
class TypeDefinition(BaseModel):
    """Represents a type definition"""
    type_name: str = Field(description="Name of the type")
    file_path: str = Field(description="Source file path containing the definition")
    line_number: int = Field(description="Line number of the type definition")
    kind: str = Field(description="Kind of type: struct, typedef, macro, enum, or union")
    definition: str = Field(description="Full definition of the type")

class TypeDefinitions(BaseModel):
    """Collection of type definitions"""
    definitions: list[TypeDefinition] = Field(description="List of type definitions")


class CodeCollectorResponse(BaseModel):
    """Structured response from Code Collector agent"""
    collected_functions: CollectedFunctions = Field(
        description="Collected source code. Key: function name, Value: source code"
    )
    call_graph: CallGraph  = Field(description="Call graph information (caller/callee relationships)")
    type_definitions: TypeDefinitions = Field(
        description="Structure and type definitions. Key: type name, Value: definition"
    )
    collection_summary: str = Field(default="", description="Summary of collected code")
    next_agent: str = Field(default="CodeAnalyzer", description="Next agent to execute: CrashObserver, CodeAnalyzer, EvidenceSynthesizer, or END")
    request_to_agent: Optional[AgentRequest] = Field(default=None, description="Request to another agent")

    @model_validator(mode='before')
    @classmethod
    def normalize_collected_functions(cls, data):
        if isinstance(data, dict) and 'collected_functions' in data:
            cf = data['collected_functions']
            if isinstance(cf, dict) and 'functions' not in cf:
                # {"func_name": {file_path, line_number, source_code}} → {"functions": [...]}
                data = data.copy()
                data['collected_functions'] = {
                    "functions": [
                        {"function_name": k, **v} if isinstance(v, dict) else {"function_name": k, "file_path": "", "line_number": 0, "source_code": str(v)}
                        for k, v in cf.items()
                    ]
                }
        return data

class CodeCollector(BaseAgent):
    def __init__(self, llm: BaseChatModel, tools: list):
        super().__init__(llm, tools, CodeCollectorResponse)

    @property
    def system_prompt(self):
        return SYSTEM_PROMPT

    @property
    def human_prompt(self):
        return HUMAN_PROMPT

    @property
    def name(self) -> str:
        return "CodeCollector"

    # def update_state(self, state: AnalysisState, response: AIMessage) -> dict:
    #     updated_code = state.collected_code.copy()
    #     updated_code.update({
    #         "functions": response.collected_functions,
    #         "call_graph": response.call_graph,
    #         "type_definitions": response.type_definitions,
    #         "summary": response.collection_summary
    #     })
        
    #     return {"collected_code": updated_code}

    def update_state(self, state: AnalysisState, response: AIMessage) -> dict:
        updated_code = state.collected_code.copy()

        # Merge functions: keep existing, add/overwrite by (function_name, file_path)
        existing_functions = state.collected_code.get("functions")
        existing_list = []
        if existing_functions is not None:
            if hasattr(existing_functions, "functions"):
                existing_list = list(existing_functions.functions)
            elif isinstance(existing_functions, list):
                existing_list = existing_functions
        by_func_key = {}
        for f in existing_list:
            fn = getattr(f, "function_name", f.get("function_name")) if isinstance(f, dict) else f.function_name
            fp = getattr(f, "file_path", f.get("file_path")) if isinstance(f, dict) else f.file_path
            key = (fn, fp)
            by_func_key[key] = f if isinstance(f, CollectedFunction) else CollectedFunction(**f)
        for f in response.collected_functions.functions:
            key = (f.function_name, f.file_path)
            by_func_key[key] = f
        updated_code["functions"] = CollectedFunctions(functions=list(by_func_key.values()))

        # Merge type_definitions: keep existing, add/overwrite by type_name
        existing_types = state.collected_code.get("type_definitions")
        existing_defs = []
        if existing_types is not None:
            if hasattr(existing_types, "definitions"):
                existing_defs = list(existing_types.definitions)
            elif isinstance(existing_types, list):
                existing_defs = existing_types
        by_type_key = {}
        for t in existing_defs:
            name = getattr(t, "type_name", t.get("type_name")) if isinstance(t, dict) else t.type_name
            by_type_key[name] = t if isinstance(t, TypeDefinition) else TypeDefinition(**t)
        for t in response.type_definitions.definitions:
            by_type_key[t.type_name] = t
        updated_code["type_definitions"] = TypeDefinitions(definitions=list(by_type_key.values()))

        # Merge call_graph: merge nodes and edges (dedupe)
        existing_cg = state.collected_code.get("call_graph")
        existing_nodes = []
        existing_edges = []
        if existing_cg is not None and hasattr(existing_cg, "nodes"):
            existing_nodes = list(existing_cg.nodes)
            existing_edges = list(existing_cg.edges)
        node_keys = {(n.function_name, n.file_path): n for n in existing_nodes}
        for n in response.call_graph.nodes:
            node_keys[(n.function_name, n.file_path)] = n
        edge_set = {(e.caller, e.callee) for e in existing_edges}
        for e in response.call_graph.edges:
            edge_set.add((e.caller, e.callee))
        updated_code["call_graph"] = CallGraph(
            nodes=list(node_keys.values()),
            edges=[CallGraphEdge(caller=c, callee=e) for c, e in edge_set],
        )

        # Summary: keep latest (this round's summary)
        updated_code["summary"] = response.collection_summary

        return {"collected_code": updated_code}