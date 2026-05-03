from dataclasses import dataclass, field
from typing import Union

@dataclass
class DataStructure:
    name: str = ""
    start_line: int = 0
    end_line: int = 0
    code_snippet: str = ""

@dataclass
class Function:
    name: str = ""
    start_line: int = 0
    end_line: int = 0
    code_snippet: str = ""

@dataclass
class Macro:
    name: str = ""
    file_path: str = ""
    start_line: int = 0
    end_line: int = 0
    code_snippet: str = ""

@dataclass
class CodeBlock:
    block_type: str = ""
    block: Union[DataStructure, Function, Macro] = None

@dataclass
class Codebase:
    kernel_version: str = ""
    kernel_commit: str = ""
    kernel_arch: str = ""
    repro_code: str = ""
    code_blocks: dict[str, list[CodeBlock]] = field(default_factory=dict)