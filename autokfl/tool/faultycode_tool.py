from pydantic import BaseModel, Field
from typing import Optional
from langchain_core.tools.base import ArgsSchema
from langchain_core.tools import BaseTool

class FaultyCodeToolInput(BaseModel):
    path_faulty_code: str = Field(description='Path to the faulty code file')

class FaultyCodeTool(BaseTool):
    name: str = 'get_faulty_code'
    description: str = 'Read the faulty code file and return the code with line numbers'
    input_schema: Optional[ArgsSchema] = FaultyCodeToolInput

    def __init__(self):
        super().__init__()

    def _run(self, path_faulty_code: str):
        print(f'[Tool] FaultyCodeTool: Reading faulty code file...')
        with open(path_faulty_code, 'r') as f:
            lines = f.readlines()
        content = ''.join(f'{i:4d} | {line}' for i, line in enumerate(lines, 1))

        return content