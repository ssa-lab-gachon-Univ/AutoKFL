import json
from pydantic import BaseModel, Field
from typing import Optional
from langchain_core.tools.base import ArgsSchema
from langchain_core.tools import BaseTool

class CrashInfoToolInput(BaseModel):
    path_crash_info: str = Field(description='Path to the crash information file')

class CrashInfoTool(BaseTool):
    name: str = 'get_crash_info'
    description: str = 'Read the crash information file and return the crash information'
    input_schema: Optional[ArgsSchema] = CrashInfoToolInput

    def __init__(self):
        super().__init__()

    def _run(self, path_crash_info: str):
        print(f'[Tool] CrashInfoTool: Reading crash information file...')

        with open(path_crash_info, 'r') as f:
            result = json.load(f)
        
        return result