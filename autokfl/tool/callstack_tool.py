import json
from pydantic import BaseModel, Field
from typing import Optional
from langchain_core.tools.base import ArgsSchema
from langchain_core.tools import BaseTool

class CallstackToolInput(BaseModel):
    path_callstack: str = Field(description="Path to the callstack file")

class CallstackTool(BaseTool):
    name: str = 'read_callstack'
    description: str = '''Read the callstack file and return the full crash data.
    Returned keys: 
    - 'callstack' (list of frames with function_name, offset, function_size, src with location/line)
    - 'entry_ctx' (list of [register, value] pairs at entry, user space CPU context) 
    - 'exit_ctx (crash_ctx)' (list of [register, value] pairs at crash point, kernel space CPU context)'''
    args_schema: Optional[ArgsSchema] = CallstackToolInput

    def __init__(self):
        super().__init__()

    def _run(self, path_callstack: str):
        print('[Tool] CallstackTool: Reading callstack file...')

        with open(path_callstack, 'r') as f:
            result = json.load(f)

        return result