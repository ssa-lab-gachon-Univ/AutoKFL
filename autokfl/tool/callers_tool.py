import os
import json
import subprocess
from typing import Optional
from langchain_core.tools import BaseTool
from langchain_core.tools.base import ArgsSchema
from pydantic import BaseModel, Field

class CallersToolInput(BaseModel):
    function_name: str = Field(description='The name of the function to get the callers from')
    reason: str = Field(description='The reason why you need to get the callers')

class CallersTool(BaseTool):
    name: str = 'get_callers'
    description: str = '''Find all call sites (callers) of a given function in the kernel source.
This tool uses cscope to search for every place where the specified function is called,
returning the file path, caller function name, line number, and surrounding context
for each call site.

Use this tool when you need to:
- Discover which functions call a specific function
- Trace call graphs and analyze data flow for crash investigation
- Find all usages of a function across the kernel source tree
- Understand how a function is invoked before analyzing its implementation

The tool returns the function name, a list of {file_path, caller_function_name, 
line_number, context} for each caller, and the total count.

Important: In this environment, the current working directory is workdir. Kernel source code
lives under workdir/crash-* directories (each crash-* is the kernel tree for the commit where
a crash occurred). Do not use workdir/linux. The search is performed within the crash-*
directory'''
    args_schema: Optional[ArgsSchema] = CallersToolInput

    def __init__(self):
        super().__init__()

    def _run(self, function_name: str, reason: str):
        print(f'[Tool] CallersTool: {function_name}: {reason}')
        
        cur_dir = os.getcwd()
        fn = os.listdir('.')
        crash_dirs = [f for f in fn if f.startswith('crash-')]
        if not crash_dirs:
            os.chdir(cur_dir)
            error_result = {
                'error': 'No crash-* directory found',
                'function_name': function_name,
            }
            return json.dumps(error_result, indent=2)
        dir_kernel = crash_dirs[0]
        os.chdir(dir_kernel)

        try:
            cmd = ['cscope', '-d', '-L', '-3', function_name]
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30
            )

            callers = []
            for line in result.stdout.split('\n'):
                if not line: continue

                parts = line.split(None, 3)
                if len(parts) >= 3:
                    file_path = parts[0]
                    caller_function_name = parts[1]
                    line_number = int(parts[2])
                    context = parts[3]
                    callers.append({
                        'file_path': file_path,
                        'caller_function_name': caller_function_name,
                        'line_number': line_number,
                        'context': context
                    })
            os.chdir(cur_dir)
            return json.dumps({
                'function_name': function_name,
                'callers': callers,
                'count': len(callers),
            }, indent=2)

        except Exception as e:
            os.chdir(cur_dir)
            error_result = {
                'error': 'Failed to get callers',
                'function_name': function_name,
            }
            return json.dumps(error_result, indent=2)