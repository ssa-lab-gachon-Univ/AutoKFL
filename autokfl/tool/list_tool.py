import os
import json
from pydantic import BaseModel, Field
from typing import Optional
from langchain_core.tools import BaseTool
from langchain_core.tools.base import ArgsSchema
from autokfl.codebase import Codebase

class ListToolInput(BaseModel):
    path: str = Field(description='Path to the directory to list, relative to the kernel source root (e.g. . or fs/btrfs)')
    reason: str = Field(description='The reason why you need to list the contents of the directory')

class ListTool(BaseTool):
    name: str = "ls"
    description: str = '''List directory contents or check if a file/directory exists at the given path.
This tool returns the contents of a directory (if the path is a directory) or file metadata 
(if the path is a file). 

IMPORTANT: You MUST use this tool BEFORE using get_function_definition, get_datastruct, or 
get_macro_expansion to verify that the directory or file path exists and is accessible. 
This prevents errors from attempting to access non-existent paths and helps you discover 
the correct file structure in the kernel source code.

Use this tool when you need to:
- Verify that a file or directory path exists before accessing it
- Explore directory structure to find source files
- List files in a directory to locate specific functions, data structures, or macros
- Check file metadata (size, existence) before reading

Important: The current working directory is workdir. Directory listing and path checks are performed
inside workdir/crash-* (the kernel tree for the commit where the crash occurred). Do not use
workdir/linux. Pass paths under workdir/crash-* (e.g. workdir/crash-<id>/ or workdir/crash-<id>/fs/btrfs).
Use this tool first to discover the crash-* directory and explore the source tree before calling
get_function_definition, get_datastruct, or get_macro_expansion with the paths you find.

The tool returns either a list of items (for directories) or file information (for files).'''
    args_schema: Optional[ArgsSchema] = ListToolInput

    def __init__(self):
        super().__init__()

    def _run(self, path: str, reason: str):
        print(f'[Tool] ListTool: {path}, {reason}')
        cur_dir = os.getcwd()
        

        fn = os.listdir('.')
        crash_dirs = [f for f in fn if f.startswith('crash-')]
        if not crash_dirs:
            error_result = {
                'error': 'No crash-* directory found',
                'path': path,
            }
            return json.dumps(error_result, indent=2)
        dir_kernel = crash_dirs[0]
        os.chdir(dir_kernel)

        if not os.path.exists(path):
            os.chdir(cur_dir)
            return json.dumps({
                'error': f'Path not found: {path}',
                'path': path,
            }, indent=2)

        if os.path.isdir(path):
            items = os.listdir(path)
            items.sort()
            result = {
                'path': path,
                'type': 'directory',
                'items': items
            }
            os.chdir(cur_dir)
            return json.dumps(result, indent=2)

        elif os.path.isfile(path):
            stat = os.stat(path)
            result = {
                'path': path,
                'type': 'file',
                'size': stat.st_size,
                'exists': True
            }
            os.chdir(cur_dir)
            return json.dumps(result, indent=2)

        os.chdir(cur_dir)
        return json.dumps({
            'error': f'Unknown path type',
            'path': path,
        }, indent=2)