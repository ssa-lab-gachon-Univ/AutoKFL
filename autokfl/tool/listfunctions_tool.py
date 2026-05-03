import os
import json
from pydantic import BaseModel, Field
from typing import Optional
from langchain_core.tools import BaseTool
from langchain_core.tools.base import ArgsSchema

try:
    import clang.cindex as ci
    from clang.cindex import CursorKind
    CLANG_AVAILABLE = True
except ImportError:
    CLANG_AVAILABLE = False

class ListFunctionsToolInput(BaseModel):
    path: str = Field(description='Path to the file relative to the kernel source root directory (e.g. fs/btrfs/qgroup.c)')
    reason: str = Field(description='The reason why you need to list the functions in the file')
    function_names: Optional[list[str]] = Field(
        default=None,
        description='Optional. If provided, return only functions whose name is in this list (exact match). Use this for large files to avoid huge responses and token limits.'
    )

class ListFunctionsTool(BaseTool):
    name: str = "list_functions"
    description: str = '''List all function definitions in a C source file. 
This tool parses the given .c file using libclang and returns the names and line ranges 
(start_line, end_line) of every implemented function.

IMPORTANT: You SHOULD use this tool BEFORE calling get_function_definition when analyzing 
a source file. Listing functions first helps you discover available function names and 
their locations, reducing errors from guessing or misspelling function names and enabling 
more efficient code collection.

Use this tool when you need to:
- Discover which functions are defined in a C source file
- Find the correct function name and line range before fetching its code
- Get an overview of the file structure before diving into specific functions
- Avoid unnecessary get_function_definition calls with wrong or non-existent function names

The tool returns the file path and a list of {name, start_line, end_line} for each function.
When you already know which function names you need (e.g. from a request), pass function_names to return only those; this keeps responses small on large files and avoids token limits.

Important: In this environment, the current working directory is workdir. Kernel source code
lives under workdir/crash-* directories (each crash-* is the kernel tree for the commit where
a crash occurred). Do not use workdir/linux. When calling this tool, use file paths under
workdir/crash-* (e.g. workdir/crash-<id>/fs/btrfs/qgroup.c).'''
    args_schema: Optional[ArgsSchema] = ListFunctionsToolInput

    def __init__(self):
        super().__init__()

    def _run(self, path: str, reason: str, function_names: Optional[list[str]] = None):
        print(f'[Tool] ListFunctionsTool: {path}, function_names: {function_names}, {reason}')

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

        index = ci.Index.create()
        args = ['-I', '.', '-I', 'include', '-D__KERNEL__', '-Wno-everything']
        tu = index.parse(path, args=args)

        functions = []
        for cursor in tu.cursor.walk_preorder():
            if cursor.kind == CursorKind.FUNCTION_DECL and cursor.is_definition():
                extent = cursor.extent
                functions.append({
                    'name': cursor.spelling,
                    'start_line': extent.start.line,
                    'end_line': extent.end.line,
                })

        if function_names:
            names_set = set(function_names)
            functions = [f for f in functions if f['name'] in names_set]

        result = {
            'source_type': '.c file',
            'path': path,
            'functions': functions,
        }
        os.chdir(cur_dir)
        return json.dumps(result, indent=2)
