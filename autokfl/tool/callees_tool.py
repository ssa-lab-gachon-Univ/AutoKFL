import os
import json
from typing import Optional
from langchain_core.tools import BaseTool
from langchain_core.tools.base import ArgsSchema
from pydantic import BaseModel, Field

try:
    import clang.cindex as ci
    from clang.cindex import CursorKind, TokenKind
    CLANG_AVAILABLE = True
except ImportError:
    CLANG_AVAILABLE = False

class CalleesToolInput(BaseModel):
    file_path: str = Field(description='Path to the file relative to the kernel source root (e.g. fs/btrfs/qgroup.c)')
    function_name: str = Field(description='The name of the function to get the callees from')
    reason: str = Field(description='The reason why you need to get the callees')

class CalleesTool(BaseTool):
    name: str = 'get_callees'
    description: str = '''Find all functions (callees) called by a given function within its body.
This tool uses libclang to parse the source file, locate the specified function definition,
and extract every function call site. It returns the unique list of function names that
the target function invokes.

Use this tool when you need to:
- Discover which functions a specific function calls
- Trace call graphs and analyze data flow for crash investigation
- Understand the dependency chain of a function before analyzing it
- Build a call graph from a function downward

The tool returns the file path, function name, and a list of callee function names
(ordered by first occurrence in the source).

Important: In this environment, the current working directory is workdir. Kernel source code
lives under workdir/crash-* directories (each crash-* is the kernel tree for the commit where
a crash occurred). Do not use workdir/linux. When calling this tool, use file paths under
workdir/crash-* (e.g. workdir/crash-<id>/fs/btrfs/qgroup.c).'''
    args_schema: Optional[ArgsSchema] = CalleesToolInput

    def __init__(self):
        super().__init__()

    def _run(self, file_path: str, function_name: str, reason: str):
        print(f'[Tool] CalleesTool: {file_path}, {function_name}, {reason}')

        cur_dir = os.getcwd()
        fn = os.listdir('.')
        crash_dirs = [f for f in fn if f.startswith('crash-')]
        if not crash_dirs:
            error_result = {
                'error': 'No crash-* directory found',
                'file_path': file_path,
                'function_name': function_name
            }
            return json.dumps(error_result, indent=2)
        dir_kernel = crash_dirs[0]
        os.chdir(dir_kernel)
        
        index = ci.Index.create()
        tu = index.parse(file_path, options=ci.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD)


        function_cursor = None
        def find_function(cursor):
            nonlocal function_cursor
            if cursor.kind == CursorKind.FUNCTION_DECL and cursor.spelling == function_name:
                function_cursor = cursor
                return
            
            for child in cursor.get_children():
                find_function(child)


        os.chdir(cur_dir)
        find_function(tu.cursor)
        if function_cursor:
            callees = self._find_callees(function_cursor)
            return {
                'file_path': file_path,
                'function_name': function_name,
                'callees': callees
            }
        else:
            return {
                'error': 'Function not found',
                'file_path': file_path,
                'function_name': function_name
            }

    def _find_callees(self, function_cursor) -> list[str]:
        callees_with_pos = []

        def get_function_name(cursor):
            if cursor.kind == CursorKind.DECL_REF_EXPR:
                return cursor.spelling
            elif cursor.kind == CursorKind.MEMBER_REF_EXPR:
                return cursor.spelling
            elif cursor.kind == CursorKind.UNEXPOSED_EXPR:
                for child in cursor.get_children():
                    name = get_function_name(child)
                    if name:
                        return name
            tokens = list(cursor.get_tokens())
            if tokens:
                for token in tokens:
                    if token.kind == TokenKind.IDENTIFIER:
                        return token.spelling
            return None

        function_extent = function_cursor.extent
        all_tokens = list(function_cursor.get_tokens())
        
        for i, token in enumerate(all_tokens):
            if (token.kind == TokenKind.IDENTIFIER and 
                i + 1 < len(all_tokens) and 
                all_tokens[i + 1].kind == TokenKind.PUNCTUATION and 
                all_tokens[i + 1].spelling == '('):
                if token.location.line == function_cursor.location.line:
                    continue
                callees_with_pos.append((token.location.line, token.location.column, token.spelling))

        def visit_cursor(cursor):
            if cursor.kind == CursorKind.CALL_EXPR:
                callee_cursor = next(cursor.get_children(), None)
                if callee_cursor:
                    callee_name = get_function_name(callee_cursor)
                    if callee_name:
                        loc = cursor.location
                        callees_with_pos.append((loc.line, loc.column, callee_name))
            
            for child in cursor.get_children():
                visit_cursor(child)
        
        visit_cursor(function_cursor)
        
        callees_with_pos.sort(key=lambda x: (x[0], x[1]))
        
        seen = set()
        result = []
        for _, _, name in callees_with_pos:
            if name not in seen:
                seen.add(name)
                result.append(name)
        
        return result