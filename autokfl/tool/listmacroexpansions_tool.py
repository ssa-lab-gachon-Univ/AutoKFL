import os
import json
from pydantic import BaseModel, Field
from typing import Optional
from langchain_core.tools import BaseTool
from langchain_core.tools.base import ArgsSchema

try:
    import clang.cindex as ci
    from clang.cindex import TokenKind
    CLANG_AVAILABLE = True
except ImportError:
    CLANG_AVAILABLE = False


class ListMacroExpansionsToolInput(BaseModel):
    path: str = Field(description='Path to the file relative to the kernel source root (e.g. fs/btrfs/qgroup.c or include/linux/xyz.h)')
    reason: str = Field(description='The reason why you need to list the macros in the file')

class ListMacroExpansionsTool(BaseTool):
    name: str = "list_macros"
    description: str = '''List all #define macro definitions in a C source or header file.
This tool parses the given file using libclang and returns the names and line ranges 
(start_line, end_line) of every #define macro.

IMPORTANT: You SHOULD use this tool BEFORE calling get_macro_expansion when analyzing a source file.
Listing macros first helps you discover available macro names and their locations, reducing 
errors from guessing or misspelling names and enabling more efficient code collection.

Use this tool when you need to:
- Discover which macros are defined in a file
- Find the correct macro name and line range before fetching its expansion
- Get an overview of the file structure before diving into specific macros
- Avoid unnecessary get_macro_expansion calls with wrong or non-existent macro names

The tool returns the file path and a list of {name, start_line, end_line} for each macro.
Multi-line macros (ending with \\) are reported with the full line range.

Important: In this environment, the current working directory is workdir. Kernel source code
lives under workdir/crash-* directories (each crash-* is the kernel tree for the commit where
a crash occurred). Do not use workdir/linux. When calling this tool, use file paths under
workdir/crash-* (e.g. workdir/crash-<id>/fs/btrfs/qgroup.h).'''
    args_schema: Optional[ArgsSchema] = ListMacroExpansionsToolInput

    def __init__(self):
        super().__init__()

    def _run(self, path: str, reason: str):
        print(f'[Tool] ListMacroExpansionsTool: {path}, {reason}')

        cur_dir = os.getcwd()
        fn = os.listdir('.')
        crash_dirs = [f for f in fn if f.startswith('crash-')]
        if not crash_dirs:
            return json.dumps({
                'error': 'No crash-* directory found',
                'path': path,
            }, indent=2)
        dir_kernel = crash_dirs[0]
        os.chdir(dir_kernel)

        if not os.path.exists(path):
            os.chdir(cur_dir)
            return json.dumps({
                'error': f'Path not found: {path}',
                'path': path,
            }, indent=2)

        macros = []
        try:
            index = ci.Index.create()
            tu = index.parse(path, options=ci.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD)
            tokens = list(tu.get_tokens(extent=tu.cursor.extent))
            req_abspath = os.path.abspath(path)

            for i in range(2, len(tokens)):
                t_hash, t_define, t_name = tokens[i - 2], tokens[i - 1], tokens[i]
                if not (t_hash.kind == TokenKind.PUNCTUATION and t_hash.spelling == '#' and
                        t_define.kind == TokenKind.IDENTIFIER and t_define.spelling == 'define' and
                        t_name.kind == TokenKind.IDENTIFIER):
                    continue
                loc = t_hash.location
                if loc.file is None or os.path.abspath(loc.file.name) != req_abspath:
                    continue

                start_line = loc.line
                end_line = self._get_macro_end_line(path, start_line)
                name = t_name.spelling
                macros.append({
                    'name': name,
                    'start_line': start_line,
                    'end_line': end_line,
                })
        except Exception as e:
            os.chdir(cur_dir)
            return json.dumps({
                'error': f'Failed to parse file: {e}',
                'path': path,
            }, indent=2)

        os.chdir(cur_dir)
        result = {
            'path': path,
            'macros': macros,
        }
        return json.dumps(result, indent=2)

    def _get_macro_end_line(self, file_path: str, start_line: int) -> int:
        """Multi-line macros end with \\; returns the last line of the macro."""
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        line_idx = start_line - 1
        while line_idx < len(lines) and lines[line_idx].rstrip().endswith('\\'):
            line_idx += 1
        return line_idx + 1