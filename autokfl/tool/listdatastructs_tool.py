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

class ListDatastructsToolInput(BaseModel):
    path: str = Field(description='Path to the file relative to the kernel source root (e.g. fs/btrfs/qgroup.c or include/linux/xyz.h)')
    reason: str = Field(description='The reason why you need to list the data structures in the file')

class ListDatastructsTool(BaseTool):
    name: str = "list_datastructs"
    description: str = '''List all data structure definitions (struct, union, enum) in a C source or header file.
This tool parses the given file using libclang and returns the names, kinds, and line ranges 
(start_line, end_line) of every defined struct, union, and enum.

IMPORTANT: You SHOULD use this tool BEFORE calling get_datastruct when analyzing a source file.
Listing data structures first helps you discover available struct/union/enum names and their
locations, reducing errors from guessing or misspelling names and enabling more efficient
code collection.

Use this tool when you need to:
- Discover which structs, unions, or enums are defined in a file
- Find the correct structure name and line range before fetching its definition
- Get an overview of the file structure before diving into specific data structures
- Avoid unnecessary get_datastruct calls with wrong or non-existent structure names

The tool returns the file path and a list of {name, kind, start_line, end_line} for each 
data structure. The kind is one of "struct", "union", or "enum".

Important: In this environment, the current working directory is workdir. Kernel source code
lives under workdir/crash-* directories (each crash-* is the kernel tree for the commit where
a crash occurred). Do not use workdir/linux. When calling this tool, use file paths under
workdir/crash-* (e.g. workdir/crash-<id>/fs/btrfs/qgroup.h).'''
    args_schema: Optional[ArgsSchema] = ListDatastructsToolInput

    def __init__(self):
        super().__init__()

    def _run(self, path: str, reason: str):
        print(f'[Tool] ListDatastructsTool: {path}, {reason}')

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

        datastructs = []
        try:
            index = ci.Index.create()
            args = ['-I', '.', '-I', 'include', '-D__KERNEL__', '-Wno-everything']
            tu = index.parse(path, args=args)
            req_abspath = os.path.abspath(path)

            for cursor in tu.cursor.walk_preorder():
                if cursor.kind not in (CursorKind.STRUCT_DECL, CursorKind.UNION_DECL, CursorKind.ENUM_DECL):
                    continue
                # Skip forward declarations (no fields)
                has_fields = any(
                    c.kind in (CursorKind.FIELD_DECL, CursorKind.ENUM_CONSTANT_DECL)
                    for c in cursor.get_children()
                )
                if not has_fields:
                    continue
                # Only from the requested file
                loc = cursor.extent.start
                if loc.file is None:
                    continue
                if os.path.abspath(loc.file.name) != req_abspath:
                    continue

                extent = cursor.extent
                kind_map = {
                    CursorKind.STRUCT_DECL: 'struct',
                    CursorKind.UNION_DECL: 'union',
                    CursorKind.ENUM_DECL: 'enum',
                }
                name = cursor.spelling or '(anonymous)'
                datastructs.append({
                    'name': name,
                    'kind': kind_map[cursor.kind],
                    'start_line': extent.start.line,
                    'end_line': extent.end.line,
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
            'datastructs': datastructs,
        }
        return json.dumps(result, indent=2)