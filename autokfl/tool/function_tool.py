import json
import os
import subprocess
from typing import Optional

from pydantic import BaseModel, Field
from langchain_core.tools import BaseTool
from langchain_core.tools.base import ArgsSchema

try:
    import clang.cindex as ci
    from clang.cindex import CursorKind
    CLANG_AVAILABLE = True
except ImportError:
    CLANG_AVAILABLE = False


class FunctionToolInput(BaseModel):
    path: str = Field(
        description='Path to the file relative to the kernel source root directory (e.g. fs/btrfs/qgroup.c)'
    )
    reason: str = Field(description='The reason why you need to list the functions in the file')
    function_names: list[str] = Field(
        description='List of function names to find. Required. Returns error for functions not found by cscope.'
    )


def _find_end_line_by_bracket_matching(file_path: str, start_line: int) -> Optional[int]:
    """Find function end line by matching braces from start_line. Returns 1-based line number."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except OSError:
        return None

    if start_line < 1 or start_line > len(lines):
        return None

    depth = 0
    in_string = False
    string_char = None
    i = start_line - 1  # 0-based index

    while i < len(lines):
        line = lines[i]
        j = 0
        while j < len(line):
            c = line[j]
            if in_string:
                if c == '\\' and j + 1 < len(line):
                    j += 2
                    continue
                if c == string_char:
                    in_string = False
                j += 1
                continue
            if c in '"\'':
                in_string = True
                string_char = c
                j += 1
                continue
            if c == '/':
                if j + 1 < len(line) and line[j + 1] == '*':
                    j += 2
                    while j < len(line) - 1:
                        if line[j:j + 2] == '*/':
                            j += 2
                            break
                        j += 1
                    continue
                if j + 1 < len(line) and line[j + 1] == '/':
                    break  # rest of line is comment
            if c == '{':
                depth += 1
            elif c == '}':
                depth -= 1
                if depth == 0:
                    return i + 1  # 1-based
            j += 1
        i += 1

    return None


def _find_function_extents_libclang(full_path: str, path_for_parse: str, dir_kernel: str, function_names: list[str]) -> dict[str, tuple[int, int]]:
    """
    Use libclang to get (start_line, end_line) for each function definition.
    Returns dict mapping function_name -> (start_line, end_line). Only includes names in function_names that were found.
    """
    if not CLANG_AVAILABLE:
        return {}
    result = {}
    try:
        old_cwd = os.getcwd()
        os.chdir(dir_kernel)
        try:
            index = ci.Index.create()
            args = ['-I', '.', '-I', 'include', '-D__KERNEL__', '-Wno-everything']
            tu = index.parse(path_for_parse, args=args)
            names_set = set(function_names)
            for cursor in tu.cursor.walk_preorder():
                if cursor.kind == CursorKind.FUNCTION_DECL and cursor.is_definition():
                    if cursor.spelling in names_set:
                        extent = cursor.extent
                        result[cursor.spelling] = (extent.start.line, extent.end.line)
        finally:
            os.chdir(old_cwd)
    except Exception:
        pass
    return result


def _find_functions_by_cscope(
    path: str,
    function_names: list[str],
    dir_kernel: str,
) -> tuple[list[dict], list[dict]]:
    """
    Use cscope to find functions, then libclang (or bracket matching) to get full body extent.
    Returns (found_functions, not_found_list).
    not_found_list: list of {"name": str, "reason": "not_found_by_cscope"|"defined_in_other_file", "path"?: str}.
    """
    cscope_path = os.path.join(dir_kernel, 'cscope.out')
    if not os.path.exists(cscope_path):
        return [], [{"name": n, "reason": "not_found_by_cscope"} for n in function_names]

    target_path = path
    if os.path.sep in path and any(p.startswith('crash-') for p in path.split(os.path.sep)):
        parts = path.split(os.path.sep)
        for idx, p in enumerate(parts):
            if p.startswith('crash-') and idx + 1 < len(parts):
                target_path = os.path.sep.join(parts[idx + 1:])
                break

    # Try libclang first for accurate extents
    extents_by_name = _find_function_extents_libclang(
        os.path.join(dir_kernel, target_path), target_path, dir_kernel, function_names
    )

    functions = []
    not_found: list[dict] = []

    for func_name in function_names:
        found_in_other_file: str | None = None
        try:
            result = subprocess.run(
                ['cscope', '-d', '-L', '-1', func_name],
                capture_output=True,
                text=True,
                timeout=10,
                cwd=dir_kernel,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            not_found.append({"name": func_name, "reason": "not_found_by_cscope"})
            continue

        if result.returncode != 0 or not result.stdout.strip():
            not_found.append({"name": func_name, "reason": "not_found_by_cscope"})
            continue

        found_in_file = False
        for line in result.stdout.strip().split('\n'):
            if not line.strip():
                continue
            parts = line.split(None, 3)
            if len(parts) < 3:
                continue
            file_path, found_name, line_num_str = parts[0], parts[1], parts[2]
            if found_name != func_name:
                continue

            try:
                line_num = int(line_num_str)
            except ValueError:
                continue

            norm_file = os.path.normpath(file_path)
            norm_target = os.path.normpath(target_path)
            if norm_file != norm_target:
                if found_in_other_file is None:
                    found_in_other_file = file_path
                continue

            full_path = os.path.join(dir_kernel, file_path)
            if not os.path.exists(full_path):
                continue

            # Prefer libclang extent; fall back to bracket matching
            if func_name in extents_by_name:
                start_line, end_line = extents_by_name[func_name]
            else:
                start_line = line_num
                end_line = _find_end_line_by_bracket_matching(full_path, line_num)
                if end_line is None:
                    end_line = line_num

            code_snippet = ''
            try:
                with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                    file_lines = f.readlines()
                func_lines = file_lines[start_line - 1 : end_line]
                code_snippet = ''.join(f"{start_line + i}:{line}" for i, line in enumerate(func_lines))
            except OSError:
                pass

            functions.append({
                'name': func_name,
                'start_line': start_line,
                'end_line': end_line,
                'code_snippet': code_snippet,
            })
            found_in_file = True
            break

        if not found_in_file:
            if found_in_other_file:
                not_found.append({
                    "name": func_name,
                    "reason": "defined_in_other_file",
                    "path": found_in_other_file,
                })
            else:
                not_found.append({"name": func_name, "reason": "not_found_by_cscope"})

    return functions, not_found


class FunctionTool(BaseTool):
    name: str = "get_function_definition"
    description: str = '''List function definitions in a C source file using cscope.
Returns {name, start_line, end_line, code_snippet} for each found function; code_snippet is the full function body with line numbers (e.g. "1647:    int ret;\\n1648:    ...").
Uses libclang when available for accurate body extent; otherwise falls back to bracket matching.
You MUST provide function_names (required). Found functions are in "functions"; any not found by cscope are listed in "errors.not_found" with "errors.message" describing the cause.

Important: In this environment, the current working directory is workdir. Kernel source code
lives under workdir/crash-* directories (each crash-* is the kernel tree for the commit where
a crash occurred). Do not use workdir/linux. When calling this tool, use file paths under
workdir/crash-* (e.g. workdir/crash-<id>/fs/btrfs/qgroup.c).'''
    args_schema: Optional[ArgsSchema] = FunctionToolInput

    def __init__(self):
        super().__init__()

    def _run(self, path: str, reason: str, function_names: list[str]):
        print(f'[Tool] FunctionTool: {path}, function_names: {function_names}, {reason}')

        cur_dir = os.getcwd()
        fn = os.listdir('.')
        crash_dirs = [f for f in fn if f.startswith('crash-')]
        if not crash_dirs:
            return json.dumps({
                'error': 'No crash-* directory found',
                'path': path,
            }, indent=2)

        dir_kernel = crash_dirs[0]
        abs_dir = os.path.join(cur_dir, dir_kernel)

        functions, not_found = _find_functions_by_cscope(path, function_names, abs_dir)

        out = {
            'source_type': '.c file',
            'path': path,
            'functions': functions,
        }
        if not_found:
            parts = []
            for e in not_found:
                if e["reason"] == "defined_in_other_file":
                    parts.append(f"{e['name']} (defined in {e['path']})")
                else:
                    parts.append(f"{e['name']} (not found by cscope)")
            out['errors'] = {
                'message': '; '.join(parts),
                'not_found': not_found,
            }
        return json.dumps(out, indent=2)
