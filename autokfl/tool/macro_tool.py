"""
Playground: cscope-based tools.
- MacroToolCscope: Search macros via cscope, return source with line numbers.
"""

import json
import os
import re
import subprocess
from typing import Optional

from pydantic import BaseModel, Field
from langchain_core.tools import BaseTool
from langchain_core.tools.base import ArgsSchema

try:
    import clang.cindex as ci
    from clang.cindex import TokenKind
    CLANG_AVAILABLE = True
except ImportError:
    CLANG_AVAILABLE = False


class MacroToolInput(BaseModel):
    path: str = Field(
        description='Path to the file relative to the kernel source root (e.g. include/linux/gfp_types.h)'
    )
    reason: str = Field(description='The reason why you need to get the macro expansion')
    macro_names: list[str] = Field(
        description='List of macro names to find (e.g. GFP_KERNEL). Required.'
    )


def _find_macro_end_line(file_path: str, start_line: int) -> int:
    """Multi-line macros end with \\. Returns 1-based end line."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except OSError:
        return start_line
    if start_line < 1 or start_line > len(lines):
        return start_line
    line_idx = start_line - 1
    while line_idx < len(lines) and lines[line_idx].rstrip().endswith('\\'):
        line_idx += 1
    return line_idx + 1


def _find_macro_extents_libclang(
    path_for_parse: str, dir_kernel: str, macro_names: list[str]
) -> dict[str, int]:
    """
    Use libclang tokens to find #define macro start lines in the file.
    Returns dict mapping macro name -> start_line (1-based). End line is always
    computed by _find_macro_end_line (backslash continuation). Only includes names in macro_names.
    """
    if not CLANG_AVAILABLE:
        return {}
    result = {}
    try:
        old_cwd = os.getcwd()
        os.chdir(dir_kernel)
        try:
            index = ci.Index.create()
            tu = index.parse(
                path_for_parse,
                options=ci.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD,
            )
            tokens = list(tu.get_tokens(extent=tu.cursor.extent))
            req_abspath = os.path.abspath(path_for_parse)
            names_set = set(macro_names)
            for i in range(2, len(tokens)):
                t_hash, t_define, t_name = tokens[i - 2], tokens[i - 1], tokens[i]
                if not (
                    t_hash.kind == TokenKind.PUNCTUATION
                    and t_hash.spelling == '#'
                    and t_define.kind == TokenKind.IDENTIFIER
                    and t_define.spelling == 'define'
                    and t_name.kind == TokenKind.IDENTIFIER
                ):
                    continue
                loc = t_hash.location
                if loc.file is None or os.path.abspath(loc.file.name) != req_abspath:
                    continue
                name = t_name.spelling
                if name not in names_set:
                    continue
                result[name] = loc.line
        finally:
            os.chdir(old_cwd)
    except Exception:
        pass
    return result


def _find_macros_by_cscope(
    path: str,
    macro_names: list[str],
    dir_kernel: str,
) -> tuple[list[dict], list[dict]]:
    """Use cscope to find #define macros, then libclang (or cscope line) for start line.
    Returns (found_list, not_found_list).
    not_found_list: list of {"name": str, "reason": "not_found_by_cscope"|"defined_in_other_file", "path"?: str}.
    """
    cscope_path = os.path.join(dir_kernel, 'cscope.out')
    if not os.path.exists(cscope_path):
        return [], [{"name": n, "reason": "not_found_by_cscope"} for n in macro_names]

    target_path = path
    if os.path.sep in path and any(p.startswith('crash-') for p in path.split(os.path.sep)):
        parts = path.split(os.path.sep)
        for idx, p in enumerate(parts):
            if p.startswith('crash-') and idx + 1 < len(parts):
                target_path = os.path.sep.join(parts[idx + 1:])
                break

    # Try libclang first for accurate macro start lines
    start_line_by_name = _find_macro_extents_libclang(target_path, dir_kernel, macro_names)

    macros = []
    not_found: list[dict] = []

    for name in macro_names:
        found_any = False
        found_in_other_file: str | None = None
        for cscope_field in ['-1', '-0']:
            try:
                result = subprocess.run(
                    ['cscope', '-d', '-L', cscope_field, name],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    cwd=dir_kernel,
                )
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                continue

            if result.returncode != 0 or not result.stdout.strip():
                continue

            for line in result.stdout.strip().split('\n'):
                if not line.strip():
                    continue
                parts = line.split(None, 3)
                if len(parts) < 3:
                    continue
                file_path, found_name, line_num_str = parts[0], parts[1], parts[2]
                if found_name != name:
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

                # Prefer libclang start line; fall back to cscope line_num
                start_line = start_line_by_name.get(name, line_num)

                first_line = ''
                try:
                    with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                        file_lines = f.readlines()
                    if start_line >= 1 and start_line <= len(file_lines):
                        first_line = file_lines[start_line - 1]
                except OSError:
                    pass

                if not re.search(r'#\s*define\s+' + re.escape(name) + r'\b', first_line):
                    continue

                end_line = _find_macro_end_line(full_path, start_line)

                try:
                    with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                        file_lines = f.readlines()
                    macro_lines = file_lines[start_line - 1:end_line]
                    code_snippet = ''.join(
                        f"{start_line + i}:{line}" for i, line in enumerate(macro_lines)
                    )
                except OSError:
                    code_snippet = ''

                macros.append({
                    'name': name,
                    'start_line': start_line,
                    'end_line': end_line,
                    'code_snippet': code_snippet,
                })
                found_any = True
                break

            if found_any:
                break

        if not found_any:
            if found_in_other_file:
                not_found.append({
                    "name": name,
                    "reason": "defined_in_other_file",
                    "path": found_in_other_file,
                })
            else:
                not_found.append({"name": name, "reason": "not_found_by_cscope"})

    return macros, not_found


class MacroTool(BaseTool):
    name: str = "get_macro_expansion"
    description: str = '''Get #define macro definitions from a C source/header file using cscope.
Returns {name, start_line, end_line, code_snippet} for each found macro; code_snippet is the full macro definition with line numbers (e.g. "372:#define GFP_KERNEL ...").
Multi-line macros (ending with \\) are fully included.
Uses libclang when available for accurate start line; end line from backslash continuation.
You MUST provide macro_names (required). Found macros are in "macros"; any not found are in "errors.not_found" with "errors.message" (reason: defined in other file vs not found by cscope).

Important: In this environment, the current working directory is workdir. Kernel source code
lives under workdir/crash-* directories (each crash-* is the kernel tree for the commit where
a crash occurred). Do not use workdir/linux. When calling this tool, use file paths under
workdir/crash-* (e.g. workdir/crash-<id>/fs/btrfs/qgroup.h).'''
    args_schema: Optional[ArgsSchema] = MacroToolInput

    def __init__(self):
        super().__init__()

    def _run(self, path: str, reason: str, macro_names: list[str]):
        print(f'[Tool] MacroTool: {path}, macro_names: {macro_names}, {reason}')

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

        macros, not_found = _find_macros_by_cscope(path, macro_names, abs_dir)

        out = {
            'source_type': 'macro',
            'path': path,
            'macros': macros,
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

