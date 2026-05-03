"""
Playground: cscope-based tools.
- DatastructToolCscope: Search struct, union, enum via cscope, return source with line numbers.
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
    from clang.cindex import CursorKind
    CLANG_AVAILABLE = True
except ImportError:
    CLANG_AVAILABLE = False


class DatastructToolInput(BaseModel):
    path: str = Field(
        description='Path to the file relative to the kernel source root (e.g. fs/btrfs/qgroup.c or include/linux/xyz.h)'
    )
    reason: str = Field(description='The reason why you need to get the data structures')
    struct_names: list[str] = Field(
        description='List of struct/union/enum names to find (tag names, e.g. btrfs_qgroup). Required.'
    )


def _find_end_line_datastruct(file_path: str, start_line: int) -> Optional[int]:
    """Find struct/union/enum end line by bracket matching. Includes trailing ; if present. Returns 1-based."""
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
    i = start_line - 1

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
                    break
            if c == '{':
                depth += 1
            elif c == '}':
                depth -= 1
                if depth == 0:
                    end_line_0based = i
                    if end_line_0based + 1 < len(lines):
                        next_line = lines[end_line_0based + 1].strip()
                        if next_line == ';' or next_line.startswith(';'):
                            return end_line_0based + 2
                    return i + 1
            j += 1
        i += 1

    return None


def _infer_kind(file_path: str, start_line: int, name: str) -> str:
    """Infer struct/union/enum from the definition line."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except OSError:
        return 'struct'
    idx = start_line - 1
    for offset in range(min(3, len(lines) - idx)):
        line = lines[idx + offset]
        if re.search(rf'\bstruct\s+{re.escape(name)}\b', line):
            return 'struct'
        if re.search(rf'\bunion\s+{re.escape(name)}\b', line):
            return 'union'
        if re.search(rf'\benum\s+{re.escape(name)}\b', line):
            return 'enum'
    return 'struct'


def _collect_included_paths(dir_kernel: str, target_path: str, max_includes: int = 50) -> set[str]:
    """Collect file paths that are #included by target_path. Returns set of paths relative to dir_kernel (normpath)."""
    full_path = os.path.join(dir_kernel, target_path)
    if not os.path.isfile(full_path):
        return set()
    allowed = set()
    try:
        with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except OSError:
        return set()
    # Skip lines that are inside block comments (simple: only consider lines that are just #include)
    include_re = re.compile(r'#\s*include\s*(["\'])([^"\']+)\1|#\s*include\s*<([^>]+)>')
    dir_source = os.path.dirname(target_path) or '.'
    count = 0
    for m in include_re.finditer(content):
        if count >= max_includes:
            break
        if m.group(2):
            # "local.h"
            inc = m.group(2).strip()
            resolved = os.path.normpath(os.path.join(dir_source, inc))
        else:
            # <linux/foo.h>
            inc = m.group(3).strip()
            resolved = None
            for prefix in ('include/', 'include/uapi/'):
                candidate = os.path.normpath(prefix + inc)
                if os.path.isfile(os.path.join(dir_kernel, candidate)):
                    resolved = candidate
                    break
            if resolved is None:
                resolved = os.path.normpath('include/' + inc)
        if resolved and os.path.isfile(os.path.join(dir_kernel, resolved)):
            allowed.add(resolved)
            count += 1
    return allowed


def _find_datastruct_extents_libclang(
    full_path: str, path_for_parse: str, dir_kernel: str, struct_names: list[str]
) -> dict[str, tuple[int, int, str]]:
    """
    Use libclang to get (start_line, end_line, kind) for each struct/union/enum definition.
    Returns dict mapping name -> (start_line, end_line, kind). Only includes names in struct_names that were found.
    """
    if not CLANG_AVAILABLE:
        return {}
    result = {}
    kind_map = {
        CursorKind.STRUCT_DECL: 'struct',
        CursorKind.UNION_DECL: 'union',
        CursorKind.ENUM_DECL: 'enum',
    }
    try:
        old_cwd = os.getcwd()
        os.chdir(dir_kernel)
        try:
            index = ci.Index.create()
            args = ['-I', '.', '-I', 'include', '-D__KERNEL__', '-Wno-everything']
            tu = index.parse(path_for_parse, args=args)
            names_set = set(struct_names)
            req_abspath = os.path.abspath(path_for_parse)
            for cursor in tu.cursor.walk_preorder():
                if cursor.kind not in (CursorKind.STRUCT_DECL, CursorKind.UNION_DECL, CursorKind.ENUM_DECL):
                    continue
                has_fields = any(
                    c.kind in (CursorKind.FIELD_DECL, CursorKind.ENUM_CONSTANT_DECL)
                    for c in cursor.get_children()
                )
                if not has_fields:
                    continue
                loc = cursor.extent.start
                if loc.file is None:
                    continue
                if os.path.abspath(loc.file.name) != req_abspath:
                    continue
                name = cursor.spelling
                if not name or name not in names_set:
                    continue
                extent = cursor.extent
                result[name] = (extent.start.line, extent.end.line, kind_map[cursor.kind])
        finally:
            os.chdir(old_cwd)
    except Exception:
        pass
    return result


def _search_names_in_allowed_paths(
    names: list[str],
    allowed_paths: set[str],
    dir_kernel: str,
    extents_by_name: dict[str, tuple[int, int, str]],
    target_normpath: str,
) -> tuple[list[dict], list[str]]:
    """Run cscope for each name; accept only results in allowed_paths. Use extents_by_name when result file is target_normpath. Returns (datastructs, not_found)."""
    datastructs = []
    not_found = []

    for name in names:
        found_any = False
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
                if norm_file not in allowed_paths:
                    continue

                full_path = os.path.join(dir_kernel, file_path)
                if not os.path.exists(full_path):
                    continue

                # Prefer libclang extent when we have it for this file; else bracket matching
                if norm_file == target_normpath and name in extents_by_name:
                    start_line, end_line, kind = extents_by_name[name]
                else:
                    start_line = line_num
                    end_line = _find_end_line_datastruct(full_path, line_num)
                    if end_line is None:
                        end_line = line_num
                    kind = _infer_kind(full_path, line_num, name)

                try:
                    with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                        file_lines = f.readlines()
                    struct_lines = file_lines[start_line - 1:end_line]
                    code_snippet = ''.join(
                        f"{start_line + i}:{line}" for i, line in enumerate(struct_lines)
                    )
                except OSError:
                    code_snippet = ''

                datastructs.append({
                    'name': name,
                    'kind': kind,
                    'start_line': start_line,
                    'end_line': end_line,
                    'code_snippet': code_snippet,
                    'file_path': norm_file,
                })
                found_any = True
                break

            if found_any:
                break

        if not found_any:
            not_found.append(name)

    return datastructs, not_found


def _find_datastructs_by_cscope(
    path: str,
    struct_names: list[str],
    dir_kernel: str,
) -> tuple[list[dict], list[str]]:
    """Use cscope to find struct/union/enum. First search only in path; if not found, expand to #included headers. Returns (found_list, not_found_names)."""
    cscope_path = os.path.join(dir_kernel, 'cscope.out')
    if not os.path.exists(cscope_path):
        return [], list(struct_names)

    target_path = path
    if os.path.sep in path and any(p.startswith('crash-') for p in path.split(os.path.sep)):
        parts = path.split(os.path.sep)
        for idx, p in enumerate(parts):
            if p.startswith('crash-') and idx + 1 < len(parts):
                target_path = os.path.sep.join(parts[idx + 1:])
                break

    norm_target = os.path.normpath(target_path)
    allowed_1 = {norm_target}

    # Libclang extents only for the primary file
    extents_by_name = _find_datastruct_extents_libclang(
        os.path.join(dir_kernel, target_path), target_path, dir_kernel, struct_names
    )

    datastructs, not_found = _search_names_in_allowed_paths(
        struct_names, allowed_1, dir_kernel, extents_by_name, norm_target
    )

    # If some names were not found, expand to headers #included by the source file
    if not_found and os.path.isfile(os.path.join(dir_kernel, target_path)):
        included = _collect_included_paths(dir_kernel, target_path)
        allowed_2 = allowed_1 | included
        more_datastructs, still_not_found = _search_names_in_allowed_paths(
            not_found, allowed_2, dir_kernel, {}, norm_target
        )
        datastructs.extend(more_datastructs)
        not_found = still_not_found

    return datastructs, not_found


class DatastructTool(BaseTool):
    name: str = "get_datastruct"
    description: str = '''Get struct, union, or enum definitions using cscope.
Search order: (1) the file at the given path; (2) if not found there, headers #included by that file.
Response: request_path (path you asked for), path (actual file where definition was found), datastructs (each with name, kind, start_line, end_line, code_snippet, file_path).
You MUST provide struct_names (required). Only if cscope finds nothing in the path or its includes is an error returned.

Important: In this environment, the current working directory is workdir. Kernel source code
lives under workdir/crash-* directories. Use file paths under workdir/crash-* (e.g. workdir/crash-<id>/fs/btrfs/qgroup.c).'''
    args_schema: Optional[ArgsSchema] = DatastructToolInput

    def __init__(self):
        super().__init__()

    def _run(self, path: str, reason: str, struct_names: list[str]):
        print(f'[Tool] DatastructTool: {path}, struct_names: {struct_names}, {reason}')

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

        datastructs, not_found = _find_datastructs_by_cscope(path, struct_names, abs_dir)

        if not datastructs:
            return json.dumps({
                'error': 'No datastruct found',
                'request_path': path,
                'not_found': not_found,
            }, indent=2)

        # path: actual file where definition was found (first datastruct)
        resolved_path = datastructs[0].get('file_path', path)
        return json.dumps({
            'source_type': 'datastruct',
            'request_path': path,
            'path': resolved_path,
            'datastructs': datastructs,
        }, indent=2)

