import os
import json
import subprocess
from typing import Optional, Dict, Set, Tuple
from pydantic import BaseModel, Field
from langchain_core.tools import BaseTool
from langchain_core.tools.base import ArgsSchema

try:
    import clang.cindex as ci
    from clang.cindex import CursorKind
    CLANG_AVAILABLE = True
except ImportError:
    CLANG_AVAILABLE = False

class CallGraphToolInput(BaseModel):
    function_names: list[str] = Field(description='List of function names to build call graph for. Typically suspicious functions from crash analysis.')
    max_depth: int = Field(default=2, description='Maximum depth to traverse call relationships. Default is 2 (direct calls and their direct calls).')
    reason: str = Field(description='The reason why you need to build the call graph')

class CallGraphTool(BaseTool):
    name: str = "get_call_graph"
    description: str = '''Build a call graph showing function call relationships for a given set of functions.
This tool uses libclang to parse C code and identify which functions call which other functions,
creating a graph structure that shows caller-callee relationships.

Use this tool when you need to:
- Understand the call flow between functions in crash-related code
- Trace how data flows through function calls
- Identify all functions that call or are called by suspicious functions
- Build a comprehensive view of function relationships for analysis

The tool returns a call graph with nodes (functions) and edges (caller-callee relationships).
Each node includes the function name, file path, and line number. Each edge shows which function
calls which other function.

Important: In this environment, the current working directory is workdir. Kernel source code
lives under workdir/crash-* directories (each crash-* is the kernel tree for the commit where
a crash occurred). Do not use workdir/linux. When calling this tool, use file paths under
workdir/crash-* (e.g. workdir/crash-<id>/fs/btrfs/qgroup.c).'''
    args_schema: Optional[ArgsSchema] = CallGraphToolInput

    def __init__(self):
        super().__init__()
        self._location_cache: Dict[str, Optional[Tuple[str, int]]] = {}
        self._callees_cache: Dict[Tuple[str, str], Set[str]] = {}
        self._file_parse_cache: Dict[str, ci.TranslationUnit] = {}
        self._file_functions_cache: Dict[str, Dict[str, Tuple[int, ci.Cursor]]] = {}

    def _run(self, function_names: list[str], reason: str, max_depth: int = 2):
        print(f'[Tool] CallGraphTool: {function_names} max_depth: {max_depth}, {reason}')
        cur_dir = os.getcwd()
        fn = os.listdir('.')
        crash_dirs = [f for f in fn if f.startswith('crash-')]
        if not crash_dirs:
            error_result = {
                'error': 'No crash-* directory found',
                'function_names': function_names
            }
            return json.dumps(error_result, indent=2)
        
        dir_kernel = crash_dirs[0]
        os.chdir(dir_kernel)

        nodes = {}
        edges = []
        visited = set()
        edge_set = set()
        
        def find_function_location_cscope(func_name):
            if func_name in self._location_cache:
                cached = self._location_cache[func_name]
                return cached if cached else None
            
            try:
                cscope_path = 'cscope.out'
                if not os.path.exists(cscope_path):
                    return None
                
                result = subprocess.run(
                    ['cscope', '-d', '-L1', func_name],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    cwd=os.getcwd()
                )
                
                if result.returncode == 0 and result.stdout:
                    lines = result.stdout.strip().split('\n')
                    candidates = []
                    for line in lines:
                        if not line.strip():
                            continue
                        parts = line.split(None, 3)
                        if len(parts) >= 3:
                            file_path = parts[0]
                            found_func_name = parts[1]
                            try:
                                line_num = int(parts[2])
                                
                                if found_func_name == func_name and os.path.exists(file_path) and line_num > 0:
                                    priority = 100
                                    
                                    if file_path.endswith('.c'):
                                        priority = 10
                                        if 'tools/' in file_path:
                                            priority += 50
                                        elif 'drivers/' in file_path and ('test' in file_path.lower() or 'selftest' in file_path.lower()):
                                            priority += 30
                                    elif file_path.endswith('.h'):
                                        priority = 0
                                        if file_path.startswith('include/linux/'):
                                            priority = -1
                                        elif file_path.startswith('include/uapi/linux/'):
                                            priority = 0
                                        elif file_path.startswith('tools/include/'):
                                            priority = 10
                                        elif 'include/' in file_path:
                                            priority = 1
                                        else:
                                            priority = 5
                                    else:
                                        priority = 20
                                    
                                    is_definition = False
                                    try:
                                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                            file_lines = f.readlines()
                                            if line_num <= len(file_lines):
                                                line_content = file_lines[line_num - 1]
                                                if func_name in line_content:
                                                    if '{' in line_content:
                                                        is_definition = True
                                                        priority -= 2
                                                    elif line_num < len(file_lines) and '{' in file_lines[line_num]:
                                                        is_definition = True
                                                        priority -= 2
                                    except Exception:
                                        continue
                                    
                                    candidates.append((priority, file_path, line_num, is_definition))
                            except (ValueError, IndexError):
                                continue
                    
                    candidates.sort(key=lambda x: x[0])
                    
                    for priority, file_path, line_num, is_definition in candidates:
                        location = (file_path, line_num)
                        self._location_cache[func_name] = location
                        return location
                    
                    if candidates:
                        priority, file_path, line_num, is_definition = candidates[0]
                        location = (file_path, line_num)
                        self._location_cache[func_name] = location
                        return location
            except Exception:
                pass
            
            self._location_cache[func_name] = None
            return None
        
        def parse_file_once(file_path: str) -> Optional[ci.TranslationUnit]:
            if file_path in self._file_parse_cache:
                return self._file_parse_cache[file_path]
            
            if not os.path.exists(file_path):
                return None
            
            try:
                index = ci.Index.create()
                args = ['-I', '.', '-I', 'include', '-D__KERNEL__', '-Wno-everything']
                tu = index.parse(file_path, args=args)
                if tu:
                    self._file_parse_cache[file_path] = tu
                    self._file_functions_cache[file_path] = {}
                    for cursor in tu.cursor.walk_preorder():
                        if (cursor.kind == CursorKind.FUNCTION_DECL and 
                            cursor.is_definition()):
                            func_name = cursor.spelling
                            if func_name:
                                self._file_functions_cache[file_path][func_name] = (
                                    cursor.location.line, cursor
                                )
                return tu
            except Exception:
                return None
        
        def find_function_location_libclang(func_name):
            if func_name in self._location_cache:
                cached = self._location_cache[func_name]
                return cached if cached else None
            
            for file_path, funcs in self._file_functions_cache.items():
                if func_name in funcs:
                    line_num, _ = funcs[func_name]
                    location = (file_path, line_num)
                    self._location_cache[func_name] = location
                    return location
            
            search_dirs = ['fs', 'kernel', 'mm', 'drivers', 'net']
            search_paths = []
            
            for search_dir in search_dirs:
                if os.path.exists(search_dir):
                    for root, dirs, files in os.walk(search_dir):
                        depth = root.replace(os.sep, '/').count('/')
                        if depth > 5:
                            dirs[:] = []
                            continue
                        dirs[:] = [d for d in dirs if not d.startswith('.')]
                        for file in files:
                            if file.endswith('.c'):
                                search_paths.append(os.path.join(root, file))
                                if len(search_paths) >= 500:
                                    break
                        if len(search_paths) >= 500:
                            break
                    if len(search_paths) >= 500:
                        break
            
            for file_path in search_paths:
                tu = parse_file_once(file_path)
                if tu and file_path in self._file_functions_cache:
                    if func_name in self._file_functions_cache[file_path]:
                        line_num, _ = self._file_functions_cache[file_path][func_name]
                        location = (file_path, line_num)
                        self._location_cache[func_name] = location
                        return location
            
            self._location_cache[func_name] = None
            return None
        
        def find_function_location(func_name):
            location = find_function_location_cscope(func_name)
            if location:
                return location
            return find_function_location_libclang(func_name)
        
        def extract_callees(file_path, func_name):
            cache_key = (file_path, func_name)
            if cache_key in self._callees_cache:
                return self._callees_cache[cache_key]
            
            callees = set()
            if not CLANG_AVAILABLE or not os.path.exists(file_path):
                return callees
            
            tu = parse_file_once(file_path)
            if tu is None:
                return callees
            
            func_cursor = None
            if file_path in self._file_functions_cache:
                if func_name in self._file_functions_cache[file_path]:
                    _, func_cursor = self._file_functions_cache[file_path][func_name]
            
            if func_cursor is None:
                for cursor in tu.cursor.walk_preorder():
                    if (cursor.kind == CursorKind.FUNCTION_DECL and 
                        cursor.spelling == func_name and 
                        cursor.is_definition()):
                        func_cursor = cursor
                        break
            
            if func_cursor is None:
                return callees
            
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
                try:
                    from clang.cindex import TokenKind
                    tokens = list(cursor.get_tokens())
                    if tokens:
                        for token in tokens:
                            if token.kind == TokenKind.IDENTIFIER:
                                return token.spelling
                except:
                    pass
                return None
            
            try:
                from clang.cindex import TokenKind
                all_tokens = list(func_cursor.get_tokens())
                for i, token in enumerate(all_tokens):
                    if (token.kind == TokenKind.IDENTIFIER and 
                        i + 1 < len(all_tokens) and 
                        all_tokens[i + 1].kind == TokenKind.PUNCTUATION and 
                        all_tokens[i + 1].spelling == '('):
                        if token.location.line != func_cursor.location.line:
                            func_name_token = token.spelling
                            if func_name_token and func_name_token not in ['', 'NULL']:
                                callees.add(func_name_token)
            except Exception:
                pass
            
            def visit_cursor(cursor):
                if cursor.kind == CursorKind.CALL_EXPR:
                    callee_cursor = next(cursor.get_children(), None)
                    if callee_cursor:
                        callee_name = get_function_name(callee_cursor)
                        if callee_name and callee_name not in ['', 'NULL']:
                            callees.add(callee_name)
                
                for child in cursor.get_children():
                    visit_cursor(child)
            
            visit_cursor(func_cursor)
            
            self._callees_cache[cache_key] = callees
            return callees
        
        def build_graph_recursive(func_name, depth):
            if depth > max_depth:
                return
            
            key = (func_name, depth)
            if key in visited:
                return
            visited.add(key)
            
            location = find_function_location(func_name)
            if location is None:
                if func_name not in nodes:
                    nodes[func_name] = {
                        'function_name': func_name,
                        'file_path': 'unknown',
                        'line_number': 0
                    }
                return
            
            file_path, line_num = location
            
            if func_name not in nodes:
                nodes[func_name] = {
                    'function_name': func_name,
                    'file_path': file_path,
                    'line_number': line_num
                }
            
            callees = extract_callees(file_path, func_name)
            
            for callee in callees:
                if callee and callee != func_name:
                    edge = (func_name, callee)
                    if edge not in edge_set:
                        edge_set.add(edge)
                        edges.append(edge)
                    build_graph_recursive(callee, depth + 1)
        
        for func_name in function_names:
            if func_name:
                build_graph_recursive(func_name, 0)
        
        os.chdir(cur_dir)
        
        result = {
            'nodes': [nodes[name] for name in sorted(nodes.keys())],
            'edges': [{'caller': caller, 'callee': callee} for caller, callee in edges],
            'summary': f'Call graph with {len(nodes)} nodes and {len(edges)} edges'
        }
        
        return json.dumps(result, indent=2)