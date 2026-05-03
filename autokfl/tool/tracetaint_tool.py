import os
import json
from typing import Optional, Set, Dict, List, Tuple
from pydantic import BaseModel, Field
from langchain_core.tools import BaseTool
from langchain_core.tools.base import ArgsSchema

try:
    import clang.cindex as ci
    from clang.cindex import CursorKind, TokenKind
    CLANG_AVAILABLE = True
except ImportError:
    CLANG_AVAILABLE = False


class TraceTaintToolInput(BaseModel):
    file_path: str = Field(
        description='Path to the file relative to the kernel source root (e.g. fs/btrfs/qgroup.c)'
    )
    function_name: Optional[str] = Field(
        default=None,
        description='Name of the function to analyze. If not provided, analyzes the entire file.'
    )
    taint_source: Optional[str] = Field(
        default=None,
        description='Variable name or parameter name that is the taint source (untrusted input). If not provided, all function parameters are considered taint sources.'
    )
    reason: str = Field(
        description='The reason why you need to trace taint propagation in this code'
    )


class TraceTaintTool(BaseTool):
    name: str = 'trace_taint'
    description: str = '''Trace taint propagation in C kernel code using static analysis.
    
Taint analysis tracks how untrusted data (taint sources) flows through code to potentially dangerous operations (taint sinks).

This tool identifies:
- Taint sources: Function parameters, specific variables (untrusted inputs)
- Taint propagation: How tainted data flows through assignments, function calls, field accesses
- Taint sinks: Dangerous operations like pointer dereferences, array accesses, buffer operations

Use this tool when you need to:
- Understand how user input or untrusted data flows to crash points
- Identify if tainted data reaches dangerous operations
- Trace data flow from source to sink
- Analyze security vulnerabilities related to untrusted input

The tool returns:
- taint_sources: List of identified taint sources (parameters, variables)
- taint_propagation: List of propagation points showing how taint flows
- taint_sinks: List of dangerous operations reached by tainted data
- propagation_paths: Complete paths from sources to sinks
- summary: Summary of taint analysis results

Important: In this environment, the current working directory is workdir. Kernel source code
lives under workdir/crash-* directories (each crash-* is the kernel tree for the commit where
a crash occurred). Do not use workdir/linux. When calling this tool, use file paths under
workdir/crash-* (e.g. workdir/crash-<id>/fs/btrfs/qgroup.c).'''
    args_schema: Optional[ArgsSchema] = TraceTaintToolInput

    # Common taint sink operations
    TAINT_SINK_OPERATIONS: List[str] = [
        'memcpy', 'memmove', 'strcpy', 'strncpy', 'sprintf', 'snprintf',
        'copy_from_user', 'copy_to_user', '__copy_from_user', '__copy_to_user'
    ]

    def __init__(self):
        super().__init__()

    def _run(self, file_path: str, reason: str, function_name: Optional[str] = None, taint_source: Optional[str] = None):
        print(f'[Tool] TraceTaintTool: {file_path}, {function_name}, taint_source={taint_source}: {reason}')

        if not CLANG_AVAILABLE:
            return json.dumps({
                'error': 'libclang not available',
                'file_path': file_path,
                'function_name': function_name,
                'taint_source': taint_source
            }, indent=2)

        cur_dir = os.getcwd()
        fn = os.listdir('.')
        crash_dirs = [f for f in fn if f.startswith('crash-')]
        if not crash_dirs:
            return json.dumps({
                'error': 'No crash-* directory found',
                'file_path': file_path,
                'function_name': function_name,
                'taint_source': taint_source
            }, indent=2)

        dir_kernel = crash_dirs[0]
        os.chdir(dir_kernel)
        
        # Adjust file path - remove crash-* prefix if present
        if file_path.startswith(dir_kernel + '/'):
            file_path = file_path[len(dir_kernel) + 1:]
        elif '/' in file_path and not file_path.startswith('./'):
            # Assume it's relative to kernel root
            pass
        elif not os.path.exists(file_path):
            # Try to find the file
            basename = os.path.basename(file_path)
            for root, dirs, files in os.walk('.'):
                if basename in files:
                    file_path = os.path.join(root, basename)
                    break

        try:
            result = self._trace_taint(file_path, function_name, taint_source)
            os.chdir(cur_dir)
            return json.dumps(result, indent=2)
        except Exception as e:
            os.chdir(cur_dir)
            return json.dumps({
                'error': f'Error during taint analysis: {str(e)}',
                'file_path': file_path,
                'function_name': function_name,
                'taint_source': taint_source,
                'traceback': str(e.__traceback__) if hasattr(e, '__traceback__') else None
            }, indent=2)

    def _trace_taint(self, file_path: str, function_name: Optional[str], taint_source: Optional[str]):
        """Perform taint analysis on the specified function"""
        index = ci.Index.create()
        args = ['-I', '.', '-I', 'include', '-D__KERNEL__', '-Wno-everything']
        
        # Try parsing with error recovery
        try:
            tu = index.parse(file_path, args=args, options=ci.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD)
        except Exception as e:
            # Try with error recovery - skip function bodies if full parse fails
            try:
                tu = index.parse(file_path, args=args, 
                               options=ci.TranslationUnit.PARSE_SKIP_FUNCTION_BODIES)
            except Exception as e2:
                return {
                    'error': f'Failed to parse file: {str(e2)}',
                    'file_path': file_path,
                    'function_name': function_name
                }

        if tu is None:
            return {'error': 'Failed to parse file (tu is None)', 'file_path': file_path}

        # Get absolute path for comparison
        abs_file_path = os.path.abspath(file_path)
        results = []

        if function_name:
            function_cursor = None
            for cursor in tu.cursor.walk_preorder():
                if (cursor.kind == CursorKind.FUNCTION_DECL and
                    cursor.spelling == function_name):
                    if cursor.location.file:
                        cursor_file = cursor.location.file.name
                        # Check if it's the same file
                        if os.path.abspath(cursor_file) == abs_file_path or cursor_file == file_path:
                            if cursor.is_definition():
                                function_cursor = cursor
                                break
            
            # If not found with is_definition, try without
            if function_cursor is None:
                for cursor in tu.cursor.walk_preorder():
                    if (cursor.kind == CursorKind.FUNCTION_DECL and
                        cursor.spelling == function_name):
                        if cursor.location.file:
                            cursor_file = cursor.location.file.name
                            if os.path.abspath(cursor_file) == abs_file_path or cursor_file == file_path:
                                function_cursor = cursor
                                break

            if function_cursor:
                results.append(self._analyze_function_taint(function_cursor, file_path, taint_source))
            else:
                return {'error': f'Function {function_name} not found in {file_path}', 'file_path': file_path}
        else:
            for cursor in tu.cursor.walk_preorder():
                if (cursor.kind == CursorKind.FUNCTION_DECL and
                    cursor.is_definition()):
                    if cursor.location.file:
                        cursor_file = cursor.location.file.name
                        if os.path.abspath(cursor_file) == abs_file_path or cursor_file == file_path:
                            results.append(self._analyze_function_taint(cursor, file_path, taint_source))

        if len(results) == 1:
            return results[0]
        else:
            return {
                'file_path': file_path,
                'function_name': function_name,
                'functions': results,
                'total_functions': len(results)
            }

    def _analyze_function_taint(self, function_cursor, file_path: str, taint_source: Optional[str]):
        """Analyze taint propagation for a single function"""
        function_name = function_cursor.spelling

        # Step 1: Identify taint sources
        taint_sources = self._identify_taint_sources(function_cursor, taint_source)
        
        if not taint_sources:
            return {
                'function_name': function_name,
                'file_path': file_path,
                'taint_sources': [],
                'taint_propagation': [],
                'taint_sinks': [],
                'propagation_paths': [],
                'summary': 'No taint sources identified'
            }

        # Step 2: Track taint propagation
        tainted_vars: Set[str] = set(taint_sources)
        propagation_points = []
        propagation_points_set = set()  # To avoid duplicates
        taint_map: Dict[str, List[str]] = {var: [var] for var in tainted_vars}  # var -> list of source vars

        # Step 3: Find taint sinks
        taint_sinks = []
        taint_sinks_set = set()  # To avoid duplicates

        # Process function body to track propagation and find sinks
        def visit_cursor(cursor, parent_tainted: bool = False):
            loc = cursor.location
            if not loc.file:
                return

            # Check if we're in the right file
            if loc.file.name != function_cursor.location.file.name:
                return

            line = loc.line

            # Assignment: propagate taint
            if cursor.kind == CursorKind.BINARY_OPERATOR:
                tokens = list(cursor.get_tokens())
                if '=' in [t.spelling for t in tokens]:
                    children = list(cursor.get_children())
                    if len(children) >= 2:
                        left = children[0]
                        right = children[1]

                        # Get left-hand variable
                        left_var = self._get_variable_name(left)
                        
                        # Check if right-hand side is tainted
                        right_tainted_vars = self._check_tainted_in_expression(right, tainted_vars)
                        
                        if right_tainted_vars:
                            if left_var:
                                tainted_vars.add(left_var)
                                # Track propagation path
                                for source_var in right_tainted_vars:
                                    if source_var in taint_map:
                                        if left_var not in taint_map:
                                            taint_map[left_var] = []
                                        taint_map[left_var].extend(taint_map[source_var])
                                
                                prop_key = (line, left_var, tuple(sorted(right_tainted_vars)))
                                if prop_key not in propagation_points_set:
                                    propagation_points_set.add(prop_key)
                                    propagation_points.append({
                                        'type': 'assignment',
                                        'file_path': loc.file.name if loc.file else file_path,
                                        'line': line,
                                        'column': loc.column,
                                        'target': left_var,
                                        'source': list(right_tainted_vars),
                                        'context': self._get_context_line(loc)
                                    })

            # Function call: check if tainted data is passed, and check for sinks
            elif cursor.kind == CursorKind.CALL_EXPR:
                func_name = self._get_function_name(cursor)
                
                # Check if this is a taint sink
                if func_name and func_name in self.TAINT_SINK_OPERATIONS:
                    # Check if any argument is tainted
                    children = list(cursor.get_children())
                    for i, arg in enumerate(children[1:], 1):  # Skip function name
                        arg_tainted = self._check_tainted_in_expression(arg, tainted_vars)
                        if arg_tainted:
                            sink_key = (line, 'function_call', func_name, i)
                            if sink_key not in taint_sinks_set:
                                taint_sinks_set.add(sink_key)
                                taint_sinks.append({
                                    'type': 'function_call',
                                    'file_path': loc.file.name if loc.file else file_path,
                                    'line': line,
                                    'column': loc.column,
                                    'function': func_name,
                                    'argument_index': i,
                                    'tainted_vars': list(arg_tainted),
                                    'severity': 'high',
                                    'context': self._get_context_line(loc)
                                })

                # Check if tainted variables are passed as arguments (only if not a sink)
                if not (func_name and func_name in self.TAINT_SINK_OPERATIONS):
                    children = list(cursor.get_children())
                    for i, arg in enumerate(children[1:], 1):
                        arg_tainted = self._check_tainted_in_expression(arg, tainted_vars)
                        if arg_tainted:
                            prop_key = (line, 'function_argument', func_name or 'unknown', i)
                            if prop_key not in propagation_points_set:
                                propagation_points_set.add(prop_key)
                                propagation_points.append({
                                    'type': 'function_argument',
                                    'file_path': loc.file.name if loc.file else file_path,
                                    'line': line,
                                    'column': loc.column,
                                    'function': func_name or 'unknown',
                                    'argument_index': i,
                                    'tainted_vars': list(arg_tainted),
                                    'context': self._get_context_line(loc)
                                })

            # Pointer dereference: potential sink
            elif cursor.kind == CursorKind.UNARY_OPERATOR:
                tokens = list(cursor.get_tokens())
                has_deref = any(t.spelling == '*' for t in tokens)
                
                if has_deref:
                    # Check if dereferenced variable is tainted
                    children = list(cursor.get_children())
                    for child in children:
                        child_tainted = self._check_tainted_in_expression(child, tainted_vars)
                        if child_tainted:
                            sink_key = (line, 'pointer_dereference', '*')
                            if sink_key not in taint_sinks_set:
                                taint_sinks_set.add(sink_key)
                                taint_sinks.append({
                                    'type': 'pointer_dereference',
                                    'file_path': loc.file.name if loc.file else file_path,
                                    'line': line,
                                    'column': loc.column,
                                    'tainted_vars': list(child_tainted),
                                    'severity': 'high',
                                    'context': self._get_context_line(loc)
                                })

            # Array access: potential sink
            elif cursor.kind == CursorKind.ARRAY_SUBSCRIPT_EXPR:
                children = list(cursor.get_children())
                if children:
                    base_tainted = self._check_tainted_in_expression(children[0], tainted_vars)
                    if base_tainted:
                        sink_key = (line, 'array_access')
                        if sink_key not in taint_sinks_set:
                            taint_sinks_set.add(sink_key)
                            taint_sinks.append({
                                'type': 'array_access',
                                'file_path': loc.file.name if loc.file else file_path,
                                'line': line,
                                'column': loc.column,
                                'tainted_vars': list(base_tainted),
                                'severity': 'medium',
                                'context': self._get_context_line(loc)
                            })

            # Member access (->): potential sink if base is tainted
            elif cursor.kind == CursorKind.MEMBER_REF_EXPR:
                children = list(cursor.get_children())
                if children:
                    base_tainted = self._check_tainted_in_expression(children[0], tainted_vars)
                    if base_tainted:
                        # Check if this is a pointer dereference (->)
                        tokens = list(cursor.get_tokens())
                        is_pointer_deref = any(t.spelling == '->' for t in tokens)
                        
                        if is_pointer_deref:
                            sink_key = (line, 'member_dereference', cursor.spelling)
                            if sink_key not in taint_sinks_set:
                                taint_sinks_set.add(sink_key)
                                taint_sinks.append({
                                    'type': 'member_dereference',
                                    'file_path': loc.file.name if loc.file else file_path,
                                    'line': line,
                                    'column': loc.column,
                                    'field': cursor.spelling,
                                    'tainted_vars': list(base_tainted),
                                    'severity': 'high',
                                    'context': self._get_context_line(loc)
                                })

            # Recursively visit children
            for child in cursor.get_children():
                visit_cursor(child)

        visit_cursor(function_cursor)

        # Step 4: Build propagation paths from sources to sinks
        propagation_paths = self._build_propagation_paths(
            taint_sources, taint_sinks, propagation_points, taint_map
        )

        # Build summary
        summary = f"Found {len(taint_sources)} taint source(s), {len(propagation_points)} propagation point(s), "
        summary += f"and {len(taint_sinks)} taint sink(s). "
        if taint_sinks:
            summary += f"Tainted data reaches {len(taint_sinks)} dangerous operation(s)."
        else:
            summary += "No tainted data reaches dangerous operations."

        return {
            'function_name': function_name,
            'file_path': file_path,
            'taint_sources': [
                {
                    'name': source,
                    'type': 'parameter' if source in [p.spelling for p in function_cursor.get_children() 
                                                      if p.kind == CursorKind.PARM_DECL] else 'variable',
                    'line': function_cursor.location.line
                }
                for source in taint_sources
            ],
            'taint_propagation': propagation_points,
            'taint_sinks': taint_sinks,
            'propagation_paths': propagation_paths,
            'summary': summary
        }

    def _identify_taint_sources(self, function_cursor, taint_source: Optional[str]) -> List[str]:
        """Identify taint sources (function parameters or specified variable)"""
        sources = []

        if taint_source:
            # Specific variable requested
            for cursor in function_cursor.walk_preorder():
                if cursor.kind == CursorKind.VAR_DECL and cursor.spelling == taint_source:
                    sources.append(taint_source)
                    break
                elif cursor.kind == CursorKind.PARM_DECL and cursor.spelling == taint_source:
                    sources.append(taint_source)
                    break
        else:
            # All function parameters are taint sources
            for child in function_cursor.get_children():
                if child.kind == CursorKind.PARM_DECL and child.spelling:
                    sources.append(child.spelling)

        return sources

    def _get_variable_name(self, cursor) -> Optional[str]:
        """Extract variable name from cursor"""
        if cursor.kind == CursorKind.DECL_REF_EXPR:
            return cursor.spelling
        elif cursor.kind == CursorKind.VAR_DECL:
            return cursor.spelling
        elif cursor.kind == CursorKind.PARM_DECL:
            return cursor.spelling
        elif cursor.kind == CursorKind.MEMBER_REF_EXPR:
            # For member access, get the base variable
            for child in cursor.get_children():
                var_name = self._get_variable_name(child)
                if var_name:
                    return var_name
        return None

    def _check_tainted_in_expression(self, cursor, tainted_vars: Set[str]) -> Set[str]:
        """Check if expression contains tainted variables, return set of tainted vars found"""
        found_tainted = set()

        if cursor.kind == CursorKind.DECL_REF_EXPR:
            if cursor.spelling in tainted_vars:
                found_tainted.add(cursor.spelling)
        elif cursor.kind == CursorKind.MEMBER_REF_EXPR:
            # Check base variable
            for child in cursor.get_children():
                child_tainted = self._check_tainted_in_expression(child, tainted_vars)
                found_tainted.update(child_tainted)
        elif cursor.kind == CursorKind.ARRAY_SUBSCRIPT_EXPR:
            # Check base array
            children = list(cursor.get_children())
            if children:
                child_tainted = self._check_tainted_in_expression(children[0], tainted_vars)
                found_tainted.update(child_tainted)
        else:
            # Recursively check children
            for child in cursor.get_children():
                child_tainted = self._check_tainted_in_expression(child, tainted_vars)
                found_tainted.update(child_tainted)

        return found_tainted

    def _get_function_name(self, cursor) -> Optional[str]:
        """Extract function name from call expression"""
        if cursor.kind == CursorKind.CALL_EXPR:
            children = list(cursor.get_children())
            if children:
                func_cursor = children[0]
                if func_cursor.kind == CursorKind.DECL_REF_EXPR:
                    return func_cursor.spelling
                elif func_cursor.kind == CursorKind.MEMBER_REF_EXPR:
                    # For method calls, get the method name
                    return func_cursor.spelling
                elif func_cursor.kind == CursorKind.UNEXPOSED_EXPR:
                    # Try to find function name in tokens
                    tokens = list(func_cursor.get_tokens())
                    if tokens:
                        return tokens[0].spelling
                # Try to get from tokens
                tokens = list(cursor.get_tokens())
                if tokens:
                    # First token is usually the function name
                    return tokens[0].spelling
        return None

    def _get_context_line(self, location, num_lines=2):
        """Get context lines around a location"""
        try:
            if location.file:
                with open(location.file.name, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                    line_idx = location.line - 1
                    if 0 <= line_idx < len(lines):
                        context = []
                        start = max(0, line_idx - num_lines)
                        end = min(len(lines), line_idx + num_lines + 1)
                        for i in range(start, end):
                            marker = '>>>' if i == line_idx else '   '
                            context.append(f"{marker} {i+1}:{lines[i].rstrip()}")
                        return '\n'.join(context)
        except Exception:
            pass
        return ""

    def _build_propagation_paths(self, taint_sources: List[str], taint_sinks: List[Dict],
                                 propagation_points: List[Dict], taint_map: Dict[str, List[str]]) -> List[Dict]:
        """Build paths from taint sources to sinks"""
        paths = []

        for sink in taint_sinks:
            sink_tainted_vars = sink.get('tainted_vars', [])
            
            for tainted_var in sink_tainted_vars:
                # Find source vars for this tainted var
                source_vars = taint_map.get(tainted_var, [tainted_var])
                
                for source_var in source_vars:
                    if source_var in taint_sources:
                        # Build path from source to sink
                        path = {
                            'source': source_var,
                            'sink': {
                                'type': sink['type'],
                                'line': sink['line'],
                                'function': sink.get('function', 'N/A')
                            },
                            'intermediate_vars': [],
                            'propagation_steps': []
                        }

                        # Find intermediate propagation steps
                        current_var = tainted_var
                        while current_var != source_var:
                            # Find where current_var was assigned from source
                            for prop in propagation_points:
                                if prop['target'] == current_var:
                                    if source_var in prop.get('source', []):
                                        path['propagation_steps'].append(prop)
                                        break
                            # Try to find previous var in taint_map
                            if current_var in taint_map:
                                prev_vars = [v for v in taint_map[current_var] if v != current_var]
                                if prev_vars:
                                    current_var = prev_vars[0]
                                    path['intermediate_vars'].append(current_var)
                                else:
                                    break
                            else:
                                break

                        paths.append(path)

        return paths