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

class TraceDataDependencyToolInput(BaseModel):
    file_path: str = Field(description='Path to the file relative to the kernel source root (e.g. fs/btrfs/qgroup.c)')
    function_name: str = Field(description='The name of the function where the variable is used')
    variable_name: str = Field(description='The name of the variable to trace data dependency for')
    reason: str = Field(description='The reason why you need to trace data dependency for this variable')

class TraceDataDependencyTool(BaseTool):
    name: str = 'trace_data_dependency'
    description: str = '''Trace data dependency for a variable within a function, finding all definitions, 
uses, field accesses, and pointer dereferences. This tool uses libclang to parse C code and identify 
where a variable is defined, how it is used, which structure fields are accessed, and where pointer 
dereferences occur.

Use this tool when you need to:
- Understand how a variable flows through a function
- Find all places where a variable is used or modified
- Trace pointer dereferences that might cause crashes
- Analyze data dependencies for bug investigation
- Track structure field accesses (variable->field or variable.field)

The tool returns:
- definitions: Where the variable is declared/defined
- uses: All places where the variable is referenced
- field_accesses: Structure field accesses (-> or .)
- pointer_dereferences: Pointer dereference operations (* or ->)
- parameter_passing: Where the variable is passed as function argument

Important: In this environment, the current working directory is workdir. Kernel source code
lives under workdir/crash-* directories (each crash-* is the kernel tree for the commit where
a crash occurred). Do not use workdir/linux. When calling this tool, use file paths under
workdir/crash-* (e.g. workdir/crash-<id>/fs/btrfs/qgroup.c).'''
    args_schema: Optional[ArgsSchema] = TraceDataDependencyToolInput

    def __init__(self):
        super().__init__()

    def _run(self, file_path: str, function_name: str, variable_name: str, reason: str):
        print(f'[Tool] TraceDataDependencyTool: {file_path}, {function_name}, {variable_name}: {reason}')

        cur_dir = os.getcwd()
        fn = os.listdir('.')
        crash_dirs = [f for f in fn if f.startswith('crash-')]
        if not crash_dirs:
            error_result = {
                'error': 'No crash-* directory found',
                'file_path': file_path,
                'function_name': function_name,
                'variable_name': variable_name
            }
            return json.dumps(error_result, indent=2)
        
        dir_kernel = crash_dirs[0]
        os.chdir(dir_kernel)

        if not CLANG_AVAILABLE:
            os.chdir(cur_dir)
            return json.dumps({
                'error': 'libclang not available',
                'file_path': file_path,
                'function_name': function_name,
                'variable_name': variable_name
            }, indent=2)

        try:
            index = ci.Index.create()
            args = ['-I', '.', '-I', 'include', '-D__KERNEL__', '-Wno-everything']
            tu = index.parse(file_path, args=args, options=ci.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD)
            
            if tu is None:
                os.chdir(cur_dir)
                return json.dumps({
                    'error': 'Failed to parse file',
                    'file_path': file_path,
                    'function_name': function_name,
                    'variable_name': variable_name
                }, indent=2)

            # Find the function using walk_preorder (more reliable)
            function_cursor = None

                        # First try with is_definition check, only in the actual file
            for cursor in tu.cursor.walk_preorder():
                if cursor.kind == CursorKind.FUNCTION_DECL and cursor.spelling == function_name:
                    # Check if function is in the actual file (not in included headers)
                    if cursor.location.file and cursor.location.file.name == file_path:
                        if cursor.is_definition():
                            function_cursor = cursor
                            break

            # If not found, try without is_definition check, but still in actual file
            if function_cursor is None:
                for cursor in tu.cursor.walk_preorder():
                    if cursor.kind == CursorKind.FUNCTION_DECL and cursor.spelling == function_name:
                        if cursor.location.file and cursor.location.file.name == file_path:
                            function_cursor = cursor
                            break

            # Debug: list all functions if still not found
            if function_cursor is None:
                print(f"[Debug] Function '{function_name}' not found. Searching for similar functions...")
                available_functions = []
                similar_functions = []
                
                for cursor in tu.cursor.walk_preorder():
                    if cursor.kind == CursorKind.FUNCTION_DECL:
                        func_name = cursor.spelling
                        if func_name:
                            # Only collect functions from the actual file (not headers)
                            if cursor.location.file and cursor.location.file.name == file_path:
                                if func_name not in available_functions:
                                    available_functions.append(func_name)
                            
                            # Find similar function names
                            if function_name.lower() in func_name.lower() or func_name.lower() in function_name.lower():
                                if func_name not in similar_functions:
                                    similar_functions.append(func_name)
                
                # Print similar functions
                if similar_functions:
                    print(f"Similar function names found:")
                    for func in similar_functions[:10]:  # Limit to 10
                        print(f"  - {func}")
                
                # Print some available functions from the file
                if available_functions:
                    print(f"\nSome functions in {file_path} (showing first 20):")
                    for func in available_functions[:20]:
                        print(f"  - {func}")
                    if len(available_functions) > 20:
                        print(f"  ... and {len(available_functions) - 20} more functions")
                
                os.chdir(cur_dir)
                return json.dumps({
                    'error': 'Function not found',
                    'file_path': file_path,
                    'function_name': function_name,
                    'variable_name': variable_name,
                    'available_functions_count': len(available_functions),
                    'similar_functions': similar_functions[:10],
                    'hint': f'Function not found. Found {len(available_functions)} functions in file. Similar: {similar_functions[:5] if similar_functions else "none"}'
                }, indent=2)

            # Trace data dependency
            definitions, uses, field_accesses, pointer_dereferences, parameter_passing = \
                self._trace_variable(function_cursor, variable_name, file_path)

            os.chdir(cur_dir)

            result = {
                'variable_name': variable_name,
                'function_name': function_name,
                'file_path': file_path,
                'definitions': definitions,
                'uses': uses,
                'field_accesses': field_accesses,
                'pointer_dereferences': pointer_dereferences,
                'parameter_passing': parameter_passing,
                'summary': f'Found {len(definitions)} definition(s), {len(uses)} use(s), '
                          f'{len(field_accesses)} field access(es), {len(pointer_dereferences)} '
                          f'pointer dereference(s), {len(parameter_passing)} parameter passing(s)'
            }

            return json.dumps(result, indent=2)

        except Exception as e:
            os.chdir(cur_dir)
            return json.dumps({
                'error': f'Error during analysis: {str(e)}',
                'file_path': file_path,
                'function_name': function_name,
                'variable_name': variable_name
            }, indent=2)

    def _get_context_line(self, location, num_lines=1):
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
                            context.append(f"{i+1}:{lines[i].rstrip()}")
                        return '\n'.join(context)
        except Exception:
            pass
        return ""

    def _trace_variable(self, function_cursor, var_name, file_path):
        """Trace variable definitions, uses, field accesses, and dereferences"""
        definitions = []
        uses = []
        field_accesses = []
        pointer_dereferences = []
        parameter_passing = []

        def get_variable_name(cursor):
            """Extract variable name from cursor"""
            if cursor.kind == CursorKind.DECL_REF_EXPR:
                return cursor.spelling
            elif cursor.kind == CursorKind.VAR_DECL:
                return cursor.spelling
            elif cursor.kind == CursorKind.PARM_DECL:
                return cursor.spelling
            return None

        def is_variable_reference(cursor, var_name):
            """Check if cursor references the variable"""
            if cursor.kind == CursorKind.DECL_REF_EXPR:
                return cursor.spelling == var_name
            elif cursor.kind == CursorKind.MEMBER_REF_EXPR:
                # Check if parent is the variable
                parent = cursor.semantic_parent
                if parent and parent.kind == CursorKind.DECL_REF_EXPR:
                    return parent.spelling == var_name
            return False

        def visit_cursor(cursor):
            loc = cursor.location
            
            # Variable declaration/definition
            if cursor.kind == CursorKind.VAR_DECL:
                if cursor.spelling == var_name:
                    definitions.append({
                        'file_path': loc.file.name if loc.file else file_path,
                        'line': loc.line,
                        'column': loc.column,
                        'type': cursor.type.spelling if cursor.type else 'unknown',
                        'context': self._get_context_line(loc)
                    })

            # Variable use (reference) - MUST come before CALL_EXPR
            elif cursor.kind == CursorKind.DECL_REF_EXPR:
                if cursor.spelling == var_name:
                    parent_kind = cursor.semantic_parent.kind if cursor.semantic_parent else None
                    parent_kind_str = str(parent_kind) if parent_kind else 'unknown'
                    
                    uses.append({
                        'file_path': loc.file.name if loc.file else file_path,
                        'line': loc.line,
                        'column': loc.column,
                        'parent_kind': parent_kind_str,
                        'context': self._get_context_line(loc)
                    })

            # Function call - check if our variable is an argument
            elif cursor.kind == CursorKind.CALL_EXPR:
                # Check all children (arguments) of the call
                children_list = list(cursor.get_children())
                if len(children_list) > 1:  # Skip if only function name
                    for child in children_list[1:]:  # Skip first child (function name)
                        # Check if child is directly our variable
                        if child.kind == CursorKind.DECL_REF_EXPR and child.spelling == var_name:
                            parameter_passing.append({
                                'file_path': loc.file.name if loc.file else file_path,
                                'line': loc.line,
                                'column': loc.column,
                                'context': self._get_context_line(loc)
                            })
                            break

                        # Also check nested expressions (but not field accesses)
                        def check_child_for_var(child_cursor):
                            # First check if this cursor itself is our variable
                            if child_cursor.kind == CursorKind.DECL_REF_EXPR and child_cursor.spelling == var_name:
                                # Check parent chain to see if it's part of field access or address-of
                                parent = child_cursor.semantic_parent if hasattr(child_cursor, 'semantic_parent') else None
                                depth = 0
                                while parent and depth < 3:  # Check up to 3 levels
                                    # Skip if parent is MEMBER_REF_EXPR (fs_info->field)
                                    if parent.kind == CursorKind.MEMBER_REF_EXPR:
                                        return False
                                    # Skip if parent is UNARY_OPERATOR with & (address-of)
                                    if parent.kind == CursorKind.UNARY_OPERATOR:
                                        tokens = list(parent.get_tokens())
                                        if any(t.spelling == '&' for t in tokens):
                                            return False
                                    parent = parent.semantic_parent if hasattr(parent, 'semantic_parent') and parent.semantic_parent else None
                                    depth += 1
                                return True
                            
                            # Before recursively checking children, check if this cursor itself is problematic
                            # Skip MEMBER_REF_EXPR and UNARY_OPERATOR with & to avoid false positives
                            if child_cursor.kind == CursorKind.MEMBER_REF_EXPR:
                                return False  # Don't recurse into field accesses
                            if child_cursor.kind == CursorKind.UNARY_OPERATOR:
                                tokens = list(child_cursor.get_tokens())
                                if any(t.spelling == '&' for t in tokens):
                                    return False  # Don't recurse into address-of operators
                            
                            # Recursively check children
                            for grandchild in child_cursor.get_children():
                                if check_child_for_var(grandchild):
                                    return True
                            return False
                        
                        if check_child_for_var(child):
                            parameter_passing.append({
                                'file_path': loc.file.name if loc.file else file_path,
                                'line': loc.line,
                                'column': loc.column,
                                'context': self._get_context_line(loc)
                            })
                            break

            # Structure field access (variable->field or variable.field)
            elif cursor.kind == CursorKind.MEMBER_REF_EXPR:
                # Get the base object (the variable before -> or .)
                base_cursor = None
                for child in cursor.get_children():
                    if child.kind == CursorKind.DECL_REF_EXPR:
                        base_cursor = child
                        break
                    # Also check nested structures
                    for grandchild in child.get_children():
                        if grandchild.kind == CursorKind.DECL_REF_EXPR:
                            base_cursor = grandchild
                            break
                    if base_cursor:
                        break
                
                # Check if base is our variable
                if base_cursor and base_cursor.spelling == var_name:
                    # Determine access type from tokens
                    tokens = list(cursor.get_tokens())
                    access_type = '->' if any(t.spelling == '->' for t in tokens) else '.'
                    
                    field_accesses.append({
                        'field_name': cursor.spelling,
                        'file_path': loc.file.name if loc.file else file_path,
                        'line': loc.line,
                        'column': loc.column,
                        'access_type': access_type,
                        'context': self._get_context_line(loc)
                    })
                    
                    # Also record as pointer dereference if using ->
                    if access_type == '->':
                        pointer_dereferences.append({
                            'file_path': loc.file.name if loc.file else file_path,
                            'line': loc.line,
                            'column': loc.column,
                            'operator': '->',
                            'context': self._get_context_line(loc)
                        })

            # Pointer dereference (*var)
            elif cursor.kind == CursorKind.UNARY_OPERATOR:
                # Check if this is a dereference operator
                tokens = list(cursor.get_tokens())
                has_deref = any(t.spelling == '*' for t in tokens)
                
                if has_deref:
                    # Check if variable is involved
                    for child in cursor.get_children():
                        child_name = get_variable_name(child)
                        if child_name == var_name:
                            pointer_dereferences.append({
                                'file_path': loc.file.name if loc.file else file_path,
                                'line': loc.line,
                                'column': loc.column,
                                'operator': '*',
                                'context': self._get_context_line(loc)
                            })
                            break

            # Recursively visit children
            for child in cursor.get_children():
                visit_cursor(child)

        visit_cursor(function_cursor)

        # Sort results by line number
        definitions.sort(key=lambda x: (x['line'], x['column']))
        uses.sort(key=lambda x: (x['line'], x['column']))
        field_accesses.sort(key=lambda x: (x['line'], x['column']))
        pointer_dereferences.sort(key=lambda x: (x['line'], x['column']))
        parameter_passing.sort(key=lambda x: (x['line'], x['column']))

        return definitions, uses, field_accesses, pointer_dereferences, parameter_passing