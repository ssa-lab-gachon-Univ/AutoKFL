import os
import json
import re
from typing import Optional, ClassVar, Dict, List, Tuple, Set
from pydantic import BaseModel, Field
from langchain_core.tools import BaseTool
from langchain_core.tools.base import ArgsSchema

try:
    import clang.cindex as ci
    from clang.cindex import CursorKind, TokenKind
    CLANG_AVAILABLE = True
except ImportError:
    CLANG_AVAILABLE = False


class TrackMemoryOperationsToolInput(BaseModel):
    file_path: str = Field(
        description='Path to the file relative to the kernel source root (e.g. fs/btrfs/qgroup.c)'
    )
    function_name: Optional[str] = Field(
        default=None,
        description='Name of the function to analyze. If not provided, analyzes the entire file.'
    )
    variable_name: Optional[str] = Field(
        default=None,
        description='Specific variable name to track. If provided, only tracks operations on this variable.'
    )
    reason: str = Field(
        description='The reason why you need to track memory operations in this code'
    )


class TrackMemoryOperationsTool(BaseTool):
    name: str = 'track_memory_operations'
    description: str = '''Track memory allocation and deallocation operations in C kernel code.
    
This tool provides detailed tracking of memory operations including:
- Memory allocations (kmalloc, kzalloc, vmalloc, etc.)
- Memory deallocations (kfree, vfree, etc.)
- Allocation-deallocation pairs
- Memory usage patterns (dereferences, assignments)
- Potential issues: use-after-free, double-free, memory leaks

Use this tool when you need to:
- Understand memory lifecycle in a function or file
- Track specific variable's memory operations
- Identify memory-related bug patterns
- Analyze memory allocation/deallocation flow
- Find potential use-after-free or memory leak issues

The tool returns:
- allocations: List of memory allocations with variable name, line, function, and type
- deallocations: List of memory deallocations with variable name, line, and function
- allocation_pairs: Matched allocation-deallocation pairs
- memory_usage: Memory access patterns (dereferences, assignments)
- potential_issues: List of potential memory-related bugs
- memory_lifecycle: Complete lifecycle tracking for each allocated variable

Important: In this environment, the current working directory is workdir. Kernel source code
lives under workdir/crash-* directories (each crash-* is the kernel tree for the commit where
a crash occurred). Do not use workdir/linux. When calling this tool, use file paths under
workdir/crash-* (e.g. workdir/crash-<id>/fs/btrfs/qgroup.c).'''
    args_schema: Optional[ArgsSchema] = TrackMemoryOperationsToolInput

    ALLOC_FUNCTIONS: ClassVar[list[str]] = [
        'kmalloc', 'kzalloc', 'kcalloc', 'vmalloc', 'vzalloc',
        'kmalloc_noprof', 'kzalloc_noprof',
        'alloc_pages', 'get_free_pages', 'kmem_cache_alloc',
        'kmem_cache_zalloc', 'devm_kmalloc', 'devm_kzalloc',
        'alloc_skb', 'dev_alloc_skb', 'netdev_alloc_skb'
    ]
    
    FREE_FUNCTIONS: ClassVar[list[str]] = [
        'kfree', 'vfree', 'free_pages', 'kmem_cache_free',
        'put_page', 'slab_free', 'devm_kfree',
        'kfree_skb', 'dev_kfree_skb', 'consume_skb'
    ]

    def __init__(self):
        super().__init__()

    def _run(self, file_path: str, reason: str, function_name: Optional[str] = None, variable_name: Optional[str] = None):
        print(f'[Tool] TrackMemoryOperationsTool: {file_path} {function_name} {variable_name} {reason}')
        if not CLANG_AVAILABLE:
            return json.dumps({
                'error': 'libclang not available',
                'file_path': file_path,
                'function_name': function_name,
                'variable_name': variable_name
            }, indent=2)
        
        cur_dir = os.getcwd()
        fn = os.listdir('.')
        crash_dirs = [f for f in fn if f.startswith('crash-')]
        if not crash_dirs:
            return json.dumps({
                'error': 'No crash-* directory found',
                'file_path': file_path,
                'function_name': function_name
            }, indent=2)
        
        dir_kernel = crash_dirs[0]
        os.chdir(dir_kernel)
        
        try:
            result = self._track_memory_operations(file_path, function_name, variable_name)
            os.chdir(cur_dir)
            return json.dumps(result, indent=2)
        except Exception as e:
            os.chdir(cur_dir)
            return json.dumps({
                'error': f'Error during analysis: {str(e)}',
                'file_path': file_path,
                'function_name': function_name,
                'variable_name': variable_name
            }, indent=2)

    def _track_memory_operations(self, file_path: str, function_name: Optional[str] = None, variable_name: Optional[str] = None):
        """Track memory operations using libclang"""
        index = ci.Index.create()
        args = ['-I', '.', '-I', 'include', '-D__KERNEL__', '-Wno-everything']
        tu = index.parse(file_path, args=args, options=ci.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD)
        
        if tu is None:
            return {'error': 'Failed to parse file', 'file_path': file_path}
        
        abs_file_path = os.path.abspath(file_path)
        
        if function_name:
            function_cursor = None
            for cursor in tu.cursor.walk_preorder():
                if (cursor.kind == CursorKind.FUNCTION_DECL and 
                    cursor.spelling == function_name and 
                    cursor.is_definition()):
                    if cursor.location.file:
                        cursor_file = os.path.abspath(cursor.location.file.name)
                        if cursor_file == abs_file_path or cursor_file.endswith(file_path):
                            function_cursor = cursor
                            break
            
            if function_cursor:
                return self._analyze_function_memory(function_cursor, file_path, variable_name)
            else:
                return {'error': f'Function {function_name} not found', 'file_path': file_path}
        else:
            # Analyze all functions in file
            all_results = {
                'file_path': file_path,
                'functions': []
            }
            
            for cursor in tu.cursor.walk_preorder():
                if (cursor.kind == CursorKind.FUNCTION_DECL and 
                    cursor.is_definition()):
                    if cursor.location.file:
                        cursor_file = os.path.abspath(cursor.location.file.name)
                        if cursor_file == abs_file_path or cursor_file.endswith(file_path):
                            func_result = self._analyze_function_memory(cursor, file_path, variable_name)
                            func_result['function_name'] = cursor.spelling
                            all_results['functions'].append(func_result)
            
            return all_results

    def _analyze_function_memory(self, function_cursor, file_path: str, target_variable: Optional[str] = None):
        """Analyze memory operations in a single function"""
        allocations = {}  # var_name -> (line, alloc_func, alloc_type)
        deallocations = []  # List of (line, var_name, free_func)
        memory_usage = []  # List of (line, var_name, operation_type, context)
        variable_assignments = {}  # Track variable assignments to find aliases
        null_assignments = set()  # Track variables assigned NULL
        seen_usage = set()  # Track seen usage to avoid duplicates
        
        actual_file_path = function_cursor.location.file.name if function_cursor.location.file else file_path
        
        # Get function parameters to filter them out
        function_params = self._get_function_parameters(function_cursor)
        
        def visit_cursor(cursor):
            loc = cursor.location
            
            if not loc.file:
                return
            
            cursor_file = loc.file.name
            cursor_basename = os.path.basename(cursor_file)
            expected_basename = os.path.basename(file_path)
            
            if not (cursor_basename == expected_basename or cursor_basename == os.path.basename(actual_file_path)):
                return
            
            line = loc.line
            
            # Track memory allocations
            if cursor.kind == CursorKind.CALL_EXPR:
                func_name = self._get_function_name(cursor)
                if func_name:
                    if func_name in self.ALLOC_FUNCTIONS:
                        var_name = self._get_assigned_variable(cursor, function_cursor, line)
                        if var_name:
                            if target_variable is None or var_name == target_variable:
                                alloc_type = self._get_alloc_type(func_name)
                                allocations[var_name] = {
                                    'line': line,
                                    'function': func_name,
                                    'type': alloc_type,
                                    'variable': var_name
                                }
                    
                    elif func_name in self.FREE_FUNCTIONS:
                        var_name = self._get_argument_variable(cursor, 0)
                        if var_name:
                            if target_variable is None or var_name == target_variable:
                                deallocations.append({
                                    'line': line,
                                    'function': func_name,
                                    'variable': var_name
                                })
            
            # Track memory usage (dereferences, assignments)
            elif cursor.kind == CursorKind.MEMBER_REF_EXPR:
                var_name = self._get_base_variable(cursor)
                # Only track if: (1) variable is allocated, (2) not a function parameter, (3) not in sizeof
                if var_name and (target_variable is None or var_name == target_variable):
                    if var_name in allocations and var_name not in function_params:
                        # Skip if this is the same line as allocation (likely sizeof)
                        if allocations[var_name]['line'] != line:
                            if not self._is_in_sizeof(cursor):
                                usage_key = (line, var_name, 'dereference')
                                if usage_key not in seen_usage:
                                    seen_usage.add(usage_key)
                                    memory_usage.append({
                                        'line': line,
                                        'variable': var_name,
                                        'operation': 'dereference',
                                        'context': self._get_code_context(cursor)
                                    })

            elif cursor.kind == CursorKind.UNARY_OPERATOR:
                tokens = list(cursor.get_tokens())
                if any(t.spelling == '*' for t in tokens):
                    var_name = self._get_dereferenced_variable(cursor)
                    # Only track if: (1) variable is allocated, (2) not a function parameter, (3) not in sizeof
                    if var_name and (target_variable is None or var_name == target_variable):
                        if var_name in allocations and var_name not in function_params:
                            # Skip if this is the same line as allocation (likely sizeof)
                            if allocations[var_name]['line'] != line:
                                if not self._is_in_sizeof(cursor):
                                    usage_key = (line, var_name, 'dereference')
                                    if usage_key not in seen_usage:
                                        seen_usage.add(usage_key)
                                        memory_usage.append({
                                            'line': line,
                                            'variable': var_name,
                                            'operation': 'dereference',
                                            'context': self._get_code_context(cursor)
                                        })
            
            # Track variable assignments (for alias detection)
            elif cursor.kind == CursorKind.BINARY_OPERATOR:
                tokens = list(cursor.get_tokens())
                if '=' in [t.spelling for t in tokens]:
                    left_var, right_var = self._get_assignment_variables(cursor)
                    if left_var and right_var:
                        if right_var in allocations or right_var in [d['variable'] for d in deallocations]:
                            variable_assignments[left_var] = right_var
                    
                    # Track NULL assignments
                    if left_var and left_var in allocations:
                        if self._is_null_assignment(cursor, left_var):
                            null_assignments.add(left_var)
            
            for child in cursor.get_children():
                visit_cursor(child)
        
        visit_cursor(function_cursor)
        
        # Match allocation-deallocation pairs
        allocation_pairs = []
        freed_vars = set()
        for dealloc in deallocations:
            var_name = dealloc['variable']
            freed_vars.add(var_name)
            
            if var_name in allocations:
                allocation_pairs.append({
                    'variable': var_name,
                    'alloc_line': allocations[var_name]['line'],
                    'alloc_function': allocations[var_name]['function'],
                    'free_line': dealloc['line'],
                    'free_function': dealloc['function'],
                    'lifetime_lines': dealloc['line'] - allocations[var_name]['line']
                })
        
        # Find potential issues
        potential_issues = []
        
        # Memory leaks: allocated but not freed
        for var_name, alloc_info in allocations.items():
            if var_name not in freed_vars:
                # Check if variable was assigned NULL (might be transferred to another owner)
                is_transferred = var_name in null_assignments
                
                # Check if variable is passed to another function (might be freed there)
                is_passed_to_function = False
                for usage in memory_usage:
                    if usage['variable'] == var_name:
                        # Check if this usage is in a function call argument
                        # This is a simplified check - you might want to enhance it
                        context = usage.get('context', '')
                        if '->' in context or '.' in context:
                            is_passed_to_function = True
                            break
                
                if not is_transferred and not is_passed_to_function:
                    potential_issues.append({
                        'type': 'memory_leak',
                        'variable': var_name,
                        'alloc_line': alloc_info['line'],
                        'alloc_function': alloc_info['function'],
                        'severity': 'medium',
                        'description': f'Variable {var_name} allocated at line {alloc_info["line"]} but never freed'
                    })
                elif is_transferred:
                    # Add note about NULL assignment
                    potential_issues.append({
                        'type': 'possible_transfer',
                        'variable': var_name,
                        'alloc_line': alloc_info['line'],
                        'alloc_function': alloc_info['function'],
                        'severity': 'low',
                        'description': f'Variable {var_name} allocated at line {alloc_info["line"]} and assigned NULL (possibly transferred to another owner)'
                    })
        
        # Double free: freed multiple times
        free_counts = {}
        for dealloc in deallocations:
            var_name = dealloc['variable']
            free_counts[var_name] = free_counts.get(var_name, 0) + 1
        
        for var_name, count in free_counts.items():
            if count > 1:
                potential_issues.append({
                    'type': 'double_free',
                    'variable': var_name,
                    'free_count': count,
                    'severity': 'high',
                    'description': f'Variable {var_name} freed {count} times'
                })
        
        # Use-after-free: memory used after deallocation
        for dealloc in deallocations:
            var_name = dealloc['variable']
            free_line = dealloc['line']
            
            for usage in memory_usage:
                if usage['variable'] == var_name and usage['line'] > free_line:
                    potential_issues.append({
                        'type': 'use_after_free',
                        'variable': var_name,
                        'free_line': free_line,
                        'use_line': usage['line'],
                        'operation': usage['operation'],
                        'severity': 'high',
                        'description': f'Variable {var_name} used at line {usage["line"]} after being freed at line {free_line}'
                    })
        
        # Build memory lifecycle for each allocated variable
        memory_lifecycle = {}
        for var_name, alloc_info in allocations.items():
            lifecycle = {
                'variable': var_name,
                'allocation': alloc_info,
                'deallocations': [d for d in deallocations if d['variable'] == var_name],
                'usage': [u for u in memory_usage if u['variable'] == var_name],
                'status': 'transferred' if var_name in null_assignments else ('leaked' if var_name not in freed_vars else 'freed')
            }
            memory_lifecycle[var_name] = lifecycle
        
        return {
            'file_path': file_path,
            'function_name': function_cursor.spelling if function_cursor else None,
            'allocations': list(allocations.values()),
            'deallocations': deallocations,
            'allocation_pairs': allocation_pairs,
            'memory_usage': memory_usage,
            'potential_issues': potential_issues,
            'memory_lifecycle': memory_lifecycle,
            'summary': {
                'total_allocations': len(allocations),
                'total_deallocations': len(deallocations),
                'matched_pairs': len(allocation_pairs),
                'potential_issues_count': len(potential_issues),
                'leaked_variables': len([v for v in allocations.keys() if v not in freed_vars and v not in null_assignments])
            }
        }

    def _get_function_name(self, cursor):
        """Extract function name from CALL_EXPR cursor"""
        children = list(cursor.get_children())
        if children:
            first_child = children[0]
            if first_child.kind == CursorKind.DECL_REF_EXPR:
                return first_child.spelling
            elif first_child.kind == CursorKind.UNEXPOSED_EXPR:
                for child in first_child.walk_preorder():
                    if child.kind == CursorKind.DECL_REF_EXPR and child.spelling:
                        return child.spelling
            tokens = list(cursor.get_tokens())
            if tokens:
                return tokens[0].spelling
        return None

    def _get_assigned_variable(self, cursor, function_cursor, line):
        """Get variable name that allocation result is assigned to"""
        # Try direct parent assignment
        parent = cursor.semantic_parent
        depth = 0
        while parent and depth < 5:
            if parent.kind == CursorKind.BINARY_OPERATOR:
                tokens = list(parent.get_tokens())
                if '=' in [t.spelling for t in tokens]:
                    children = list(parent.get_children())
                    if children:
                        left = children[0]
                        if left.kind == CursorKind.DECL_REF_EXPR:
                            return left.spelling
                        else:
                            for desc in left.walk_preorder():
                                if desc.kind == CursorKind.DECL_REF_EXPR and desc.spelling:
                                    return desc.spelling
            parent = getattr(parent, 'semantic_parent', None)
            depth += 1
        
        # Try sibling search at same line
        for sibling in function_cursor.walk_preorder():
            if (sibling.kind == CursorKind.BINARY_OPERATOR and 
                sibling.location.file and cursor.location.file and
                sibling.location.file.name == cursor.location.file.name and
                sibling.location.line == line):
                tokens = list(sibling.get_tokens())
                if '=' in [t.spelling for t in tokens]:
                    for child in sibling.walk_preorder():
                        if child == cursor:
                            children = list(sibling.get_children())
                            if children:
                                left = children[0]
                                for desc in left.walk_preorder():
                                    if desc.kind == CursorKind.DECL_REF_EXPR and desc.spelling:
                                        return desc.spelling
                            break
        
        return None

    def _get_argument_variable(self, cursor, arg_index):
        """Get variable name from function argument"""
        children = list(cursor.get_children())
        if len(children) > arg_index + 1:
            arg_cursor = children[arg_index + 1]
            if arg_cursor.kind == CursorKind.DECL_REF_EXPR:
                return arg_cursor.spelling
            else:
                for desc in arg_cursor.walk_preorder():
                    if desc.kind == CursorKind.DECL_REF_EXPR and desc.spelling:
                        return desc.spelling
        return None

    def _get_base_variable(self, cursor):
        """Get base variable name from member reference (ptr->field)"""
        for child in cursor.get_children():
            if child.kind == CursorKind.DECL_REF_EXPR:
                return child.spelling
            elif child.kind in (CursorKind.UNEXPOSED_EXPR, CursorKind.PAREN_EXPR):
                for desc in child.walk_preorder():
                    if desc.kind == CursorKind.DECL_REF_EXPR and desc.spelling:
                        return desc.spelling
        
        tokens = list(cursor.get_tokens())
        if len(tokens) >= 1:
            for i, token in enumerate(tokens):
                if token.spelling in ['->', '.'] and i > 0:
                    return tokens[i-1].spelling
        return None

    def _is_in_sizeof(self, cursor):
        """Check if cursor is inside sizeof() expression"""
        parent = cursor.semantic_parent
        depth = 0
        while parent and depth < 10:
            # Check parent's tokens for sizeof
            try:
                tokens = list(parent.get_tokens())
                for i, token in enumerate(tokens):
                    if token.spelling == 'sizeof':
                        # Check if cursor is in the argument of sizeof
                        return True
            except:
                pass
            
            if parent.kind == CursorKind.UNEXPOSED_EXPR:
                tokens = list(parent.get_tokens())
                if any('sizeof' in t.spelling for t in tokens):
                    return True
            elif parent.kind == CursorKind.CALL_EXPR:
                func_name = self._get_function_name(parent)
                if func_name == 'sizeof':
                    return True
            
            parent = getattr(parent, 'semantic_parent', None)
            depth += 1
        return False

    def _is_null_assignment(self, cursor, var_name):
        """Check if variable is assigned NULL"""
        if cursor.kind == CursorKind.BINARY_OPERATOR:
            tokens = list(cursor.get_tokens())
            if '=' in [t.spelling for t in tokens]:
                children = list(cursor.get_children())
                if len(children) >= 2:
                    left = children[0]
                    right = children[1]
                    
                    # Check if left side is our variable
                    left_var = None
                    if left.kind == CursorKind.DECL_REF_EXPR:
                        left_var = left.spelling
                    else:
                        for desc in left.walk_preorder():
                            if desc.kind == CursorKind.DECL_REF_EXPR and desc.spelling:
                                left_var = desc.spelling
                                break
                    
                    if left_var == var_name:
                        # Check if right side is NULL - more robust check
                        right_tokens = list(right.get_tokens())
                        # Also check parent tokens for NULL
                        parent_tokens = tokens
                        all_tokens = right_tokens + parent_tokens
                        if any(t.spelling in ['NULL', 'nullptr', '0'] for t in all_tokens):
                            return True
        return False

    def _get_function_parameters(self, function_cursor):
        """Get list of function parameter names"""
        params = set()
        for child in function_cursor.get_children():
            if child.kind == CursorKind.PARM_DECL:
                params.add(child.spelling)
        return params

    def _get_dereferenced_variable(self, cursor):
        """Get variable name from unary operator dereference (*var)"""
        children = list(cursor.get_children())
        if children:
            child = children[0]
            if child.kind == CursorKind.DECL_REF_EXPR:
                return child.spelling
            else:
                for desc in child.walk_preorder():
                    if desc.kind == CursorKind.DECL_REF_EXPR and desc.spelling:
                        return desc.spelling
        return None

    def _get_assignment_variables(self, cursor):
        """Get left and right variable names from assignment"""
        children = list(cursor.get_children())
        if len(children) >= 2:
            left = children[0]
            right = children[1]
            
            left_var = None
            if left.kind == CursorKind.DECL_REF_EXPR:
                left_var = left.spelling
            else:
                for desc in left.walk_preorder():
                    if desc.kind == CursorKind.DECL_REF_EXPR and desc.spelling:
                        left_var = desc.spelling
                        break
            
            right_var = None
            if right.kind == CursorKind.DECL_REF_EXPR:
                right_var = right.spelling
            else:
                for desc in right.walk_preorder():
                    if desc.kind == CursorKind.DECL_REF_EXPR and desc.spelling:
                        right_var = desc.spelling
                        break
            
            return left_var, right_var
        return None, None

    def _get_alloc_type(self, func_name: str) -> str:
        """Determine allocation type from function name"""
        if 'vmalloc' in func_name:
            return 'vmalloc'
        elif 'kmem_cache' in func_name:
            return 'slab'
        elif 'pages' in func_name:
            return 'pages'
        elif 'skb' in func_name:
            return 'skb'
        elif 'devm' in func_name:
            return 'devm'
        else:
            return 'kmalloc'

    def _get_code_context(self, cursor):
        """Get code context around cursor for better understanding"""
        try:
            loc = cursor.location
            if not loc.file:
                return None
            
            file_path = loc.file.name
            line = loc.line
            
            with open(file_path, 'r') as f:
                lines = f.readlines()
                start = max(0, line - 2)
                end = min(len(lines), line + 2)
                context_lines = [lines[i].strip() for i in range(start, end)]
                return '\n'.join(context_lines)
        except:
            return None