import os
import json
from typing import Optional, Dict, List, Set, Tuple
from pydantic import BaseModel, Field
from langchain_core.tools import BaseTool
from langchain_core.tools.base import ArgsSchema

try:
    import clang.cindex as ci
    from clang.cindex import CursorKind, TokenKind
    CLANG_AVAILABLE = True
except ImportError:
    CLANG_AVAILABLE = False


class AnalyzePointerAliasingToolInput(BaseModel):
    file_path: str = Field(
        description='Path to the file relative to the kernel source root (e.g. fs/btrfs/qgroup.c)'
    )
    function_name: Optional[str] = Field(
        default=None,
        description='Name of the function to analyze. If not provided, analyzes the entire file.'
    )
    pointer_name: Optional[str] = Field(
        default=None,
        description='Specific pointer variable name to analyze. If provided, only analyzes aliasing for this pointer.'
    )
    reason: str = Field(
        description='The reason why you need to analyze pointer aliasing in this code'
    )


class AnalyzePointerAliasingTool(BaseTool):
    name: str = 'analyze_pointer_aliasing'
    description: str = '''Analyze pointer aliasing relationships in C kernel code.
    
IMPORTANT WARNINGS:
- This tool provides CANDIDATE aliasing relationships, NOT confirmed aliases
- Results may contain FALSE POSITIVES - always verify with code review
- Confidence scores are heuristic estimates, not guarantees
- You MUST analyze the code yourself to validate these findings
- Use this tool to get hints, not as definitive evidence

This tool analyzes code to identify:
- Pointer assignment relationships (ptr1 = ptr2)
- Aliasing groups (pointers that may point to the same memory)
- Potential use-after-free scenarios (aliased pointer used after original freed)
- Potential double-free scenarios (aliased pointers both freed)
- Pointer dereference patterns with aliasing

Use this tool when you need to:
- Understand pointer relationships in code
- Identify if multiple pointers point to the same memory
- Verify use-after-free or double-free candidates
- Analyze complex pointer interactions
- Find potential memory safety issues related to aliasing

The tool returns:
- aliasing_groups: Groups of pointers that may alias (point to same memory)
- assignment_relationships: Direct pointer assignments (ptr1 = ptr2)
- potential_issues: List of potential aliasing-related bugs
- dereference_patterns: Pointer dereferences with aliasing context
- summary: Summary of aliasing analysis

Remember: Always cross-check tool results with actual code analysis. Low confidence scores (<0.6) are especially unreliable.

Important: In this environment, the current working directory is workdir. Kernel source code
lives under workdir/crash-* directories (each crash-* is the kernel tree for the commit where
a crash occurred). Do not use workdir/linux. When calling this tool, use file paths under
workdir/crash-* (e.g. workdir/crash-<id>/fs/btrfs/qgroup.c).'''
    args_schema: Optional[ArgsSchema] = AnalyzePointerAliasingToolInput

    ALLOC_FUNCTIONS: List[str] = [
        'kmalloc', 'kzalloc', 'kcalloc', 'vmalloc', 'vzalloc',
        'kmalloc_noprof', 'kzalloc_noprof',
        'alloc_pages', 'get_free_pages', 'kmem_cache_alloc',
        'kmem_cache_zalloc', 'devm_kmalloc', 'devm_kzalloc',
        'alloc_skb', 'dev_alloc_skb', 'netdev_alloc_skb'
    ]
    
    FREE_FUNCTIONS: List[str] = [
        'kfree', 'vfree', 'free_pages', 'kmem_cache_free',
        'put_page', 'slab_free', 'devm_kfree',
        'kfree_skb', 'dev_kfree_skb', 'consume_skb'
    ]

    def __init__(self):
        super().__init__()

    def _run(self, file_path: str, reason: str, function_name: Optional[str] = None, pointer_name: Optional[str] = None):
        print(f'[Tool] AnalyzePointerAliasingTool: {file_path} {function_name} {pointer_name} {reason}')
        if not CLANG_AVAILABLE:
            return json.dumps({
                'error': 'libclang not available',
                'file_path': file_path,
                'function_name': function_name,
                'pointer_name': pointer_name
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
            result = self._analyze_aliasing(file_path, function_name, pointer_name)
            os.chdir(cur_dir)
            return json.dumps(result, indent=2)
        except Exception as e:
            import traceback
            os.chdir(cur_dir)
            return json.dumps({
                'error': f'Error during analysis: {str(e)}',
                'traceback': traceback.format_exc(),
                'file_path': file_path,
                'function_name': function_name,
                'pointer_name': pointer_name
            }, indent=2)

    def _analyze_aliasing(self, file_path: str, function_name: Optional[str] = None, target_pointer: Optional[str] = None):
        """Analyze pointer aliasing using libclang"""
        # Remove crash-* prefix if present (we're already in crash-* directory)
        if '/' in file_path:
            parts = file_path.split('/', 1)
            if len(parts) > 1 and parts[0].startswith('crash-'):
                file_path = parts[1]
        
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
                return self._analyze_function_aliasing(function_cursor, file_path, target_pointer)
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
                            func_result = self._analyze_function_aliasing(cursor, file_path, target_pointer)
                            func_result['function_name'] = cursor.spelling
                            all_results['functions'].append(func_result)
            
            return all_results

    def _analyze_function_aliasing(self, function_cursor, file_path: str, target_pointer: Optional[str] = None):
        """Analyze pointer aliasing in a single function"""
        # Track pointer assignments: left_var -> right_var (left points to what right points to)
        assignments: Dict[str, List[Tuple[str, int]]] = {}  # var -> [(aliased_var, line), ...]
        
        # Track memory allocations: var -> (line, alloc_func)
        allocations: Dict[str, Tuple[int, str]] = {}
        
        # Track memory deallocations: var -> (line, free_func)
        deallocations: Dict[str, Tuple[int, str]] = {}
        
        # Track pointer dereferences: (var, line)
        dereferences: List[Tuple[str, int]] = []
        
        # Track function parameters
        function_params = set()
        for child in function_cursor.get_children():
            if child.kind == CursorKind.PARM_DECL:
                function_params.add(child.spelling)
        
        actual_file_path = function_cursor.location.file.name if function_cursor.location.file else file_path
        
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
                            if target_pointer is None or var_name == target_pointer:
                                allocations[var_name] = (line, func_name)
                    
                    elif func_name in self.FREE_FUNCTIONS:
                        var_name = self._get_argument_variable(cursor, 0)
                        if var_name:
                            if target_pointer is None or var_name == target_pointer:
                                deallocations[var_name] = (line, func_name)
            
            # Track pointer assignments (ptr1 = ptr2)
            elif cursor.kind == CursorKind.BINARY_OPERATOR:
                tokens = list(cursor.get_tokens())
                if '=' in [t.spelling for t in tokens]:
                    left_var, right_var = self._get_assignment_variables(cursor)
                    if left_var and right_var and not self._is_macro_variable(left_var) and not self._is_macro_variable(right_var):
                        if target_pointer is None or left_var == target_pointer or right_var == target_pointer:
                            if left_var not in assignments:
                                assignments[left_var] = []
                            assignments[left_var].append((right_var, line))
            
            # Track pointer dereferences
            elif cursor.kind == CursorKind.UNARY_OPERATOR:
                tokens = list(cursor.get_tokens())
                if any(t.spelling == '*' for t in tokens):
                    var_name = self._get_dereferenced_variable(cursor)
                    if var_name and not self._is_macro_variable(var_name):
                        if target_pointer is None or var_name == target_pointer:
                            dereferences.append((var_name, line))
            
            elif cursor.kind == CursorKind.MEMBER_REF_EXPR:
                var_name = self._get_base_variable(cursor)
                if var_name and not self._is_macro_variable(var_name):
                    if target_pointer is None or var_name == target_pointer:
                        dereferences.append((var_name, line))
            
            # Recursively visit children
            for child in cursor.get_children():
                visit_cursor(child)
        
        visit_cursor(function_cursor)
        
        # Build aliasing groups using transitive closure
        aliasing_groups = self._build_aliasing_groups(assignments, allocations)
        
        # Find potential issues
        potential_issues = self._find_aliasing_issues(
            aliasing_groups, assignments, allocations, deallocations, dereferences
        )
        
        # Build assignment relationships summary
        assignment_relationships = []
        for left_var, aliases in assignments.items():
            for right_var, line in aliases:
                assignment_relationships.append({
                    'left': left_var,
                    'right': right_var,
                    'line': line,
                    'description': f'{left_var} = {right_var}'
                })
        
        # Build dereference patterns with aliasing context
        dereference_patterns = []
        for var, line in dereferences:
            aliases = self._get_aliases(var, aliasing_groups)
            dereference_patterns.append({
                'variable': var,
                'line': line,
                'aliases': aliases,
                'has_aliases': len(aliases) > 0
            })
        
        return {
            'file_path': file_path,
            'function_name': function_cursor.spelling,
            'aliasing_groups': aliasing_groups,
            'assignment_relationships': assignment_relationships,
            'potential_issues': potential_issues,
            'dereference_patterns': dereference_patterns,
            'summary': self._generate_summary(
                aliasing_groups, assignment_relationships, potential_issues
            ),
            'statistics': {
                'total_pointers': len(set([v for v in allocations.keys()] + 
                                          [v for v in deallocations.keys()] + 
                                          [v for v in assignments.keys()] + 
                                          [v for v, _ in dereferences])),
                'aliasing_groups_count': len(aliasing_groups),
                'assignments_count': len(assignment_relationships),
                'potential_issues_count': len(potential_issues)
            }
        }

    def _build_aliasing_groups(self, assignments: Dict[str, List[Tuple[str, int]]], 
                               allocations: Dict[str, Tuple[int, str]]) -> List[Dict]:
        """Build groups of pointers that may alias (point to same memory)"""
        # Build a graph of aliasing relationships
        aliasing_graph: Dict[str, Set[str]] = {}
        
        # Initialize graph with all variables
        all_vars = set(assignments.keys())
        for aliases in assignments.values():
            for alias, _ in aliases:
                all_vars.add(alias)
        all_vars.update(allocations.keys())
        
        for var in all_vars:
            aliasing_graph[var] = {var}  # Each var aliases itself
        
        # Add direct assignments
        for left_var, aliases in assignments.items():
            for right_var, _ in aliases:
                aliasing_graph[left_var].add(right_var)
                aliasing_graph[right_var].add(left_var)
        
        # Compute transitive closure (if A = B and B = C, then A, B, C all alias)
        changed = True
        while changed:
            changed = False
            for var in aliasing_graph:
                new_aliases = set(aliasing_graph[var])
                for alias in list(aliasing_graph[var]):
                    if alias in aliasing_graph:
                        new_aliases.update(aliasing_graph[alias])
                if new_aliases != aliasing_graph[var]:
                    aliasing_graph[var] = new_aliases
                    changed = True
        
        # Group variables that alias each other
        groups = []
        processed = set()
        
        for var in aliasing_graph:
            if var in processed:
                continue
            
            group = aliasing_graph[var]
            if len(group) > 1:  # Only groups with multiple pointers
                groups.append({
                    'pointers': sorted(list(group)),
                    'size': len(group),
                    'description': f'Pointers that may alias: {", ".join(sorted(group))}'
                })
                processed.update(group)
        
        return groups

    def _find_aliasing_issues(self, aliasing_groups: List[Dict], 
                               assignments: Dict[str, List[Tuple[str, int]]],
                               allocations: Dict[str, Tuple[int, str]],
                               deallocations: Dict[str, Tuple[int, str]],
                               dereferences: List[Tuple[str, int]]) -> List[Dict]:
        """Find potential issues related to pointer aliasing"""
        issues = []
        
        # Issue 1: Use-after-free via aliasing
        # If ptr1 is freed, and ptr2 aliases ptr1, and ptr2 is used after free
        for freed_var, (free_line, free_func) in deallocations.items():
            aliases = self._get_aliases(freed_var, aliasing_groups)
            for alias_var in aliases:
                if alias_var == freed_var:
                    continue
                # Check if alias is dereferenced after free
                for deref_var, deref_line in dereferences:
                    if deref_var == alias_var and deref_line > free_line:
                        issues.append({
                            'type': 'use_after_free_via_aliasing',
                            'severity': 'high',
                            'confidence': 0.7,
                            'description': (
                                f'Pointer {freed_var} freed at line {free_line}, '
                                f'but aliased pointer {alias_var} dereferenced at line {deref_line}'
                            ),
                            'freed_pointer': freed_var,
                            'freed_line': free_line,
                            'aliased_pointer': alias_var,
                            'dereference_line': deref_line
                        })
        
        # Issue 2: Double-free via aliasing
        # If ptr1 and ptr2 alias, and both are freed
        for freed_var1, (free_line1, _) in deallocations.items():
            aliases = self._get_aliases(freed_var1, aliasing_groups)
            for freed_var2, (free_line2, _) in deallocations.items():
                if freed_var1 == freed_var2:
                    continue
                if freed_var2 in aliases:
                    issues.append({
                        'type': 'double_free_via_aliasing',
                        'severity': 'high',
                        'confidence': 0.8,
                        'description': (
                            f'Pointers {freed_var1} and {freed_var2} alias each other, '
                            f'and both are freed (lines {free_line1} and {free_line2})'
                        ),
                        'pointer1': freed_var1,
                        'free_line1': free_line1,
                        'pointer2': freed_var2,
                        'free_line2': free_line2
                    })
        
        # Issue 3: Dereference of uninitialized alias
        # If ptr1 = ptr2, and ptr2 is never allocated/initialized
        for left_var, aliases in assignments.items():
            for right_var, assign_line in aliases:
                if right_var not in allocations and right_var not in deallocations:
                    # Check if right_var is dereferenced
                    for deref_var, deref_line in dereferences:
                        if deref_var == left_var and deref_line > assign_line:
                            issues.append({
                                'type': 'dereference_uninitialized_alias',
                                'severity': 'medium',
                                'confidence': 0.6,
                                'description': (
                                    f'Pointer {left_var} assigned from {right_var} at line {assign_line}, '
                                    f'but {right_var} may be uninitialized when {left_var} is dereferenced at line {deref_line}'
                                ),
                                'assigned_pointer': left_var,
                                'source_pointer': right_var,
                                'assignment_line': assign_line,
                                'dereference_line': deref_line
                            })
        
        return issues

    def _get_aliases(self, var: str, aliasing_groups: List[Dict]) -> List[str]:
        """Get all aliases of a variable"""
        for group in aliasing_groups:
            if var in group['pointers']:
                return [v for v in group['pointers'] if v != var]
        return []

    def _generate_summary(self, aliasing_groups: List[Dict], 
                         assignment_relationships: List[Dict],
                         potential_issues: List[Dict]) -> str:
        """Generate a summary of the aliasing analysis"""
        summary_parts = []
        
        summary_parts.append(f'Found {len(aliasing_groups)} aliasing group(s) with {sum(g["size"] for g in aliasing_groups)} total pointers.')
        summary_parts.append(f'Found {len(assignment_relationships)} pointer assignment(s).')
        
        if potential_issues:
            summary_parts.append(f'Found {len(potential_issues)} potential aliasing-related issue(s):')
            for issue in potential_issues[:5]:  # Show first 5
                summary_parts.append(f'  - {issue["type"]}: {issue["description"]}')
        else:
            summary_parts.append('No obvious aliasing-related issues detected.')
        
        return '\n'.join(summary_parts)

    # Helper methods for extracting information from AST
    def _get_function_name(self, cursor):
        """Get function name from call expression"""
        if cursor.kind == CursorKind.CALL_EXPR:
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

    def _is_macro_variable(self, var_name: str) -> bool:
        """Check if variable name is a macro (e.g., __UNIQUE_ID_*)"""
        if not var_name:
            return True
        # Filter out common macro patterns
        if var_name.startswith('__UNIQUE_ID_'):
            return True
        if var_name.startswith('__') and var_name.endswith('__'):
            return True
        if var_name.startswith('__builtin_'):
            return True
        return False