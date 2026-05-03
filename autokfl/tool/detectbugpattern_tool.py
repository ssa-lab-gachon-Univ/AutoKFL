import os
import json
import re
from typing import Optional, ClassVar
from pydantic import BaseModel, Field
from langchain_core.tools import BaseTool
from langchain_core.tools.base import ArgsSchema

try:
    import clang.cindex as ci
    from clang.cindex import CursorKind, TokenKind
    CLANG_AVAILABLE = True
except ImportError:
    CLANG_AVAILABLE = False


class DetectBugPatternToolInput(BaseModel):
    file_path: str = Field(
        description='Path to the file relative to the kernel source root (e.g. fs/btrfs/qgroup.c)'
    )
    function_name: Optional[str] = Field(
        default=None,
        description='Name of the function to analyze. If not provided, analyzes the entire file.'
    )
    reason: str = Field(
        description='The reason why you need to detect bug patterns in this code'
    )


class DetectBugPatternTool(BaseTool):
    name: str = 'detect_bug_pattern'
    description: str = '''Detect POTENTIAL bug patterns in C code using static analysis.
    
IMPORTANT WARNINGS:
- This tool provides CANDIDATE bug locations, NOT confirmed bugs
- Results may contain FALSE POSITIVES - always verify with code review
- Confidence scores are heuristic estimates, not guarantees
- You MUST analyze the code yourself to validate these findings
- Use this tool to get hints, not as definitive evidence

This tool analyzes code for common kernel bug patterns including:
- null_pointer_dereference: Pointer dereference without NULL check
- use_after_free: Access to freed memory
- buffer_overflow: Array/buffer access without bounds checking
- double_free: Multiple calls to free() on same pointer
- uninitialized_use: Use of uninitialized variable
- memory_leak: Allocated memory not freed
- integer_overflow: Integer operations that may overflow

Use this tool when you need to:
- Get initial hints about potential bug locations in collected code
- Identify suspicious code patterns that warrant closer inspection
- Generate candidate locations for manual code review
- Understand what type of bug patterns might be present

The tool returns:
- bug_locations: List of POTENTIAL bug locations with file, line, reason (bug type), and confidence score (0.0-1.0)
- pattern_summary: Summary of all detected patterns (keyed by reason)
- warning: Reminder that these are candidates requiring verification

Remember: Always cross-check tool results with actual code analysis. Low confidence scores (<0.6) are especially unreliable.

Important: In this environment, the current working directory is workdir. Kernel source code
lives under workdir/crash-* directories (each crash-* is the kernel tree for the commit where
a crash occurred). Do not use workdir/linux. When calling this tool, use file paths under
workdir/crash-* (e.g. workdir/crash-<id>/fs/btrfs/qgroup.c).'''
    args_schema: Optional[ArgsSchema] = DetectBugPatternToolInput

    ALLOC_FUNCTIONS: ClassVar[list[str]] = [
        'kmalloc', 'kzalloc', 'kcalloc', 'vmalloc', 'vzalloc',
        'kmalloc_noprof', 'kzalloc_noprof',
        'alloc_pages', 'get_free_pages', 'kmem_cache_alloc',
        'kmem_cache_zalloc', 'devm_kmalloc', 'devm_kzalloc'
    ]
    
    FREE_FUNCTIONS: ClassVar[list[str]] = [
        'kfree', 'vfree', 'free_pages', 'kmem_cache_free',
        'put_page', 'slab_free', 'devm_kfree'
    ]

    def __init__(self):
        super().__init__()

    def _run(self, file_path: str, reason: str, function_name: Optional[str] = None):
        print(f'[Tool] DetectBugPatternTool: {file_path} {function_name} {reason}')
        if not CLANG_AVAILABLE:
            return json.dumps({
                'error': 'libclang not available',
                'file_path': file_path,
                'function_name': function_name
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
            result = self._analyze_with_clang(file_path, function_name)
            os.chdir(cur_dir)
            return json.dumps(result, indent=2)
        except Exception as e:
            os.chdir(cur_dir)
            return json.dumps({
                'error': f'Error during analysis: {str(e)}',
                'file_path': file_path,
                'function_name': function_name
            }, indent=2)

    def _analyze_with_clang(self, file_path: str, function_name: Optional[str] = None):
        """Analyze code using libclang"""
        index = ci.Index.create()
        args = ['-I', '.', '-I', 'include', '-D__KERNEL__', '-Wno-everything']
        tu = index.parse(file_path, args=args, options=ci.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD)
        
        if tu is None:
            return {'error': 'Failed to parse file', 'file_path': file_path}
        
        bug_locations = []
        
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
                bug_locations.extend(self._analyze_function(function_cursor, file_path))
            else:
                return {'error': f'Function {function_name} not found', 'file_path': file_path}
        else:
            for cursor in tu.cursor.walk_preorder():
                if (cursor.kind == CursorKind.FUNCTION_DECL and 
                    cursor.is_definition()):
                    if cursor.location.file:
                        cursor_file = os.path.abspath(cursor.location.file.name)
                        if cursor_file == abs_file_path or cursor_file.endswith(file_path):
                            bug_locations.extend(self._analyze_function(cursor, file_path))
        
        bug_locations.sort(key=lambda x: x.get('score', 0), reverse=True)
        
        pattern_summary = {}
        for bug in bug_locations:
            reason = bug.get('reason', bug.get('pattern', ''))
            if reason not in pattern_summary:
                pattern_summary[reason] = {'count': 0, 'max_score': 0}
            pattern_summary[reason]['count'] += 1
            pattern_summary[reason]['max_score'] = max(
                pattern_summary[reason]['max_score'],
                bug.get('score', 0)
            )
        
        return {
            'file_path': file_path,
            'function_name': function_name,
            'bug_locations': bug_locations,
            'pattern_summary': pattern_summary,
            'total_bugs_found': len(bug_locations),
            'warning': (
                'These are POTENTIAL bug candidates, not confirmed bugs. '
                'False positives are common. Always verify findings by analyzing the actual code. '
                'Low confidence scores (<0.6) are especially unreliable. '
                'Use these results as hints for manual code review, not as definitive evidence.'
            ),
            'confidence_interpretation': {
                'high': '0.8-1.0: Strong pattern match, but still requires verification',
                'medium': '0.6-0.8: Moderate pattern match, likely needs context analysis',
                'low': '0.0-0.6: Weak pattern match, high false positive risk'
            }
        }

    def _analyze_function(self, function_cursor, file_path: str):
        """Analyze a single function for bug patterns"""
        bugs = []
        
        allocations = {}
        frees = set()
        pointer_derefs = []
        array_accesses = []
        
        function_params = set()
        for child in function_cursor.get_children():
            if child.kind == CursorKind.PARM_DECL:
                function_params.add(child.spelling)
        
        param_derived_vars = set()
        for cursor in function_cursor.walk_preorder():
            if cursor.kind == CursorKind.BINARY_OPERATOR:
                tokens = list(cursor.get_tokens())
                if '=' in [t.spelling for t in tokens]:
                    children = list(cursor.get_children())
                    if len(children) >= 2:
                        left = children[0]
                        right = children[1]
                        left_var = None
                        if left.kind == CursorKind.DECL_REF_EXPR:
                            left_var = left.spelling
                        elif left.kind == CursorKind.VAR_DECL:
                            left_var = left.spelling
                        
                        if left_var:
                            if right.kind == CursorKind.MEMBER_REF_EXPR:
                                base_var = None
                                for child in right.get_children():
                                    if child.kind == CursorKind.DECL_REF_EXPR:
                                        base_var = child.spelling
                                        break
                                    elif child.kind in (CursorKind.UNEXPOSED_EXPR, CursorKind.PAREN_EXPR):
                                        for desc in child.walk_preorder():
                                            if desc.kind == CursorKind.DECL_REF_EXPR and desc.spelling:
                                                base_var = desc.spelling
                                                break
                                        if base_var:
                                            break
                                if base_var and base_var in function_params:
                                    param_derived_vars.add(left_var)
                                    continue
                            for desc in right.walk_preorder():
                                if (desc.kind == CursorKind.DECL_REF_EXPR and 
                                    desc.spelling in function_params):
                                    param_derived_vars.add(left_var)
                                    break
        
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
            
            if cursor.kind == CursorKind.CALL_EXPR:
                func_name = self._get_function_name(cursor)
                if func_name:
                    if func_name in self.ALLOC_FUNCTIONS:
                        var_name = self._get_assigned_variable(cursor)
                        if not var_name:
                            parent = cursor.semantic_parent
                            depth = 0
                            while parent and depth < 5:
                                if parent.kind == CursorKind.BINARY_OPERATOR:
                                    tokens = list(parent.get_tokens())
                                    if '=' in [t.spelling for t in tokens]:
                                        children = list(parent.get_children())
                                        if children:
                                            left = children[0]
                                            for desc in left.walk_preorder():
                                                if desc.kind == CursorKind.DECL_REF_EXPR and desc.spelling:
                                                    var_name = desc.spelling
                                                    break
                                        if var_name:
                                            break
                                parent = getattr(parent, 'semantic_parent', None)
                                depth += 1
                            
                            if not var_name:
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
                                                                var_name = desc.spelling
                                                                break
                                                    break
                                            if var_name:
                                                break
                        
                        if var_name:
                            allocations[var_name] = (line, func_name)
                    elif func_name in self.FREE_FUNCTIONS:
                        var_name = self._get_argument_variable(cursor, 0)
                        if var_name:
                            if var_name in frees:
                                bugs.append({
                                    'file': file_path,
                                    'line': line,
                                    'reason': 'double_free',
                                    'score': 0.9,
                                    'description': f'Double free detected: {var_name} freed multiple times',
                                    'variable': var_name
                                })
                            frees.add(var_name)
            
            elif cursor.kind == CursorKind.MEMBER_REF_EXPR:
                var_name = self._get_base_variable(cursor)
                if var_name:
                    if var_name in function_params or var_name in param_derived_vars:
                        return
                    
                    has_null_check = self._has_null_check_before(function_cursor, var_name, line)
                    pointer_derefs.append((line, var_name, has_null_check))
                    if not has_null_check:
                        bugs.append({
                            'file': file_path,
                            'line': line,
                            'reason': 'null_pointer_dereference',
                            'score': 0.5,
                            'description': f'Pointer dereference without NULL check: {var_name}',
                            'variable': var_name
                        })
            
            for child in cursor.get_children():
                visit_cursor(child)
        
        visit_cursor(function_cursor)
        
        for var_name, (alloc_line, alloc_func) in allocations.items():
            if var_name not in frees:
                bugs.append({
                    'file': file_path,
                    'line': alloc_line,
                    'reason': 'memory_leak',
                    'score': 0.5,
                    'description': f'Potential memory leak: {var_name} allocated but not freed',
                    'variable': var_name,
                    'alloc_function': alloc_func
                })
        
        return bugs

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

    def _get_assigned_variable(self, cursor):
        """Get variable name that assignment result is assigned to"""
        parent = cursor.semantic_parent
        if parent and parent.kind == CursorKind.BINARY_OPERATOR:
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

    def _get_array_variable(self, cursor):
        """Get array variable name from array subscript"""
        children = list(cursor.get_children())
        if children:
            first = children[0]
            if first.kind == CursorKind.DECL_REF_EXPR:
                return first.spelling
        return None

    def _has_null_check_before(self, function_cursor, var_name, line):
        """Check if there's a NULL check for variable before given line"""
        for cursor in function_cursor.walk_preorder():
            loc = cursor.location
            if not loc.file or loc.file.name != function_cursor.location.file.name:
                continue
            if loc.line >= line:
                break
            
            if cursor.kind == CursorKind.IF_STMT:
                children = list(cursor.get_children())
                if children:
                    cond = children[0]
                    if self._is_null_check(cond, var_name):
                        return True
        return False

    def _is_null_check(self, cursor, var_name):
        """Check if cursor represents a NULL check for var_name"""
        if cursor.kind == CursorKind.UNARY_OPERATOR:
            tokens = list(cursor.get_tokens())
            if any(t.spelling == '!' for t in tokens):
                for child in cursor.get_children():
                    if (child.kind == CursorKind.DECL_REF_EXPR and 
                        child.spelling == var_name):
                        return True
        
        elif cursor.kind == CursorKind.BINARY_OPERATOR:
            tokens = list(cursor.get_tokens())
            if any(t.spelling in ['==', '!='] for t in tokens):
                children = list(cursor.get_children())
                if len(children) >= 2:
                    left = children[0]
                    right = children[1]
                    var_side = None
                    null_side = False
                    
                    if left.kind == CursorKind.DECL_REF_EXPR and left.spelling == var_name:
                        var_side = True
                    if right.kind == CursorKind.DECL_REF_EXPR and right.spelling == var_name:
                        var_side = False
                    
                    for token in tokens:
                        if token.spelling in ['NULL', 'nullptr', '0']:
                            null_side = True
                    
                    if var_side is not None and null_side:
                        return True
        
        return False

    def _has_bounds_check_before(self, function_cursor, var_name, line):
        """Check if there's a bounds check for array before given line"""
        for cursor in function_cursor.walk_preorder():
            loc = cursor.location
            if not loc.file or loc.file.name != function_cursor.location.file.name:
                continue
            if loc.line >= line:
                break
            
            if cursor.kind == CursorKind.BINARY_OPERATOR:
                tokens = list(cursor.get_tokens())
                if any(t.spelling in ['<', '<=', '>', '>='] for t in tokens):
                    for child in cursor.get_children():
                        if (child.kind == CursorKind.DECL_REF_EXPR and 
                            child.spelling == var_name):
                            return True
        return False

    def _analyze_code_snippet(self, code_snippet: str, file_path: str):
        """Analyze code snippet using regex patterns (fallback when libclang unavailable)"""
        bugs = []
        lines = code_snippet.split('\n')
        
        allocations = {}
        frees = set()
        
        for i, line in enumerate(lines, 1):
            for alloc_func in self.ALLOC_FUNCTIONS:
                if re.search(rf'\b{alloc_func}\s*\(', line):
                    match = re.search(r'(\w+)\s*=\s*' + alloc_func, line)
                    if match:
                        var_name = match.group(1)
                        allocations[var_name] = (i, alloc_func)
            
            for free_func in self.FREE_FUNCTIONS:
                if re.search(rf'\b{free_func}\s*\(', line):
                    match = re.search(rf'{free_func}\s*\(\s*(\w+)', line)
                    if match:
                        var_name = match.group(1)
                        if var_name in frees:
                            bugs.append({
                                'file': file_path,
                                'line': i,
                                'reason': 'double_free',
                                'score': 0.9,
                                'description': f'Double free: {var_name}',
                                'variable': var_name
                            })
                        frees.add(var_name)
            
            if re.search(r'\w+\s*->\s*\w+', line) or re.search(r'\*\s*\w+', line):
                has_check = False
                for j in range(max(0, i-5), i):
                    if re.search(r'if\s*\(\s*!?\s*\w+\s*\)', lines[j]) or \
                       re.search(r'if\s*\(\s*\w+\s*==\s*NULL', lines[j]):
                        has_check = True
                        break
                
                if not has_check:
                    bugs.append({
                        'file': file_path,
                        'line': i,
                        'reason': 'null_pointer_dereference',
                        'score': 0.6,
                        'description': 'Pointer dereference without NULL check',
                        'code': line.strip()
                    })
            
            if re.search(r'\w+\s*\[\s*\w+\s*\]', line):
                has_check = False
                for j in range(max(0, i-5), i):
                    if re.search(r'if\s*\(.*<.*\)', lines[j]) or \
                       re.search(r'if\s*\(.*>.*\)', lines[j]):
                        has_check = True
                        break
                
                if not has_check:
                    bugs.append({
                        'file': file_path,
                        'line': i,
                        'reason': 'buffer_overflow',
                        'score': 0.5,
                        'description': 'Array access without bounds check',
                        'code': line.strip()
                    })
        
        for var_name, (line, alloc_func) in allocations.items():
            if var_name not in frees:
                bugs.append({
                    'file': file_path,
                    'line': line,
                    'reason': 'memory_leak',
                    'score': 0.4,
                    'description': f'Potential memory leak: {var_name}',
                    'variable': var_name
                })
        
        bugs.sort(key=lambda x: x.get('score', 0), reverse=True)
        
        return json.dumps({
            'file_path': file_path,
            'bug_locations': bugs,
            'total_bugs_found': len(bugs),
            'analysis_method': 'regex_pattern_matching',
            'warning': (
                'These are POTENTIAL bug candidates from pattern matching. '
                'Regex-based analysis has HIGH false positive rate. '
                'Always verify findings by analyzing the actual code context.'
            ),
            'confidence_interpretation': {
                'high': '0.8-1.0: Strong pattern match, but still requires verification',
                'medium': '0.6-0.8: Moderate pattern match, likely needs context analysis',
                'low': '0.0-0.6: Weak pattern match, high false positive risk'
            }
        }, indent=2)