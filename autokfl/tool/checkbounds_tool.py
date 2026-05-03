import os
import json
import re
from typing import Optional, ClassVar, List, Dict, Tuple, Set
from pydantic import BaseModel, Field
from langchain_core.tools import BaseTool
from langchain_core.tools.base import ArgsSchema

try:
    import clang.cindex as ci
    from clang.cindex import CursorKind, TokenKind
    CLANG_AVAILABLE = True
except ImportError:
    CLANG_AVAILABLE = False


class CheckBoundsToolInput(BaseModel):
    file_path: str = Field(
        description='Path to the file relative to the kernel source root (e.g. fs/btrfs/qgroup.c)'
    )
    function_name: Optional[str] = Field(
        default=None,
        description='Name of the function to analyze. If not provided, analyzes the entire file.'
    )
    array_name: Optional[str] = Field(
        default=None,
        description='Specific array/buffer variable name to check. If provided, only checks bounds for this variable.'
    )
    reason: str = Field(
        description='The reason why you need to check bounds for this code'
    )


class CheckBoundsTool(BaseTool):
    name: str = 'check_bounds'
    description: str = '''Check for buffer/array bounds violations in C kernel code.
    
IMPORTANT WARNINGS:
- This tool provides CANDIDATE locations where bounds checking may be missing
- Results may contain FALSE POSITIVES - always verify with code review
- Confidence scores are heuristic estimates, not guarantees
- You MUST analyze the code yourself to validate these findings
- Use this tool to get hints, not as definitive evidence

This tool analyzes code for potential buffer overflow/underflow issues:
- Array/buffer access without bounds checking
- Index out of bounds access
- Negative index access
- Buffer size mismatches
- Loop bounds violations

Use this tool when you need to:
- Identify potential buffer overflow vulnerabilities
- Check if array accesses are properly bounded
- Find suspicious index calculations
- Analyze buffer size validation

The tool returns:
- bounds_violations: List of POTENTIAL bounds violation locations with file, line, array name, index expression, and confidence score (0.0-1.0)
- bounds_checks: List of bounds checks found in the code
- array_accesses: All array/buffer accesses found
- summary: Summary of bounds checking analysis

Remember: Always cross-check tool results with actual code analysis. Low confidence scores (<0.6) are especially unreliable.

Important: In this environment, the current working directory is workdir. Kernel source code
lives under workdir/crash-* directories (each crash-* is the kernel tree for the commit where
a crash occurred). Do not use workdir/linux. When calling this tool, use file paths under
workdir/crash-* (e.g. workdir/crash-<id>/fs/btrfs/qgroup.c).'''
    args_schema: Optional[ArgsSchema] = CheckBoundsToolInput

    def __init__(self):
        super().__init__()

    def _run(self, file_path: str, reason: str, function_name: Optional[str] = None, array_name: Optional[str] = None):
        print(f'[Tool] CheckBoundsTool: {file_path} {function_name} {array_name} {reason}')
        if not CLANG_AVAILABLE:
            return json.dumps({
                'error': 'libclang not available',
                'file_path': file_path,
                'function_name': function_name,
                'array_name': array_name
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
            result = self._analyze_bounds(file_path, function_name, array_name)
            os.chdir(cur_dir)
            return json.dumps(result, indent=2)
        except Exception as e:
            os.chdir(cur_dir)
            return json.dumps({
                'error': f'Error during analysis: {str(e)}',
                'file_path': file_path,
                'function_name': function_name,
                'array_name': array_name
            }, indent=2)

    def _analyze_bounds(self, file_path: str, function_name: Optional[str] = None, array_name: Optional[str] = None):
        """Analyze code for bounds violations using libclang"""
        index = ci.Index.create()
        args = ['-I', '.', '-I', 'include', '-D__KERNEL__', '-Wno-everything']
        tu = index.parse(file_path, args=args, options=ci.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD)
        
        if tu is None:
            return {'error': 'Failed to parse file', 'file_path': file_path}
        
        bounds_violations = []
        bounds_checks = []
        array_accesses = []
        
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
                result = self._analyze_function_bounds(function_cursor, file_path, array_name)
                bounds_violations.extend(result['violations'])
                bounds_checks.extend(result['checks'])
                array_accesses.extend(result['accesses'])
            else:
                return {'error': f'Function {function_name} not found', 'file_path': file_path}
        else:
            for cursor in tu.cursor.walk_preorder():
                if (cursor.kind == CursorKind.FUNCTION_DECL and 
                    cursor.is_definition()):
                    if cursor.location.file:
                        cursor_file = os.path.abspath(cursor.location.file.name)
                        if cursor_file == abs_file_path or cursor_file.endswith(file_path):
                            result = self._analyze_function_bounds(cursor, file_path, array_name)
                            bounds_violations.extend(result['violations'])
                            bounds_checks.extend(result['checks'])
                            array_accesses.extend(result['accesses'])
        
        bounds_violations.sort(key=lambda x: x.get('confidence', 0), reverse=True)
        
        summary = {
            'total_violations': len(bounds_violations),
            'total_checks': len(bounds_checks),
            'total_accesses': len(array_accesses),
            'violations_by_array': {}
        }
        
        for violation in bounds_violations:
            arr_name = violation.get('array_name', 'unknown')
            if arr_name not in summary['violations_by_array']:
                summary['violations_by_array'][arr_name] = 0
            summary['violations_by_array'][arr_name] += 1
        
        return {
            'file_path': file_path,
            'function_name': function_name,
            'array_name': array_name,
            'bounds_violations': bounds_violations,
            'bounds_checks': bounds_checks,
            'array_accesses': array_accesses,
            'summary': summary,
            'warning': (
                'These are POTENTIAL bounds violation candidates, not confirmed bugs. '
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

    def _analyze_function_bounds(self, function_cursor, file_path: str, target_array: Optional[str] = None):
        """Analyze a single function for bounds violations"""
        violations = []
        checks = []
        accesses = []
        
        array_vars = set()
        array_sizes = {}
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
            
            file_matches = (
                cursor_basename == expected_basename or 
                cursor_basename == os.path.basename(actual_file_path) or
                os.path.abspath(cursor_file) == os.path.abspath(file_path) or
                os.path.abspath(cursor_file).endswith(file_path)
            )
            
            if not file_matches:
                return
            
            line = loc.line
            
            if cursor.kind == CursorKind.ARRAY_SUBSCRIPT_EXPR:
                array_info = self._extract_array_access(cursor)
                if array_info:
                    arr_name, index_expr, index_line = array_info
                    
                    if target_array and arr_name != target_array:
                        return
                    
                    array_vars.add(arr_name)
                    accesses.append({
                        'file': file_path,
                        'line': index_line,
                        'array_name': arr_name,
                        'index_expression': index_expr,
                        'code': self._get_code_snippet(cursor)
                    })
                    
                    has_bounds_check = self._has_bounds_check_before(
                        function_cursor, arr_name, index_line
                    )
                    
                    is_safe_index = self._is_safe_index(index_expr, arr_name, function_cursor)
                    
                    array_size = array_sizes.get(arr_name)
                    
                    if not has_bounds_check and not is_safe_index:
                        confidence = 0.7
                        if array_size:
                            if self._index_exceeds_size(index_expr, array_size):
                                confidence = 0.9
                        elif arr_name in function_params:
                            confidence = 0.8
                        
                        violations.append({
                            'file': file_path,
                            'line': index_line,
                            'array_name': arr_name,
                            'index_expression': index_expr,
                            'confidence': confidence,
                            'issue_type': 'missing_bounds_check',
                            'description': f'Array access {arr_name}[{index_expr}] without apparent bounds check',
                            'code': self._get_code_snippet(cursor)
                        })
            
            if cursor.kind == CursorKind.BINARY_OPERATOR:
                tokens = list(cursor.get_tokens())
                if '=' in [t.spelling for t in tokens]:
                    size_info = self._extract_size_assignment(cursor)
                    if size_info:
                        var_name, size_value = size_info
                        if var_name in array_vars or var_name.endswith('_size') or var_name.endswith('_len'):
                            array_sizes[var_name] = size_value
            
            if cursor.kind == CursorKind.IF_STMT or cursor.kind == CursorKind.FOR_STMT:
                check_info = self._extract_bounds_check(cursor)
                if check_info:
                    checks.append({
                        'file': file_path,
                        'line': line,
                        'array_name': check_info.get('array_name'),
                        'check_type': check_info.get('check_type'),
                        'code': self._get_code_snippet(cursor)
                    })
            
            for child in cursor.get_children():
                visit_cursor(child)
        
        visit_cursor(function_cursor)
        
        return {
            'violations': violations,
            'checks': checks,
            'accesses': accesses
        }

    def _extract_array_access(self, cursor):
        """Extract array name and index from ARRAY_SUBSCRIPT_EXPR"""
        children = list(cursor.get_children())
        if len(children) < 2:
            return None
        
        array_cursor = children[0]
        index_cursor = children[1]
        
        array_name = None
        
        if array_cursor.kind == CursorKind.DECL_REF_EXPR:
            array_name = array_cursor.spelling
        
        elif array_cursor.kind == CursorKind.MEMBER_REF_EXPR:
            tokens = list(array_cursor.get_tokens())
            if tokens:
                parts = []
                for token in tokens:
                    if token.spelling not in ['->', '.']:
                        parts.append(token.spelling)
                array_name = ''.join(parts)
        
        else:
            for desc in array_cursor.walk_preorder():
                if desc.kind == CursorKind.DECL_REF_EXPR and desc.spelling:
                    parent = desc.semantic_parent
                    if parent and parent.kind == CursorKind.MEMBER_REF_EXPR:
                        tokens = list(parent.get_tokens())
                        if tokens:
                            parts = [t.spelling for t in tokens if t.spelling not in ['->', '.']]
                            array_name = '_'.join(parts)
                    else:
                        array_name = desc.spelling
                    break
        
        if not array_name:
            return None
        index_expr = self._get_expression_string(index_cursor)
        index_line = index_cursor.location.line if index_cursor.location else cursor.location.line
        
        return (array_name, index_expr, index_line)

    def _get_expression_string(self, cursor):
        """Get string representation of an expression"""
        tokens = list(cursor.get_tokens())
        if tokens:
            return ' '.join([t.spelling for t in tokens])
        return 'unknown'

    def _get_code_snippet(self, cursor):
        """Get code snippet for a cursor"""
        loc = cursor.location
        if not loc.file:
            return ''
        
        try:
            with open(loc.file.name, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                if 0 < loc.line <= len(lines):
                    return lines[loc.line - 1].strip()
        except:
            pass
        
        return ''

    def _has_bounds_check_before(self, function_cursor, array_name, line):
        """Check if there's a bounds check for array before given line"""
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
                    if self._is_bounds_check(cond, array_name):
                        return True
            
            elif cursor.kind == CursorKind.FOR_STMT:
                children = list(cursor.get_children())
                if len(children) >= 2:
                    cond = children[1]
                    if self._is_loop_bounds_check(cond, array_name):
                        return True
        
        return False

    def _is_loop_bounds_check(self, cursor, array_name):
        """Check if cursor represents a loop bounds check"""
        if cursor.kind == CursorKind.BINARY_OPERATOR:
            tokens = list(cursor.get_tokens())
            if any(t.spelling in ['<', '<='] for t in tokens):
                children = list(cursor.get_children())
                if len(children) >= 2:
                    left = children[0]
                    right = children[1]
                    
                    left_vars = self._extract_variables(left)
                    right_tokens = [t.spelling for t in list(right.get_tokens())]
                    
                    if left_vars and any('SIZE' in t or 'LAST' in t or t.isupper() for t in right_tokens):
                        return True
        
        return False

    def _is_bounds_check(self, cursor, array_name):
        """Check if cursor represents a bounds check for array_name"""
        if cursor.kind == CursorKind.BINARY_OPERATOR:
            tokens = list(cursor.get_tokens())
            comparison_ops = ['<', '<=', '>', '>=', '==', '!=']
            if any(t.spelling in comparison_ops for t in tokens):
                children = list(cursor.get_children())
                if len(children) >= 2:
                    left = children[0]
                    right = children[1]
                    
                    left_vars = self._extract_variables(left)
                    right_vars = self._extract_variables(right)
                    
                    if array_name in left_vars or array_name in right_vars:
                        all_tokens = [t.spelling for t in tokens]
                        size_indicators = ['size', 'len', 'length', 'count', 'limit', 'max']
                        if any(indicator in ' '.join(all_tokens).lower() for indicator in size_indicators):
                            return True
                        
                        if any(t.kind == TokenKind.LITERAL for t in tokens):
                            return True
        
        elif cursor.kind == CursorKind.CALL_EXPR:
            func_name = self._get_function_name(cursor)
            if func_name and any(name in func_name.lower() for name in ['warn', 'bug', 'check', 'verify']):
                for child in cursor.get_children():
                    if array_name in self._extract_variables(child):
                        return True
        
        return False

    def _extract_variables(self, cursor):
        """Extract all variable names from an expression"""
        variables = set()
        
        if cursor.kind == CursorKind.DECL_REF_EXPR:
            if cursor.spelling:
                variables.add(cursor.spelling)
        
        for child in cursor.get_children():
            variables.update(self._extract_variables(child))
        
        return variables

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

    def _is_safe_index(self, index_expr, array_name, function_cursor):
        """Check if index expression is provably safe"""
        index_expr_lower = index_expr.lower()
        
        if index_expr.strip().isdigit():
            return True
        
        if 'i' in index_expr or 'j' in index_expr or 'idx' in index_expr:
            for cursor in function_cursor.walk_preorder():
                if cursor.kind == CursorKind.FOR_STMT:
                    children = list(cursor.get_children())
                    if len(children) >= 2:
                        cond = children[1]
                        loop_code = self._get_code_snippet(cursor)
                        if ('<' in loop_code or '<=' in loop_code) and \
                        any(keyword in loop_code.upper() for keyword in ['SIZE', 'LAST', 'MAX', 'LIMIT']):
                            return True
        
        return False

    def _extract_size_assignment(self, cursor):
        """Extract size assignment information"""
        children = list(cursor.get_children())
        if len(children) < 2:
            return None
        
        left = children[0]
        right = children[1]
        
        var_name = None
        if left.kind == CursorKind.DECL_REF_EXPR:
            var_name = left.spelling
        else:
            for desc in left.walk_preorder():
                if desc.kind == CursorKind.DECL_REF_EXPR and desc.spelling:
                    var_name = desc.spelling
                    break
        
        if not var_name:
            return None
        
        size_value = None
        tokens = list(right.get_tokens())
        for token in tokens:
            if token.kind == TokenKind.LITERAL:
                try:
                    size_value = int(token.spelling)
                    break
                except:
                    pass
        
        if var_name:
            return (var_name, size_value)
        
        return None

    def _extract_bounds_check(self, cursor):
        """Extract bounds check information from IF_STMT or FOR_STMT"""
        children = list(cursor.get_children())
        if not children:
            return None
        
        check_info = {
            'check_type': 'unknown',
            'array_name': None
        }
        
        if cursor.kind == CursorKind.IF_STMT:
            cond = children[0]
            if cond.kind == CursorKind.BINARY_OPERATOR:
                tokens = list(cond.get_tokens())
                if any(t.spelling in ['<', '<=', '>', '>='] for t in tokens):
                    check_info['check_type'] = 'comparison'
                    vars_in_check = self._extract_variables(cond)
                    if vars_in_check:
                        check_info['array_name'] = list(vars_in_check)[0]
        
        elif cursor.kind == CursorKind.FOR_STMT:
            if len(children) >= 2:
                cond = children[1]
                if cond.kind == CursorKind.BINARY_OPERATOR:
                    tokens = list(cond.get_tokens())
                    if any(t.spelling in ['<', '<='] for t in tokens):
                        check_info['check_type'] = 'loop_bounds'
                        vars_in_check = self._extract_variables(cond)
                        if vars_in_check:
                            check_info['array_name'] = list(vars_in_check)[0]
        
        return check_info if check_info['array_name'] else None

    def _index_exceeds_size(self, index_expr, array_size):
        """Check if index expression might exceed array size"""
        if not array_size:
            return False
        
        index_expr = index_expr.strip()
        
        if index_expr.isdigit():
            return int(index_expr) >= array_size
        
        if '+' in index_expr:
            parts = index_expr.split('+')
            try:
                base = int(parts[0].strip())
                if base >= array_size:
                    return True
            except:
                pass
        
        return False