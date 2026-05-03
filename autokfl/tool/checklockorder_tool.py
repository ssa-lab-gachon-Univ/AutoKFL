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


class CheckLockOrderToolInput(BaseModel):
    file_path: str = Field(
        description='Path to the file relative to the kernel source root (e.g. fs/btrfs/qgroup.c)'
    )
    function_name: Optional[str] = Field(
        default=None,
        description='Name of the function to analyze. If not provided, analyzes the entire file.'
    )
    reason: str = Field(
        description='The reason why you need to check lock order in this code'
    )


class CheckLockOrderTool(BaseTool):
    name: str = 'check_lock_order'
    description: str = '''Check for lock ordering issues and potential deadlocks in C kernel code.
    
IMPORTANT WARNINGS:
- This tool provides CANDIDATE lock ordering issues, NOT confirmed deadlocks
- Results may contain FALSE POSITIVES - always verify with code review
- Confidence scores are heuristic estimates, not guarantees
- You MUST analyze the code yourself to validate these findings
- Use this tool to get hints, not as definitive evidence

This tool analyzes code for:
- Lock acquisition order: Tracks order in which locks are acquired
- Lock dependency graph: Builds graph of lock dependencies
- Potential deadlocks: Detects circular dependencies in lock acquisition
- Race conditions: Identifies shared resource access without proper locking
- Lock/unlock mismatches: Detects missing unlocks or double unlocks

Use this tool when you need to:
- Understand lock ordering in a function or file
- Identify potential deadlock scenarios
- Analyze concurrent access patterns
- Find lock-related bug patterns
- Verify lock acquisition/release pairs

The tool returns:
- lock_operations: List of lock acquisitions and releases with line numbers
- lock_order_graph: Graph showing lock acquisition order
- potential_deadlocks: List of potential deadlock scenarios
- lock_pairs: Matched lock/unlock pairs
- potential_race_conditions: List of potential race conditions
- summary: Summary of lock analysis results

Remember: Always cross-check tool results with actual code analysis. Low confidence scores (<0.6) are especially unreliable.

Important: In this environment, the current working directory is workdir. Kernel source code
lives under workdir/crash-* directories (each crash-* is the kernel tree for the commit where
a crash occurred). Do not use workdir/linux. When calling this tool, use file paths under
workdir/crash-* (e.g. workdir/crash-<id>/fs/btrfs/qgroup.c).'''
    args_schema: Optional[ArgsSchema] = CheckLockOrderToolInput

    # Lock acquisition functions
    LOCK_FUNCTIONS: List[str] = [
        # Mutex
        'mutex_lock', 'mutex_unlock', 'mutex_trylock', 'mutex_lock_interruptible',
        'mutex_lock_nested', 'mutex_unlock_nested',
        # Spinlock
        'spin_lock', 'spin_unlock', 'spin_trylock',
        'spin_lock_irq', 'spin_unlock_irq', 'spin_lock_irqsave', 'spin_unlock_irqrestore',
        'spin_lock_bh', 'spin_unlock_bh',
        # Read-Write locks
        'read_lock', 'read_unlock', 'write_lock', 'write_unlock',
        'read_lock_irq', 'read_unlock_irq', 'write_lock_irq', 'write_unlock_irq',
        'read_lock_irqsave', 'read_unlock_irqrestore', 'write_lock_irqsave', 'write_unlock_irqrestore',
        'read_lock_bh', 'read_unlock_bh', 'write_lock_bh', 'write_unlock_bh',
        # RCU
        'rcu_read_lock', 'rcu_read_unlock', 'rcu_read_lock_bh', 'rcu_read_unlock_bh',
        # Semaphore
        'down', 'up', 'down_interruptible', 'down_trylock',
        # Read-Write semaphore
        'down_read', 'down_write', 'up_read', 'up_write',
        'down_read_trylock', 'down_write_trylock',
        # Raw spinlock
        'raw_spin_lock', 'raw_spin_unlock', 'raw_spin_trylock',
        'raw_spin_lock_irq', 'raw_spin_unlock_irq',
        'raw_spin_lock_irqsave', 'raw_spin_unlock_irqrestore',
        'raw_spin_lock_bh', 'raw_spin_unlock_bh',
    ]

    def __init__(self):
        super().__init__()

    def _run(self, file_path: str, reason: str, function_name: Optional[str] = None):
        print(f'[Tool] CheckLockOrderTool: {file_path} {function_name} {reason}')
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
            result = self._check_lock_order(file_path, function_name)
            os.chdir(cur_dir)
            return json.dumps(result, indent=2)
        except Exception as e:
            import traceback
            os.chdir(cur_dir)
            return json.dumps({
                'error': f'Error during analysis: {str(e)}',
                'traceback': traceback.format_exc(),
                'file_path': file_path,
                'function_name': function_name
            }, indent=2)

    def _check_lock_order(self, file_path: str, function_name: Optional[str] = None):
        """Check lock ordering using libclang"""
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
                return self._analyze_function_locks(function_cursor, file_path)
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
                            func_result = self._analyze_function_locks(cursor, file_path)
                            func_result['function_name'] = cursor.spelling
                            all_results['functions'].append(func_result)
            
            return all_results

    def _analyze_function_locks(self, function_cursor, file_path: str):
        """Analyze lock operations in a single function"""
        lock_operations = []  # List of (line, operation_type, lock_var, lock_func)
        lock_variables = {}  # Track lock variables and their types
        lock_order_sequence = []  # Sequence of lock acquisitions
        lock_stack = []  # Stack to track nested locks
        
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
            
            # Track lock operations
            if cursor.kind == CursorKind.CALL_EXPR:
                func_name = self._get_function_name(cursor)
                if func_name and func_name in self.LOCK_FUNCTIONS:
                    lock_var = self._get_lock_variable(cursor, func_name)
                    operation_type = 'acquire' if 'unlock' not in func_name and 'up' not in func_name and 'complete' not in func_name else 'release'
                    
                    if lock_var:
                        lock_operations.append({
                            'line': line,
                            'operation': operation_type,
                            'function': func_name,
                            'variable': lock_var,
                            'context': self._get_code_context(cursor)
                        })
                        
                        if operation_type == 'acquire':
                            lock_order_sequence.append({
                                'line': line,
                                'lock_var': lock_var,
                                'lock_func': func_name
                            })
                            lock_stack.append(lock_var)
                            
                            # Store lock variable type
                            if lock_var not in lock_variables:
                                lock_variables[lock_var] = {
                                    'type': self._get_lock_type(func_name),
                                    'first_acquired': line
                                }
                        else:  # release
                            if lock_var in lock_stack:
                                lock_stack.remove(lock_var)
            
            for child in cursor.get_children():
                visit_cursor(child)
        
        visit_cursor(function_cursor)
        
        # Build lock order graph
        lock_order_graph = self._build_lock_order_graph(lock_order_sequence)
        
        # Detect potential deadlocks (circular dependencies)
        potential_deadlocks = self._detect_deadlocks(lock_order_sequence, lock_order_graph)
        
        # Match lock/unlock pairs
        lock_pairs = self._match_lock_pairs(lock_operations)
        
        # Detect potential race conditions
        potential_race_conditions = self._detect_race_conditions(function_cursor, lock_operations, file_path)
        
        # Detect lock/unlock mismatches
        lock_mismatches = self._detect_lock_mismatches(lock_operations, lock_variables)
        
        return {
            'file_path': file_path,
            'function_name': function_cursor.spelling if function_cursor else None,
            'lock_operations': lock_operations,
            'lock_order_graph': lock_order_graph,
            'potential_deadlocks': potential_deadlocks,
            'lock_pairs': lock_pairs,
            'potential_race_conditions': potential_race_conditions,
            'lock_mismatches': lock_mismatches,
            'summary': {
                'total_lock_operations': len(lock_operations),
                'total_locks': len(lock_variables),
                'lock_sequence_length': len(lock_order_sequence),
                'potential_deadlocks_count': len(potential_deadlocks),
                'matched_pairs': len(lock_pairs),
                'race_conditions_count': len(potential_race_conditions),
                'mismatches_count': len(lock_mismatches)
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

    def _get_lock_variable(self, cursor, lock_func: str):
        """Get the lock variable name from lock function call"""
        # Lock functions typically take the lock variable as first argument
        children = list(cursor.get_children())
        if len(children) > 1:
            # First child is usually the function reference, second is the argument
            arg_cursor = children[1]
            
            # Try to get variable name from argument
            if arg_cursor.kind == CursorKind.DECL_REF_EXPR:
                return arg_cursor.spelling
            elif arg_cursor.kind == CursorKind.UNARY_OPERATOR:
                # Handle &lock_var or *lock_var
                # Need to get the operand
                for child in arg_cursor.get_children():
                    if child.kind == CursorKind.MEMBER_REF_EXPR:
                        # Handle &struct->lock
                        base_var = self._get_base_variable(child)
                        member_name = self._get_member_name(child)
                        if base_var and member_name:
                            return f"{base_var}->{member_name}"
                    elif child.kind == CursorKind.DECL_REF_EXPR:
                        return child.spelling
            elif arg_cursor.kind == CursorKind.MEMBER_REF_EXPR:
                # Handle struct->lock or struct.lock
                base_var = self._get_base_variable(arg_cursor)
                member_name = self._get_member_name(arg_cursor)
                if base_var and member_name:
                    return f"{base_var}->{member_name}"
            
            # Fallback: try to extract from tokens
            tokens = list(arg_cursor.get_tokens())
            if tokens:
                # Filter out operators and parentheses, but keep structure
                var_parts = []
                for t in tokens:
                    if t.kind == TokenKind.IDENTIFIER:
                        var_parts.append(t.spelling)
                    elif t.spelling in ['->', '.']:
                        var_parts.append(t.spelling)
                if var_parts:
                    return ''.join(var_parts)
        
        return None

    def _get_base_variable(self, cursor):
        """Get base variable from member reference (struct->field or struct.field)"""
        children = list(cursor.get_children())
        if children:
            base = children[0]
            if base.kind == CursorKind.DECL_REF_EXPR:
                return base.spelling
            elif base.kind == CursorKind.UNARY_OPERATOR:
                for child in base.walk_preorder():
                    if child.kind == CursorKind.DECL_REF_EXPR and child.spelling:
                        return child.spelling
        return None

    def _get_member_name(self, cursor):
        """Get member name from member reference"""
        tokens = list(cursor.get_tokens())
        for i, token in enumerate(tokens):
            if token.spelling in ['->', '.'] and i + 1 < len(tokens):
                return tokens[i + 1].spelling
        return None

    def _get_code_context(self, cursor, max_length: int = 100):
        """Get code context around cursor"""
        try:
            tokens = list(cursor.get_tokens())
            if tokens:
                context = ' '.join([t.spelling for t in tokens[:10]])
                if len(context) > max_length:
                    context = context[:max_length] + '...'
                return context
        except:
            pass
        return ''

    def _get_lock_type(self, lock_func: str):
        """Determine lock type from function name"""
        if 'mutex' in lock_func:
            return 'mutex'
        elif 'spin' in lock_func:
            return 'spinlock'
        elif 'read' in lock_func or 'write' in lock_func:
            return 'rwlock'
        elif 'rcu' in lock_func:
            return 'rcu'
        elif 'down' in lock_func or 'up' in lock_func:
            return 'semaphore'
        elif 'complete' in lock_func:
            return 'completion'
        else:
            return 'unknown'

    def _build_lock_order_graph(self, lock_sequence: List[Dict]):
        """Build graph showing lock acquisition order"""
        graph = {
            'nodes': [],
            'edges': []
        }
        
        seen_locks = set()
        for lock_op in lock_sequence:
            lock_var = lock_op['lock_var']
            if lock_var not in seen_locks:
                graph['nodes'].append({
                    'lock_var': lock_var,
                    'first_line': lock_op['line']
                })
                seen_locks.add(lock_var)
        
        # Create edges based on acquisition order
        for i in range(len(lock_sequence) - 1):
            current = lock_sequence[i]['lock_var']
            next_lock = lock_sequence[i + 1]['lock_var']
            if current != next_lock:
                graph['edges'].append({
                    'from': current,
                    'to': next_lock,
                    'from_line': lock_sequence[i]['line'],
                    'to_line': lock_sequence[i + 1]['line']
                })
        
        return graph

    def _detect_deadlocks(self, lock_sequence: List[Dict], lock_graph: Dict):
        """Detect potential deadlocks by finding circular dependencies"""
        deadlocks = []
        
        # Build adjacency list
        adj_list = {}
        for edge in lock_graph.get('edges', []):
            from_lock = edge['from']
            to_lock = edge['to']
            if from_lock not in adj_list:
                adj_list[from_lock] = []
            adj_list[from_lock].append(to_lock)
        
        # Detect cycles using DFS
        def has_cycle(node, visited, rec_stack, path):
            visited.add(node)
            rec_stack.add(node)
            path.append(node)
            
            if node in adj_list:
                for neighbor in adj_list[node]:
                    if neighbor not in visited:
                        if has_cycle(neighbor, visited, rec_stack, path):
                            return True
                    elif neighbor in rec_stack:
                        # Found cycle
                        cycle_start = path.index(neighbor)
                        cycle = path[cycle_start:] + [neighbor]
                        deadlocks.append({
                            'type': 'circular_dependency',
                            'cycle': cycle,
                            'confidence': 0.7,
                            'description': f'Circular lock dependency detected: {" -> ".join(cycle)}'
                        })
                        return True
            
            rec_stack.remove(node)
            path.pop()
            return False
        
        visited = set()
        for node in adj_list:
            if node not in visited:
                has_cycle(node, visited, set(), [])
        
        # Also check for inconsistent lock ordering
        # If same locks are acquired in different orders, it's a potential deadlock
        lock_order_map = {}  # lock_var -> list of locks acquired after it
        for i, lock_op in enumerate(lock_sequence):
            lock_var = lock_op['lock_var']
            if lock_var not in lock_order_map:
                lock_order_map[lock_var] = []
            
            # Track what locks come after this one
            for j in range(i + 1, len(lock_sequence)):
                next_lock = lock_sequence[j]['lock_var']
                if next_lock != lock_var and next_lock not in lock_order_map[lock_var]:
                    lock_order_map[lock_var].append(next_lock)
        
        # Check for inconsistent ordering
        for lock_var, after_locks in lock_order_map.items():
            for after_lock in after_locks:
                if after_lock in lock_order_map and lock_var in lock_order_map[after_lock]:
                    # Inconsistent ordering detected
                    deadlocks.append({
                        'type': 'inconsistent_ordering',
                        'locks': [lock_var, after_lock],
                        'confidence': 0.8,
                        'description': f'Inconsistent lock ordering: {lock_var} and {after_lock} are acquired in different orders'
                    })
        
        return deadlocks

    def _match_lock_pairs(self, lock_operations: List[Dict]):
        """Match lock acquire/release pairs"""
        pairs = []
        # Group by lock variable and lock type
        acquired = {}  # (lock_var, lock_type) -> list of acquisition operations
        
        for op in lock_operations:
            lock_var = op['variable']
            lock_type = self._get_lock_type(op['function'])
            key = (lock_var, lock_type)
            
            if op['operation'] == 'acquire':
                if key not in acquired:
                    acquired[key] = []
                acquired[key].append(op)
            elif op['operation'] == 'release':
                if key in acquired and acquired[key]:
                    acquire_op = acquired[key].pop(0)
                    pairs.append({
                        'lock_var': lock_var,
                        'lock_type': lock_type,
                        'acquire_line': acquire_op['line'],
                        'acquire_func': acquire_op['function'],
                        'release_line': op['line'],
                        'release_func': op['function'],
                        'lifetime_lines': op['line'] - acquire_op['line']
                    })
        
        return pairs

    def _detect_race_conditions(self, function_cursor, lock_operations: List[Dict], file_path: str):
        """Detect potential race conditions (shared resource access without locks)"""
        race_conditions = []
        
        # This is a simplified check - in practice, you'd need more sophisticated analysis
        # to identify shared resources and verify they're protected by locks
        
        # For now, we'll just note if there are lock operations but flag potential issues
        if len(lock_operations) == 0:
            # No locks at all - might be a race condition if there's shared state
            race_conditions.append({
                'type': 'no_locks',
                'confidence': 0.3,
                'description': 'No lock operations found in function - potential race condition if shared resources are accessed'
            })
        
        return race_conditions

    def _detect_lock_mismatches(self, lock_operations: List[Dict], lock_variables: Dict):
        """Detect lock/unlock mismatches (missing unlocks, double unlocks, etc.)"""
        mismatches = []
        
        # Group by lock variable and lock type
        lock_counts = {}  # (lock_var, lock_type) -> (acquire_count, release_count)
        
        for op in lock_operations:
            lock_var = op['variable']
            lock_type = self._get_lock_type(op['function'])
            key = (lock_var, lock_type)
            
            if key not in lock_counts:
                lock_counts[key] = [0, 0]
            
            if op['operation'] == 'acquire':
                lock_counts[key][0] += 1
            else:
                lock_counts[key][1] += 1
        
        for (lock_var, lock_type), (acquire_count, release_count) in lock_counts.items():
            if acquire_count > release_count:
                mismatches.append({
                    'type': 'missing_unlock',
                    'lock_var': lock_var,
                    'lock_type': lock_type,
                    'acquire_count': acquire_count,
                    'release_count': release_count,
                    'confidence': 0.9,
                    'description': f'Lock {lock_var} ({lock_type}) acquired {acquire_count} times but only released {release_count} times'
                })
            elif release_count > acquire_count:
                mismatches.append({
                    'type': 'double_unlock',
                    'lock_var': lock_var,
                    'lock_type': lock_type,
                    'acquire_count': acquire_count,
                    'release_count': release_count,
                    'confidence': 0.9,
                    'description': f'Lock {lock_var} ({lock_type}) released {release_count} times but only acquired {acquire_count} times'
                })
        
        return mismatches