import os
import json
from typing import Optional, ClassVar, List, Dict, Set, Tuple
from pydantic import BaseModel, Field
from langchain_core.tools import BaseTool
from langchain_core.tools.base import ArgsSchema

try:
    import clang.cindex as ci
    from clang.cindex import CursorKind, TokenKind
    CLANG_AVAILABLE = True
except ImportError:
    CLANG_AVAILABLE = False


class GenerateCFGToolInput(BaseModel):
    file_path: str = Field(
        description='Path to the file relative to the kernel source root (e.g. fs/btrfs/qgroup.c)'
    )
    function_name: Optional[str] = Field(
        default=None,
        description='Name of the function to generate CFG for. If not provided, generates CFG for all functions in the file.'
    )
    reason: str = Field(
        description='The reason why you need to generate the control flow graph'
    )


class GenerateCFGTool(BaseTool):
    name: str = 'generate_cfg'
    description: str = '''Generate Control Flow Graph (CFG) for C kernel code.
    
This tool analyzes code structure and generates a control flow graph showing:
- Basic blocks: Sequences of statements without branches
- Control flow edges: Conditional branches, loops, function calls, returns
- Control structures: if/else, for/while/do-while loops, switch-case statements
- Function entry and exit points

Use this tool when you need to:
- Understand the control flow structure of a function
- Analyze execution paths and branches
- Identify all possible code paths
- Understand loop structures and nesting
- Trace conditional logic flow
- Prepare for data flow analysis or taint tracking

The tool returns:
- cfg: Control flow graph with nodes (basic blocks) and edges (control flow)
- basic_blocks: List of basic blocks with start/end lines and statements
- edges: List of control flow edges with source, target, and edge type
- control_structures: List of control structures (if, loops, switch) found
- entry_block: Entry point of the function
- exit_blocks: Exit points (return statements)

Edge types include:
- 'sequential': Normal sequential flow
- 'conditional_true': True branch of if statement
- 'conditional_false': False branch of if statement
- 'loop_entry': Entry to loop body
- 'loop_exit': Exit from loop
- 'switch_case': Case in switch statement
- 'switch_default': Default case in switch
- 'function_call': Call to another function
- 'return': Return statement

Important: In this environment, the current working directory is workdir. Kernel source code
lives under workdir/crash-* directories (each crash-* is the kernel tree for the commit where
a crash occurred). Do not use workdir/linux. When calling this tool, use file paths under
workdir/crash-* (e.g. workdir/crash-<id>/fs/btrfs/qgroup.c).'''
    args_schema: Optional[ArgsSchema] = GenerateCFGToolInput

    def __init__(self):
        super().__init__()

    def _run(self, file_path: str, reason: str, function_name: Optional[str] = None):
        print(f'[Tool] GenerateCFGTool: {file_path} {function_name} {reason}')
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
            result = self._generate_cfg(file_path, function_name)
            os.chdir(cur_dir)
            return json.dumps(result, indent=2)
        except Exception as e:
            os.chdir(cur_dir)
            return json.dumps({
                'error': f'Error during CFG generation: {str(e)}',
                'file_path': file_path,
                'function_name': function_name
            }, indent=2)

    def _generate_cfg(self, file_path: str, function_name: Optional[str] = None):
        """Generate CFG using libclang"""
        index = ci.Index.create()
        args = ['-I', '.', '-I', 'include', '-D__KERNEL__', '-Wno-everything']
        tu = index.parse(file_path, args=args, options=ci.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD)
        
        if tu is None:
            return {'error': 'Failed to parse file', 'file_path': file_path}
        
        abs_file_path = os.path.abspath(file_path)
        results = []
        
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
                results.append(self._build_cfg_for_function(function_cursor, file_path))
            else:
                return {'error': f'Function {function_name} not found', 'file_path': file_path}
        else:
            for cursor in tu.cursor.walk_preorder():
                if (cursor.kind == CursorKind.FUNCTION_DECL and 
                    cursor.is_definition()):
                    if cursor.location.file:
                        cursor_file = os.path.abspath(cursor.location.file.name)
                        if cursor_file == abs_file_path or cursor_file.endswith(file_path):
                            results.append(self._build_cfg_for_function(cursor, file_path))
        
        if len(results) == 1:
            return results[0]
        else:
            return {
                'file_path': file_path,
                'function_name': function_name,
                'functions': results,
                'total_functions': len(results)
            }

    def _build_cfg_for_function(self, function_cursor, file_path: str):
        """Build CFG for a single function"""
        function_name = function_cursor.spelling
        function_start_line = function_cursor.location.line
        
        # Extract basic blocks and control flow
        basic_blocks = []
        edges = []
        control_structures = []
        block_id_counter = 0
        
        # Map line numbers to block IDs
        line_to_block = {}
        
        # Track current block
        current_block = None
        current_block_id = None
        current_block_start = None
        
        # Stack for nested control structures
        control_stack = []
        
        def get_or_create_block(start_line: int) -> int:
            """Get existing block or create new one"""
            nonlocal block_id_counter, current_block, current_block_id, current_block_start
            
            if start_line in line_to_block:
                return line_to_block[start_line]
            
            block_id = block_id_counter
            block_id_counter += 1
            
            basic_blocks.append({
                'id': block_id,
                'start_line': start_line,
                'end_line': start_line,
                'statements': [],
                'type': 'normal'
            })
            
            line_to_block[start_line] = block_id
            return block_id
        
        def finalize_current_block(end_line: int):
            """Finalize current block"""
            nonlocal current_block, current_block_id, current_block_start
            
            if current_block_id is not None:
                if current_block_id < len(basic_blocks):
                    basic_blocks[current_block_id]['end_line'] = end_line
                current_block_id = None
                current_block_start = None
        
        def add_statement_to_block(block_id: int, line: int, stmt_type: str, content: str = None):
            """Add statement to a block"""
            if block_id < len(basic_blocks):
                # Check for duplicates
                existing = [s for s in basic_blocks[block_id]['statements'] 
                          if s['line'] == line and s['type'] == stmt_type]
                if existing:
                    return  # Already added
                
                basic_blocks[block_id]['statements'].append({
                    'line': line,
                    'type': stmt_type,
                    'content': content
                })
                # Update end line
                basic_blocks[block_id]['end_line'] = max(
                    basic_blocks[block_id]['end_line'], line
                )
        
        # Entry block
        entry_block_id = get_or_create_block(function_start_line)
        basic_blocks[entry_block_id]['type'] = 'entry'
        
        # Track processed cursors to avoid duplicates
        processed_cursors = set()
        
        # Process function body
        def process_cursor(cursor, parent_block_id: Optional[int] = None, skip_children: bool = False):
            nonlocal current_block_id, current_block_start, control_stack
            
            # Skip if already processed
            cursor_id = id(cursor)
            if cursor_id in processed_cursors:
                return
            processed_cursors.add(cursor_id)
            
            loc = cursor.location
            if not loc.file:
                return
            
            line = loc.line
            
            # Skip if not in the same file
            if loc.file.name != function_cursor.location.file.name:
                return
            
            # Determine block for this statement
            block_id = parent_block_id if parent_block_id is not None else current_block_id
            
            if cursor.kind == CursorKind.COMPOUND_STMT:
                # Function body or block scope
                for child in cursor.get_children():
                    process_cursor(child, block_id)
            
            elif cursor.kind == CursorKind.IF_STMT:
                # If statement
                if_block_id = get_or_create_block(line)
                control_structures.append({
                    'type': 'if',
                    'line': line,
                    'condition_line': line
                })
                
                # Process condition (mark as processed to avoid duplicate)
                children = list(cursor.get_children())
                if children:
                    cond_cursor = children[0]
                    processed_cursors.add(id(cond_cursor))  # Mark condition as processed
                    add_statement_to_block(if_block_id, line, 'condition', 
                                         self._get_code_snippet(cond_cursor))
                
                # Process then block
                then_block_id = None
                if len(children) > 1:
                    then_cursor = children[1]
                    then_start = then_cursor.location.line
                    then_block_id = get_or_create_block(then_start)
                    process_cursor(then_cursor, then_block_id)
                    edges.append({
                        'from': if_block_id,
                        'to': then_block_id,
                        'type': 'conditional_true',
                        'condition_line': line
                    })
                
                # Process else block
                else_block_id = None
                if len(children) > 2:
                    else_cursor = children[2]
                    else_start = else_cursor.location.line
                    else_block_id = get_or_create_block(else_start)
                    process_cursor(else_cursor, else_block_id)
                    edges.append({
                        'from': if_block_id,
                        'to': else_block_id,
                        'type': 'conditional_false',
                        'condition_line': line
                    })
                
                # Connect to next block
                next_block_id = get_or_create_block(line + 1)
                if then_block_id is not None:
                    edges.append({
                        'from': then_block_id,
                        'to': next_block_id,
                        'type': 'sequential'
                    })
                if else_block_id is not None:
                    edges.append({
                        'from': else_block_id,
                        'to': next_block_id,
                        'type': 'sequential'
                    })
                elif then_block_id is None:
                    # No else, connect if directly to next
                    edges.append({
                        'from': if_block_id,
                        'to': next_block_id,
                        'type': 'conditional_false'
                    })
                
                current_block_id = next_block_id
                # Mark all children as processed to avoid duplicate processing
                for child in children:
                    processed_cursors.add(id(child))
                # Don't process children again - already handled explicitly
                return
            
            elif cursor.kind == CursorKind.WHILE_STMT:
                # While loop
                loop_block_id = get_or_create_block(line)
                control_structures.append({
                    'type': 'while',
                    'line': line,
                    'condition_line': line
                })
                
                children = list(cursor.get_children())
                if children:
                    cond_cursor = children[0]
                    add_statement_to_block(loop_block_id, line, 'condition',
                                         self._get_code_snippet(cond_cursor))
                
                # Loop body
                body_block_id = None
                exit_block_id = get_or_create_block(line + 1)
                
                if len(children) > 1:
                    body_cursor = children[1]
                    body_start = body_cursor.location.line
                    body_block_id = get_or_create_block(body_start)
                    process_cursor(body_cursor, body_block_id)
                    
                    # Loop edges
                    edges.append({
                        'from': loop_block_id,
                        'to': body_block_id,
                        'type': 'loop_entry',
                        'condition_line': line
                    })
                    edges.append({
                        'from': body_block_id,
                        'to': loop_block_id,
                        'type': 'loop_back',
                        'condition_line': line
                    })
                
                # Exit edge
                edges.append({
                    'from': loop_block_id,
                    'to': exit_block_id,
                    'type': 'loop_exit',
                    'condition_line': line
                })
                
                current_block_id = exit_block_id
                # Don't process children again - already handled explicitly
                return
            
            elif cursor.kind == CursorKind.FOR_STMT:
                # For loop
                loop_block_id = get_or_create_block(line)
                control_structures.append({
                    'type': 'for',
                    'line': line,
                    'condition_line': line
                })
                
                children = list(cursor.get_children())
                # Init, condition, increment, body
                
                body_block_id = None
                exit_block_id = get_or_create_block(line + 1)
                
                if len(children) >= 4:
                    body_cursor = children[3]
                    body_start = body_cursor.location.line
                    body_block_id = get_or_create_block(body_start)
                    process_cursor(body_cursor, body_block_id)
                    
                    # Loop edges
                    edges.append({
                        'from': loop_block_id,
                        'to': body_block_id,
                        'type': 'loop_entry',
                        'condition_line': line
                    })
                    edges.append({
                        'from': body_block_id,
                        'to': loop_block_id,
                        'type': 'loop_back',
                        'condition_line': line
                    })
                
                # Exit edge
                edges.append({
                    'from': loop_block_id,
                    'to': exit_block_id,
                    'type': 'loop_exit',
                    'condition_line': line
                })
                
                current_block_id = exit_block_id
                # Don't process children again - already handled explicitly
                return
            
            elif cursor.kind == CursorKind.DO_STMT:
                # Do-while loop
                loop_block_id = get_or_create_block(line)
                control_structures.append({
                    'type': 'do_while',
                    'line': line,
                    'condition_line': line
                })
                
                children = list(cursor.get_children())
                
                body_block_id = None
                exit_block_id = get_or_create_block(line + 1)
                
                if children:
                    body_cursor = children[0]
                    body_start = body_cursor.location.line
                    body_block_id = get_or_create_block(body_start)
                    process_cursor(body_cursor, body_block_id)
                    
                    # Loop edges (do-while always enters body first)
                    edges.append({
                        'from': loop_block_id,
                        'to': body_block_id,
                        'type': 'loop_entry',
                        'condition_line': line
                    })
                    edges.append({
                        'from': body_block_id,
                        'to': loop_block_id,
                        'type': 'loop_back',
                        'condition_line': line
                    })
                
                # Exit edge
                edges.append({
                    'from': loop_block_id,
                    'to': exit_block_id,
                    'type': 'loop_exit',
                    'condition_line': line
                })
                
                current_block_id = exit_block_id
                # Don't process children again - already handled explicitly
                return
            
            elif cursor.kind == CursorKind.SWITCH_STMT:
                # Switch statement
                switch_block_id = get_or_create_block(line)
                control_structures.append({
                    'type': 'switch',
                    'line': line
                })
                
                children = list(cursor.get_children())
                switch_expr = children[0] if children else None
                
                exit_block_id = get_or_create_block(line + 1)
                case_blocks = []
                
                # Process cases
                for i, child in enumerate(children[1:], 1):
                    if child.kind == CursorKind.CASE_STMT:
                        case_start = child.location.line
                        case_block_id = get_or_create_block(case_start)
                        case_blocks.append(case_block_id)
                        process_cursor(child, case_block_id)
                        edges.append({
                            'from': switch_block_id,
                            'to': case_block_id,
                            'type': 'switch_case',
                            'case_line': case_start
                        })
                        edges.append({
                            'from': case_block_id,
                            'to': exit_block_id,
                            'type': 'sequential'
                        })
                    elif child.kind == CursorKind.DEFAULT_STMT:
                        default_start = child.location.line
                        default_block_id = get_or_create_block(default_start)
                        process_cursor(child, default_block_id)
                        edges.append({
                            'from': switch_block_id,
                            'to': default_block_id,
                            'type': 'switch_default',
                            'case_line': default_start
                        })
                        edges.append({
                            'from': default_block_id,
                            'to': exit_block_id,
                            'type': 'sequential'
                        })
                
                current_block_id = exit_block_id
                # Don't process children again - already handled explicitly
                return
            
            elif cursor.kind == CursorKind.CALL_EXPR:
                # Function call
                if block_id is not None:
                    func_name = self._get_function_name(cursor)
                    add_statement_to_block(block_id, line, 'function_call', func_name)
                    # Only add edge once per function call
                    existing_edge = [e for e in edges 
                                    if e['from'] == block_id and e['to'] == block_id and 
                                    e.get('type') == 'function_call' and e.get('line') == line]
                    if not existing_edge:
                        edges.append({
                            'from': block_id,
                            'to': block_id,  # Self-reference for call
                            'type': 'function_call',
                            'function': func_name,
                            'line': line
                        })
                # Don't process children - function call is a leaf
                return
            
            elif cursor.kind == CursorKind.RETURN_STMT:
                # Return statement
                return_block_id = get_or_create_block(line)
                basic_blocks[return_block_id]['type'] = 'exit'
                add_statement_to_block(return_block_id, line, 'return',
                                     self._get_code_snippet(cursor))
                if block_id is not None and block_id != return_block_id:
                    # Check if edge already exists
                    existing_edge = [e for e in edges 
                                    if e['from'] == block_id and e['to'] == return_block_id]
                    if not existing_edge:
                        edges.append({
                            'from': block_id,
                            'to': return_block_id,
                            'type': 'sequential'
                        })
                # Mark return expression as processed
                for child in cursor.get_children():
                    processed_cursors.add(id(child))
                # Don't process children - return is a leaf
                return
            
            elif cursor.kind == CursorKind.BINARY_OPERATOR:
                # Assignment or expression
                # Only process if it's a top-level statement, not part of condition/expression
                parent = cursor.semantic_parent
                if parent and parent.kind in (CursorKind.COMPOUND_STMT, CursorKind.EXPR_STMT):
                    if block_id is not None:
                        add_statement_to_block(block_id, line, 'statement',
                                             self._get_code_snippet(cursor))
                # Don't process children - binary operator is usually a leaf in statement context
                return
            
            elif cursor.kind == CursorKind.UNARY_OPERATOR:
                # Unary operation - usually part of expression, skip children
                return
            
            elif cursor.kind == CursorKind.DECL_STMT:
                # Variable declaration
                if block_id is not None:
                    add_statement_to_block(block_id, line, 'declaration',
                                         self._get_code_snippet(cursor))
                # Don't process children - declaration is a leaf
                return
            
            # Process children only if not explicitly handled above
            # Most cursor types will fall through here and process children
            if not skip_children:
                for child in cursor.get_children():
                    process_cursor(child, block_id)
        
        # Process function body
        for child in function_cursor.get_children():
            if child.kind == CursorKind.COMPOUND_STMT:
                process_cursor(child, entry_block_id)
                break
        
        # Find exit blocks (returns or end of function)
        exit_blocks = [bb['id'] for bb in basic_blocks if bb['type'] == 'exit']
        if not exit_blocks:
            # No explicit return, function ends at last block
            if basic_blocks:
                last_block = max(basic_blocks, key=lambda x: x['end_line'])
                last_block['type'] = 'exit'
                exit_blocks = [last_block['id']]
        
        # Clean up and sort
        basic_blocks.sort(key=lambda x: x['start_line'])
        
        return {
            'file_path': file_path,
            'function_name': function_name,
            'entry_block': entry_block_id,
            'exit_blocks': exit_blocks,
            'basic_blocks': basic_blocks,
            'edges': edges,
            'control_structures': control_structures,
            'summary': {
                'total_blocks': len(basic_blocks),
                'total_edges': len(edges),
                'total_control_structures': len(control_structures),
                'entry_line': function_start_line
            }
        }
    
    def _get_code_snippet(self, cursor) -> str:
        """Extract code snippet for a cursor"""
        try:
            extent = cursor.extent
            start = extent.start
            end = extent.end
            
            if start.file:
                with open(start.file.name, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                    if start.line <= len(lines):
                        snippet_lines = lines[start.line - 1:end.line]
                        return ''.join(snippet_lines).strip()
        except:
            pass
        return ''
    
    def _get_function_name(self, cursor) -> Optional[str]:
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
