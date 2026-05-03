import re
from pydantic import BaseModel, Field
from typing import Optional
from langchain_core.tools.base import ArgsSchema
from langchain_core.tools import BaseTool


class InferCrashTypeInput(BaseModel):
    callstack: list = Field(
        description="List of callstack frames from CallstackTool. "
                    "Each frame contains function_name, offset, function_size, src"
    )
    entry_ctx: list = Field(
        description="List of [register, value] pairs at entry point from CallstackTool"
    )
    exit_ctx: list = Field(
        description="List of [register, value] pairs at crash point from CallstackTool"
    )
    # crash_code: str = Field(description="Crash-triggering C code")


class InferCrashTypeTool(BaseTool):
    name: str = 'infer_crash_type'
    description: str = (
        "Infer the crash type based on callstack, register contexts, and crash code. "
        "Use this after reading crash data with CallstackTool and crash code file."
    )
    args_schema: Optional[ArgsSchema] = InferCrashTypeInput

    UAF_FUNCTIONS: list = [
        'kfree', 'kmem_cache_free', 'vfree', 'free_pages',
        'put_page', 'slab_free'
    ]
    BUFFER_OVERFLOW_FUNCTIONS: list = [
        'memcpy', 'memmove', 'copy_from_user', 'copy_to_user',
        'strncpy', 'strcpy', 'strcat'
    ]
    LOCK_FUNCTIONS: list = [
        'spin_lock', 'spin_unlock', 'mutex_lock', 'mutex_unlock',
        'rw_semaphore_lock', 'rw_semaphore_unlock'
    ]

    def __init__(self):
        super().__init__()

    # ----------------------------------------------------------
    # Helpers
    # ----------------------------------------------------------

    def _ctx_to_dict(self, ctx: list) -> dict:
        """Convert [[register, value], ...] to {register: value}"""
        return {reg: val for reg, val in ctx}

    def _parse_reg_value(self, value_str: str) -> Optional[int]:
        """Parse register value string to integer.
        Handles:
        - "ffffffffffffffda"          → plain hex
        - "0033:0x7f54841e2779"       → segment:hex with 0x prefix
        - "002b:00007ffe7faaee88"     → segment:hex without 0x prefix
        - "0010:func+0x1d2/0x320"     → symbolic, returns None
        """
        try:
            if ':' in value_str:
                value_str = value_str.split(':', 1)[1]
            if '+' in value_str or '/' in value_str:
                return None
            return int(value_str, 16)
        except (ValueError, IndexError):
            return None

    def _get_privilege_level(self, ctx: dict) -> str:
        """Determine privilege level from CS register or RIP segment.
        CS & 0x3 gives CPL (Current Privilege Level): 0 = kernel, 3 = user.
        Fallback: RIP segment 0010 = kernel, 0033 = user.
        """
        if 'CS' in ctx:
            cs_val = self._parse_reg_value(ctx['CS'])
            if cs_val is not None:
                cpl = cs_val & 0x3
                return "kernel" if cpl == 0 else "user"

        if 'RIP' in ctx and ':' in ctx['RIP']:
            segment = ctx['RIP'].split(':')[0]
            return "kernel" if segment == "0010" else "user"

        return "unknown"

    # ----------------------------------------------------------
    # Method 1: Faulting address analysis (CR2)
    # ----------------------------------------------------------
    def _analyze_faulting_address(self, exit_ctx: dict) -> dict:
        """Infer crash type from CR2 register (page fault address).
        CR2 is only meaningful when a page fault occurred.
        """
        scores = {}

        if 'CR2' not in exit_ctx:
            return scores

        fault_addr = self._parse_reg_value(exit_ctx['CR2'])
        if fault_addr is None:
            return scores

        # NULL pointer range (accounts for large struct field offsets)
        if 0 <= fault_addr < 0x10000:
            scores['null_pointer_dereference'] = 0.9

        return scores

    # ----------------------------------------------------------
    # Method 2: Entry vs exit context comparison
    # ----------------------------------------------------------
    def _compare_contexts(self, entry_ctx: dict, exit_ctx: dict) -> dict:
        """Compare register values between entry and exit contexts.
        Skips comparison if contexts are at different privilege levels
        (e.g., user entry vs kernel crash) since register semantics differ.
        """
        scores = {}

        # Skip if privilege levels differ
        entry_priv = self._get_privilege_level(entry_ctx)
        exit_priv = self._get_privilege_level(exit_ctx)
        if entry_priv != exit_priv:
            return scores

        pointer_regs = ['RAX', 'RBX', 'RCX', 'RDX', 'RSI', 'RDI',
                        'R8', 'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15']

        changed_pointers = 0
        null_pointers = 0

        for reg in pointer_regs:
            if reg not in entry_ctx or reg not in exit_ctx:
                continue

            entry_val = self._parse_reg_value(entry_ctx[reg])
            exit_val = self._parse_reg_value(exit_ctx[reg])

            if entry_val is None or exit_val is None:
                continue

            if entry_val != exit_val:
                changed_pointers += 1
                if exit_val == 0:
                    null_pointers += 1

        if null_pointers > 0:
            scores['null_pointer_dereference'] = min(0.7 + null_pointers * 0.1, 0.95)

        if changed_pointers > 2:
            scores['use_after_free'] = 0.5
            scores['buffer_overflow'] = 0.4

        return scores

    # ----------------------------------------------------------
    # Method 3: Callstack pattern matching
    # ----------------------------------------------------------
    def _match_callstack_patterns(self, callstack: list) -> dict:
        """Match function_name in callstack frames against known bug patterns"""
        scores = {}

        function_names = [
            frame['function_name'] for frame in callstack
            if 'function_name' in frame
        ]

        # UAF pattern
        uaf_hits = sum(
            1 for func in function_names
            if any(pattern in func for pattern in self.UAF_FUNCTIONS)
        )
        if uaf_hits > 0:
            scores['use_after_free'] = min(0.3 * uaf_hits, 0.9)

        # Buffer overflow pattern
        bo_hits = sum(
            1 for func in function_names
            if any(pattern in func for pattern in self.BUFFER_OVERFLOW_FUNCTIONS)
        )
        if bo_hits > 0:
            scores['buffer_overflow'] = min(0.3 * bo_hits, 0.9)

        # Race condition / deadlock pattern
        lock_hits = sum(
            1 for func in function_names
            if any(pattern in func for pattern in self.LOCK_FUNCTIONS)
        )
        if lock_hits >= 2:
            scores['race_condition'] = 0.5
            scores['deadlock'] = 0.4

        return scores

    # ----------------------------------------------------------
    # Method 4: Crash code pattern analysis
    # ----------------------------------------------------------
    def _analyze_crash_code(self, crash_code: str) -> dict:
        """Analyze C code for known bug patterns"""
        scores = {}
        lines = crash_code.split('\n')

        # Null pointer dereference: dereference without NULL check
        has_dereference = re.search(r'\w+\s*->\s*\w+', crash_code)
        has_null_check = re.search(r'if\s*\(\s*!?\s*\w+\s*\)', crash_code)
        if has_dereference and not has_null_check:
            scores['null_pointer_dereference'] = 0.6

        # Use-after-free: pointer access after free
        found_free = False
        for line in lines:
            if re.search(r'(kfree|kmem_cache_free|vfree)\s*\(', line):
                found_free = True
            elif found_free and re.search(r'\w+\s*->\s*\w+', line):
                scores['use_after_free'] = 0.8
                break

        # Buffer overflow: array access without bounds check
        has_array_access = re.search(r'\w+\s*\[\s*\w+\s*\]', crash_code)
        has_bounds_check = re.search(r'if\s*\(.*<.*\)', crash_code)
        if has_array_access and not has_bounds_check:
            scores['buffer_overflow'] = 0.6

        # Race condition: shared resource mutation without lock
        has_mutation = re.search(r'(->|\.)\s*\w+\s*[+\-*/]?=', crash_code)
        has_lock = re.search(r'(spin_lock|mutex_lock|rcu_read_lock)', crash_code)
        if has_mutation and not has_lock:
            scores['race_condition'] = 0.4

        return scores

    # ----------------------------------------------------------
    # Synthesize scores from all methods
    # ----------------------------------------------------------
    def _synthesize_scores(self, all_scores: list[dict]) -> dict:
        """Aggregate scores from all analysis methods by averaging"""
        combined = {}

        for scores in all_scores:
            for crash_type, score in scores.items():
                if crash_type not in combined:
                    combined[crash_type] = []
                combined[crash_type].append(score)

        result = {
            crash_type: sum(scores) / len(scores)
            for crash_type, scores in combined.items()
        }

        return dict(sorted(result.items(), key=lambda x: x[1], reverse=True))

    # ----------------------------------------------------------
    # Main
    # ----------------------------------------------------------
    def _run(self, callstack: list, entry_ctx: list, exit_ctx: list) -> dict:
        print('[Tool] InferCrashType: Inferring crash type...')
        print(callstack)
        print(entry_ctx)
        print(exit_ctx)
        # print(crash_code[:50])
        # exit(0)

        # Parse context lists to dicts
        entry_ctx_dict = self._ctx_to_dict(entry_ctx)
        exit_ctx_dict = self._ctx_to_dict(exit_ctx)

        # Run all 4 analysis methods
        faulting_addr_scores = self._analyze_faulting_address(exit_ctx_dict)
        context_scores = self._compare_contexts(entry_ctx_dict, exit_ctx_dict)
        callstack_scores = self._match_callstack_patterns(callstack)
        # code_scores = self._analyze_crash_code(crash_code)

        # Synthesize final scores
        final_scores = self._synthesize_scores([
            faulting_addr_scores,
            context_scores,
            callstack_scores,
            # code_scores
        ])

        most_likely = max(final_scores, key=final_scores.get) if final_scores else "unknown"

        print({
            "most_likely_type": most_likely,
            "scores": final_scores,
            "evidence": {
                "faulting_address": faulting_addr_scores,
                "context_comparison": context_scores,
                "callstack_patterns": callstack_scores,
                # "code_patterns": code_scores
            }
        })

        return {
            "most_likely_type": most_likely,
            "scores": final_scores,
            "evidence": {
                "faulting_address": faulting_addr_scores,
                "context_comparison": context_scores,
                "callstack_patterns": callstack_scores,
                # "code_patterns": code_scores
            }
        }