import json
import os
from typing import Optional
from pydantic import BaseModel, Field
from langchain_core.tools import BaseTool
from langchain_core.tools.base import ArgsSchema


class VerifyHypothesisConsistencyToolInput(BaseModel):
    crash_analysis_json: str = Field(
        description='JSON string of crash_analysis from CrashObserver. Format: {"crash_location": "...", "suspicious_functions": [...], "related_variables": [...], "summary": "..."}'
    )
    bug_analysis_json: str = Field(
        description='JSON string of bug_analysis list from CodeAnalyzer. Format: [{"bug_locations": [{"file": "...", "line": 123, "score": 0.8, "reason": "..."}], "bug_scenarios": [...], "summary": "..."}]'
    )
    collected_code_json: str = Field(
        description='JSON string of collected_code from CodeCollector. Format: {"functions": [...], "call_graph": {...}, "type_definitions": {...}, "summary": "..."}'
    )


class VerifyHypothesisConsistencyTool(BaseTool):
    name: str = 'verify_hypothesis_consistency'
    description: str = '''Verify consistency of hypotheses and evidence across different agents.

This tool checks for:
1. Location consistency: Do multiple agents point to the same bug locations?
2. Pattern consistency: Do bug patterns match the crash type?
3. Function consistency: Do suspicious functions match bug locations?
4. Evidence alignment: Are all evidence pieces logically consistent?

The tool returns:
- consistency_score: Overall consistency score (0.0 to 1.0)
- consistent_locations: Locations that are consistently identified by multiple agents
- contradictions: List of contradictions found between agents
- consistency_summary: Summary of consistency verification
- reasoning: Explanation of consistency check logic

Consistency factors:
1. Multiple agents pointing to same location increases consistency
2. Bug patterns matching crash characteristics increases consistency
3. Suspicious functions matching bug locations increases consistency
4. Logical alignment of all evidence increases consistency

Use this tool when you need to:
- Verify that evidence from different agents is consistent
- Identify contradictions in analysis results
- Assess reliability of synthesized conclusions
- Find locations with strong consensus'''
    args_schema: Optional[ArgsSchema] = VerifyHypothesisConsistencyToolInput

    def __init__(self):
        super().__init__()

    def _run(self, crash_analysis_json: str, bug_analysis_json: str, collected_code_json: str):
        """Verify consistency of hypotheses across agents"""
        print(f'[Tool] VerifyHypothesisConsistencyTool: {crash_analysis_json} {bug_analysis_json} {collected_code_json}')
        try:
            # Parse input JSON
            crash_analysis = json.loads(crash_analysis_json) if crash_analysis_json else {}
            bug_analysis = json.loads(bug_analysis_json) if bug_analysis_json else []
            collected_code = json.loads(collected_code_json) if collected_code_json else {}
        except json.JSONDecodeError as e:
            return json.dumps({
                'error': f'Invalid JSON input: {str(e)}',
                'consistency_score': 0.0,
                'consistent_locations': [],
                'contradictions': [],
                'consistency_summary': 'Failed to parse input data'
            }, indent=2)

        # Extract crash location information
        crash_location_str = crash_analysis.get('crash_location', '')
        suspicious_functions = crash_analysis.get('suspicious_functions', [])
        related_variables = crash_analysis.get('related_variables', [])
        
        # Extract crash location file and function if possible
        crash_file = None
        crash_function = None
        if crash_location_str:
            # Try to extract file and function from crash location string
            # Format might be: "file.c:123 in function()" or "file.c:123"
            parts = crash_location_str.split()
            for part in parts:
                if ':' in part and part.endswith('.c'):
                    crash_file = part.split(':')[0]
                elif 'in' in crash_location_str:
                    func_part = crash_location_str.split('in')
                    if len(func_part) > 1:
                        crash_function = func_part[1].strip().rstrip('()')
        
        # Collect all bug locations from Code Analyzer
        all_bug_locations = {}
        all_patterns = set()
        all_scenarios = []
        
        for analysis in bug_analysis:
            bug_locations = analysis.get('bug_locations', [])
            for loc in bug_locations:
                file = loc.get('file', '')
                line = loc.get('line', 0)
                reason = loc.get('reason', '')
                score = loc.get('score', 0.0)
                
                key = f"{file}:{line}"
                
                if key not in all_bug_locations:
                    all_bug_locations[key] = {
                        'file': file,
                        'line': line,
                        'reasons': [],
                        'scores': [],
                        'agents': []
                    }
                
                all_bug_locations[key]['reasons'].append(reason)
                all_bug_locations[key]['scores'].append(score)
                all_bug_locations[key]['agents'].append('code_analyzer')
                
                if reason:
                    all_patterns.add(reason)
            
            scenarios = analysis.get('bug_scenarios', [])
            all_scenarios.extend(scenarios)
        
        # Check consistency: Crash Observer vs Code Analyzer
        consistent_locations = []
        contradictions = []
        consistency_factors = []
        
        # Factor 1: Location consistency (do agents point to same files/functions?)
        location_consistency = 0.0
        location_matches = 0
        location_total = 0
        
        for key, loc_data in all_bug_locations.items():
            file = loc_data['file']
            line = loc_data['line']
            location_total += 1
            
            # Check if this location matches crash location
            matches_crash = False
            if crash_file and crash_file in file:
                matches_crash = True
            elif crash_location_str and file in crash_location_str:
                matches_crash = True
            
            # Check if function matches suspicious functions
            matches_function = False
            if crash_function:
                # Extract function name from file path or check suspicious functions
                for sus_func in suspicious_functions:
                    if sus_func in file or sus_func in crash_location_str:
                        matches_function = True
                        break
            
            if matches_crash or matches_function:
                location_matches += 1
                consistent_locations.append({
                    'location': key,
                    'file': file,
                    'line': line,
                    'matches_crash_location': matches_crash,
                    'matches_suspicious_function': matches_function,
                    'reasons': list(set(loc_data['reasons'])),
                    'avg_score': sum(loc_data['scores']) / len(loc_data['scores']) if loc_data['scores'] else 0.0
                })
        
        if location_total > 0:
            location_consistency = location_matches / location_total
            consistency_factors.append({
                'factor': 'location_consistency',
                'score': round(location_consistency, 3),
                'description': f'{location_matches}/{location_total} bug locations match crash location or suspicious functions'
            })
        
        # Factor 2: Pattern consistency (do patterns make sense together?)
        pattern_consistency = 0.0
        if all_patterns:
            # Check if patterns are consistent (e.g., null-pointer-dereference is consistent with null check missing)
            consistent_pattern_groups = [
                {'null-pointer-dereference', 'null-check-missing'},
                {'use-after-free', 'double-free', 'memory-leak'},
                {'buffer-overflow', 'out-of-bounds', 'bounds-check-missing'},
                {'race-condition', 'deadlock', 'lock-order-violation'}
            ]
            
            pattern_groups_matched = 0
            for group in consistent_pattern_groups:
                if any(p in all_patterns for p in group):
                    pattern_groups_matched += 1
            
            if len(all_patterns) > 0:
                pattern_consistency = min(1.0, pattern_groups_matched / len(all_patterns))
            
            consistency_factors.append({
                'factor': 'pattern_consistency',
                'score': round(pattern_consistency, 3),
                'description': f'{len(all_patterns)} distinct patterns found, {pattern_groups_matched} consistent groups'
            })
        
        # Factor 3: Function consistency (do suspicious functions appear in bug locations?)
        function_consistency = 0.0
        if suspicious_functions and all_bug_locations:
            function_matches = 0
            for sus_func in suspicious_functions:
                # Check if function appears in any bug location file
                for key, loc_data in all_bug_locations.items():
                    file = loc_data['file']
                    if sus_func in file or sus_func.lower() in file.lower():
                        function_matches += 1
                        break
            
            if len(suspicious_functions) > 0:
                function_consistency = function_matches / len(suspicious_functions)
            
            consistency_factors.append({
                'factor': 'function_consistency',
                'score': round(function_consistency, 3),
                'description': f'{function_matches}/{len(suspicious_functions)} suspicious functions appear in bug locations'
            })
        
        # Factor 4: Evidence alignment (logical consistency)
        evidence_alignment = 0.0
        alignment_checks = 0
        alignment_passed = 0
        
        # Check 1: If crash location exists, bug locations should be nearby
        if crash_location_str and all_bug_locations:
            alignment_checks += 1
            if location_consistency > 0.3:  # At least 30% match
                alignment_passed += 1
        
        # Check 2: If patterns found, they should be relevant to crash
        if all_patterns:
            alignment_checks += 1
            if pattern_consistency > 0.5:  # Patterns are consistent
                alignment_passed += 1
        
        # Check 3: If suspicious functions exist, they should match bug locations
        if suspicious_functions and all_bug_locations:
            alignment_checks += 1
            if function_consistency > 0.5:  # Functions match
                alignment_passed += 1
        
        if alignment_checks > 0:
            evidence_alignment = alignment_passed / alignment_checks
            consistency_factors.append({
                'factor': 'evidence_alignment',
                'score': round(evidence_alignment, 3),
                'description': f'{alignment_passed}/{alignment_checks} alignment checks passed'
            })
        
        # Identify contradictions
        # Contradiction 1: Bug locations far from crash location
        if crash_location_str and all_bug_locations:
            for key, loc_data in all_bug_locations.items():
                file = loc_data['file']
                matches = False
                if crash_file and crash_file in file:
                    matches = True
                elif crash_location_str and file in crash_location_str:
                    matches = True
                
                if not matches:
                    # Check if function matches
                    for sus_func in suspicious_functions:
                        if sus_func in file:
                            matches = True
                            break
                    
                    if not matches:
                        contradictions.append({
                            'type': 'location_mismatch',
                            'description': f'Bug location {key} does not match crash location {crash_location_str}',
                            'severity': 'medium',
                            'location': key
                        })
        
        # Contradiction 2: Conflicting patterns
        conflicting_patterns = [
            {'null-pointer-dereference', 'use-after-free'},  # Usually mutually exclusive
        ]
        
        for conflict_pair in conflicting_patterns:
            if conflict_pair.issubset(all_patterns):
                contradictions.append({
                    'type': 'pattern_conflict',
                    'description': f'Conflicting patterns detected: {conflict_pair}',
                    'severity': 'high',
                    'patterns': list(conflict_pair)
                })
        
        # Calculate overall consistency score
        # Weighted average of all factors
        weights = {
            'location_consistency': 0.4,
            'pattern_consistency': 0.2,
            'function_consistency': 0.2,
            'evidence_alignment': 0.2
        }
        
        consistency_score = (
            location_consistency * weights['location_consistency'] +
            pattern_consistency * weights['pattern_consistency'] +
            function_consistency * weights['function_consistency'] +
            evidence_alignment * weights['evidence_alignment']
        )
        
        # Penalize for contradictions
        contradiction_penalty = min(0.3, len(contradictions) * 0.1)
        consistency_score = max(0.0, consistency_score - contradiction_penalty)
        consistency_score = round(consistency_score, 3)
        
        # Generate consistency summary
        consistency_summary = f"Consistency score: {consistency_score:.1%}. "
        
        if consistency_score >= 0.7:
            consistency_summary += "Evidence is highly consistent. "
        elif consistency_score >= 0.5:
            consistency_summary += "Evidence is moderately consistent. "
        elif consistency_score >= 0.3:
            consistency_summary += "Evidence has some inconsistencies. "
        else:
            consistency_summary += "Evidence has significant inconsistencies. "
        
        if consistent_locations:
            consistency_summary += f"{len(consistent_locations)} locations have strong consensus. "
        
        if contradictions:
            consistency_summary += f"{len(contradictions)} contradiction(s) found. "
        
        # Generate reasoning
        reasoning = "Consistency verification: "
        reasoning += f"(1) Location consistency: {location_consistency:.1%} - {location_matches} locations match crash context. "
        reasoning += f"(2) Pattern consistency: {pattern_consistency:.1%} - patterns are logically related. "
        reasoning += f"(3) Function consistency: {function_consistency:.1%} - suspicious functions match bug locations. "
        reasoning += f"(4) Evidence alignment: {evidence_alignment:.1%} - evidence pieces align logically. "
        if contradictions:
            reasoning += f"Found {len(contradictions)} contradiction(s) that reduce confidence."
        
        return json.dumps({
            'consistency_score': consistency_score,
            'consistent_locations': consistent_locations,
            'contradictions': contradictions,
            'consistency_factors': consistency_factors,
            'consistency_summary': consistency_summary,
            'reasoning': reasoning
        }, indent=2)