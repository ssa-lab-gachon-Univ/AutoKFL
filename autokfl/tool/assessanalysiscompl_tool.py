import json
import os
from typing import Optional
from pydantic import BaseModel, Field
from langchain_core.tools import BaseTool
from langchain_core.tools.base import ArgsSchema


class AssessAnalysisCompletenessToolInput(BaseModel):
    crash_analysis_json: str = Field(
        description='JSON string of crash_analysis from CrashObserver. Format: {"crash_location": "...", "suspicious_functions": [...], "related_variables": [...], "summary": "..."}'
    )
    bug_analysis_json: str = Field(
        description='JSON string of bug_analysis list from CodeAnalyzer. Format: [{"bug_locations": [{"file": "...", "line": 123, "score": 0.8, "reason": "..."}], "bug_scenarios": [...], "summary": "..."}]'
    )
    collected_code_json: str = Field(
        description='JSON string of collected_code from CodeCollector. Format: {"functions": [...], "call_graph": {...}, "type_definitions": {...}, "summary": "..."}'
    )


class AssessAnalysisCompletenessTool(BaseTool):
    name: str = 'assess_analysis_completeness'
    description: str = '''Assess the completeness of fault localization analysis across all agents.

This tool evaluates:
1. Required evidence collection: Are all essential pieces of evidence gathered?
2. Analysis depth: How deep and thorough is each agent's analysis?
3. Missing evidence areas: What evidence is still needed?
4. Completeness score: Overall completeness score (0.0 to 1.0)

The tool returns:
- completeness_score: Overall completeness score (0.0 to 1.0)
- agent_completeness: Completeness scores for each agent
- missing_evidence: List of missing evidence items
- analysis_depth: Depth assessment for each agent
- recommendations: Recommendations for improving completeness
- completeness_summary: Summary of completeness assessment

Required evidence:
- Crash Observer: crash_location, suspicious_functions, related_variables
- Code Analyzer: bug_locations (with reasons), bug_scenarios
- Code Collector: functions, call_graph, type_definitions

Use this tool when you need to:
- Determine if analysis is complete enough to draw conclusions
- Identify what additional evidence is needed
- Assess quality and depth of current analysis
- Decide whether to request more analysis from agents'''
    args_schema: Optional[ArgsSchema] = AssessAnalysisCompletenessToolInput

    def __init__(self):
        super().__init__()

    def _run(self, crash_analysis_json: str, bug_analysis_json: str, collected_code_json: str):
        """Assess completeness of analysis across all agents"""
        print(f'[Tool] AssessAnalysisCompletenessTool: {crash_analysis_json} {bug_analysis_json} {collected_code_json}')
        try:
            # Parse input JSON
            crash_analysis = json.loads(crash_analysis_json) if crash_analysis_json else {}
            bug_analysis = json.loads(bug_analysis_json) if bug_analysis_json else []
            collected_code = json.loads(collected_code_json) if collected_code_json else {}
        except json.JSONDecodeError as e:
            return json.dumps({
                'error': f'Invalid JSON input: {str(e)}',
                'completeness_score': 0.0,
                'agent_completeness': {},
                'missing_evidence': [],
                'analysis_depth': {},
                'recommendations': [],
                'completeness_summary': 'Failed to parse input data'
            }, indent=2)

        # Assess Crash Observer completeness
        crash_observer_completeness = 0.0
        crash_observer_missing = []
        crash_observer_depth = 'none'
        
        if crash_analysis:
            # Required fields
            has_crash_location = bool(crash_analysis.get('crash_location'))
            has_suspicious_functions = bool(crash_analysis.get('suspicious_functions'))
            has_related_variables = bool(crash_analysis.get('related_variables'))
            has_summary = bool(crash_analysis.get('summary'))
            
            # Calculate completeness
            required_count = 0
            if has_crash_location:
                required_count += 1
                crash_observer_completeness += 0.4
            else:
                crash_observer_missing.append('crash_location')
            
            if has_suspicious_functions:
                required_count += 1
                crash_observer_completeness += 0.3
            else:
                crash_observer_missing.append('suspicious_functions')
            
            if has_related_variables:
                crash_observer_completeness += 0.2
            else:
                crash_observer_missing.append('related_variables')
            
            if has_summary:
                crash_observer_completeness += 0.1
            
            # Assess depth
            if required_count == 2:
                crash_observer_depth = 'complete'
            elif required_count == 1:
                crash_observer_depth = 'partial'
            else:
                crash_observer_depth = 'minimal'
        else:
            crash_observer_missing = ['crash_location', 'suspicious_functions', 'related_variables']
            crash_observer_depth = 'none'
        
        crash_observer_completeness = round(crash_observer_completeness, 3)
        
        # Assess Code Analyzer completeness
        code_analyzer_completeness = 0.0
        code_analyzer_missing = []
        code_analyzer_depth = 'none'
        
        if bug_analysis:
            total_locations = 0
            total_reasons = 0
            total_scenarios = 0
            
            for analysis in bug_analysis:
                bug_locations = analysis.get('bug_locations', [])
                total_locations += len(bug_locations)
                
                # Count unique reasons
                reasons = set()
                for loc in bug_locations:
                    reason = loc.get('reason', '')
                    if reason:
                        reasons.add(reason)
                total_reasons += len(reasons)
                
                scenarios = analysis.get('bug_scenarios', [])
                total_scenarios += len(scenarios)
            
            # Calculate completeness
            if total_locations > 0:
                code_analyzer_completeness += 0.4
            else:
                code_analyzer_missing.append('bug_locations')
            
            if total_reasons > 0:
                code_analyzer_completeness += 0.3
            else:
                code_analyzer_missing.append('bug_reasons')
            
            if total_scenarios > 0:
                code_analyzer_completeness += 0.2
            else:
                code_analyzer_missing.append('bug_scenarios')
            
            # Depth assessment based on quantity and quality
            if total_locations >= 3 and total_reasons >= 2:
                code_analyzer_depth = 'deep'
            elif total_locations >= 1 and total_reasons >= 1:
                code_analyzer_depth = 'moderate'
            elif total_locations >= 1:
                code_analyzer_depth = 'shallow'
            else:
                code_analyzer_depth = 'minimal'
        else:
            code_analyzer_missing = ['bug_locations', 'bug_reasons', 'bug_scenarios']
            code_analyzer_depth = 'none'
        
        code_analyzer_completeness = round(code_analyzer_completeness, 3)
        
        # Assess Code Collector completeness
        code_collector_completeness = 0.0
        code_collector_missing = []
        code_collector_depth = 'none'
        
        if collected_code:
            # Check functions
            functions = collected_code.get('functions', {})
            has_functions = False
            if isinstance(functions, dict):
                func_list = functions.get('functions', [])
                has_functions = len(func_list) > 0
            elif isinstance(functions, list):
                has_functions = len(functions) > 0
            
            if has_functions:
                code_collector_completeness += 0.4
            else:
                code_collector_missing.append('functions')
            
            # Check call graph
            call_graph = collected_code.get('call_graph', {})
            has_call_graph = bool(call_graph.get('nodes') or call_graph.get('edges'))
            
            if has_call_graph:
                code_collector_completeness += 0.3
            else:
                code_collector_missing.append('call_graph')
            
            # Check type definitions
            type_definitions = collected_code.get('type_definitions', {})
            has_type_defs = False
            if isinstance(type_definitions, dict):
                defs_list = type_definitions.get('definitions', [])
                has_type_defs = len(defs_list) > 0
            elif isinstance(type_definitions, list):
                has_type_defs = len(type_definitions) > 0
            
            if has_type_defs:
                code_collector_completeness += 0.3
            else:
                code_collector_missing.append('type_definitions')
            
            # Depth assessment
            count = sum([has_functions, has_call_graph, has_type_defs])
            if count == 3:
                code_collector_depth = 'comprehensive'
            elif count == 2:
                code_collector_depth = 'moderate'
            elif count == 1:
                code_collector_depth = 'minimal'
            else:
                code_collector_depth = 'none'
        else:
            code_collector_missing = ['functions', 'call_graph', 'type_definitions']
            code_collector_depth = 'none'
        
        code_collector_completeness = round(code_collector_completeness, 3)
        
        # Calculate overall completeness score
        # Weighted average: Crash Observer (40%), Code Analyzer (40%), Code Collector (20%)
        weights = {
            'crash_observer': 0.4,
            'code_analyzer': 0.4,
            'code_collector': 0.2
        }
        
        completeness_score = (
            crash_observer_completeness * weights['crash_observer'] +
            code_analyzer_completeness * weights['code_analyzer'] +
            code_collector_completeness * weights['code_collector']
        )
        completeness_score = round(completeness_score, 3)
        
        # Collect all missing evidence
        all_missing = []
        if crash_observer_missing:
            all_missing.extend([f'CrashObserver: {item}' for item in crash_observer_missing])
        if code_analyzer_missing:
            all_missing.extend([f'CodeAnalyzer: {item}' for item in code_analyzer_missing])
        if code_collector_missing:
            all_missing.extend([f'CodeCollector: {item}' for item in code_collector_missing])
        
        # Generate recommendations
        recommendations = []
        
        if crash_observer_completeness < 0.7:
            recommendations.append({
                'agent': 'CrashObserver',
                'priority': 'high',
                'action': 'Collect missing crash information: ' + ', '.join(crash_observer_missing)
            })
        
        if code_analyzer_completeness < 0.7:
            recommendations.append({
                'agent': 'CodeAnalyzer',
                'priority': 'high',
                'action': 'Perform deeper analysis to find more bug locations and reasons'
            })
        
        if code_collector_completeness < 0.5:
            recommendations.append({
                'agent': 'CodeCollector',
                'priority': 'medium',
                'action': 'Collect more code context: ' + ', '.join(code_collector_missing)
            })
        
        if completeness_score < 0.6:
            recommendations.append({
                'agent': 'all',
                'priority': 'high',
                'action': 'Analysis is incomplete. Request additional analysis from agents with missing evidence.'
            })
        
        # Generate completeness summary
        completeness_summary = f"Overall completeness: {completeness_score:.1%}. "
        
        if completeness_score >= 0.8:
            completeness_summary += "Analysis is highly complete. "
        elif completeness_score >= 0.6:
            completeness_summary += "Analysis is moderately complete. "
        elif completeness_score >= 0.4:
            completeness_summary += "Analysis is partially complete. "
        else:
            completeness_summary += "Analysis is incomplete. "
        
        completeness_summary += f"Crash Observer ({crash_observer_completeness:.1%}, {crash_observer_depth}), "
        completeness_summary += f"Code Analyzer ({code_analyzer_completeness:.1%}, {code_analyzer_depth}), "
        completeness_summary += f"Code Collector ({code_collector_completeness:.1%}, {code_collector_depth}). "
        
        if all_missing:
            completeness_summary += f"Missing: {len(all_missing)} evidence items."
        
        return json.dumps({
            'completeness_score': completeness_score,
            'agent_completeness': {
                'crash_observer': crash_observer_completeness,
                'code_analyzer': code_analyzer_completeness,
                'code_collector': code_collector_completeness
            },
            'missing_evidence': all_missing,
            'analysis_depth': {
                'crash_observer': crash_observer_depth,
                'code_analyzer': code_analyzer_depth,
                'code_collector': code_collector_depth
            },
            'recommendations': recommendations,
            'completeness_summary': completeness_summary
        }, indent=2)