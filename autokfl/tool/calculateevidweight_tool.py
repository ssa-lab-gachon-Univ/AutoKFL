import json
import os
from typing import Optional
from pydantic import BaseModel, Field
from langchain_core.tools import BaseTool
from langchain_core.tools.base import ArgsSchema


class CalculateEvidenceWeightToolInput(BaseModel):
    crash_analysis_json: str = Field(
        description='JSON string of crash_analysis from CrashObserver. Format: {"crash_location": "...", "suspicious_functions": [...], "related_variables": [...], "summary": "..."}'
    )
    bug_analysis_json: str = Field(
        description='JSON string of bug_analysis list from CodeAnalyzer. Format: [{"bug_locations": [{"file": "...", "line": 123, "score": 0.8, "reason": "..."}], "bug_scenarios": [...], "summary": "..."}]'
    )
    collected_code_json: str = Field(
        description='JSON string of collected_code from CodeCollector. Format: {"functions": [...], "call_graph": {...}, "type_definitions": {...}, "summary": "..."}'
    )


class CalculateEvidenceWeightTool(BaseTool):
    name: str = 'calculate_evidence_weight'
    description: str = '''Calculate evidence weights for different agent outputs to properly synthesize evidence.

This tool assigns weights to evidence from different agents based on their reliability:
- Crash Observer: High weight (0.5-0.6) - Direct observation of crash location
- Code Analyzer: Medium weight (0.3-0.4) - Pattern-based inference
- Code Collector: Low weight (0.1-0.2) - Contextual information

The tool returns:
- evidence_weights: Weights for each agent/evidence type
- weighted_evidence: Evidence with applied weights
- weight_summary: Summary of weight calculation
- reasoning: Explanation of weight assignment logic

Weight calculation factors:
1. Evidence type: Direct observation > Inference > Context
2. Evidence quality: Complete evidence gets higher weight
3. Evidence consistency: Consistent evidence across agents gets higher weight
4. Evidence completeness: More complete evidence gets higher weight

Use this tool when you need to:
- Determine how much to trust evidence from each agent
- Calculate weighted evidence for synthesis
- Understand which evidence contributes most to final result'''
    args_schema: Optional[ArgsSchema] = CalculateEvidenceWeightToolInput

    def __init__(self):
        super().__init__()

    def _run(self, crash_analysis_json: str, bug_analysis_json: str, collected_code_json: str):
        """Calculate evidence weights based on agent types and evidence quality"""
        print(f'[Tool] CalculateEvidenceWeightTool: {crash_analysis_json} {bug_analysis_json} {collected_code_json}')
        try:
            # Parse input JSON
            crash_analysis = json.loads(crash_analysis_json) if crash_analysis_json else {}
            bug_analysis = json.loads(bug_analysis_json) if bug_analysis_json else []
            collected_code = json.loads(collected_code_json) if collected_code_json else {}
        except json.JSONDecodeError as e:
            return json.dumps({
                'error': f'Invalid JSON input: {str(e)}',
                'evidence_weights': {},
                'weighted_evidence': [],
                'weight_summary': 'Failed to parse input data'
            }, indent=2)

        # Base weights for each agent type
        base_weights = {
            'crash_observer': 0.55,  # High weight - direct observation
            'code_analyzer': 0.35,   # Medium weight - pattern inference
            'code_collector': 0.10   # Low weight - contextual info
        }

        # Adjust weights based on evidence quality and completeness
        weight_adjustments = {
            'crash_observer': 0.0,
            'code_analyzer': 0.0,
            'code_collector': 0.0
        }

        # Evaluate Crash Observer evidence quality
        crash_observer_quality = 0.0
        if crash_analysis:
            if crash_analysis.get('crash_location'):
                crash_observer_quality += 0.3
            if crash_analysis.get('suspicious_functions'):
                crash_observer_quality += 0.2
            if crash_analysis.get('related_variables'):
                crash_observer_quality += 0.1
            if crash_analysis.get('summary'):
                crash_observer_quality += 0.1
        
        # Adjust weight based on quality (max +0.1 bonus)
        if crash_observer_quality >= 0.5:
            weight_adjustments['crash_observer'] = 0.05
        elif crash_observer_quality >= 0.3:
            weight_adjustments['crash_observer'] = 0.0
        else:
            weight_adjustments['crash_observer'] = -0.05

        # Evaluate Code Analyzer evidence quality
        code_analyzer_quality = 0.0
        if bug_analysis:
            # Count number of analyses
            num_analyses = len(bug_analysis)
            code_analyzer_quality += min(0.2, num_analyses * 0.05)
            
            # Count total bug locations found
            total_locations = sum(len(analysis.get('bug_locations', [])) for analysis in bug_analysis)
            code_analyzer_quality += min(0.2, total_locations * 0.02)
            
            # Check for bug scenarios
            total_scenarios = sum(len(analysis.get('bug_scenarios', [])) for analysis in bug_analysis)
            code_analyzer_quality += min(0.1, total_scenarios * 0.01)
            
            # Check for reason diversity
            all_reasons = set()
            for analysis in bug_analysis:
                for loc in analysis.get('bug_locations', []):
                    reason = loc.get('reason', '')
                    if reason:
                        all_reasons.add(reason)
            code_analyzer_quality += min(0.1, len(all_reasons) * 0.02)
        
        # Adjust weight based on quality (max +0.1 bonus)
        if code_analyzer_quality >= 0.4:
            weight_adjustments['code_analyzer'] = 0.05
        elif code_analyzer_quality >= 0.2:
            weight_adjustments['code_analyzer'] = 0.0
        else:
            weight_adjustments['code_analyzer'] = -0.05

        # Evaluate Code Collector evidence quality
        code_collector_quality = 0.0
        if collected_code:
            functions = collected_code.get('functions', {})
            if isinstance(functions, dict) and functions.get('functions'):
                code_collector_quality += 0.2
            elif isinstance(functions, list) and len(functions) > 0:
                code_collector_quality += 0.2
            
            call_graph = collected_code.get('call_graph', {})
            if call_graph.get('nodes') or call_graph.get('edges'):
                code_collector_quality += 0.1
            
            type_definitions = collected_code.get('type_definitions', {})
            if isinstance(type_definitions, dict) and type_definitions.get('definitions'):
                code_collector_quality += 0.1
            elif isinstance(type_definitions, list) and len(type_definitions) > 0:
                code_collector_quality += 0.1
        
        # Adjust weight based on quality (max +0.05 bonus)
        if code_collector_quality >= 0.3:
            weight_adjustments['code_collector'] = 0.05
        elif code_collector_quality >= 0.2:
            weight_adjustments['code_collector'] = 0.0
        else:
            weight_adjustments['code_collector'] = -0.05

        # Calculate final weights
        final_weights = {}
        for agent, base_weight in base_weights.items():
            adjusted_weight = base_weight + weight_adjustments[agent]
            # Ensure weights stay within reasonable bounds
            if agent == 'crash_observer':
                adjusted_weight = max(0.4, min(0.7, adjusted_weight))
            elif agent == 'code_analyzer':
                adjusted_weight = max(0.2, min(0.5, adjusted_weight))
            else:  # code_collector
                adjusted_weight = max(0.05, min(0.2, adjusted_weight))
            final_weights[agent] = round(adjusted_weight, 3)

        # Normalize weights to sum to 1.0
        total_weight = sum(final_weights.values())
        if total_weight > 0:
            normalized_weights = {
                agent: round(weight / total_weight, 3)
                for agent, weight in final_weights.items()
            }
        else:
            normalized_weights = final_weights

        # Create weighted evidence list
        weighted_evidence = []
        
        # Crash Observer evidence
        if crash_analysis:
            crash_evidence = {
                'agent': 'crash_observer',
                'weight': normalized_weights['crash_observer'],
                'evidence_type': 'direct_observation',
                'evidence': {
                    'crash_location': crash_analysis.get('crash_location', ''),
                    'suspicious_functions': crash_analysis.get('suspicious_functions', []),
                    'related_variables': crash_analysis.get('related_variables', []),
                    'quality_score': round(crash_observer_quality, 3)
                }
            }
            weighted_evidence.append(crash_evidence)
        
        # Code Analyzer evidence
        if bug_analysis:
            analyzer_evidence = {
                'agent': 'code_analyzer',
                'weight': normalized_weights['code_analyzer'],
                'evidence_type': 'pattern_inference',
                'evidence': {
                    'num_analyses': len(bug_analysis),
                    'total_locations': sum(len(analysis.get('bug_locations', [])) for analysis in bug_analysis),
                    'total_scenarios': sum(len(analysis.get('bug_scenarios', [])) for analysis in bug_analysis),
                    'quality_score': round(code_analyzer_quality, 3)
                }
            }
            weighted_evidence.append(analyzer_evidence)
        
        # Code Collector evidence
        if collected_code:
            collector_evidence = {
                'agent': 'code_collector',
                'weight': normalized_weights['code_collector'],
                'evidence_type': 'contextual_info',
                'evidence': {
                    'has_functions': bool(collected_code.get('functions')),
                    'has_call_graph': bool(collected_code.get('call_graph')),
                    'has_type_definitions': bool(collected_code.get('type_definitions')),
                    'quality_score': round(code_collector_quality, 3)
                }
            }
            weighted_evidence.append(collector_evidence)

        # Generate weight summary
        weight_summary = f"Evidence weights calculated: "
        weight_summary += f"Crash Observer ({normalized_weights.get('crash_observer', 0.0):.1%}), "
        weight_summary += f"Code Analyzer ({normalized_weights.get('code_analyzer', 0.0):.1%}), "
        weight_summary += f"Code Collector ({normalized_weights.get('code_collector', 0.0):.1%}). "
        
        if crash_observer_quality >= 0.5:
            weight_summary += "Crash Observer evidence is high quality. "
        if code_analyzer_quality >= 0.4:
            weight_summary += "Code Analyzer evidence is comprehensive. "
        if code_collector_quality >= 0.3:
            weight_summary += "Code Collector evidence is complete. "

        # Generate reasoning
        reasoning = "Weight calculation logic: "
        reasoning += "(1) Base weights assigned by evidence type (direct observation > inference > context). "
        reasoning += "(2) Quality adjustments: +0.05 for high quality, -0.05 for low quality. "
        reasoning += "(3) Weights normalized to sum to 1.0. "
        reasoning += f"Crash Observer quality: {crash_observer_quality:.2f}, "
        reasoning += f"Code Analyzer quality: {code_analyzer_quality:.2f}, "
        reasoning += f"Code Collector quality: {code_collector_quality:.2f}."

        return json.dumps({
            'evidence_weights': normalized_weights,
            'weighted_evidence': weighted_evidence,
            'weight_summary': weight_summary,
            'reasoning': reasoning,
            'quality_scores': {
                'crash_observer': round(crash_observer_quality, 3),
                'code_analyzer': round(code_analyzer_quality, 3),
                'code_collector': round(code_collector_quality, 3)
            }
        }, indent=2)