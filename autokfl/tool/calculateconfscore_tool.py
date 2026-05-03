import json
from typing import Optional
from pydantic import BaseModel, Field
from langchain_core.tools import BaseTool
from langchain_core.tools.base import ArgsSchema


class CalculateConfidenceScoreToolInput(BaseModel):
    crash_analysis_json: str = Field(
        description='JSON string of crash_analysis from CrashObserver. Format: {"crash_location": "...", "suspicious_functions": [...], "related_variables": [...], "summary": "..."}'
    )
    bug_analysis_json: str = Field(
        description='JSON string of bug_analysis list from CodeAnalyzer. Format: [{"bug_locations": [{"file": "...", "line": 123, "score": 0.8, "reason": "..."}], "bug_scenarios": [...], "summary": "..."}]'
    )
    collected_code_json: str = Field(
        description='JSON string of collected_code from CodeCollector. Format: {"functions": [...], "call_graph": {...}, "type_definitions": {...}, "summary": "..."}'
    )


class CalculateConfidenceScoreTool(BaseTool):
    name: str = 'calculate_confidence_score'
    description: str = '''Calculate confidence scores for bug locations based on evidence from all agents.

This tool synthesizes evidence from:
- Crash Observer: Crash location and suspicious functions (high weight)
- Code Analyzer: Bug pattern detections with scores (medium weight)
- Code Collector: Collected code context (low weight for confidence, but important for context)

The tool returns:
- location_confidences: List of bug locations with calculated confidence scores
- overall_confidence: Overall confidence score for the entire analysis (0.0 to 1.0)
- evidence_summary: Summary of how confidence was calculated
- reasoning: Explanation of confidence calculation logic

Confidence calculation factors:
1. Crash location proximity: Locations closer to crash point get higher confidence
2. Pattern match strength: Higher scores from Code Analyzer increase confidence
3. Evidence consistency: Multiple agents pointing to same location increases confidence
4. Evidence quality: Direct observations (Crash Observer) weighted higher than inferences (Code Analyzer)

Use this tool when you need to:
- Calculate final confidence scores for ranked_locations
- Determine overall confidence for the analysis
- Understand which evidence contributes most to confidence'''
    args_schema: Optional[ArgsSchema] = CalculateConfidenceScoreToolInput

    def __init__(self):
        super().__init__()

    def _run(self, crash_analysis_json: str, bug_analysis_json: str, collected_code_json: str):
        """Calculate confidence scores based on evidence from all agents"""
        print(f'[Tool] CalculateConfidenceScoreTool: {crash_analysis_json} {bug_analysis_json} {collected_code_json}')
        try:
            # Parse input JSON
            crash_analysis = json.loads(crash_analysis_json) if crash_analysis_json else {}
            bug_analysis = json.loads(bug_analysis_json) if bug_analysis_json else []
            collected_code = json.loads(collected_code_json) if collected_code_json else {}
        except json.JSONDecodeError as e:
            return json.dumps({
                'error': f'Invalid JSON input: {str(e)}',
                'location_confidences': [],
                'overall_confidence': 0.0,
                'evidence_summary': 'Failed to parse input data'
            }, indent=2)

        # Extract crash location
        crash_location_str = crash_analysis.get('crash_location', '')
        suspicious_functions = crash_analysis.get('suspicious_functions', [])
        
        # Collect all bug locations from bug_analysis
        all_bug_locations = {}
        for analysis in bug_analysis:
            bug_locations = analysis.get('bug_locations', [])
            for loc in bug_locations:
                file = loc.get('file', '')
                line = loc.get('line', 0)
                key = f"{file}:{line}"
                
                if key not in all_bug_locations:
                    all_bug_locations[key] = {
                        'file': file,
                        'line': line,
                        'scores': [],
                        'reasons': [],
                        'scenarios': []
                    }
                
                # Collect scores and reasons
                score = loc.get('score', 0.0)
                reason = loc.get('reason', '')
                all_bug_locations[key]['scores'].append(score)
                if reason:
                    all_bug_locations[key]['reasons'].append(reason)
            
            # Collect scenarios
            scenarios = analysis.get('bug_scenarios', [])
            for scenario in scenarios:
                # Try to extract file:line from scenario text
                # This is a heuristic - scenarios might mention locations
                for key in all_bug_locations:
                    if key.replace(':', ':') in scenario or key.split('/')[-1] in scenario:
                        all_bug_locations[key]['scenarios'].append(scenario)

        # Calculate confidence for each location
        location_confidences = []
        
        for key, loc_data in all_bug_locations.items():
            file = loc_data['file']
            line = loc_data['line']
            scores = loc_data['scores']
            reasons = loc_data['reasons']
            
            # Base confidence from Code Analyzer scores (medium weight: 0.4)
            avg_score = sum(scores) / len(scores) if scores else 0.0
            base_confidence = avg_score * 0.4
            
            # Crash location proximity bonus (high weight: 0.4)
            crash_proximity = 0.0
            if crash_location_str:
                # Check if this location is mentioned in crash location
                if file in crash_location_str or any(fn in crash_location_str for fn in suspicious_functions):
                    crash_proximity = 0.4
                # Check if function name matches suspicious functions
                elif any(fn in file or file.endswith(fn.split('/')[-1]) for fn in suspicious_functions):
                    crash_proximity = 0.3
            
            # Reason consistency bonus (medium weight: 0.15)
            pattern_bonus = 0.0
            if len(set(reasons)) > 1:  # Multiple different reasons
                pattern_bonus = 0.1
            elif len(reasons) > 1:  # Same reason multiple times
                pattern_bonus = 0.15
            
            # Evidence count bonus (low weight: 0.05)
            evidence_count_bonus = min(0.05, len(scores) * 0.01)
            
            # Calculate final confidence
            confidence = min(1.0, base_confidence + crash_proximity + pattern_bonus + evidence_count_bonus)
            
            location_confidences.append({
                'file': file,
                'line': line,
                'confidence': round(confidence, 3),
                'factors': {
                    'base_score': round(base_confidence, 3),
                    'crash_proximity': round(crash_proximity, 3),
                    'pattern_consistency': round(pattern_bonus, 3),
                    'evidence_count': len(scores)
                }
            })
        
        # Sort by confidence (descending)
        location_confidences.sort(key=lambda x: x['confidence'], reverse=True)
        
        # Calculate overall confidence
        if location_confidences:
            # Overall confidence is weighted average of top locations
            top_3_confidences = [loc['confidence'] for loc in location_confidences[:3]]
            overall_confidence = sum(top_3_confidences) / len(top_3_confidences)
            
            # Adjust based on evidence quality
            if crash_analysis and crash_analysis.get('crash_location'):
                overall_confidence = min(1.0, overall_confidence * 1.1)  # Boost if crash location available
            
            if len(bug_analysis) > 1:
                overall_confidence = min(1.0, overall_confidence * 1.05)  # Boost if multiple analyses
        else:
            overall_confidence = 0.0
        
        overall_confidence = round(min(1.0, max(0.0, overall_confidence)), 3)
        
        # Generate evidence summary
        evidence_summary = f"Analyzed {len(location_confidences)} bug locations from {len(bug_analysis)} Code Analyzer results. "
        if crash_analysis.get('crash_location'):
            evidence_summary += f"Crash location: {crash_analysis.get('crash_location')}. "
        if location_confidences:
            evidence_summary += f"Top location: {location_confidences[0]['file']}:{location_confidences[0]['line']} (confidence: {location_confidences[0]['confidence']}). "
        evidence_summary += f"Overall confidence: {overall_confidence}."
        
        # Generate reasoning
        reasoning = "Confidence calculated using: "
        reasoning += "(1) Code Analyzer pattern scores (40% weight), "
        reasoning += "(2) Crash location proximity (40% weight), "
        reasoning += "(3) Pattern consistency (15% weight), "
        reasoning += "(4) Evidence count (5% weight). "
        reasoning += "Overall confidence is weighted average of top 3 locations, adjusted by evidence quality."
        
        return json.dumps({
            'location_confidences': location_confidences,
            'overall_confidence': overall_confidence,
            'evidence_summary': evidence_summary,
            'reasoning': reasoning
        }, indent=2)