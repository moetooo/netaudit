from netaudit.rules.engine import Finding

def format_findings(findings: list[Finding]) -> str:
    if not findings:
        return "No issues found."
        
    lines = []
    for finding in findings:
        lines.append(f"Rule ID: {finding.rule_id}")
        lines.append(f"Severity: {finding.severity}")
        lines.append(f"Device: {finding.device}")
        lines.append(f"Interface: {finding.interface}")
        lines.append(f"Evidence: {finding.evidence}")
        lines.append(f"Description: {finding.description}")
        lines.append("-" * 40)
        
    return "\n".join(lines)

import json
from dataclasses import asdict

def format_findings_json(findings: list[Finding]) -> str:
    return json.dumps([asdict(f) for f in findings], indent=2)
