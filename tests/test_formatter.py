from netaudit.reports.formatter import format_findings
from netaudit.rules.engine import Finding

def test_format_empty_findings():
    assert format_findings([]) == "No issues found."

def test_format_one_finding():
    finding = Finding(
        rule_id="TEST-001",
        severity="ERROR",
        device="SW1",
        interface="Gi0/1",
        evidence="Some evidence",
        description="A test description"
    )
    result = format_findings([finding])
    assert "Rule ID: TEST-001" in result
    assert "Severity: ERROR" in result
    assert "Device: SW1" in result
    assert "Interface: Gi0/1" in result
    assert "Evidence: Some evidence" in result
    assert "Description: A test description" in result
    assert "----------------------------------------" in result

def test_format_multiple_findings():
    f1 = Finding(
        rule_id="TEST-001",
        severity="ERROR",
        device="SW1",
        interface="Gi0/1",
        evidence="Ev1",
        description="Desc1"
    )
    f2 = Finding(
        rule_id="TEST-002",
        severity="WARNING",
        device="SW1",
        interface="Gi0/2",
        evidence="Ev2",
        description="Desc2"
    )
    result = format_findings([f1, f2])
    assert "Rule ID: TEST-001" in result
    assert "Rule ID: TEST-002" in result
    assert result.count("----------------------------------------") == 2

import json
from netaudit.reports.formatter import format_findings_json

def test_format_json_empty_findings():
    assert format_findings_json([]) == "[]"

def test_format_json_one_finding():
    finding = Finding(
        rule_id="TEST-001",
        severity="ERROR",
        device="SW1",
        interface="Gi0/1",
        evidence="Some evidence",
        description="A test description"
    )
    result = format_findings_json([finding])
    parsed = json.loads(result)
    assert len(parsed) == 1
    assert parsed[0]["rule_id"] == "TEST-001"
    assert parsed[0]["severity"] == "ERROR"
    assert parsed[0]["device"] == "SW1"
    assert parsed[0]["interface"] == "Gi0/1"
    assert parsed[0]["evidence"] == "Some evidence"
    assert parsed[0]["description"] == "A test description"

def test_format_json_multiple_findings():
    f1 = Finding(
        rule_id="TEST-001",
        severity="ERROR",
        device="SW1",
        interface="Gi0/1",
        evidence="Ev1",
        description="Desc1"
    )
    f2 = Finding(
        rule_id="TEST-002",
        severity="WARNING",
        device="SW1",
        interface="Gi0/2",
        evidence="Ev2",
        description="Desc2"
    )
    result = format_findings_json([f1, f2])
    parsed = json.loads(result)
    assert len(parsed) == 2
    assert parsed[0]["rule_id"] == "TEST-001"
    assert parsed[1]["rule_id"] == "TEST-002"
