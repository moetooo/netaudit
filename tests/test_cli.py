import pytest
from unittest.mock import patch
import sys
from pathlib import Path
from netaudit.cli import main
from netaudit.models.config import Device, Interface, Vlan
from netaudit.rules.engine import Finding

def test_cli_missing_file(capsys):
    with patch("sys.argv", ["netaudit", "nonexistent_file.cfg"]):
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == 1
        
    captured = capsys.readouterr()
    assert "Error: Configuration file 'nonexistent_file.cfg' not found" in captured.err

@patch("netaudit.cli.IOSParser")
@patch("netaudit.cli.audit_device")
@patch("pathlib.Path.is_file")
@patch("pathlib.Path.read_text")
def test_cli_no_findings(mock_read_text, mock_is_file, mock_audit, mock_parser_cls, capsys):
    mock_is_file.return_value = True
    mock_read_text.return_value = "hostname SW1"
    
    mock_parser_instance = mock_parser_cls.return_value
    mock_parser_instance.parse.return_value = Device(hostname="SW1")
    
    mock_audit.return_value = []
    
    with patch("sys.argv", ["netaudit", "valid_file.cfg"]):
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == 0
        
    captured = capsys.readouterr()
    assert "No issues found." in captured.out

@patch("netaudit.cli.IOSParser")
@patch("netaudit.cli.audit_device")
@patch("pathlib.Path.is_file")
@patch("pathlib.Path.read_text")
def test_cli_with_findings(mock_read_text, mock_is_file, mock_audit, mock_parser_cls, capsys):
    mock_is_file.return_value = True
    mock_read_text.return_value = "hostname SW1"
    
    mock_parser_instance = mock_parser_cls.return_value
    mock_parser_instance.parse.return_value = Device(hostname="SW1")
    
    finding = Finding(
        rule_id="VLAN-001",
        severity="ERROR",
        device="SW1",
        interface="Gi0/1",
        evidence="10",
        description="VLAN 10 is used as access VLAN but not defined."
    )
    mock_audit.return_value = [finding]
    
    with patch("sys.argv", ["netaudit", "valid_file.cfg"]):
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == 1
        
    captured = capsys.readouterr()
    assert "Rule ID: VLAN-001" in captured.out
    assert "Severity: ERROR" in captured.out
    assert "Device: SW1" in captured.out
    assert "Interface: Gi0/1" in captured.out
    assert "Evidence: 10" in captured.out
    assert "VLAN 10 is used as access VLAN but not defined." in captured.out

import json

@patch("netaudit.cli.IOSParser")
@patch("netaudit.cli.audit_device")
@patch("pathlib.Path.is_file")
@patch("pathlib.Path.read_text")
def test_cli_json_no_findings(mock_read_text, mock_is_file, mock_audit, mock_parser_cls, capsys):
    mock_is_file.return_value = True
    mock_read_text.return_value = "hostname SW1"
    
    mock_parser_instance = mock_parser_cls.return_value
    mock_parser_instance.parse.return_value = Device(hostname="SW1")
    
    mock_audit.return_value = []
    
    with patch("sys.argv", ["netaudit", "--json", "valid_file.cfg"]):
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == 0
        
    captured = capsys.readouterr()
    parsed = json.loads(captured.out)
    assert parsed == []

@patch("netaudit.cli.IOSParser")
@patch("netaudit.cli.audit_device")
@patch("pathlib.Path.is_file")
@patch("pathlib.Path.read_text")
def test_cli_json_with_findings(mock_read_text, mock_is_file, mock_audit, mock_parser_cls, capsys):
    mock_is_file.return_value = True
    mock_read_text.return_value = "hostname SW1"
    
    mock_parser_instance = mock_parser_cls.return_value
    mock_parser_instance.parse.return_value = Device(hostname="SW1")
    
    finding = Finding(
        rule_id="VLAN-001",
        severity="ERROR",
        device="SW1",
        interface="Gi0/1",
        evidence="10",
        description="Desc"
    )
    mock_audit.return_value = [finding]
    
    with patch("sys.argv", ["netaudit", "--json", "valid_file.cfg"]):
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == 1
        
    captured = capsys.readouterr()
    parsed = json.loads(captured.out)
    assert len(parsed) == 1
    assert parsed[0]["rule_id"] == "VLAN-001"
    assert parsed[0]["severity"] == "ERROR"
