import sys
import argparse
from pathlib import Path

from netaudit.parser.ios_parser import IOSParser
from netaudit.rules.engine import audit_device

def main(args=None):
    parser = argparse.ArgumentParser(description="NetAudit: Network Configuration Auditor")
    parser.add_argument("config_file", help="Path to the Cisco IOS configuration file to audit")
    
    parser.add_argument("--json", action="store_true", help="Output findings in JSON format")
    
    parsed_args = parser.parse_args(args)
    
    config_path = Path(parsed_args.config_file)
    if not config_path.is_file():
        print(f"Error: Configuration file '{parsed_args.config_file}' not found.", file=sys.stderr)
        sys.exit(1)
        
    try:
        content = config_path.read_text(encoding="utf-8")
    except Exception as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        sys.exit(1)
        
    parser_instance = IOSParser()
    device = parser_instance.parse(content)
    
    from netaudit.reports.formatter import format_findings, format_findings_json
    
    findings = audit_device(device)
    
    if parsed_args.json:
        output = format_findings_json(findings)
    else:
        output = format_findings(findings)
        
    print(output)
    
    if not findings:
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()
