# NetAudit

NetAudit is a deterministic, fast, and extensible Cisco IOS configuration auditing tool.

## Problem

Network configuration mistakes on Cisco devices—such as mismatched native VLANs, overlapping subnets, or undefined access VLANs—can cause catastrophic connectivity drops, spanning tree loops, and subtle security vulnerabilities. NetAudit catches these configuration inconsistencies *before* they are deployed to production.

## Features

NetAudit provides a robust engine for offline auditing of Cisco IOS configuration files:
- Built-in Cisco IOS configuration parser
- Structured models for Devices, Interfaces, and VLANs
- Deterministic rules engine (no hallucinations or guesswork)
- VLAN-001: undefined VLAN reference
- VLAN-002: defined but unused VLAN
- VLAN-003: native VLAN mismatch
- VLAN-004: trunk allowed VLAN mismatch
- IP-001: invalid IPv4 address/subnet
- IP-002: duplicate IPv4 address
- IP-003: overlapping IPv4 subnets
- SVI-001: SVI references undefined VLAN
- IP-004: SVI uses network/broadcast address
- Clear, evidence-based human-readable reports
- JSON output for pipeline integration and automation
- Clean command-line interface (CLI)
- Realistic broken and clean Cisco configuration examples
- Automated test coverage with 79 passing tests

## Architecture

NetAudit follows a simple, unidirectional data flow:
1. **Cisco IOS config**: Raw text configuration.
2. **Parser**: `IOSParser` converts the text into structured objects.
3. **Device model**: The configuration is mapped to a `Device` containing `Vlan` and `Interface` entities.
4. **Audit engine**: The `audit_device()` engine applies deterministic rules to the device structure.
5. **Findings**: The engine yields a list of evidence-backed `Finding` objects.
6. **Report**: The formatter renders these findings into a human-readable or JSON output.

## Project Structure

```text
netaudit/
├── examples/               # Broken and clean config examples
│   ├── broken_switch.cfg
│   └── clean_switch.cfg
├── netaudit/
│   ├── cli.py              # CLI entry point
│   ├── models/             # Device, Interface, and Vlan structures
│   ├── parser/             # Cisco IOS regex-based parser
│   ├── reports/            # Human and JSON output formatters
│   └── rules/              # Audit rules engine
└── tests/                  # Unit and end-to-end test suite
```

## Installation

NetAudit is built using standard Python 3. No external runtime dependencies are required for the core engine. 
To install testing dependencies (if developing) and set up the environment:

```bash
python -m venv .venv
source .venv/bin/activate  # Or .venv\Scripts\activate on Windows
pip install -r requirements.txt
```

## Usage

### Auditing a configuration

You can run the audit tool via the CLI:
```bash
python -m netaudit.cli examples/broken_switch.cfg
```

### JSON Output

To get a machine-readable JSON array of findings:
```bash
python -m netaudit.cli --json examples/broken_switch.cfg
```

### Running on a clean config

```bash
python -m netaudit.cli examples/clean_switch.cfg
# Output: No issues found.
```

### Example Human-Readable Output

```text
Rule ID: VLAN-001
Severity: ERROR
Device: BROKEN-SW1
Interface: GigabitEthernet0/1
Evidence: 50
Description: VLAN 50 is used as access VLAN but not defined on the device.
----------------------------------------
Rule ID: VLAN-003
Severity: ERROR
Device: BROKEN-SW1
Interface: GigabitEthernet0/2, GigabitEthernet0/3
Evidence: 10, 20
Description: Trunk interfaces GigabitEthernet0/2, GigabitEthernet0/3 have mismatched native VLANs.
----------------------------------------
```

### Example JSON Output

```json
[
  {
    "rule_id": "VLAN-001",
    "severity": "ERROR",
    "device": "BROKEN-SW1",
    "interface": "GigabitEthernet0/1",
    "evidence": "50",
    "description": "VLAN 50 is used as access VLAN but not defined on the device."
  }
]
```

## Audit Rules Table

| Rule ID  | What it detects                                                                 | Severity |
|----------|---------------------------------------------------------------------------------|----------|
| VLAN-001 | An interface references an access, native, or allowed VLAN that is not defined. | ERROR    |
| VLAN-002 | A VLAN is globally defined but completely unused on the device.                 | WARNING  |
| VLAN-003 | Native VLAN mismatch between explicitly peered trunk interfaces across devices.      | ERROR    |
| VLAN-004 | Allowed VLAN list mismatch between explicitly peered trunk interfaces across devices.| ERROR    |
| IP-001   | An interface has an invalid IPv4 address or invalid subnet mask.                | ERROR    |
| IP-002   | The exact same IPv4 address is assigned to multiple interfaces (duplicate).     | ERROR    |
| IP-003   | IPv4 subnet overlap between two different interfaces.                           | ERROR    |
| SVI-001  | An SVI (e.g. Vlan10) references a VLAN ID that is not defined on the device.    | ERROR    |
| IP-004   | An interface uses the network or broadcast address of its own subnet (except /31).| ERROR    |

> **Current scope:** VLAN-003 and VLAN-004 are topology-aware and require explicit peer link information to be provided. NetAudit does not currently discover physical links automatically. Without peer information, these checks are skipped.

## Testing

NetAudit is thoroughly tested. You can run the entire test suite using `pytest`:

```bash
pytest -q
```
*Current test suite: 79 passing tests.*

## Design Principles

- **Deterministic rules**: The parser and engine represent the single source of truth. Rules are strictly hardcoded and evaluated systematically to ensure consistency.
- **Evidence-based findings**: Every rule outputs the exact interface pair, VLAN ID, or subnet that triggered the alert. 
- **AI as an Explainer, Not an Arbiter**: If AI capabilities are added in the future, they will be used to explain deterministic findings rather than decide whether a configuration is valid. The audit engine remains the source of truth.

---
*Disclaimer: NetAudit is a local configuration auditor and is not intended for automated production deployment without proper review.*
