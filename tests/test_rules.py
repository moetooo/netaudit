import pytest
from pathlib import Path
from netaudit.models.config import Device, Interface, Vlan
from netaudit.rules.engine import audit_device
from netaudit.parser.ios_parser import parse_ios_config

def test_valid_access_vlan_no_finding():
    device = Device(hostname="SW1")
    device.vlans[10] = Vlan(vlan_id=10, name="USERS")
    device.interfaces["Gi0/1"] = Interface(name="Gi0/1", mode="access", access_vlan=10)
    
    findings = audit_device(device)
    assert len(findings) == 0

def test_undefined_access_vlan_finding():
    device = Device(hostname="SW1")
    # VLAN 10 is NOT defined in device.vlans
    device.interfaces["Gi0/1"] = Interface(name="Gi0/1", mode="access", access_vlan=10)
    
    findings = audit_device(device)
    assert len(findings) == 1
    assert findings[0].rule_id == "VLAN-001"
    assert findings[0].evidence == "10"
    assert findings[0].interface == "Gi0/1"

def test_valid_trunk_allowed_vlans_no_finding():
    device = Device(hostname="SW1")
    device.vlans[10] = Vlan(vlan_id=10)
    device.vlans[20] = Vlan(vlan_id=20)
    device.interfaces["Gi0/1"] = Interface(name="Gi0/1", mode="trunk", allowed_vlans=[10, 20])
    
    findings = audit_device(device)
    assert len(findings) == 0

def test_undefined_trunk_allowed_vlan_finding():
    device = Device(hostname="SW1")
    device.vlans[10] = Vlan(vlan_id=10)
    # VLAN 20 is NOT defined
    device.interfaces["Gi0/1"] = Interface(name="Gi0/1", mode="trunk", allowed_vlans=[10, 20])
    
    findings = audit_device(device)
    assert len(findings) == 1
    assert findings[0].rule_id == "VLAN-001"
    assert findings[0].evidence == "20"
    assert findings[0].interface == "Gi0/1"

def test_undefined_native_vlan_finding():
    device = Device(hostname="SW1")
    # Native VLAN 99 is NOT defined
    device.interfaces["Gi0/1"] = Interface(name="Gi0/1", mode="trunk", native_vlan=99)
    
    findings = audit_device(device)
    assert len(findings) == 1
    assert findings[0].rule_id == "VLAN-001"
    assert findings[0].evidence == "99"
    assert findings[0].interface == "Gi0/1"

def test_multiple_undefined_vlans():
    device = Device(hostname="SW1")
    device.interfaces["Gi0/1"] = Interface(
        name="Gi0/1", mode="trunk", native_vlan=99, allowed_vlans=[10, 20]
    )
    # 99, 10, 20 are all undefined
    findings = audit_device(device)
    assert len(findings) == 3
    evidences = {f.evidence for f in findings}
    assert evidences == {"10", "20", "99"}

def test_duplicate_findings_not_reported():
    device = Device(hostname="SW1")
    device.interfaces["Gi0/1"] = Interface(
        name="Gi0/1", mode="access", access_vlan=10
    )
    # Let's say it's somehow in allowed_vlans as well (e.g. misconfigured model)
    device.interfaces["Gi0/1"].allowed_vlans = [10]
    
    findings = audit_device(device)
    assert len(findings) == 1
    assert findings[0].evidence == "10"

def test_clean_fixture_produces_zero_findings():
    fixture_path = Path(__file__).parent / "fixtures" / "switch1.cfg"
    content = fixture_path.read_text(encoding="utf-8")
    device = parse_ios_config(content)
    
    findings = audit_device(device)
    assert len(findings) == 0
