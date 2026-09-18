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

def test_valid_ip_and_mask_no_finding():
    device = Device(hostname="SW1")
    device.vlans[10] = Vlan(vlan_id=10)
    device.interfaces["Vlan10"] = Interface(
        name="Vlan10", ip_address="192.168.10.1", subnet_mask="255.255.255.0"
    )
    findings = audit_device(device)
    assert len(findings) == 0

def test_invalid_ipv4_address_finding():
    device = Device(hostname="SW1")
    device.vlans[10] = Vlan(vlan_id=10)
    device.interfaces["Vlan10"] = Interface(
        name="Vlan10", ip_address="192.168.10.999", subnet_mask="255.255.255.0"
    )
    findings = audit_device(device)
    assert len(findings) == 1
    assert findings[0].rule_id == "IP-001"
    assert findings[0].evidence == "192.168.10.999 / 255.255.255.0"

def test_invalid_subnet_mask_finding():
    device = Device(hostname="SW1")
    device.vlans[10] = Vlan(vlan_id=10)
    device.interfaces["Vlan10"] = Interface(
        name="Vlan10", ip_address="192.168.10.1", subnet_mask="255.0.255.0"
    )
    findings = audit_device(device)
    assert len(findings) == 1
    assert findings[0].rule_id == "IP-001"
    assert findings[0].evidence == "192.168.10.1 / 255.0.255.0"

def test_interface_without_ip_no_finding():
    device = Device(hostname="SW1")
    device.interfaces["Gi0/1"] = Interface(name="Gi0/1")
    findings = audit_device(device)
    assert len(findings) == 0

def test_multiple_interfaces_only_invalid_gets_finding():
    device = Device(hostname="SW1")
    device.vlans[10] = Vlan(vlan_id=10)
    device.interfaces["Vlan10"] = Interface(
        name="Vlan10", ip_address="192.168.10.1", subnet_mask="255.255.255.0"
    )
    device.vlans[20] = Vlan(vlan_id=20)
    device.interfaces["Vlan20"] = Interface(
        name="Vlan20", ip_address="192.168.20.999", subnet_mask="255.255.255.0"
    )
    findings = audit_device(device)
    assert len(findings) == 1
    assert findings[0].rule_id == "IP-001"
    assert findings[0].interface == "Vlan20"

def test_two_interfaces_same_ip_finding():
    device = Device(hostname="SW1")
    device.vlans[10] = Vlan(vlan_id=10)
    device.interfaces["Vlan10"] = Interface(
        name="Vlan10", ip_address="192.168.10.1", subnet_mask="255.255.255.0"
    )
    device.vlans[20] = Vlan(vlan_id=20)
    device.interfaces["Vlan20"] = Interface(
        name="Vlan20", ip_address="192.168.10.1", subnet_mask="255.255.255.0"
    )
    findings = audit_device(device)
    assert len(findings) == 1
    assert findings[0].rule_id == "IP-002"
    assert findings[0].evidence == "192.168.10.1"
    assert findings[0].interface == "Vlan10, Vlan20"

def test_two_interfaces_different_ips_no_finding():
    device = Device(hostname="SW1")
    device.vlans[10] = Vlan(vlan_id=10)
    device.interfaces["Vlan10"] = Interface(
        name="Vlan10", ip_address="192.168.10.1", subnet_mask="255.255.255.0"
    )
    device.vlans[20] = Vlan(vlan_id=20)
    device.interfaces["Vlan20"] = Interface(
        name="Vlan20", ip_address="192.168.20.1", subnet_mask="255.255.255.0"
    )
    findings = audit_device(device)
    assert len(findings) == 0

def test_ip_002_ignores_interface_without_ip():
    device = Device(hostname="SW1")
    device.vlans[10] = Vlan(vlan_id=10)
    device.interfaces["Vlan10"] = Interface(
        name="Vlan10", ip_address="192.168.10.1", subnet_mask="255.255.255.0"
    )
    device.interfaces["Gi0/1"] = Interface(name="Gi0/1")
    findings = audit_device(device)
    assert len(findings) == 0

def test_three_interfaces_same_ip_one_finding():
    device = Device(hostname="SW1")
    device.vlans[10] = Vlan(vlan_id=10)
    device.interfaces["Vlan10"] = Interface(
        name="Vlan10", ip_address="192.168.10.1", subnet_mask="255.255.255.0"
    )
    device.vlans[20] = Vlan(vlan_id=20)
    device.interfaces["Vlan20"] = Interface(
        name="Vlan20", ip_address="192.168.10.1", subnet_mask="255.255.255.0"
    )
    device.vlans[30] = Vlan(vlan_id=30)
    device.interfaces["Vlan30"] = Interface(
        name="Vlan30", ip_address="192.168.10.1", subnet_mask="255.255.255.0"
    )
    findings = audit_device(device)
    assert len(findings) == 1
    assert findings[0].rule_id == "IP-002"
    assert findings[0].interface == "Vlan10, Vlan20, Vlan30"

def test_overlapping_24_and_25_networks_finding():
    device = Device(hostname="SW1")
    device.vlans[10] = Vlan(vlan_id=10)
    device.interfaces["Vlan10"] = Interface(
        name="Vlan10", ip_address="192.168.10.1", subnet_mask="255.255.255.0"
    )
    device.vlans[20] = Vlan(vlan_id=20)
    device.interfaces["Vlan20"] = Interface(
        name="Vlan20", ip_address="192.168.10.129", subnet_mask="255.255.255.128"
    )
    findings = audit_device(device)
    assert len(findings) == 1
    assert findings[0].rule_id == "IP-003"
    assert "192.168.10.0/24" in findings[0].evidence
    assert "192.168.10.128/25" in findings[0].evidence
    assert findings[0].interface == "Vlan10, Vlan20"

def test_non_overlapping_networks_no_finding():
    device = Device(hostname="SW1")
    device.vlans[10] = Vlan(vlan_id=10)
    device.interfaces["Vlan10"] = Interface(
        name="Vlan10", ip_address="192.168.10.1", subnet_mask="255.255.255.0"
    )
    device.vlans[20] = Vlan(vlan_id=20)
    device.interfaces["Vlan20"] = Interface(
        name="Vlan20", ip_address="192.168.20.1", subnet_mask="255.255.255.0"
    )
    findings = audit_device(device)
    assert len(findings) == 0

def test_adjacent_networks_no_finding():
    device = Device(hostname="SW1")
    # 192.168.10.0/25 and 192.168.10.128/25 are adjacent, not overlapping
    device.vlans[10] = Vlan(vlan_id=10)
    device.interfaces["Vlan10"] = Interface(
        name="Vlan10", ip_address="192.168.10.1", subnet_mask="255.255.255.128"
    )
    device.vlans[20] = Vlan(vlan_id=20)
    device.interfaces["Vlan20"] = Interface(
        name="Vlan20", ip_address="192.168.10.129", subnet_mask="255.255.255.128"
    )
    findings = audit_device(device)
    assert len(findings) == 0

def test_duplicate_ips_gets_ip_002_but_not_ip_003():
    device = Device(hostname="SW1")
    device.vlans[10] = Vlan(vlan_id=10)
    device.interfaces["Vlan10"] = Interface(
        name="Vlan10", ip_address="192.168.10.1", subnet_mask="255.255.255.0"
    )
    device.vlans[20] = Vlan(vlan_id=20)
    device.interfaces["Vlan20"] = Interface(
        name="Vlan20", ip_address="192.168.10.1", subnet_mask="255.255.255.128"
    )
    findings = audit_device(device)
    assert len(findings) == 1
    assert findings[0].rule_id == "IP-002"

def test_three_overlapping_interfaces_no_duplicate_pairs():
    device = Device(hostname="SW1")
    device.vlans[10] = Vlan(vlan_id=10)
    device.interfaces["Vlan10"] = Interface(
        name="Vlan10", ip_address="10.0.0.1", subnet_mask="255.0.0.0"
    )
    device.vlans[20] = Vlan(vlan_id=20)
    device.interfaces["Vlan20"] = Interface(
        name="Vlan20", ip_address="10.1.0.1", subnet_mask="255.255.0.0"
    )
    device.vlans[30] = Vlan(vlan_id=30)
    device.interfaces["Vlan30"] = Interface(
        name="Vlan30", ip_address="10.1.1.1", subnet_mask="255.255.255.0"
    )
    findings = audit_device(device)
    
    ip_003_findings = [f for f in findings if f.rule_id == "IP-003"]
    # There are exactly 3 unique pairs: (10, 20), (10, 30), (20, 30)
    assert len(ip_003_findings) == 3
    interfaces_involved = {f.interface for f in ip_003_findings}
    assert interfaces_involved == {"Vlan10, Vlan20", "Vlan10, Vlan30", "Vlan20, Vlan30"}

def test_svi_with_defined_vlan_no_finding():
    device = Device(hostname="SW1")
    device.vlans[10] = Vlan(vlan_id=10, name="USERS")
    device.vlans[10] = Vlan(vlan_id=10)
    device.interfaces["Vlan10"] = Interface(name="Vlan10", ip_address="192.168.10.1", subnet_mask="255.255.255.0")
    findings = audit_device(device)
    assert len(findings) == 0

def test_svi_with_undefined_vlan_finding():
    device = Device(hostname="SW1")
    # VLAN 50 is NOT defined in device.vlans
    device.interfaces["Vlan50"] = Interface(name="Vlan50", ip_address="192.168.50.1", subnet_mask="255.255.255.0")
    findings = audit_device(device)
    assert len(findings) == 1
    assert findings[0].rule_id == "SVI-001"
    assert findings[0].evidence == "50"
    assert findings[0].interface == "Vlan50"

def test_svi_without_ip_but_undefined_vlan_finding():
    device = Device(hostname="SW1")
    # VLAN 50 is NOT defined in device.vlans
    device.interfaces["Vlan50"] = Interface(name="Vlan50")
    findings = audit_device(device)
    assert len(findings) == 1
    assert findings[0].rule_id == "SVI-001"
    assert findings[0].evidence == "50"
    assert findings[0].interface == "Vlan50"

def test_physical_interface_ignored_by_svi_001():
    device = Device(hostname="SW1")
    device.interfaces["GigabitEthernet0/1"] = Interface(name="GigabitEthernet0/1")
    findings = audit_device(device)
    assert len(findings) == 0

def test_vlan_used_as_access_no_finding():
    device = Device(hostname="SW1")
    device.vlans[10] = Vlan(vlan_id=10)
    device.interfaces["Gi0/1"] = Interface(name="Gi0/1", access_vlan=10)
    findings = audit_device(device)
    assert len(findings) == 0

def test_vlan_used_as_native_no_finding():
    device = Device(hostname="SW1")
    device.vlans[20] = Vlan(vlan_id=20)
    device.interfaces["Gi0/1"] = Interface(name="Gi0/1", native_vlan=20)
    findings = audit_device(device)
    assert len(findings) == 0

def test_vlan_used_in_allowed_no_finding():
    device = Device(hostname="SW1")
    device.vlans[30] = Vlan(vlan_id=30)
    device.interfaces["Gi0/1"] = Interface(name="Gi0/1", allowed_vlans=[30])
    findings = audit_device(device)
    assert len(findings) == 0

def test_vlan_used_as_svi_no_finding():
    device = Device(hostname="SW1")
    device.vlans[40] = Vlan(vlan_id=40)
    device.interfaces["Vlan40"] = Interface(name="Vlan40")
    findings = audit_device(device)
    assert len(findings) == 0

def test_defined_vlan_with_no_references_finding():
    device = Device(hostname="SW1")
    device.vlans[50] = Vlan(vlan_id=50)
    findings = audit_device(device)
    assert len(findings) == 1
    assert findings[0].rule_id == "VLAN-002"
    assert findings[0].evidence == "50"

def test_multiple_unused_vlans_multiple_findings():
    device = Device(hostname="SW1")
    device.vlans[60] = Vlan(vlan_id=60)
    device.vlans[70] = Vlan(vlan_id=70)
    findings = audit_device(device)
    assert len(findings) == 2
    rule_ids = {f.rule_id for f in findings}
    evidences = {f.evidence for f in findings}
    assert rule_ids == {"VLAN-002"}
    assert evidences == {"60", "70"}

def test_two_trunks_same_native_vlan_no_finding():
    device = Device(hostname="SW1")
    device.vlans[10] = Vlan(vlan_id=10)
    device.interfaces["Gi0/1"] = Interface(name="Gi0/1", mode="trunk", native_vlan=10)
    device.interfaces["Gi0/2"] = Interface(name="Gi0/2", mode="trunk", native_vlan=10)
    findings = audit_device(device)
    assert len(findings) == 0

def test_two_trunks_different_native_vlans_finding():
    device = Device(hostname="SW1")
    device.vlans[10] = Vlan(vlan_id=10)
    device.vlans[20] = Vlan(vlan_id=20)
    device.interfaces["Gi0/1"] = Interface(name="Gi0/1", mode="trunk", native_vlan=10)
    device.interfaces["Gi0/2"] = Interface(name="Gi0/2", mode="trunk", native_vlan=20)
    findings = audit_device(device)
    assert len(findings) == 1
    assert findings[0].rule_id == "VLAN-003"
    assert findings[0].interface == "Gi0/1, Gi0/2"
    assert findings[0].evidence == "10, 20"

def test_trunk_without_native_vlan_ignored():
    device = Device(hostname="SW1")
    device.vlans[10] = Vlan(vlan_id=10)
    device.interfaces["Gi0/1"] = Interface(name="Gi0/1", mode="trunk", native_vlan=10)
    device.interfaces["Gi0/2"] = Interface(name="Gi0/2", mode="trunk")
    findings = audit_device(device)
    assert len(findings) == 0

def test_access_interfaces_ignored_by_vlan_003():
    device = Device(hostname="SW1")
    device.vlans[10] = Vlan(vlan_id=10)
    device.vlans[20] = Vlan(vlan_id=20)
    device.interfaces["Gi0/1"] = Interface(name="Gi0/1", mode="access", native_vlan=10)
    device.interfaces["Gi0/2"] = Interface(name="Gi0/2", mode="access", native_vlan=20)
    findings = audit_device(device)
    assert len(findings) == 0

def test_three_trunks_one_mismatch_findings():
    device = Device(hostname="SW1")
    device.vlans[10] = Vlan(vlan_id=10)
    device.vlans[20] = Vlan(vlan_id=20)
    device.interfaces["Gi0/1"] = Interface(name="Gi0/1", mode="trunk", native_vlan=10)
    device.interfaces["Gi0/2"] = Interface(name="Gi0/2", mode="trunk", native_vlan=10)
    device.interfaces["Gi0/3"] = Interface(name="Gi0/3", mode="trunk", native_vlan=20)
    findings = audit_device(device)
    assert len(findings) == 2
    rule_ids = {f.rule_id for f in findings}
    interfaces = {f.interface for f in findings}
    assert rule_ids == {"VLAN-003"}
    assert interfaces == {"Gi0/1, Gi0/3", "Gi0/2, Gi0/3"}

def test_vlan_004_identical_allowed_vlans_no_finding():
    device = Device(hostname="SW1")
    device.vlans[10] = Vlan(vlan_id=10)
    device.interfaces["Gi0/1"] = Interface(name="Gi0/1", mode="trunk", allowed_vlans=[10])
    device.interfaces["Gi0/2"] = Interface(name="Gi0/2", mode="trunk", allowed_vlans=[10])
    findings = audit_device(device)
    assert len(findings) == 0

def test_vlan_004_same_vlans_different_order_no_finding():
    device = Device(hostname="SW1")
    device.vlans[10] = Vlan(vlan_id=10)
    device.vlans[20] = Vlan(vlan_id=20)
    device.interfaces["Gi0/1"] = Interface(name="Gi0/1", mode="trunk", allowed_vlans=[10, 20])
    device.interfaces["Gi0/2"] = Interface(name="Gi0/2", mode="trunk", allowed_vlans=[20, 10])
    findings = audit_device(device)
    assert len(findings) == 0

def test_vlan_004_different_allowed_vlans_finding():
    device = Device(hostname="SW1")
    device.vlans[10] = Vlan(vlan_id=10)
    device.vlans[20] = Vlan(vlan_id=20)
    device.interfaces["Gi0/1"] = Interface(name="Gi0/1", mode="trunk", allowed_vlans=[10])
    device.interfaces["Gi0/2"] = Interface(name="Gi0/2", mode="trunk", allowed_vlans=[20])
    findings = audit_device(device)
    assert len(findings) == 1
    assert findings[0].rule_id == "VLAN-004"
    assert findings[0].interface == "Gi0/1, Gi0/2"
    assert findings[0].evidence == "[10] vs [20]"

def test_vlan_004_trunk_without_allowed_vlans_ignored():
    device = Device(hostname="SW1")
    device.vlans[10] = Vlan(vlan_id=10)
    device.interfaces["Gi0/1"] = Interface(name="Gi0/1", mode="trunk", allowed_vlans=[10])
    device.interfaces["Gi0/2"] = Interface(name="Gi0/2", mode="trunk")
    findings = audit_device(device)
    assert len(findings) == 0

def test_vlan_004_access_interfaces_ignored():
    device = Device(hostname="SW1")
    device.vlans[10] = Vlan(vlan_id=10)
    device.vlans[20] = Vlan(vlan_id=20)
    device.interfaces["Gi0/1"] = Interface(name="Gi0/1", mode="access", allowed_vlans=[10])
    device.interfaces["Gi0/2"] = Interface(name="Gi0/2", mode="access", allowed_vlans=[20])
    findings = audit_device(device)
    assert len(findings) == 0

def test_vlan_004_three_trunks_one_mismatch():
    device = Device(hostname="SW1")
    device.vlans[10] = Vlan(vlan_id=10)
    device.vlans[20] = Vlan(vlan_id=20)
    device.interfaces["Gi0/1"] = Interface(name="Gi0/1", mode="trunk", allowed_vlans=[10, 20])
    device.interfaces["Gi0/2"] = Interface(name="Gi0/2", mode="trunk", allowed_vlans=[10, 20])
    device.interfaces["Gi0/3"] = Interface(name="Gi0/3", mode="trunk", allowed_vlans=[10])
    findings = audit_device(device)
    
    vlan4_findings = [f for f in findings if f.rule_id == "VLAN-004"]
    assert len(vlan4_findings) == 2
    interfaces = {f.interface for f in vlan4_findings}
    assert interfaces == {"Gi0/1, Gi0/3", "Gi0/2, Gi0/3"}
    # The sorted evidence strings
    evidences = {f.evidence for f in vlan4_findings}
    assert evidences == {"[10, 20] vs [10]", "[10, 20] vs [10]"}
