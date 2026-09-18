from pathlib import Path
from netaudit.parser.ios_parser import IOSParser
from netaudit.rules.engine import audit_device

EXAMPLES_DIR = Path(__file__).parent.parent / "examples"

def test_broken_switch_end_to_end():
    config_path = EXAMPLES_DIR / "broken_switch.cfg"
    content = config_path.read_text(encoding="utf-8")
    
    parser = IOSParser()
    device = parser.parse(content)
    
    findings = audit_device(device)
    
    rule_ids = {f.rule_id for f in findings}
    
    assert "VLAN-001" in rule_ids
    assert "VLAN-002" in rule_ids
    assert "IP-004" in rule_ids
    
    # VLAN-003 and VLAN-004 are no longer triggered without explicit topology
    assert "VLAN-003" not in rule_ids
    assert "VLAN-004" not in rule_ids
    
    assert len(findings) >= 3

from netaudit.models.config import PeerLink

def test_broken_switch_topology_end_to_end():
    config_path = EXAMPLES_DIR / "broken_switch.cfg"
    content = config_path.read_text(encoding="utf-8")
    
    parser = IOSParser()
    device = parser.parse(content)
    
    # Simulate a remote peer device that is correctly configured,
    # so broken_switch's Gi0/2 and Gi0/3 both have mismatches with it.
    remote_device = parser.parse(content)
    remote_device.hostname = "CORE-SW1"
    
    # Force peer interfaces to have different native/allowed VLANs to trigger rules
    remote_device.interfaces["GigabitEthernet0/2"].native_vlan = 99
    remote_device.interfaces["GigabitEthernet0/3"].allowed_vlans = [10, 20, 30]
    
    topology = [
        PeerLink(local_interface="GigabitEthernet0/2", remote_device="CORE-SW1", remote_interface="GigabitEthernet0/2"),
        PeerLink(local_interface="GigabitEthernet0/3", remote_device="CORE-SW1", remote_interface="GigabitEthernet0/3")
    ]
    network = {"CORE-SW1": remote_device}
    
    findings = audit_device(device, network=network, topology=topology)
    rule_ids = {f.rule_id for f in findings}
    
    assert "VLAN-003" in rule_ids
    assert "VLAN-004" in rule_ids

def test_clean_switch_end_to_end():
    config_path = EXAMPLES_DIR / "clean_switch.cfg"
    content = config_path.read_text(encoding="utf-8")
    
    parser = IOSParser()
    device = parser.parse(content)
    
    findings = audit_device(device)
    
    assert len(findings) == 0
