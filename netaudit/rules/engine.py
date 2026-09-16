from dataclasses import dataclass
from netaudit.models.config import Device

@dataclass
class Finding:
    rule_id: str
    severity: str
    device: str
    interface: str
    evidence: str
    description: str

def audit_device(device: Device) -> list[Finding]:
    findings = []
    seen = set()

    def add_finding(rule_id: str, severity: str, dev_name: str, iface_name: str, vlan_id: int, description: str):
        key = (dev_name, iface_name, str(vlan_id), rule_id)
        if key not in seen:
            seen.add(key)
            findings.append(
                Finding(
                    rule_id=rule_id,
                    severity=severity,
                    device=dev_name,
                    interface=iface_name,
                    evidence=str(vlan_id),
                    description=description,
                )
            )

    dev_name = device.hostname or "Unknown"

    for iface_name, iface in device.interfaces.items():
        # Check access VLAN
        if iface.access_vlan is not None and iface.access_vlan not in device.vlans:
            add_finding(
                rule_id="VLAN-001",
                severity="ERROR",
                dev_name=dev_name,
                iface_name=iface_name,
                vlan_id=iface.access_vlan,
                description=f"VLAN {iface.access_vlan} is used as access VLAN but not defined on the device."
            )
        
        # Check native VLAN
        if iface.native_vlan is not None and iface.native_vlan not in device.vlans:
            add_finding(
                rule_id="VLAN-001",
                severity="ERROR",
                dev_name=dev_name,
                iface_name=iface_name,
                vlan_id=iface.native_vlan,
                description=f"VLAN {iface.native_vlan} is used as native VLAN but not defined on the device."
            )

        # Check allowed VLANs
        for vlan in iface.allowed_vlans:
            if vlan not in device.vlans:
                add_finding(
                    rule_id="VLAN-001",
                    severity="ERROR",
                    dev_name=dev_name,
                    iface_name=iface_name,
                    vlan_id=vlan,
                    description=f"VLAN {vlan} is allowed on trunk but not defined on the device."
                )

    return findings
