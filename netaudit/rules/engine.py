import ipaddress
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

    def add_finding(rule_id: str, severity: str, dev_name: str, iface_name: str, evidence: str, description: str):
        key = (dev_name, iface_name, evidence, rule_id)
        if key not in seen:
            seen.add(key)
            findings.append(
                Finding(
                    rule_id=rule_id,
                    severity=severity,
                    device=dev_name,
                    interface=iface_name,
                    evidence=evidence,
                    description=description,
                )
            )

    dev_name = device.hostname or "Unknown"
    ip_to_interfaces = {}
    valid_networks = []

    for iface_name, iface in device.interfaces.items():
        # Check access VLAN
        if iface.access_vlan is not None and iface.access_vlan not in device.vlans:
            add_finding(
                rule_id="VLAN-001",
                severity="ERROR",
                dev_name=dev_name,
                iface_name=iface_name,
                evidence=str(iface.access_vlan),
                description=f"VLAN {iface.access_vlan} is used as access VLAN but not defined on the device."
            )
        
        # Check native VLAN
        if iface.native_vlan is not None and iface.native_vlan not in device.vlans:
            add_finding(
                rule_id="VLAN-001",
                severity="ERROR",
                dev_name=dev_name,
                iface_name=iface_name,
                evidence=str(iface.native_vlan),
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
                    evidence=str(vlan),
                    description=f"VLAN {vlan} is allowed on trunk but not defined on the device."
                )

        # Check IP-001 and track valid networks for IP-003
        if iface.ip_address and iface.subnet_mask:
            try:
                ip_iface = ipaddress.IPv4Interface(f"{iface.ip_address}/{iface.subnet_mask}")
                valid_networks.append((iface_name, iface.ip_address, ip_iface.network))
            except (ValueError, ipaddress.AddressValueError, ipaddress.NetmaskValueError):
                add_finding(
                    rule_id="IP-001",
                    severity="ERROR",
                    dev_name=dev_name,
                    iface_name=iface_name,
                    evidence=f"{iface.ip_address} / {iface.subnet_mask}",
                    description=f"Interface {iface_name} has an invalid IPv4 address or subnet mask.",
                )
                
        # Track IPs for IP-002
        if iface.ip_address:
            ip_to_interfaces.setdefault(iface.ip_address, []).append(iface_name)

    # Check IP-002: Duplicate IP addresses
    for ip_addr, ifaces in ip_to_interfaces.items():
        if len(ifaces) > 1:
            ifaces_str = ", ".join(sorted(ifaces))
            add_finding(
                rule_id="IP-002",
                severity="ERROR",
                dev_name=dev_name,
                iface_name=ifaces_str,
                evidence=ip_addr,
                description=f"IPv4 address {ip_addr} is configured on multiple interfaces: {ifaces_str}.",
            )

    # Check IP-003: Overlapping subnets
    for i in range(len(valid_networks)):
        for j in range(i + 1, len(valid_networks)):
            iface1_name, ip1, net1 = valid_networks[i]
            iface2_name, ip2, net2 = valid_networks[j]
            
            if ip1 == ip2:
                continue
                
            if net1.overlaps(net2):
                ifaces_str = ", ".join(sorted([iface1_name, iface2_name]))
                evidence = f"{net1}, {net2}"
                add_finding(
                    rule_id="IP-003",
                    severity="ERROR",
                    dev_name=dev_name,
                    iface_name=ifaces_str,
                    evidence=evidence,
                    description=f"IPv4 subnets overlap between {iface1_name} ({net1}) and {iface2_name} ({net2}).",
                )

    return findings
