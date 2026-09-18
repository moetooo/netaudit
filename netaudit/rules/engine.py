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
    used_vlans = set()
    trunk_native_vlans = []
    trunk_allowed_vlans = []

    for iface_name, iface in device.interfaces.items():
        # Check SVI-001 and track used VLANs
        if iface_name.startswith("Vlan"):
            try:
                svi_vlan_id = int(iface_name[4:])
                used_vlans.add(svi_vlan_id)
                if svi_vlan_id not in device.vlans:
                    add_finding(
                        rule_id="SVI-001",
                        severity="ERROR",
                        dev_name=dev_name,
                        iface_name=iface_name,
                        evidence=str(svi_vlan_id),
                        description=f"SVI {iface_name} references VLAN {svi_vlan_id} which is not defined on the device.",
                    )
            except ValueError:
                pass

        # Check access VLAN and track used VLANs
        if iface.access_vlan is not None:
            used_vlans.add(iface.access_vlan)
            if iface.access_vlan not in device.vlans:
                add_finding(
                    rule_id="VLAN-001",
                    severity="ERROR",
                    dev_name=dev_name,
                    iface_name=iface_name,
                    evidence=str(iface.access_vlan),
                    description=f"VLAN {iface.access_vlan} is used as access VLAN but not defined on the device."
                )
        
        # Check native VLAN and track used VLANs
        if iface.native_vlan is not None:
            used_vlans.add(iface.native_vlan)
            if iface.native_vlan not in device.vlans:
                add_finding(
                    rule_id="VLAN-001",
                    severity="ERROR",
                    dev_name=dev_name,
                    iface_name=iface_name,
                    evidence=str(iface.native_vlan),
                    description=f"VLAN {iface.native_vlan} is used as native VLAN but not defined on the device."
                )

        # Track trunk native VLANs for VLAN-003
        if iface.mode == "trunk" and iface.native_vlan is not None:
            trunk_native_vlans.append((iface_name, iface.native_vlan))

        # Track trunk allowed VLANs for VLAN-004
        if iface.mode == "trunk" and iface.allowed_vlans:
            trunk_allowed_vlans.append((iface_name, iface.allowed_vlans))

        # Check allowed VLANs and track used VLANs
        for vlan in iface.allowed_vlans:
            used_vlans.add(vlan)
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
                
                # Check IP-004: SVI gateway address validity
                if iface_name.startswith("Vlan"):
                    if ip_iface.ip == ip_iface.network.network_address or ip_iface.ip == ip_iface.network.broadcast_address:
                        add_finding(
                            rule_id="IP-004",
                            severity="ERROR",
                            dev_name=dev_name,
                            iface_name=iface_name,
                            evidence=str(ip_iface),
                            description=f"SVI {iface_name} IP address cannot be the network or broadcast address.",
                        )
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

    # Check VLAN-002: Defined but unused VLANs
    for vlan_id in device.vlans:
        if vlan_id not in used_vlans:
            add_finding(
                rule_id="VLAN-002",
                severity="WARNING",
                dev_name=dev_name,
                iface_name="",
                evidence=str(vlan_id),
                description=f"VLAN {vlan_id} is defined but not referenced by any interface or SVI.",
            )

    # Check VLAN-003: Native VLAN mismatch on trunk interfaces
    for i in range(len(trunk_native_vlans)):
        for j in range(i + 1, len(trunk_native_vlans)):
            iface1_name, nvlan1 = trunk_native_vlans[i]
            iface2_name, nvlan2 = trunk_native_vlans[j]
            
            if nvlan1 != nvlan2:
                # Sort interface names alphabetically to ensure consistent string formatting
                if iface1_name < iface2_name:
                    ifaces_str = f"{iface1_name}, {iface2_name}"
                    evidence_str = f"{nvlan1}, {nvlan2}"
                else:
                    ifaces_str = f"{iface2_name}, {iface1_name}"
                    evidence_str = f"{nvlan2}, {nvlan1}"
                
                add_finding(
                    rule_id="VLAN-003",
                    severity="ERROR",
                    dev_name=dev_name,
                    iface_name=ifaces_str,
                    evidence=evidence_str,
                    description=f"Trunk interfaces {ifaces_str} have mismatched native VLANs.",
                )

    # Check VLAN-004: Trunk allowed VLAN mismatch
    for i in range(len(trunk_allowed_vlans)):
        for j in range(i + 1, len(trunk_allowed_vlans)):
            iface1_name, allowed1 = trunk_allowed_vlans[i]
            iface2_name, allowed2 = trunk_allowed_vlans[j]
            
            if set(allowed1) != set(allowed2):
                if iface1_name < iface2_name:
                    ifaces_str = f"{iface1_name}, {iface2_name}"
                    evidence_str = f"{sorted(allowed1)} vs {sorted(allowed2)}"
                else:
                    ifaces_str = f"{iface2_name}, {iface1_name}"
                    evidence_str = f"{sorted(allowed2)} vs {sorted(allowed1)}"
                
                add_finding(
                    rule_id="VLAN-004",
                    severity="ERROR",
                    dev_name=dev_name,
                    iface_name=ifaces_str,
                    evidence=evidence_str,
                    description=f"Trunk interfaces {ifaces_str} have mismatched allowed VLAN lists.",
                )

    return findings
