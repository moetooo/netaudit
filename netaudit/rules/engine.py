import ipaddress
from dataclasses import dataclass
from netaudit.models.config import Device, PeerLink

@dataclass
class Finding:
    rule_id: str
    severity: str
    device: str
    interface: str
    evidence: str
    description: str

def audit_device(device: Device, network: dict[str, Device] = None, topology: list[PeerLink] = None) -> list[Finding]:
    findings = []
    seen = set()
    
    if network is None:
        network = {}
    if topology is None:
        topology = []

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
                
                # Check IP-004: Interface gateway address validity
                if ip_iface.network.prefixlen not in (31, 32):
                    if ip_iface.ip == ip_iface.network.network_address or ip_iface.ip == ip_iface.network.broadcast_address:
                        add_finding(
                            rule_id="IP-004",
                            severity="ERROR",
                            dev_name=dev_name,
                            iface_name=iface_name,
                            evidence=str(ip_iface),
                            description=f"Interface {iface_name} IP address cannot be the network or broadcast address.",
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

    # Check VLAN-003 and VLAN-004: Topology-aware trunk comparisons
    for link in topology:
        if link.local_interface in device.interfaces:
            # We only process the link if the local device's hostname is alphabetically less than the remote device's hostname
            # to avoid generating duplicate findings when auditing the whole network.
            if link.remote_device in network and dev_name < link.remote_device:
                local_iface = device.interfaces[link.local_interface]
                remote_dev = network[link.remote_device]
                
                if link.remote_interface in remote_dev.interfaces:
                    remote_iface = remote_dev.interfaces[link.remote_interface]
                    
                    if local_iface.mode == "trunk" and remote_iface.mode == "trunk":
                        # VLAN-003: Native VLAN mismatch
                        if local_iface.native_vlan != remote_iface.native_vlan:
                            ifaces_str = f"{dev_name}:{link.local_interface}, {link.remote_device}:{link.remote_interface}"
                            evidence_str = f"{local_iface.native_vlan}, {remote_iface.native_vlan}"
                            add_finding(
                                rule_id="VLAN-003",
                                severity="ERROR",
                                dev_name=dev_name,
                                iface_name=ifaces_str,
                                evidence=evidence_str,
                                description=f"Trunk interfaces {ifaces_str} have mismatched native VLANs.",
                            )
                            
                        # VLAN-004: Trunk allowed VLAN mismatch
                        if set(local_iface.allowed_vlans) != set(remote_iface.allowed_vlans):
                            ifaces_str = f"{dev_name}:{link.local_interface}, {link.remote_device}:{link.remote_interface}"
                            evidence_str = f"{sorted(local_iface.allowed_vlans)} vs {sorted(remote_iface.allowed_vlans)}"
                            add_finding(
                                rule_id="VLAN-004",
                                severity="ERROR",
                                dev_name=dev_name,
                                iface_name=ifaces_str,
                                evidence=evidence_str,
                                description=f"Trunk interfaces {ifaces_str} have mismatched allowed VLAN lists.",
                            )

    return findings
