"""Cisco IOS configuration parser for NetAudit."""

import re
from typing import Optional

from netaudit.models.config import Device, Interface, Vlan

# Mapping of common abbreviated interface prefixes to standard Cisco IOS names
INTERFACE_PREFIX_MAP = {
    "gi": "GigabitEthernet",
    "gigabitethernet": "GigabitEthernet",
    "fa": "FastEthernet",
    "fastethernet": "FastEthernet",
    "te": "TenGigabitEthernet",
    "tengigabitethernet": "TenGigabitEthernet",
    "fo": "FortyGigabitEthernet",
    "fortygigabitethernet": "FortyGigabitEthernet",
    "hu": "HundredGigabitEthernet",
    "hundredgigabitethernet": "HundredGigabitEthernet",
    "eth": "Ethernet",
    "ethernet": "Ethernet",
    "lo": "Loopback",
    "loopback": "Loopback",
    "vl": "Vlan",
    "vlan": "Vlan",
    "po": "Port-channel",
    "port-channel": "Port-channel",
}


def normalize_interface_name(raw_name: str) -> str:
    """Normalize interface names (e.g., 'Gi0/1' -> 'GigabitEthernet0/1', 'Vl10' -> 'Vlan10')."""
    cleaned = raw_name.strip()
    match = re.match(r"^([a-zA-Z\-]+)\s*(\d.*)$", cleaned)
    if not match:
        return cleaned

    prefix = match.group(1).lower()
    suffix = match.group(2).strip()

    if prefix in INTERFACE_PREFIX_MAP:
        return f"{INTERFACE_PREFIX_MAP[prefix]}{suffix}"
    return cleaned


def parse_vlan_list(vlan_str: str) -> list[int]:
    """Parse comma-separated VLAN IDs and ranges (e.g., '10,20,30' or '10-12,20') into sorted ints."""
    vlan_set: set[int] = set()
    
    # Remove Cisco modifiers before processing
    cleaned = re.sub(r'^(add|remove|except)\s+', '', vlan_str.strip(), flags=re.IGNORECASE).strip()

    if not cleaned or cleaned.lower() == "none" or cleaned.lower() == "all":
        return []

    for token in cleaned.split(","):
        token = token.strip()
        if not token:
            continue
        if "-" in token:
            start_str, end_str = token.split("-", 1)
            try:
                start = int(start_str.strip())
                end = int(end_str.strip())
                vlan_set.update(range(start, end + 1))
            except ValueError:
                continue
        else:
            try:
                vlan_set.add(int(token))
            except ValueError:
                continue

    return sorted(vlan_set)


class IOSParser:
    """Parser for Cisco IOS configuration text."""

    def parse(self, config_text: str) -> Device:
        """Parse Cisco IOS configuration string into a structured Device object."""
        device = Device()
        current_vlan: Optional[Vlan] = None
        current_interface: Optional[Interface] = None

        for raw_line in config_text.splitlines():
            line = raw_line.strip()

            # Ignore empty lines and comment/delimiter lines starting with '!'
            if not line or line.startswith("!"):
                current_vlan = None
                current_interface = None
                continue

            # 1. Hostname
            hostname_match = re.match(r"^hostname\s+(\S+)$", line, re.IGNORECASE)
            if hostname_match:
                current_vlan = None
                current_interface = None
                device.hostname = hostname_match.group(1)
                continue

            # 2. VLAN definition block
            vlan_match = re.match(r"^vlan\s+(\d+)$", line, re.IGNORECASE)
            if vlan_match:
                current_interface = None
                vlan_id = int(vlan_match.group(1))
                if vlan_id not in device.vlans:
                    device.vlans[vlan_id] = Vlan(vlan_id=vlan_id)
                current_vlan = device.vlans[vlan_id]
                continue

            # 3. Interface definition block
            iface_match = re.match(r"^interface\s+(\S.*)$", line, re.IGNORECASE)
            if iface_match:
                current_vlan = None
                norm_name = normalize_interface_name(iface_match.group(1))
                if norm_name not in device.interfaces:
                    device.interfaces[norm_name] = Interface(name=norm_name)
                current_interface = device.interfaces[norm_name]
                continue

            # Check if line is inside an active VLAN block
            if current_vlan is not None:
                vlan_name_match = re.match(r"^name\s+(\S.*)$", line, re.IGNORECASE)
                if vlan_name_match:
                    current_vlan.name = vlan_name_match.group(1).strip()
                    continue

            # Check if line is inside an active Interface block
            if current_interface is not None:
                # switchport mode access | trunk
                mode_match = re.match(r"^switchport\s+mode\s+(access|trunk)$", line, re.IGNORECASE)
                if mode_match:
                    current_interface.mode = mode_match.group(1).lower()
                    continue

                # switchport access vlan <id>
                access_match = re.match(r"^switchport\s+access\s+vlan\s+(\d+)$", line, re.IGNORECASE)
                if access_match:
                    current_interface.access_vlan = int(access_match.group(1))
                    continue

                # switchport trunk native vlan <id>
                native_match = re.match(r"^switchport\s+trunk\s+native\s+vlan\s+(\d+)$", line, re.IGNORECASE)
                if native_match:
                    current_interface.native_vlan = int(native_match.group(1))
                    continue

                # switchport trunk allowed vlan <list>
                allowed_match = re.match(r"^switchport\s+trunk\s+allowed\s+vlan\s+(\S.*)$", line, re.IGNORECASE)
                if allowed_match:
                    current_interface.allowed_vlans = parse_vlan_list(allowed_match.group(1))
                    continue

                # ip address <IPv4> <subnet-mask>
                ip_match = re.match(
                    r"^ip\s+address\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(\d{1,3}(?:\.\d{1,3}){3})(?:\s+(secondary))?$",
                    line,
                    re.IGNORECASE,
                )
                if ip_match:
                    is_secondary = bool(ip_match.group(3))
                    if not is_secondary:
                        current_interface.ip_address = ip_match.group(1)
                        current_interface.subnet_mask = ip_match.group(2)
                    continue

            # If an unindented unknown global command is encountered, exit active blocks
            is_indented = raw_line.startswith((" ", "\t"))
            if not is_indented:
                current_vlan = None
                current_interface = None

        return device


def parse_ios_config(config_text: str) -> Device:
    """Convenience function to parse Cisco IOS configuration text."""
    return IOSParser().parse(config_text)
