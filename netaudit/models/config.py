"""Data models representing parsed Cisco network device configurations."""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Vlan:
    """Represents a VLAN definition."""
    vlan_id: int
    name: Optional[str] = None


@dataclass
class Interface:
    """Represents a network interface configuration."""
    name: str
    mode: Optional[str] = None
    access_vlan: Optional[int] = None
    native_vlan: Optional[int] = None
    allowed_vlans: list[int] = field(default_factory=list)
    ip_address: Optional[str] = None
    subnet_mask: Optional[str] = None


@dataclass
class Device:
    """Represents a network device and its parsed configuration."""
    hostname: Optional[str] = None
    vlans: dict[int, Vlan] = field(default_factory=dict)
    interfaces: dict[str, Interface] = field(default_factory=dict)
