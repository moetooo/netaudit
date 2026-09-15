"""Unit tests for NetAudit Cisco IOS configuration parser."""

from pathlib import Path

from netaudit.parser.ios_parser import (
    normalize_interface_name,
    parse_ios_config,
    parse_vlan_list,
)


def test_parse_hostname():
    """1. Parse hostname."""
    config = "hostname SW1"
    device = parse_ios_config(config)
    assert device.hostname == "SW1"


def test_parse_vlan_and_name():
    """2. Parse VLAN and VLAN name."""
    config = """
    vlan 10
     name USERS
    vlan 20
     name VOICE
    """
    device = parse_ios_config(config)
    assert len(device.vlans) == 2
    assert 10 in device.vlans
    assert device.vlans[10].vlan_id == 10
    assert device.vlans[10].name == "USERS"
    assert 20 in device.vlans
    assert device.vlans[20].vlan_id == 20
    assert device.vlans[20].name == "VOICE"


def test_parse_access_interface_and_vlan():
    """3. Parse access interface and VLAN."""
    config = """
    interface GigabitEthernet0/1
     switchport mode access
     switchport access vlan 10
    """
    device = parse_ios_config(config)
    assert "GigabitEthernet0/1" in device.interfaces
    iface = device.interfaces["GigabitEthernet0/1"]
    assert iface.name == "GigabitEthernet0/1"
    assert iface.mode == "access"
    assert iface.access_vlan == 10


def test_parse_trunk_interface():
    """4. Parse trunk interface."""
    config = """
    interface GigabitEthernet0/24
     switchport mode trunk
    """
    device = parse_ios_config(config)
    assert "GigabitEthernet0/24" in device.interfaces
    iface = device.interfaces["GigabitEthernet0/24"]
    assert iface.mode == "trunk"


def test_parse_native_vlan():
    """5. Parse native VLAN."""
    config = """
    interface GigabitEthernet0/24
     switchport mode trunk
     switchport trunk native vlan 99
    """
    device = parse_ios_config(config)
    iface = device.interfaces["GigabitEthernet0/24"]
    assert iface.native_vlan == 99


def test_parse_allowed_vlan_list():
    """6. Parse allowed VLAN list."""
    config = """
    interface GigabitEthernet0/24
     switchport mode trunk
     switchport trunk allowed vlan 10,20,30
    """
    device = parse_ios_config(config)
    iface = device.interfaces["GigabitEthernet0/24"]
    assert iface.allowed_vlans == [10, 20, 30]


def test_parse_allowed_vlan_with_ranges():
    """Parse allowed VLAN list with ranges."""
    config = """
    interface GigabitEthernet0/24
     switchport mode trunk
     switchport trunk allowed vlan 10-12,20
    """
    device = parse_ios_config(config)
    iface = device.interfaces["GigabitEthernet0/24"]
    assert iface.allowed_vlans == [10, 11, 12, 20]


def test_parse_multiple_interfaces():
    """7. Parse multiple interfaces and normalize abbreviated names."""
    config = """
    interface Gi0/1
     switchport mode access
     switchport access vlan 10
    !
    interface Gi0/2
     switchport mode access
     switchport access vlan 20
    !
    interface Vlan10
    """
    device = parse_ios_config(config)
    assert "GigabitEthernet0/1" in device.interfaces
    assert "GigabitEthernet0/2" in device.interfaces
    assert "Vlan10" in device.interfaces

    assert device.interfaces["GigabitEthernet0/1"].access_vlan == 10
    assert device.interfaces["GigabitEthernet0/2"].access_vlan == 20
    assert device.interfaces["Vlan10"].name == "Vlan10"


def test_ignore_blank_lines_and_exclamation_separators():
    """8. Ignore blank lines and ! separators."""
    config = """
    !
    ! Comment header
    !

    hostname SW1

    !
    vlan 10
     name USERS
    !

    !
    interface Gi0/1
     switchport mode access
     switchport access vlan 10
    !
    """
    device = parse_ios_config(config)
    assert device.hostname == "SW1"
    assert 10 in device.vlans
    assert device.vlans[10].name == "USERS"
    assert "GigabitEthernet0/1" in device.interfaces
    assert device.interfaces["GigabitEthernet0/1"].access_vlan == 10


def test_interface_normalization_helper():
    """Test interface name normalization utility."""
    assert normalize_interface_name("Gi0/1") == "GigabitEthernet0/1"
    assert normalize_interface_name("GigabitEthernet0/1") == "GigabitEthernet0/1"
    assert normalize_interface_name("Fa0/24") == "FastEthernet0/24"
    assert normalize_interface_name("Te0/1/1") == "TenGigabitEthernet0/1/1"
    assert normalize_interface_name("Vl10") == "Vlan10"
    assert normalize_interface_name("Lo0") == "Loopback0"


def test_parse_vlan_list_helper():
    """Test vlan list parser utility."""
    assert parse_vlan_list("10,20,30") == [10, 20, 30]
    assert parse_vlan_list("10-13, 20") == [10, 11, 12, 13, 20]
    assert parse_vlan_list("none") == []
    assert parse_vlan_list("") == []


def test_parse_switch1_fixture():
    """Test parsing the realistic switch1.cfg fixture file."""
    fixture_path = Path(__file__).parent / "fixtures" / "switch1.cfg"
    content = fixture_path.read_text(encoding="utf-8")
    device = parse_ios_config(content)

    assert device.hostname == "SW1"

    # Verify VLANs
    assert len(device.vlans) == 3
    assert device.vlans[10].name == "USERS"
    assert device.vlans[20].name == "VOICE"
    assert device.vlans[99].name == "MANAGEMENT"

    # Verify Interfaces
    assert "GigabitEthernet0/1" in device.interfaces
    gi01 = device.interfaces["GigabitEthernet0/1"]
    assert gi01.mode == "access"
    assert gi01.access_vlan == 10

    assert "GigabitEthernet0/2" in device.interfaces
    gi02 = device.interfaces["GigabitEthernet0/2"]
    assert gi02.mode == "access"
    assert gi02.access_vlan == 20

    assert "GigabitEthernet0/24" in device.interfaces
    gi24 = device.interfaces["GigabitEthernet0/24"]
    assert gi24.mode == "trunk"
    assert gi24.native_vlan == 99
    assert gi24.allowed_vlans == [10, 20, 99]

    assert "Vlan10" in device.interfaces
    vlan10 = device.interfaces["Vlan10"]
    assert vlan10.ip_address == "192.168.10.1"
    assert vlan10.subnet_mask == "255.255.255.0"
    assert gi01.ip_address is None
    assert gi01.subnet_mask is None


def test_parse_interface_ip_address_and_subnet_mask():
    """Parse interface IPv4 address and subnet mask on an SVI."""
    config = """
    interface Vlan10
     ip address 192.168.10.1 255.255.255.0
    """
    device = parse_ios_config(config)
    assert "Vlan10" in device.interfaces
    iface = device.interfaces["Vlan10"]
    assert iface.ip_address == "192.168.10.1"
    assert iface.subnet_mask == "255.255.255.0"


def test_parse_physical_interface_ip():
    """Parse IPv4 address and subnet mask on a physical interface."""
    config = """
    interface GigabitEthernet0/0
     ip address 10.0.0.1 255.255.255.252
    """
    device = parse_ios_config(config)
    assert "GigabitEthernet0/0" in device.interfaces
    iface = device.interfaces["GigabitEthernet0/0"]
    assert iface.ip_address == "10.0.0.1"
    assert iface.subnet_mask == "255.255.255.252"


def test_interface_without_ip_remains_none():
    """Interface without an IP address configured keeps ip_address and subnet_mask as None."""
    config = """
    interface GigabitEthernet0/1
     switchport mode access
     switchport access vlan 10
    """
    device = parse_ios_config(config)
    iface = device.interfaces["GigabitEthernet0/1"]
    assert iface.ip_address is None
    assert iface.subnet_mask is None


def test_ignore_secondary_ip_address():
    """Verify secondary IP addresses are ignored and do not overwrite primary IP."""
    config = """
    interface Vlan10
     ip address 192.168.10.1 255.255.255.0
     ip address 192.168.10.2 255.255.255.0 secondary
    """
    device = parse_ios_config(config)
    iface = device.interfaces["Vlan10"]
    assert iface.ip_address == "192.168.10.1"
    assert iface.subnet_mask == "255.255.255.0"
