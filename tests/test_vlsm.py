"""
Unit Tests for VLSM Subnet Allocation Engine (L3)
Course Code: CIC-307 Computer Networks Mini-Project

Covers:
- Descending host sort verification
- Bitwise power-of-two CIDR boundary alignment
- Overlap detection (mathematical zero-overlap across all intervals)
- Address space exhaustion handling
- Correct broadcast address and usable host range calculations
- Wildcard mask bitwise inversion for edge cases (/24, /27, /29, /30)
- Gateway reservation verification (Network + 1 reserved for SVI)
- Independent cross-validation with Python's ipaddress library
"""

import ipaddress
import pytest
from src.vlsm import (
    VLSMAllocator,
    VLSMResult,
    AddressSpaceExhaustionError,
    InvalidCIDRError,
    SubnetOverlapError,
    ip_to_int,
    int_to_ip,
    parse_cidr,
    prefix_to_mask_int,
    mask_int_to_wildcard_int,
    calculate_host_bits
)


class TestVLSMAllocator:
    """Comprehensive test suite for bitwise VLSM allocation."""

    def test_descending_sort_order(self):
        """Verify subnets requested in arbitrary order are sorted descending by host count."""
        unordered_subnets = [
            {"name": "Admin", "hosts": 25},
            {"name": "Engineering", "hosts": 200},
            {"name": "HR", "hosts": 50},
            {"name": "Marketing", "hosts": 100}
        ]
        result = VLSMAllocator.allocate("192.168.0.0/16", unordered_subnets)
        
        allocated_names = [a.name for a in result.allocations]
        assert allocated_names == ["Engineering", "Marketing", "HR", "Admin"]
        assert result.allocations[0].requested_hosts == 200
        assert result.allocations[-1].requested_hosts == 25

    def test_bitwise_boundary_alignment(self):
        """Verify every allocated network starts on a 32-bit boundary divisible by its size."""
        subnets = [
            {"name": "Net_A", "hosts": 500},  # /23 (size 512)
            {"name": "Net_B", "hosts": 250},  # /24 (size 256)
            {"name": "Net_C", "hosts": 120},  # /25 (size 128)
            {"name": "Net_D", "hosts": 60},   # /26 (size 64)
            {"name": "Net_E", "hosts": 20}    # /27 (size 32)
        ]
        result = VLSMAllocator.allocate("10.0.0.0/16", subnets)

        for alloc in result.allocations:
            net_int = ip_to_int(alloc.network_address)
            size = alloc.allocated_size
            # Boundary check: net_int % size == 0
            assert net_int % size == 0, f"{alloc.name} ({alloc.network_address}) not aligned to size {size}"

    def test_zero_subnet_overlap(self):
        """Verify no two allocated subnets share any IP addresses."""
        subnets = [
            {"name": "Sub_1", "hosts": 1000},
            {"name": "Sub_2", "hosts": 500},
            {"name": "Sub_3", "hosts": 200},
            {"name": "Sub_4", "hosts": 100},
            {"name": "Sub_5", "hosts": 50},
            {"name": "Sub_6", "hosts": 20},
            {"name": "Sub_7", "hosts": 6}
        ]
        result = VLSMAllocator.allocate("172.16.0.0/16", subnets)

        # Check all pairs
        for i in range(len(result.allocations)):
            for j in range(i + 1, len(result.allocations)):
                a = result.allocations[i]
                b = result.allocations[j]
                overlap = not (a.broadcast_int < b.net_int or a.net_int > b.broadcast_int)
                assert not overlap, f"Collision detected between {a.name} and {b.name}!"

    def test_address_space_exhaustion(self):
        """Verify requesting more hosts than the root network provides raises AddressSpaceExhaustionError."""
        # /28 only has 16 addresses total
        oversized_subnets = [
            {"name": "Net_Big", "hosts": 10},
            {"name": "Net_TooBig", "hosts": 10}
        ]
        with pytest.raises(AddressSpaceExhaustionError):
            VLSMAllocator.allocate("192.168.1.0/28", oversized_subnets)

    def test_broadcast_address_calculation(self):
        """Verify broadcast address is exactly (Network + BlockSize - 1)."""
        subnets = [{"name": "Sales", "hosts": 50}]  # 50 hosts -> /26 (size 64)
        result = VLSMAllocator.allocate("192.168.1.0/24", subnets)

        alloc = result.allocations[0]
        assert alloc.network_address == "192.168.1.0"
        assert alloc.prefix == 26
        assert alloc.broadcast_address == "192.168.1.63"
        assert alloc.gateway_ip == "192.168.1.1"
        assert alloc.last_usable_host == "192.168.1.62"

    def test_gateway_reservation_not_counted_as_endpoint(self):
        """Verify default gateway is reserved from usable range and not assignable to hosts."""
        subnets = [{"name": "Finance", "hosts": 60}]  # 60 hosts + 1 gateway = 61 usable -> /26 (62 usable)
        result = VLSMAllocator.allocate("10.0.0.0/24", subnets, reserve_gateway=True)
        alloc = result.allocations[0]
        
        # Gateway is Network + 1
        assert alloc.gateway_ip == "10.0.0.1"
        # First usable host pool starts at Network + 2
        assert alloc.first_usable_host == "10.0.0.2"
        # Usable endpoints pool: from .2 to .62 = 61 usable host addresses >= 60 requested
        assert ip_to_int(alloc.last_usable_host) - ip_to_int(alloc.first_usable_host) + 1 >= 60

    def test_wildcard_mask_calculations_edge_cases(self):
        """Verify bitwise inverse wildcard mask calculations across standard and edge-case prefixes."""
        test_cases = [
            (24, "255.255.255.0", "0.0.0.255"),
            (26, "255.255.255.192", "0.0.0.63"),
            (27, "255.255.255.224", "0.0.0.31"),
            (29, "255.255.255.248", "0.0.0.7"),
            (30, "255.255.255.252", "0.0.0.3"),
            (16, "255.255.0.0", "0.0.255.255"),
            (8,  "255.0.0.0", "0.255.255.255")
        ]
        for prefix, expected_mask, expected_wildcard in test_cases:
            mask_int = prefix_to_mask_int(prefix)
            wildcard_int = mask_int_to_wildcard_int(mask_int)
            assert int_to_ip(mask_int) == expected_mask, f"Mask failed for /{prefix}"
            assert int_to_ip(wildcard_int) == expected_wildcard, f"Wildcard failed for /{prefix}"

    def test_slash_30_gateway_reservation_edge_case(self):
        """
        Regression Test for Bug in Section 2:
        When a subnet requires only 1 endpoint and reserve_gateway=True, a /30 block
        must be allocated. The gateway MUST NOT be assigned the same IP as the first usable endpoint.
        Example:
          Network: 192.168.1.0/30
          Gateway: 192.168.1.1
          First Usable Endpoint: 192.168.1.2
          Last Usable Endpoint: 192.168.1.2
          Broadcast: 192.168.1.3
        """
        subnets = [{"name": "Single_Host_Sensor", "hosts": 1}]
        result = VLSMAllocator.allocate("192.168.1.0/30", subnets, reserve_gateway=True)
        alloc = result.allocations[0]

        assert alloc.prefix == 30
        assert alloc.allocated_size == 4
        assert alloc.network_address == "192.168.1.0"
        assert alloc.gateway_ip == "192.168.1.1"
        assert alloc.first_usable_host == "192.168.1.2"
        assert alloc.last_usable_host == "192.168.1.2"
        assert alloc.broadcast_address == "192.168.1.3"
        # Invariant: Gateway is NEVER identical to the assignable endpoint IP!
        assert alloc.gateway_ip != alloc.first_usable_host
        assert alloc.assignable_endpoints == 1
        assert alloc.total_usable_hosts == 2

    def test_two_hosts_gateway_reservation_boundary(self):
        """
        Verify that 2 hosts with reserve_gateway=True requires 3 usable addresses
        (2 endpoints + 1 gateway), which does NOT fit in /30 (2 usable total) and must allocate /29.
        With reserve_gateway=False (P2P router link), 2 hosts fits exactly in a /30.
        """
        subnets = [{"name": "Two_Host_Subnet", "hosts": 2}]
        # With gateway reserved (2 endpoints + 1 gateway = 3 usable -> /29)
        res_with_gw = VLSMAllocator.allocate("10.0.0.0/24", subnets, reserve_gateway=True)
        assert res_with_gw.allocations[0].prefix == 29
        assert res_with_gw.allocations[0].gateway_ip == "10.0.0.1"
        assert res_with_gw.allocations[0].first_usable_host == "10.0.0.2"
        assert res_with_gw.allocations[0].assignable_endpoints == 5

        # Without gateway reserved (2 endpoints total -> /30)
        res_no_gw = VLSMAllocator.allocate("10.0.0.0/24", subnets, reserve_gateway=False)
        assert res_no_gw.allocations[0].prefix == 30
        assert res_no_gw.allocations[0].first_usable_host == "10.0.0.1"
        assert res_no_gw.allocations[0].last_usable_host == "10.0.0.2"
        assert res_no_gw.allocations[0].assignable_endpoints == 2


    def test_invalid_cidr_strings(self):
        """Verify invalid CIDR formats raise InvalidCIDRError."""
        invalid_cidrs = [
            "192.168.1.1",       # Missing prefix slash
            "192.168.1.0/33",    # Prefix out of range > 32
            "192.168.1.0/-1",    # Negative prefix
            "192.168.1.256/24",  # Octet out of bounds
            "not.an.ip.address/24",
            "10.0.0.0/abc"
        ]
        for bad_cidr in invalid_cidrs:
            with pytest.raises(InvalidCIDRError):
                parse_cidr(bad_cidr)

    def test_independent_validation_with_ipaddress_module(self):
        """
        Cross-validates custom bitwise VLSM allocation outputs against
        Python standard library ipaddress module.
        """
        subnets = [
            {"name": "Dev", "hosts": 300},
            {"name": "QA", "hosts": 150},
            {"name": "Prod", "hosts": 70},
            {"name": "Stage", "hosts": 20}
        ]
        result = VLSMAllocator.allocate("192.168.0.0/22", subnets)

        for alloc in result.allocations:
            # Independent validation using ipaddress
            ip_net = ipaddress.IPv4Network(f"{alloc.network_address}/{alloc.prefix}")
            assert str(ip_net.network_address) == alloc.network_address
            assert str(ip_net.netmask) == alloc.subnet_mask
            assert str(ip_net.hostmask) == alloc.wildcard_mask
            assert str(ip_net.broadcast_address) == alloc.broadcast_address
            assert ip_net.num_addresses == alloc.allocated_size

            # Check gateway is the first usable host in ipaddress
            hosts_list = list(ip_net.hosts())
            assert str(hosts_list[0]) == alloc.gateway_ip

    def test_efficiency_metrics_calculation(self):
        """Verify subnet packing efficiency and root utilization formulas."""
        subnets = [
            {"name": "Alpha", "hosts": 100},
            {"name": "Beta", "hosts": 50}
        ]
        # Root is /24 (256 addresses)
        result = VLSMAllocator.allocate("192.168.10.0/24", subnets)
        # Alpha: 100 hosts -> /25 (128 addresses)
        # Beta: 50 hosts -> /26 (64 addresses)
        # Total allocated = 128 + 64 = 192 addresses
        # Total requested = 150 hosts
        # Subnet efficiency = 150 / 192 = 78.125%
        # Root utilization = 192 / 256 = 75.0%
        assert result.total_requested_hosts == 150
        assert result.total_allocated_addresses == 192
        assert abs(result.subnet_efficiency_pct - (150 / 192 * 100.0)) < 0.1
        assert abs(result.root_utilization_pct - (192 / 256 * 100.0)) < 0.1
