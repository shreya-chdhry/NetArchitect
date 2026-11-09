"""
VLSM (Variable Length Subnet Masking) Allocation Engine
Course Code: CIC-307 Computer Networks Mini-Project

Pure bitwise implementation of VLSM subnet sizing, boundary alignment,
wildcard mask computation, gateway reservation, overlap detection,
and address space efficiency calculation.
"""

import math
from dataclasses import dataclass
from typing import List, Dict, Tuple, Any, Optional


class AddressSpaceExhaustionError(Exception):
    """Raised when requested subnets exceed the root network address capacity."""
    pass


class InvalidCIDRError(Exception):
    """Raised when an invalid IPv4 CIDR string is provided."""
    pass


class SubnetOverlapError(Exception):
    """Raised if an overlapping subnet allocation is detected."""
    pass


def ip_to_int(ip_str: str) -> int:
    """Converts dotted-decimal IPv4 string to 32-bit unsigned integer using bitwise operations."""
    octets = ip_str.strip().split(".")
    if len(octets) != 4:
        raise InvalidCIDRError(f"Invalid IPv4 address format: '{ip_str}'")
    ip_int = 0
    for octet in octets:
        try:
            val = int(octet)
        except ValueError:
            raise InvalidCIDRError(f"Non-integer octet '{octet}' in IP '{ip_str}'")
        if val < 0 or val > 255:
            raise InvalidCIDRError(f"Octet {val} out of valid range (0-255) in IP '{ip_str}'")
        ip_int = (ip_int << 8) | val
    return ip_int


def int_to_ip(ip_int: int) -> str:
    """Converts 32-bit unsigned integer to dotted-decimal IPv4 string using bitwise operations."""
    return f"{(ip_int >> 24) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 8) & 0xFF}.{ip_int & 0xFF}"


def parse_cidr(cidr_str: str) -> Tuple[int, int]:
    """
    Parses a CIDR string (e.g. '192.168.0.0/16') into (network_int, prefix_length).
    Enforces valid IPv4 CIDR boundaries.
    """
    if "/" not in cidr_str:
        raise InvalidCIDRError(f"Missing prefix length in CIDR notation: '{cidr_str}' (expected format: X.X.X.X/YY)")
    parts = cidr_str.strip().split("/")
    if len(parts) != 2:
        raise InvalidCIDRError(f"Malformed CIDR notation: '{cidr_str}'")
    ip_str, prefix_str = parts[0], parts[1]
    try:
        prefix = int(prefix_str)
    except ValueError:
        raise InvalidCIDRError(f"Prefix length must be an integer, got: '{prefix_str}'")
    if prefix < 0 or prefix > 32:
        raise InvalidCIDRError(f"Prefix length /{prefix} out of bounds (must be between /0 and /32)")
    
    raw_ip = ip_to_int(ip_str)
    # Validate that host bits in the root network address are 0
    mask = prefix_to_mask_int(prefix)
    network_ip = raw_ip & mask
    if raw_ip != network_ip:
        # Normalize to root network boundary
        pass
    return network_ip, prefix


def prefix_to_mask_int(prefix: int) -> int:
    """Computes 32-bit subnet mask integer from prefix length using bitwise shifts."""
    if prefix == 0:
        return 0
    return ((0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF)


def mask_int_to_wildcard_int(mask_int: int) -> int:
    """Computes 32-bit Cisco wildcard mask using bitwise NOT."""
    return (~mask_int) & 0xFFFFFFFF


def calculate_host_bits(hosts_needed: int, reserve_gateway: bool = True) -> int:
    """
    Calculates required host bits h such that 2^h - 2 >= hosts_needed (+ 1 if gateway reserved).
    
    In enterprise subnetting:
    - 1 address is reserved for Network ID (all host bits 0)
    - 1 address is reserved for Directed Broadcast (all host bits 1)
    - 1 address is reserved for Default Gateway / Router interface
    
    Therefore, assignable endpoints = 2^h - 3.
    Required condition: 2^h - 2 >= hosts_needed + (1 if reserve_gateway else 0)
    """
    if hosts_needed <= 0:
        raise ValueError(f"Host count must be a positive integer, got: {hosts_needed}")
    
    total_usable_needed = hosts_needed + (1 if reserve_gateway else 0)
    
    # Point-to-point links (/30) require 2 usable addresses
    if hosts_needed <= 2 and not reserve_gateway:
        return 2  # /30 provides 2 usable IPs
    
    total_addresses_needed = total_usable_needed + 2  # Include network + broadcast
    
    # Minimum 2 host bits (/30, 4 addresses)
    h = 2
    while (1 << h) < total_addresses_needed:
        h += 1
    return h


@dataclass
class SubnetAllocation:
    name: str
    vlan_id: Optional[int]
    requested_hosts: int
    allocated_size: int
    prefix: int
    network_address: str
    subnet_mask: str
    wildcard_mask: str
    gateway_ip: str
    first_usable_host: str
    last_usable_host: str
    broadcast_address: str
    usable_hosts: int               # Assignable endpoint capacity (excludes reserved gateway)
    assignable_endpoints: int       # Assignable endpoint capacity (excludes reserved gateway)
    total_usable_hosts: int         # Total usable IP capacity in block (includes gateway)
    efficiency_pct: float
    # Numeric boundaries for validation
    net_int: int
    broadcast_int: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "vlan_id": self.vlan_id,
            "requested_hosts": self.requested_hosts,
            "allocated_size": self.allocated_size,
            "prefix": f"/{self.prefix}",
            "network_address": self.network_address,
            "subnet_mask": self.subnet_mask,
            "wildcard_mask": self.wildcard_mask,
            "gateway_ip": self.gateway_ip,
            "usable_range": f"{self.first_usable_host} - {self.last_usable_host}",
            "broadcast_address": self.broadcast_address,
            "total_usable_ips": self.total_usable_hosts,
            "assignable_endpoints": self.assignable_endpoints,
            "usable_capacity": self.assignable_endpoints,
            "efficiency": f"{self.efficiency_pct:.1f}%"
        }


@dataclass
class VLSMResult:
    root_network: str
    root_prefix: int
    root_capacity: int
    total_requested_hosts: int
    total_allocated_addresses: int
    remaining_unallocated_addresses: int
    subnet_efficiency_pct: float
    root_utilization_pct: float
    allocations: List[SubnetAllocation]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "root_network": f"{self.root_network}/{self.root_prefix}",
            "root_capacity": self.root_capacity,
            "total_requested_hosts": self.total_requested_hosts,
            "total_allocated_addresses": self.total_allocated_addresses,
            "remaining_unallocated_addresses": self.remaining_unallocated_addresses,
            "subnet_efficiency": f"{self.subnet_efficiency_pct:.1f}%",
            "root_utilization": f"{self.root_utilization_pct:.1f}%",
            "allocations": [a.to_dict() for a in self.allocations]
        }


class VLSMAllocator:
    """
    Algorithmic Variable-Length Subnet Mask (VLSM) Allocator.
    Enforces descending host sort, bitwise power-of-two CIDR alignment,
    gateway reservation, overlap detection, and address space exhaustion checks.
    """

    @classmethod
    def allocate(
        cls,
        root_cidr: str,
        subnets_req: List[Dict[str, Any]],
        reserve_gateway: bool = True
    ) -> VLSMResult:
        """
        Allocates non-overlapping subnets from root CIDR.
        
        Args:
            root_cidr: e.g. "192.168.0.0/16"
            subnets_req: List of dicts, e.g. [{"name": "Eng", "hosts": 200, "vlan_id": 10}, ...]
            reserve_gateway: If True, gateway is reserved from usable range and not counted as host.
            
        Returns:
            VLSMResult containing structured allocation details and utilization metrics.
            
        Raises:
            InvalidCIDRError: If root CIDR is invalid.
            ValueError: If subnet request is invalid.
            AddressSpaceExhaustionError: If allocations exceed root capacity.
            SubnetOverlapError: If an overlapping allocation occurs.
        """
        root_net_int, root_prefix = parse_cidr(root_cidr)
        root_capacity = 1 << (32 - root_prefix)
        root_end_int = root_net_int + root_capacity - 1

        if not subnets_req:
            return VLSMResult(
                root_network=int_to_ip(root_net_int),
                root_prefix=root_prefix,
                root_capacity=root_capacity,
                total_requested_hosts=0,
                total_allocated_addresses=0,
                remaining_unallocated_addresses=root_capacity,
                subnet_efficiency_pct=0.0,
                root_utilization_pct=0.0,
                allocations=[]
            )

        # 1. Validation & Sort descending by requested host count
        # Ascending/unordered allocation causes address space fragmentation and overlap!
        sorted_requests = []
        for s in subnets_req:
            name = s.get("name", "Unnamed_Subnet")
            hosts = s.get("hosts")
            if hosts is None or not isinstance(hosts, int) or hosts <= 0:
                raise ValueError(f"Subnet '{name}' must have a positive integer host count, got: {hosts}")
            vlan_id = s.get("vlan_id")
            if vlan_id is not None:
                if not isinstance(vlan_id, int) or vlan_id < 1 or vlan_id > 4094:
                    raise ValueError(f"Subnet '{name}' invalid VLAN ID {vlan_id} (must be 1-4094)")
            sorted_requests.append({
                "name": name,
                "hosts": hosts,
                "vlan_id": vlan_id
            })

        # Stable sort descending by host requirement
        sorted_requests.sort(key=lambda x: x["hosts"], reverse=True)

        allocations: List[SubnetAllocation] = []
        current_ip = root_net_int
        total_requested = 0
        total_allocated = 0

        for req in sorted_requests:
            name = req["name"]
            hosts = req["hosts"]
            vlan_id = req["vlan_id"]
            total_requested += hosts

            # Calculate host bits and block size
            h = calculate_host_bits(hosts, reserve_gateway=reserve_gateway)
            prefix = 32 - h
            block_size = 1 << h

            # Prefix cannot be smaller than root prefix
            if prefix < root_prefix:
                raise AddressSpaceExhaustionError(
                    f"Subnet '{name}' requires /{prefix} ({block_size} addresses) which is larger "
                    f"than the entire root network /{root_prefix} ({root_capacity} addresses)."
                )

            # Bitwise CIDR boundary alignment:
            # Subnet must start on a boundary divisible by its size (block_size).
            # Aligned start = (current_ip + block_size - 1) & ~(block_size - 1)
            aligned_net_int = (current_ip + block_size - 1) & ~(block_size - 1)
            subnet_broadcast_int = aligned_net_int + block_size - 1

            # Check address space exhaustion
            if subnet_broadcast_int > root_end_int:
                raise AddressSpaceExhaustionError(
                    f"Address space exhausted! Cannot allocate subnet '{name}' (needs /{prefix}, "
                    f"{block_size} addresses). Next aligned start {int_to_ip(aligned_net_int)} "
                    f"extends to {int_to_ip(subnet_broadcast_int)}, exceeding root network boundary "
                    f"{int_to_ip(root_end_int)} (/{root_prefix})."
                )

            mask_int = prefix_to_mask_int(prefix)
            wildcard_int = mask_int_to_wildcard_int(mask_int)

            # Addresses:
            # When reserve_gateway is True:
            # - Gateway IP is strictly assigned to Network + 1
            # - First assignable endpoint is strictly assigned to Network + 2
            # - Last assignable endpoint is Broadcast - 1
            # For a /30 (block size 4):
            #   Network = .0, Gateway = .1, Endpoint = .2, Broadcast = .3
            #   Gateway (.1) is NEVER identical to the assignable endpoint (.2).
            gateway_ip_int = aligned_net_int + 1
            if reserve_gateway:
                first_usable_host_int = aligned_net_int + 2
                assignable_cap = max(0, block_size - 3)
            else:
                first_usable_host_int = aligned_net_int + 1
                assignable_cap = max(0, block_size - 2)
            last_usable_host_int = subnet_broadcast_int - 1

            total_usable_cap = max(0, block_size - 2)
            efficiency = (hosts / block_size) * 100.0

            alloc = SubnetAllocation(
                name=name,
                vlan_id=vlan_id,
                requested_hosts=hosts,
                allocated_size=block_size,
                prefix=prefix,
                network_address=int_to_ip(aligned_net_int),
                subnet_mask=int_to_ip(mask_int),
                wildcard_mask=int_to_ip(wildcard_int),
                gateway_ip=int_to_ip(gateway_ip_int),
                first_usable_host=int_to_ip(first_usable_host_int),
                last_usable_host=int_to_ip(last_usable_host_int),
                broadcast_address=int_to_ip(subnet_broadcast_int),
                usable_hosts=assignable_cap,
                assignable_endpoints=assignable_cap,
                total_usable_hosts=total_usable_cap,
                efficiency_pct=efficiency,
                net_int=aligned_net_int,
                broadcast_int=subnet_broadcast_int
            )

            # 9. Overlap check against all previous allocations
            for prior in allocations:
                if not (alloc.broadcast_int < prior.net_int or alloc.net_int > prior.broadcast_int):
                    raise SubnetOverlapError(
                        f"Overlap detected between subnet '{alloc.name}' "
                        f"({alloc.network_address} - {alloc.broadcast_address}) and '{prior.name}' "
                        f"({prior.network_address} - {prior.broadcast_address})!"
                    )

            allocations.append(alloc)
            total_allocated += block_size
            current_ip = subnet_broadcast_int + 1

        overall_eff = (total_requested / total_allocated * 100.0) if total_allocated > 0 else 0.0
        root_util = (total_allocated / root_capacity * 100.0) if root_capacity > 0 else 0.0
        remaining_addresses = root_capacity - total_allocated

        return VLSMResult(
            root_network=int_to_ip(root_net_int),
            root_prefix=root_prefix,
            root_capacity=root_capacity,
            total_requested_hosts=total_requested,
            total_allocated_addresses=total_allocated,
            remaining_unallocated_addresses=remaining_addresses,
            subnet_efficiency_pct=overall_eff,
            root_utilization_pct=root_util,
            allocations=allocations
        )
