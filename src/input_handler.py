"""
Input Ingestion and Parameter Validation Engine
Course Code: CIC-307 Computer Networks Mini-Project

Parses, sanitizes, and validates enterprise network parameters from JSON files or strings.
Enforces physical and algorithmic constraints before execution.
"""

import json
import os
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from src.vlsm import parse_cidr, InvalidCIDRError


class ValidationError(Exception):
    """Base exception for network configuration input validation failures."""
    pass


class NegativeDistanceError(ValidationError):
    """Raised when a physical link distance is negative."""
    pass


class InvalidHostCountError(ValidationError):
    """Raised when a subnet host count is zero or negative."""
    pass


@dataclass
class NetworkSpecification:
    network_name: str
    network_type: str
    num_sites: int
    total_endpoints: int
    link_distance_meters: float
    redundancy_required: bool
    root_cidr: str
    subnets: List[Dict[str, Any]]
    requested_medium: Optional[str] = None
    has_cloud_vpc: bool = False
    has_external_as: bool = False
    local_as: int = 65001
    peer_as: Optional[int] = None
    qos_enabled: bool = False
    ipsec_required: bool = False
    notes: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "network_name": self.network_name,
            "network_type": self.network_type,
            "num_sites": self.num_sites,
            "total_endpoints": self.total_endpoints,
            "link_distance_meters": self.link_distance_meters,
            "redundancy_required": self.redundancy_required,
            "root_cidr": self.root_cidr,
            "requested_medium": self.requested_medium,
            "has_cloud_vpc": self.has_cloud_vpc,
            "has_external_as": self.has_external_as,
            "local_as": self.local_as,
            "peer_as": self.peer_as,
            "qos_enabled": self.qos_enabled,
            "ipsec_required": self.ipsec_required,
            "subnets": self.subnets
        }


class InputHandler:
    """
    Parses and thoroughly validates input parameters for NetArchitect.
    """

    @classmethod
    def load_from_file(cls, file_path: str) -> NetworkSpecification:
        """Loads and validates a network specification from a JSON file path."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Specification file not found: {file_path}")
        
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            raise ValidationError(f"Invalid JSON in file '{file_path}': {str(e)}")

        return cls.validate_data(data)

    @classmethod
    def load_from_string(cls, json_str: str) -> NetworkSpecification:
        """Loads and validates a network specification from a JSON string."""
        try:
            data = json.loads(json_str)
        except json.JSONDecodeError as e:
            raise ValidationError(f"Malformed JSON string: {str(e)}")
        return cls.validate_data(data)

    @classmethod
    def validate_data(cls, data: Dict[str, Any]) -> NetworkSpecification:
        """Validates all input fields against networking and physical constraints."""
        if not isinstance(data, dict):
            raise ValidationError("Top-level JSON structure must be a JSON object (dictionary).")

        # 1. Network Name
        network_name = data.get("network_name", data.get("name"))
        if not network_name or not isinstance(network_name, str) or not network_name.strip():
            raise ValidationError("Missing or invalid 'network_name'. Must be a non-empty string.")
        network_name = network_name.strip()

        # 2. Network Type
        network_type = data.get("network_type", data.get("type", "campus_lan"))
        if not isinstance(network_type, str):
            raise ValidationError("Invalid 'network_type'. Must be a string (e.g. 'campus_lan', 'metro_man', 'global_wan').")

        # 3. Number of Sites / Buildings
        num_sites = data.get("num_sites", data.get("num_buildings", 1))
        if not isinstance(num_sites, int) or num_sites < 1:
            raise ValidationError(f"Invalid 'num_sites' / 'num_buildings': {num_sites}. Must be an integer >= 1.")

        # 4. Total Endpoints
        total_endpoints = data.get("total_endpoints", data.get("endpoints", 0))
        if not isinstance(total_endpoints, int) or total_endpoints < 1:
            raise ValidationError(f"Invalid 'total_endpoints': {total_endpoints}. Must be an integer >= 1.")

        # 5. Link Distance (Metres)
        dist_val = data.get("link_distance_meters", data.get("distance_meters", data.get("distance", 0)))
        try:
            link_distance = float(dist_val)
        except (ValueError, TypeError):
            raise ValidationError(f"Invalid link distance value: '{dist_val}'. Must be a number.")
        if link_distance < 0:
            raise NegativeDistanceError(
                f"Negative link distance violation: {link_distance}m. Physical transmission distance cannot be negative."
            )

        # 6. Redundancy Requirement
        redundancy_required = bool(data.get("redundancy_required", data.get("redundancy", True)))

        # 7. Root CIDR Network
        root_cidr = data.get("root_cidr", data.get("root", data.get("root_network")))
        if not root_cidr or not isinstance(root_cidr, str):
            raise ValidationError("Missing 'root_cidr' parameter (e.g., '192.168.0.0/16').")
        root_cidr = root_cidr.strip()
        # Verify valid CIDR format
        parse_cidr(root_cidr)

        # 8. Subnets
        subnets_raw = data.get("subnets", [])
        if not isinstance(subnets_raw, list) or len(subnets_raw) == 0:
            raise ValidationError("Subnets list must contain at least one department/VLAN subnet specification.")

        validated_subnets = []
        seen_names = set()
        seen_vlans = set()

        for idx, sub in enumerate(subnets_raw):
            if not isinstance(sub, dict):
                raise ValidationError(f"Subnet entry #{idx+1} is not a valid JSON dictionary.")

            s_name = sub.get("name", f"Subnet_{idx+1}").strip()
            if not s_name:
                raise ValidationError(f"Subnet entry #{idx+1} has an empty name.")
            if s_name in seen_names:
                raise ValidationError(f"Duplicate subnet name detected: '{s_name}'. Subnet names must be unique.")
            seen_names.add(s_name)

            s_hosts = sub.get("hosts")
            if s_hosts is None or not isinstance(s_hosts, int) or s_hosts <= 0:
                raise InvalidHostCountError(
                    f"Subnet '{s_name}' has invalid host requirement: {s_hosts}. Host count must be an integer > 0."
                )

            s_vlan = sub.get("vlan_id")
            if s_vlan is not None:
                if not isinstance(s_vlan, int) or s_vlan < 1 or s_vlan > 4094:
                    raise ValidationError(
                        f"Subnet '{s_name}' has invalid VLAN ID: {s_vlan}. IEEE 802.1Q VLAN IDs must be between 1 and 4094."
                    )
                if s_vlan in seen_vlans:
                    raise ValidationError(f"Duplicate VLAN ID {s_vlan} assigned to subnet '{s_name}'.")
                seen_vlans.add(s_vlan)

            validated_subnets.append({
                "name": s_name,
                "hosts": s_hosts,
                "vlan_id": s_vlan
            })

        # Additional features
        requested_medium = data.get("requested_medium")
        has_cloud_vpc = bool(data.get("has_cloud_vpc", False))
        has_external_as = bool(data.get("has_external_as", False))
        local_as = int(data.get("local_as", 65001))
        peer_as = int(data["peer_as"]) if "peer_as" in data and data["peer_as"] is not None else None
        qos_enabled = bool(data.get("qos_enabled", False))
        ipsec_required = bool(data.get("ipsec_required", False))
        notes = data.get("notes")

        return NetworkSpecification(
            network_name=network_name,
            network_type=network_type,
            num_sites=num_sites,
            total_endpoints=total_endpoints,
            link_distance_meters=link_distance,
            redundancy_required=redundancy_required,
            root_cidr=root_cidr,
            subnets=validated_subnets,
            requested_medium=requested_medium,
            has_cloud_vpc=has_cloud_vpc,
            has_external_as=has_external_as,
            local_as=local_as,
            peer_as=peer_as,
            qos_enabled=qos_enabled,
            ipsec_required=ipsec_required,
            notes=notes
        )
