"""
L3 Routing Protocol Decision Engine
Course Code: CIC-307 Computer Networks Mini-Project

Selects appropriate routing protocols (Single-Area OSPF, Multi-Area OSPF, eBGP)
based on autonomous system boundaries, subnet scale, inter-site WAN/Cloud links,
and computes route summarization boundaries.
"""

from dataclasses import dataclass
from typing import List, Dict, Any, Optional
from src.vlsm import SubnetAllocation, ip_to_int, int_to_ip, prefix_to_mask_int


@dataclass
class RouteSummary:
    area_or_domain: str
    summary_cidr: str
    network_address: str
    subnet_mask: str
    covered_subnets: List[str]
    reduction_ratio: str


@dataclass
class RoutingRecommendation:
    primary_igp: str
    primary_igp_area_design: str
    egp_protocol: Optional[str]
    local_as: Optional[int]
    peer_as: Optional[int]
    router_id: str
    ospf_process_id: int
    justification: str
    rfc_references: List[str]
    summaries: List[RouteSummary]
    cisco_routing_commands: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "primary_igp": self.primary_igp,
            "primary_igp_area_design": self.primary_igp_area_design,
            "egp_protocol": self.egp_protocol,
            "local_as": self.local_as,
            "peer_as": self.peer_as,
            "router_id": self.router_id,
            "ospf_process_id": self.ospf_process_id,
            "justification": self.justification,
            "rfc_references": self.rfc_references,
            "summaries": [
                {
                    "domain": s.area_or_domain,
                    "summary_cidr": s.summary_cidr,
                    "covered_subnets": s.covered_subnets,
                    "reduction_ratio": s.reduction_ratio
                }
                for s in self.summaries
            ],
            "cisco_routing_commands": self.cisco_routing_commands
        }


def compute_supernet(allocations: List[SubnetAllocation], area_label: str = "Area 0") -> Optional[RouteSummary]:
    """
    Computes optimal CIDR route summarization supernet covering a list of subnets.
    Finds the common prefix length across all allocated network numbers.
    """
    if not allocations:
        return None

    min_ip = min(a.net_int for a in allocations)
    max_ip = max(a.broadcast_int for a in allocations)

    # Find the highest bit position where min_ip and max_ip differ
    xor_diff = min_ip ^ max_ip
    diff_bits = 0
    while xor_diff > 0:
        diff_bits += 1
        xor_diff >>= 1

    common_prefix = 32 - diff_bits
    mask_int = prefix_to_mask_int(common_prefix)
    summary_net_int = min_ip & mask_int

    summary_net_str = int_to_ip(summary_net_int)
    summary_mask_str = int_to_ip(mask_int)
    summary_cidr = f"{summary_net_str}/{common_prefix}"

    covered_names = [f"{a.name} ({a.network_address}/{a.prefix})" for a in allocations]
    ratio = f"{len(allocations)} routes summarized into 1 aggregate route ({summary_cidr})"

    return RouteSummary(
        area_or_domain=area_label,
        summary_cidr=summary_cidr,
        network_address=summary_net_str,
        subnet_mask=summary_mask_str,
        covered_subnets=covered_names,
        reduction_ratio=ratio
    )


class RoutingDecisionEngine:
    """
    Rule-based routing protocol recommendation engine.
    
    Decision Rules:
    1. Single autonomous system with < 50 subnets:
       - Single-Area OSPF (Area 0 Backbone)
       - Link-state fast convergence, SPF Dijkstra algorithm, no inter-area summarization overhead.
    2. Multi-site / Campus with multiple buildings or > 50 subnets:
       - Multi-Area OSPF (Area 0 Backbone + Area 1, 2, ... for distinct sites)
       - Area Border Routers (ABRs) filter Type 1 and Type 2 LSAs, inject Type 3 Summary LSAs,
         isolating SPF recalculations to localized areas.
    3. Multi-Autonomous System boundary or External Cloud VPC / ISP Peering:
       - eBGP (External Border Gateway Protocol) at the edge + internal OSPF
       - Enforces administrative domain policy boundaries, AS-Path loop prevention,
         and route filtering.
    """

    @classmethod
    def evaluate(
        cls,
        subnet_count: int,
        num_sites: int,
        has_external_as: bool,
        has_cloud_vpc: bool,
        allocations: List[SubnetAllocation],
        network_type: str = "campus_lan",
        local_as: int = 65001,
        peer_as: Optional[int] = None,
        router_id: str = "1.1.1.1"
    ) -> RoutingRecommendation:
        """
        Determines the optimal routing architecture and generates Cisco IOS routing commands.
        """
        rfc_refs = ["RFC 2328 (OSPF Version 2)"]
        ospf_process = 1
        summaries: List[RouteSummary] = []
        commands: List[str] = []
        norm_type = network_type.lower()

        # Scenario A: External AS / Cloud VPC Boundary (e.g., Global WAN or Cloud Hybrid)
        if has_external_as or has_cloud_vpc or "wan" in norm_type:
            peer_asn = peer_as if peer_as is not None else 64512  # AWS default ASN
            rfc_refs.append("RFC 4271 (A Border Gateway Protocol 4 - BGP-4)")
            rfc_refs.append("RFC 1997 (BGP Communities Attribute)")

            # Multi-Area OSPF for internal IGP + eBGP for edge transit
            primary_igp = "Multi-Area OSPFv2"
            area_design = "Area 0 (Backbone Core) with Per-Site Transit Areas (Area 10-40)"
            egp_proto = "eBGP (External BGP-4)"

            justification = (
                f"Selected hybrid Multi-Area OSPFv2 (Internal IGP) and eBGP (External Border Gateway Protocol). "
                f"Because the network spans {num_sites} geographically dispersed sites and interconnects with an "
                f"external Autonomous System / Cloud VPC (AS {peer_asn}), eBGP is required at the edge to exchange "
                f"reachability information across disparate administrative domains. Inside the enterprise, "
                f"Multi-Area OSPF provides high-speed link-state SPF convergence while containing LSA flooding "
                f"and topological flap within local area boundaries. Route summarization at ABRs minimizes WAN link overhead."
            )

            # Generate summaries for internal sites
            summary = compute_supernet(allocations, area_label="Area 10 (Enterprise Branches)")
            if summary:
                summaries.append(summary)

            # Cisco Commands
            commands.append("! --- OSPF Interior Gateway Protocol Configuration ---")
            commands.append(f"router ospf {ospf_process}")
            commands.append(f" router-id {router_id}")
            commands.append(" log-adjacency-changes")
            commands.append(" passive-interface default")
            commands.append(" no passive-interface GigabitEthernet0/0/0")
            commands.append(" no passive-interface GigabitEthernet0/0/1")
            for alloc in allocations:
                commands.append(
                    f" network {alloc.network_address} {alloc.wildcard_mask} area 0"
                )
            if summary:
                commands.append(f" area 10 range {summary.network_address} {summary.subnet_mask}")

            commands.append("!")
            commands.append("! --- eBGP Border Peering Configuration ---")
            commands.append(f"router bgp {local_as}")
            commands.append(f" bgp router-id {router_id}")
            commands.append(" bgp log-neighbor-changes")
            commands.append(f" neighbor 169.254.0.1 remote-as {peer_asn}")
            commands.append(" neighbor 169.254.0.1 description Peering-To-Cloud-VPC-or-ISP")
            commands.append(" neighbor 169.254.0.1 update-source GigabitEthernet0/0/2")
            if summary:
                commands.append(f" network {summary.network_address} mask {summary.subnet_mask}")

            return RoutingRecommendation(
                primary_igp=primary_igp,
                primary_igp_area_design=area_design,
                egp_protocol=egp_proto,
                local_as=local_as,
                peer_as=peer_asn,
                router_id=router_id,
                ospf_process_id=ospf_process,
                justification=justification,
                rfc_references=rfc_refs,
                summaries=summaries,
                cisco_routing_commands=commands
            )

        # Scenario B: Multi-Site Enterprise MAN or Scale >= 50 subnets (e.g., Metro MAN / Multi-Site)
        elif ((num_sites > 1 and "campus" not in norm_type and "lan" not in norm_type) or subnet_count >= 50 or "man" in norm_type or "metro" in norm_type):
            primary_igp = "Multi-Area OSPFv2"
            area_design = "Area 0 (Backbone Transit) with Area 1 (HQ), Area 2 (Colocation), Area 3 (Branch)"
            egp_proto = None

            justification = (
                f"Selected Multi-Area OSPFv2. With {num_sites} interconnected sites and {subnet_count} subnets, "
                f"a flat Single-Area OSPF design would force all routers to execute Dijkstra's SPF algorithm "
                f"upon any interface or link state change across any site. Dividing the network into Area 0 (Backbone) "
                f"and satellite site areas confines Type 1 Router and Type 2 Network LSAs locally. "
                f"ABRs inject consolidated Type 3 Summary LSAs, reducing routing table memory footprint and "
                f"preventing WAN/MAN control plane thrashing."
            )

            summary = compute_supernet(allocations, area_label="Area 1 (Site LAN Supernet)")
            if summary:
                summaries.append(summary)

            commands.append(f"router ospf {ospf_process}")
            commands.append(f" router-id {router_id}")
            commands.append(" log-adjacency-changes")
            commands.append(" passive-interface default")
            commands.append(" no passive-interface TenGigabitEthernet0/0/1")
            commands.append(" no passive-interface TenGigabitEthernet0/0/2")
            for i, alloc in enumerate(allocations):
                # Allocate first half to Area 0 / backbone, rest to Area 1
                area = 0 if i < 2 else 1
                commands.append(
                    f" network {alloc.network_address} {alloc.wildcard_mask} area {area}"
                )
            if summary:
                commands.append(f" area 1 range {summary.network_address} {summary.subnet_mask}")

            return RoutingRecommendation(
                primary_igp=primary_igp,
                primary_igp_area_design=area_design,
                egp_protocol=None,
                local_as=None,
                peer_as=None,
                router_id=router_id,
                ospf_process_id=ospf_process,
                justification=justification,
                rfc_references=rfc_refs,
                summaries=summaries,
                cisco_routing_commands=commands
            )

        # Scenario C: Single Autonomous System with < 50 subnets (e.g., Campus LAN)
        else:
            primary_igp = "Single-Area OSPFv2 (Area 0)"
            area_design = "Area 0 (Single Backbone Area)"
            egp_proto = None

            justification = (
                f"Selected Single-Area OSPFv2 (Area 0). For a single enterprise campus containing {subnet_count} "
                f"subnets (< 50 threshold) within a single autonomous system, a unified Area 0 is optimal. "
                f"Link-state SPF provides sub-second convergence, zero routing loops, and low protocol overhead "
                f"without the operational complexity of ABR area borders or virtual links. All internal VLAN subnets "
                f"maintain synchronized link-state databases (LSDB) on the core distribution switch."
            )

            commands.append(f"router ospf {ospf_process}")
            commands.append(f" router-id {router_id}")
            commands.append(" log-adjacency-changes")
            commands.append(" passive-interface default")
            # SVIs are passive, only inter-switch routed uplinks are active
            commands.append(" no passive-interface GigabitEthernet0/1")
            for alloc in allocations:
                commands.append(
                    f" network {alloc.network_address} {alloc.wildcard_mask} area 0"
                )

            return RoutingRecommendation(
                primary_igp=primary_igp,
                primary_igp_area_design=area_design,
                egp_protocol=None,
                local_as=None,
                peer_as=None,
                router_id=router_id,
                ospf_process_id=ospf_process,
                justification=justification,
                rfc_references=rfc_refs,
                summaries=summaries,
                cisco_routing_commands=commands
            )
