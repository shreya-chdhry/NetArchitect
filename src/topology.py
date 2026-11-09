"""
Network Topology Recommendation Engine
Course Code: CIC-307 Computer Networks Mini-Project

Recommends enterprise physical and logical topologies (Hierarchical Star, Dual-Homed MAN,
Hub-and-Spoke / Partial Mesh WAN) with resiliency mechanisms (RSTP, LACP, BFD, IPsec).
"""

from dataclasses import dataclass
from typing import List, Dict, Any, Optional


@dataclass
class TopologyRecommendation:
    topology_name: str
    architecture_model: str
    redundancy_model: str
    spanning_tree_mode: str
    interconnect_technology: str
    tiers: List[Dict[str, str]]
    justification: str
    resiliency_features: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "topology_name": self.topology_name,
            "architecture_model": self.architecture_model,
            "redundancy_model": self.redundancy_model,
            "spanning_tree_mode": self.spanning_tree_mode,
            "interconnect_technology": self.interconnect_technology,
            "tiers": self.tiers,
            "justification": self.justification,
            "resiliency_features": self.resiliency_features
        }


class TopologyRecommendationEngine:
    """
    Evaluates enterprise requirements and determines optimal topology design.
    """

    @classmethod
    def evaluate(
        cls,
        network_type: str,
        num_sites: int,
        endpoints: int,
        requires_high_availability: bool = True
    ) -> TopologyRecommendation:
        norm_type = network_type.lower()

        # 1. Metro MAN / Colocation Environment
        if "man" in norm_type or "metro" in norm_type:
            return TopologyRecommendation(
                topology_name="Dual-Homed Redundant Star / Ring Topology",
                architecture_model="Carrier Ethernet EVPL with Redundant Optical Edge Interconnects",
                redundancy_model="Active/Standby or Active/Active Dual-Homing with BFD Failover",
                spanning_tree_mode="Rapid-PVST+ (per-VLAN) on local CPE; L3 routed links over MAN",
                interconnect_technology="Metro Ethernet EVPL (IEEE 802.1ah / 802.1Q) over OS2 SMF",
                tiers=[
                    {
                        "tier": "Headquarters Core",
                        "role": "Central aggregation, primary application compute, dual CPE edge routers"
                    },
                    {
                        "tier": "Remote Colocation (Colo)",
                        "role": "Low-latency FinTech trading/hosting infrastructure, disaster recovery replicate"
                    },
                    {
                        "tier": "Branch Office Edge",
                        "role": "Redundant customer access switches connected via dual carrier links"
                    }
                ],
                justification=(
                    f"Recommended Dual-Homed Redundant Topology for {num_sites} Metro MAN sites ({endpoints} users). "
                    f"In mission-critical financial and colocation environments, a single uplink introduces a single point of failure (SPOF). "
                    f"Dual-homed fiber links to geographically diverse carrier points of presence (PoP) provide deterministic "
                    f"path redundancy. Paired with Bidirectional Forwarding Detection (BFD), failure detection drops below 50ms, "
                    f"preserving real-time financial transaction streams without TCP session resets."
                ),
                resiliency_features=[
                    "Dual-homed carrier links with disparate physical cable entry conduits",
                    "Bidirectional Forwarding Detection (BFD) for sub-50ms interface fault detection",
                    "Differentiated Services Code Point (DSCP EF/CS6) prioritization for sub-5ms latency SLA",
                    "First Hop Redundancy Protocol (HSRP/VRRP) for default gateway fault tolerance"
                ]
            )

        # 2. Global WAN / Multi-Cloud
        elif "wan" in norm_type or "global" in norm_type:
            return TopologyRecommendation(
                topology_name="Hub-and-Spoke with Partial Mesh IPsec Overlay",
                architecture_model="Hybrid SD-WAN with IPsec Tunnels & Direct Cloud Interconnect",
                redundancy_model="Dual Hub redundancy with dynamic multi-path tunnel failover",
                spanning_tree_mode="Isolated per branch (Layer 2 boundary terminated at Branch Gateway)",
                interconnect_technology="IPsec VPN (IKEv2 / AES-256-GCM) over Internet + Cloud Direct Connect",
                tiers=[
                    {
                        "tier": "Primary Hubs (NYC / London)",
                        "role": "High-throughput transit aggregation, regional routing concentration"
                    },
                    {
                        "tier": "Regional Spoke Cities (Tokyo / Singapore)",
                        "role": "Branch edge gateways terminating local IoT and user traffic"
                    },
                    {
                        "tier": "Cloud VPC Gateway",
                        "role": "Virtual Private Gateway (VGW) peering with edge routers via eBGP"
                    }
                ],
                justification=(
                    f"Recommended Hub-and-Spoke with Partial Mesh IPsec Overlay for {num_sites} cities "
                    f"and {endpoints} endpoints. Full mesh at global scale creates an $O(N^2)$ tunnel scaling bottleneck "
                    f"and prohibitive circuit expenditure. A dual-hub architecture provides regional concentration, "
                    f"while direct IPsec tunnels are provisioned between high-volume hubs and the Cloud VPC. "
                    f"This guarantees deterministic routing paths, end-to-end cryptographic confidentiality, "
                    f"and resilient egress to enterprise cloud services."
                ),
                resiliency_features=[
                    "Dual redundant enterprise hubs preventing single point of failure",
                    "IPsec VPN with AES-256-GCM encryption and automated dead peer detection (DPD)",
                    "eBGP multipath routing and BGP AS-Path prepending for predictable failover",
                    "Strict IoT device isolation through dedicated VLANs and access control lists"
                ]
            )

        # 3. Campus LAN (Default)
        else:
            return TopologyRecommendation(
                topology_name="Three-Tier Hierarchical Campus Star Topology",
                architecture_model="Core - Distribution - Access Layer Model (Cisco Enterprise Architecture)",
                redundancy_model="Redundant Distribution-to-Core uplinks with EtherChannel (LACP)",
                spanning_tree_mode="Rapid-PVST+ (IEEE 802.1w Rapid Spanning Tree Protocol)",
                interconnect_technology="10GBASE-SR OM4 MMF Building Backbone + 10GBASE-T Cat6a Access",
                tiers=[
                    {
                        "tier": "Core Layer",
                        "role": "High-speed optical packet switching, zero packet filtering, backbone routing"
                    },
                    {
                        "tier": "Distribution Layer",
                        "role": "Inter-VLAN routing, ACL security boundary, QoS classification, DHCP relay"
                    },
                    {
                        "tier": "Access Layer",
                        "role": "Port security, 802.1X endpoint authentication, 802.3at PoE+ power for APs"
                    }
                ],
                justification=(
                    f"Recommended Three-Tier Hierarchical Campus Topology for {num_sites} buildings and {endpoints} endpoints. "
                    f"Separating the campus into Core, Distribution, and Access tiers isolates broadcast domains, "
                    f"confines Layer 2 spanning-tree topology recalculations to distribution blocks, and provides modular "
                    f"capacity expansion. Dual-uplink distribution switches eliminate cable cut vulnerability, and "
                    f"Rapid-PVST+ ensures 1-second convergence in the event of an access switch uplink failure."
                ),
                resiliency_features=[
                    "Rapid Per-VLAN Spanning Tree Plus (Rapid-PVST+ IEEE 802.1w) for sub-second failover",
                    "IEEE 802.3ad Link Aggregation (LACP EtherChannel) providing redundant bundled uplinks",
                    "Spanning Tree PortFast and BPDU Guard on all endpoint access ports to prevent rogue bridges",
                    "Dynamic ARP Inspection (DAI) and DHCP Snooping for Layer 2 security hardening"
                ]
            )
