"""
Cisco IOS Configuration Generator Engine
Course Code: CIC-307 Computer Networks Mini-Project

Generates structured, role-separated Cisco IOS configurations (.cfg)
for Core / Multilayer Distribution Switches (Catalyst 3650), Access Layer Switches (Catalyst 2960),
and Enterprise WAN Edge Routers (ISR 4321).
"""

from typing import List, Dict, Any, Optional, Tuple
from src.input_handler import NetworkSpecification
from src.vlsm import VLSMResult, SubnetAllocation
from src.routing_engine import RoutingRecommendation
from src.topology import TopologyRecommendation
from src.media_engine import MediaRecommendation


class CiscoConfigGenerator:
    """
    Builds deployment-ready Cisco IOS configurations separated by device role:
    1. Core / Multilayer Distribution Switch (Cisco Catalyst 3650-24PS, Cisco IOS-XE)
    2. Access Layer Switch (Cisco Catalyst 2960-24TT, Cisco IOS 15.0)
    3. Enterprise WAN Edge Router (Cisco ISR 4321, Cisco IOS-XE)
    """

    @classmethod
    def identify_quarantined_subnets(cls, vlsm: VLSMResult) -> List[SubnetAllocation]:
        """
        Identifies subnets that require strict Layer 3 quarantine / inter-VLAN access control.
        Matches keywords: 'iot', 'surveillance', 'guest', 'scanner', 'branch'.
        """
        quarantined = [
            alloc for alloc in vlsm.allocations
            if any(k in alloc.name.lower() for k in ["iot", "surveillance", "guest", "scanner", "branch"])
        ]
        return quarantined

    @classmethod
    def calculate_access_port_ranges(
        cls,
        allocations: List[SubnetAllocation],
        total_ports: int = 24
    ) -> List[Tuple[SubnetAllocation, int, int]]:
        """
        Distributes 24 FastEthernet access ports evenly across all data VLANs.
        Returns a list of (allocation, start_port, end_port).
        """
        n = len(allocations)
        if n == 0:
            return []
        base_ports = total_ports // n
        remainder = total_ports % n

        ranges = []
        current_port = 1
        for i, alloc in enumerate(allocations):
            port_count = base_ports + (1 if i < remainder else 0)
            start_p = current_port
            end_p = current_port + port_count - 1
            ranges.append((alloc, start_p, end_p))
            current_port = end_p + 1
        return ranges

    @classmethod
    def generate_config(
        cls,
        spec: NetworkSpecification,
        media: MediaRecommendation,
        vlsm: VLSMResult,
        routing: RoutingRecommendation,
        topology: TopologyRecommendation
    ) -> str:
        """
        Generates a consolidated, role-separated multi-device Cisco IOS configuration script.
        """
        hostname = spec.network_name.replace(" ", "-").replace("_", "-").upper()
        lines: List[str] = []

        # Master Header Block
        lines.append("!" * 79)
        lines.append(f"! NETARCHITECT: CISCO IOS MULTI-DEVICE CONFIGURATION EXPORT")
        lines.append(f"! Network Name        : {spec.network_name}")
        lines.append(f"! Scenario Profile    : {spec.network_type.upper()}")
        lines.append(f"! Architecture Pattern: {topology.topology_name}")
        lines.append(f"! Physical Layer Link : {media.medium} ({media.standard})")
        lines.append(f"! Primary Routing     : {routing.primary_igp}" + (f" + {routing.egp_protocol}" if routing.egp_protocol else ""))
        lines.append(f"! Root Addressing     : {vlsm.root_network}/{vlsm.root_prefix}")
        lines.append("!")
        lines.append("! TARGET HARDWARE MODELS (PACKET TRACER / GNS3 VERIFIED):")
        lines.append("!   - DEVICE 1: Cisco Catalyst 3650-24PS (Multilayer Switch, Cisco IOS-XE 16.x)")
        lines.append("!   - DEVICE 2: Cisco Catalyst 2960-24TT (Layer 2 Edge Switch, Cisco IOS 15.0)")
        lines.append("!   - DEVICE 3: Cisco ISR 4321 (Enterprise WAN Edge Router, Cisco IOS-XE 16.x)")
        lines.append("!")
        lines.append("! DEPLOYMENT INSTRUCTIONS:")
        lines.append("! This file contains 3 DISTINCT, role-separated device configurations.")
        lines.append("! Copy each designated section into the corresponding device console in Packet Tracer.")
        lines.append("! Do not paste the entire file into a single device.")
        lines.append("!" * 79)
        lines.append("")

        # Collect data VLAN IDs
        vlan_ids: List[int] = []
        for idx, alloc in enumerate(vlsm.allocations):
            vid = alloc.vlan_id if alloc.vlan_id else (10 + idx * 10)
            vlan_ids.append(vid)
        data_vlan_str = ",".join(str(v) for v in vlan_ids)
        # Trunk allowed list: Management VLAN 99 + all data VLANs. Native VLAN 999 is intentionally excluded!
        trunk_allowed_vlans = f"99,{data_vlan_str}"
        primary_vlan = vlan_ids[0] if vlan_ids else 10

        # Identify quarantined subnets
        quarantined_allocations = cls.identify_quarantined_subnets(vlsm)

        # Multi-Area vs Single-Area OSPF Area determination
        is_campus = "campus" in spec.network_type.lower()
        data_area_num = 0 if is_campus else (10 if "wan" in spec.network_type.lower() else 1)

        # =========================================================================
        # DEVICE 1: CORE / MULTILAYER DISTRIBUTION SWITCH
        # =========================================================================
        lines.append("=" * 79)
        lines.append("! DEVICE 1 OF 3: CORE / MULTILAYER DISTRIBUTION SWITCH")
        lines.append(f"! Hostname: {hostname}-CORE-DISTR")
        lines.append("! Device Role: Inter-VLAN Routing (SVIs), Core OSPF, Trunk Downlinks, ACL Enforcement")
        lines.append("! Target Hardware Model: Cisco Catalyst 3650-24PS (Multilayer Switch, Cisco IOS-XE)")
        lines.append("! Model Compatibility Note: Catalyst 3650 natively runs IEEE 802.1Q encapsulation;")
        lines.append("! 'switchport trunk encapsulation dot1q' is unsupported and omitted.")
        lines.append("=" * 79)
        lines.append("enable")
        lines.append("configure terminal")
        lines.append(f"hostname {hostname}-CORE-DISTR")
        lines.append("!")
        lines.append("! --- Device Management & SSH Hardening ---")
        lines.append("service password-encryption")
        lines.append("no ip domain-lookup")
        lines.append("ip domain-name netarchitect.local")
        lines.append("username admin privilege 15 secret Cisco123!")
        lines.append("crypto key generate rsa modulus 2048")
        lines.append("ip ssh version 2")
        lines.append("!")
        lines.append("! --- Global Layer 3 Switching & Routing ---")
        lines.append("ip routing")
        lines.append("ipv6 unicast-routing")
        lines.append("ip cef")
        lines.append("!")
        lines.append("! --- Spanning Tree Protocol Hardening (IEEE 802.1w Rapid-PVST+) ---")
        lines.append("spanning-tree mode rapid-pvst")
        lines.append("spanning-tree extend system-id")
        lines.append("spanning-tree portfast default")
        lines.append("spanning-tree portfast bpduguard default")
        lines.append("spanning-tree vlan 1-4094 priority 24576")
        lines.append("!")
        lines.append("! --- IEEE 802.1Q VLAN Database ---")
        lines.append("vlan 99")
        lines.append(" name Network_Management")
        lines.append(" state active")
        lines.append("!")
        lines.append("vlan 999")
        lines.append(" name Unused_Native_Blackhole")
        lines.append(" state active")
        lines.append("!")
        for alloc in vlsm.allocations:
            vid = alloc.vlan_id if alloc.vlan_id else primary_vlan
            clean_name = alloc.name.replace(" ", "_")
            lines.append(f"vlan {vid}")
            lines.append(f" name {clean_name}")
            lines.append(" state active")
            lines.append("!")
        lines.append("! --- Hardened Distribution Trunk Downlink to Access Switch ---")
        lines.append("interface GigabitEthernet1/0/1")
        lines.append(" description Trunk-Downlink-To-Access-Switch-01")
        lines.append(" switchport mode trunk")
        lines.append(" switchport trunk native vlan 999")
        lines.append(f" switchport trunk allowed vlan {trunk_allowed_vlans}")
        lines.append(" switchport nonegotiate")
        lines.append(" no shutdown")
        lines.append("!")
        lines.append("! --- Layer 3 Switched Virtual Interfaces (SVIs) as Default Gateways ---")
        lines.append("interface Vlan99")
        lines.append(" description SVI: Out-of-Band Network Management Gateway")
        lines.append(" ip address 10.255.99.1 255.255.255.0")
        lines.append(" no shutdown")
        lines.append("!")
        for alloc in vlsm.allocations:
            vid = alloc.vlan_id if alloc.vlan_id else primary_vlan
            lines.append(f"interface Vlan{vid}")
            lines.append(f" description Default-Gateway-for-{alloc.name}")
            lines.append(f" ip address {alloc.gateway_ip} {alloc.subnet_mask}")
            # Bind the quarantine ACL to designated restricted subnets
            if alloc in quarantined_allocations:
                lines.append(" ip access-group HARDENED-INTERVLAN-ACL in")
            lines.append(" no shutdown")
            lines.append("!")
        lines.append("! --- Layer 3 Routed Interconnect to Edge Router ---")
        lines.append("interface GigabitEthernet1/0/24")
        lines.append(" description Routed-Link-To-WAN-Edge-Router")
        lines.append(" no switchport")
        lines.append(" ip address 10.255.255.2 255.255.255.252")
        lines.append(" ip ospf network point-to-point")
        lines.append(" no shutdown")
        lines.append("!")
        lines.append("! --- Core OSPF Routing Protocol Engine ---")
        lines.append("router ospf 1")
        lines.append(" router-id 1.1.1.2")
        lines.append(" log-adjacency-changes")
        lines.append(" passive-interface default")
        lines.append(" no passive-interface GigabitEthernet1/0/24")
        # In Multi-Area OSPF, Core Switch acts as ABR between transit Area 0 and site Area
        lines.append(" network 10.255.255.0 0.0.0.3 area 0")
        lines.append(" network 10.255.99.0 0.0.0.255 area 0")
        for alloc in vlsm.allocations:
            lines.append(f" network {alloc.network_address} {alloc.wildcard_mask} area {data_area_num}")
        if not is_campus and routing.summaries:
            for s in routing.summaries:
                lines.append(f" area {data_area_num} range {s.network_address} {s.subnet_mask}")
        lines.append("!")

        # Hardened Inter-VLAN ACL
        lines.append("! --- Enterprise Access Control Lists (ACLs) ---")
        lines.append("! Traffic Direction: INBOUND on isolated SVIs ('ip access-group HARDENED-INTERVLAN-ACL in')")
        lines.append("! Enforced Security Policy Ordering:")
        lines.append("!   1. PERMIT DHCP discovery and DNS queries to local default gateway")
        lines.append("!   2. PERMIT ICMP Echo strictly to local default gateway (link reachability test)")
        lines.append("!   3. STRICT DENY: Drop all traffic from quarantined subnets to private RFC 1918 LANs")
        lines.append("!   4. PERMIT established TCP return sessions (outbound cloud/internet replies)")
        lines.append("!   5. PERMIT outbound non-RFC 1918 public internet/cloud destinations")
        lines.append("ip access-list extended HARDENED-INTERVLAN-ACL")
        for alloc in quarantined_allocations:
            vid = alloc.vlan_id
            lines.append(f" remark --- Quarantined Subnet: {alloc.name} (VLAN {vid}) ---")
            lines.append(f" remark Permit DHCP to local broadcast / gateway relay")
            lines.append(f" permit udp {alloc.network_address} {alloc.wildcard_mask} host 255.255.255.255 eq bootps")
            lines.append(f" permit udp {alloc.network_address} {alloc.wildcard_mask} host {alloc.gateway_ip} eq bootps")
            lines.append(f" remark Permit DNS to local default gateway")
            lines.append(f" permit udp {alloc.network_address} {alloc.wildcard_mask} host {alloc.gateway_ip} eq domain")
            lines.append(f" permit tcp {alloc.network_address} {alloc.wildcard_mask} host {alloc.gateway_ip} eq domain")
            lines.append(f" remark Permit ICMP Echo strictly to local default gateway ({alloc.gateway_ip})")
            lines.append(f" permit icmp {alloc.network_address} {alloc.wildcard_mask} host {alloc.gateway_ip} echo")
            lines.append(f" permit icmp {alloc.network_address} {alloc.wildcard_mask} host {alloc.gateway_ip} echo-reply")
            lines.append(f" remark STRICT ISOLATION: Deny access from {alloc.name} to private RFC 1918 corporate networks")
            lines.append(f" deny ip {alloc.network_address} {alloc.wildcard_mask} 10.0.0.0 0.255.255.255")
            lines.append(f" deny ip {alloc.network_address} {alloc.wildcard_mask} 172.16.0.0 0.15.255.255")
            lines.append(f" deny ip {alloc.network_address} {alloc.wildcard_mask} 192.168.0.0 0.0.255.255")
        lines.append(" remark Permit return traffic for established TCP sessions")
        lines.append(" permit tcp any any established")
        lines.append(" remark Permit outbound public Internet / Cloud traffic (RFC 1918 private subnets already denied)")
        lines.append(" permit ip any any")
        lines.append("!")
        lines.append("! --- Device Management Line Security ---")
        lines.append("line con 0")
        lines.append(" exec-timeout 5 0")
        lines.append(" logging synchronous")
        lines.append(" login local")
        lines.append("line vty 0 4")
        lines.append(" exec-timeout 5 0")
        lines.append(" logging synchronous")
        lines.append(" login local")
        lines.append(" transport input ssh")
        lines.append("!")
        lines.append("end")
        lines.append("")

        # =========================================================================
        # DEVICE 2: ACCESS LAYER SWITCH
        # =========================================================================
        lines.append("=" * 79)
        lines.append("! DEVICE 2 OF 3: ACCESS LAYER EDGE SWITCH")
        lines.append(f"! Hostname: {hostname}-ACCESS-SW01")
        lines.append("! Device Role: Layer 2 Endpoint Access Ports, 802.1Q Edge Security, STP PortFast/BPDU Guard")
        lines.append("! Target Hardware Model: Cisco Catalyst 2960-24TT (Layer 2 Switch, Cisco IOS 15.0)")
        lines.append("=" * 79)
        lines.append("enable")
        lines.append("configure terminal")
        lines.append(f"hostname {hostname}-ACCESS-SW01")
        lines.append("!")
        lines.append("! --- Device Management & SSH Hardening ---")
        lines.append("service password-encryption")
        lines.append("no ip domain-lookup")
        lines.append("ip domain-name netarchitect.local")
        lines.append("username admin privilege 15 secret Cisco123!")
        lines.append("crypto key generate rsa modulus 2048")
        lines.append("ip ssh version 2")
        lines.append("!")
        lines.append("! --- Layer 2 Spanning Tree (Rapid-PVST+) ---")
        lines.append("spanning-tree mode rapid-pvst")
        lines.append("spanning-tree extend system-id")
        lines.append("!")
        lines.append("! --- IEEE 802.1Q VLAN Database ---")
        lines.append("vlan 99")
        lines.append(" name Network_Management")
        lines.append(" state active")
        lines.append("!")
        lines.append("vlan 999")
        lines.append(" name Unused_Native_Blackhole")
        lines.append(" state active")
        lines.append("!")
        for alloc in vlsm.allocations:
            vid = alloc.vlan_id if alloc.vlan_id else primary_vlan
            clean_name = alloc.name.replace(" ", "_")
            lines.append(f"vlan {vid}")
            lines.append(f" name {clean_name}")
            lines.append(" state active")
            lines.append("!")
        lines.append("! --- Hardened Trunk Uplink to Core Distribution Switch ---")
        lines.append("interface GigabitEthernet0/1")
        lines.append(" description Trunk-Uplink-To-Core-Distribution-Switch")
        lines.append(" switchport mode trunk")
        lines.append(" switchport trunk native vlan 999")
        lines.append(f" switchport trunk allowed vlan {trunk_allowed_vlans}")
        lines.append(" switchport nonegotiate")
        lines.append(" no shutdown")
        lines.append("!")

        # Access Port Distribution across VLANs
        port_ranges = cls.calculate_access_port_ranges(vlsm.allocations, total_ports=24)
        lines.append("! --- Workstation & Endpoint Access Ports (Representative 24-Port Switch) ---")
        lines.append("! ARCHITECTURAL SCALING NOTE:")
        lines.append("! The following 24 FastEthernet ports represent a single Access Layer edge switch (Catalyst 2960-24TT)")
        lines.append("! deployed in a floor wiring closet. This demonstrates representative 802.1Q port assignment and")
        lines.append("! port security (PortFast, BPDU Guard), NOT a full physical chassis deployment for the entire")
        lines.append(f"! scenario ({spec.total_endpoints:,} total endpoints). In production, multiple 24/48-port switches are")
        lines.append("! aggregated in stacks (Cisco FlexStack) or connected via redundant uplinks.")
        lines.append("!")
        for alloc, start_p, end_p in port_ranges:
            vid = alloc.vlan_id if alloc.vlan_id else primary_vlan
            clean_name = alloc.name.replace(" ", "_")
            if start_p == end_p:
                lines.append(f"interface FastEthernet0/{start_p}")
            else:
                lines.append(f"interface range FastEthernet0/{start_p} - {end_p}")
            lines.append(f" description Access-Ports: {clean_name} (VLAN {vid})")
            lines.append(" switchport mode access")
            lines.append(f" switchport access vlan {vid}")
            lines.append(" spanning-tree portfast")
            lines.append(" spanning-tree bpduguard enable")
            lines.append(" no shutdown")
            lines.append("!")

        lines.append("! --- Access Switch In-Band Management SVI ---")
        lines.append("interface Vlan99")
        lines.append(" description In-Band Switch Management Interface")
        lines.append(" ip address 10.255.99.10 255.255.255.0")
        lines.append(" no shutdown")
        lines.append("!")
        lines.append("ip default-gateway 10.255.99.1")
        lines.append("!")
        lines.append("! --- Device Management Line Security ---")
        lines.append("line con 0")
        lines.append(" exec-timeout 5 0")
        lines.append(" logging synchronous")
        lines.append(" login local")
        lines.append("line vty 0 4")
        lines.append(" exec-timeout 5 0")
        lines.append(" logging synchronous")
        lines.append(" login local")
        lines.append(" transport input ssh")
        lines.append("!")
        lines.append("end")
        lines.append("")

        # =========================================================================
        # DEVICE 3: ENTERPRISE WAN EDGE ROUTER
        # =========================================================================
        lines.append("=" * 79)
        lines.append("! DEVICE 3 OF 3: ENTERPRISE WAN EDGE ROUTER")
        lines.append(f"! Hostname: {hostname}-EDGE-RTR")
        lines.append("! Device Role: Physical Media WAN Termination, Edge OSPF, eBGP Peering, IPsec VPN, QoS")
        lines.append("! Target Hardware Model: Cisco ISR 4321 (Integrated Services Router, Cisco IOS-XE)")
        lines.append("=" * 79)
        lines.append("enable")
        lines.append("configure terminal")
        lines.append(f"hostname {hostname}-EDGE-RTR")
        lines.append("!")
        lines.append("! --- Device Management & SSH Hardening ---")
        lines.append("service password-encryption")
        lines.append("no ip domain-lookup")
        lines.append("ip domain-name netarchitect.local")
        lines.append("username admin privilege 15 secret Cisco123!")
        lines.append("crypto key generate rsa modulus 2048")
        lines.append("ip ssh version 2")
        lines.append("!")
        lines.append("! --- LAN Interface to Core Distribution Switch ---")
        lines.append("interface GigabitEthernet0/0/0")
        lines.append(" description Interconnect-To-Core-Switch")
        lines.append(" ip address 10.255.255.1 255.255.255.252")
        lines.append(" ip ospf network point-to-point")
        lines.append(" ip ospf hello-interval 10")
        lines.append(" ip ospf dead-interval 40")
        lines.append(" no shutdown")
        lines.append("!")
        lines.append("! --- WAN Interface (Physical Media Termination) ---")
        lines.append(f"! Recommended Physical Media: {media.medium}")
        lines.append(f"! Transceiver Standard      : {media.transceiver} ({media.standard})")
        lines.append(f"! Physical Distance         : {spec.link_distance_meters:,.1f}m ({spec.link_distance_meters/1000.0:.2f} km)")
        lines.append("interface GigabitEthernet0/0/1")
        lines.append(f" description WAN-Uplink-To-Provider-({media.standard})")
        lines.append(" ! NOTE: 198.51.100.0/24 is an RFC 5737 TEST-NET-2 documentation/lab address for simulation.")
        lines.append(" ! In production environments, replace with routable public IP assigned by ISP/Telco.")
        lines.append(" ip address 198.51.100.2 255.255.255.252")
        if spec.qos_enabled:
            lines.append(" service-policy output QOS-CORE-POLICY")
        lines.append(" no shutdown")
        lines.append("!")

        # Quality of Service (QoS) for Metro MAN
        if spec.qos_enabled:
            lines.append("! --- Quality of Service (QoS) DiffServ Markings (Sub-5ms SLA) ---")
            lines.append("class-map match-any CRITICAL-FINTECH-TRAFFIC")
            lines.append(" match ip dscp ef")
            lines.append(" match ip dscp cs6")
            lines.append("class-map match-any ENTERPRISE-DATA")
            lines.append(" match ip dscp af41")
            lines.append("!")
            lines.append("policy-map QOS-CORE-POLICY")
            lines.append(" class CRITICAL-FINTECH-TRAFFIC")
            lines.append("  priority percent 35")
            lines.append(" class ENTERPRISE-DATA")
            lines.append("  bandwidth percent 40")
            lines.append(" class class-default")
            lines.append("  fair-queue")
            lines.append("!")

        # IPsec VPN Settings for Global WAN / Hybrid Cloud
        if spec.ipsec_required or spec.has_cloud_vpc:
            lines.append("! --- Cryptographic IPsec VPN Overlay (IKEv2 / AES-256-GCM) ---")
            lines.append("! NOTE: 198.51.100.0/24 is an RFC 5737 TEST-NET-2 documentation/lab address range.")
            lines.append("! In production, replace 198.51.100.1 with the provider-assigned public IP of the Cloud VPC gateway.")
            lines.append("crypto ikev2 proposal IKEV2-PROPOSAL")
            lines.append(" encryption aes-gcm-256")
            lines.append(" prf sha384")
            lines.append(" group 19 20")
            lines.append("!")
            lines.append("crypto ikev2 keyring IKEV2-KEYRING")
            lines.append(" peer CLOUD-VPC-GW")
            lines.append("  address 198.51.100.1")
            lines.append("  pre-shared-key CiscoSecureVPN2026!")
            lines.append("!")
            lines.append("crypto ikev2 policy IKEV2-POLICY")
            lines.append(" proposal IKEV2-PROPOSAL")
            lines.append("!")
            lines.append("crypto ikev2 profile IKEV2-PROFILE")
            lines.append(" match identity remote address 198.51.100.1 255.255.255.255")
            lines.append(" identity local address 198.51.100.2")
            lines.append(" authentication remote pre-share")
            lines.append(" authentication local pre-share")
            lines.append(" keyring local IKEV2-KEYRING")
            lines.append("!")
            lines.append("crypto ipsec transform-set IPSEC-TRANSFORM esp-gcm 256")
            lines.append(" mode tunnel")
            lines.append("!")
            lines.append("crypto ipsec profile IPSEC-CLOUD-PROFILE")
            lines.append(" set transform-set IPSEC-TRANSFORM")
            lines.append(" set ikev2-profile IKEV2-PROFILE")
            lines.append("!")
            lines.append("interface Tunnel100")
            lines.append(" description IPsec-Overlay-Tunnel-to-Cloud-VPC")
            lines.append(" ip address 169.254.0.2 255.255.255.252")
            lines.append(" ip mtu 1436")
            lines.append(" ip tcp adjust-mss 1396")
            lines.append(" tunnel source GigabitEthernet0/0/1")
            lines.append(" tunnel destination 198.51.100.1")
            lines.append(" tunnel mode ipsec ipv4")
            lines.append(" tunnel protection ipsec profile IPSEC-CLOUD-PROFILE")
            lines.append(" no shutdown")
            lines.append("!")

        # Dynamic Routing on Edge Router
        lines.append("! --- Dynamic Routing Protocol Engine (Edge Router) ---")
        lines.append("router ospf 1")
        lines.append(" router-id 1.1.1.1")
        lines.append(" log-adjacency-changes")
        lines.append(" passive-interface default")
        lines.append(" no passive-interface GigabitEthernet0/0/0")
        lines.append(" network 10.255.255.0 0.0.0.3 area 0")
        if not is_campus and routing.summaries:
            for s in routing.summaries:
                lines.append(f" area {data_area_num} range {s.network_address} {s.subnet_mask}")
        lines.append("!")

        # BGP Configuration if applicable
        if spec.has_external_as or spec.has_cloud_vpc or "wan" in spec.network_type.lower():
            peer_asn = spec.peer_as if spec.peer_as is not None else 64512
            lines.append(f"router bgp {spec.local_as}")
            lines.append(" bgp router-id 1.1.1.1")
            lines.append(" bgp log-neighbor-changes")
            lines.append(f" neighbor 169.254.0.1 remote-as {peer_asn}")
            lines.append(" neighbor 169.254.0.1 description Peering-To-Cloud-VPC")
            lines.append(" neighbor 169.254.0.1 update-source Tunnel100")
            if routing.summaries:
                s = routing.summaries[0]
                lines.append(f" network {s.network_address} mask {s.subnet_mask}")
            lines.append("!")

        # Edge Router Security & Banner
        lines.append("! --- Edge Router Banner & Management Security ---")
        lines.append("banner motd ^C")
        lines.append("***********************************************************************")
        lines.append(f"* WARNING: UNAUTHORIZED ACCESS TO {hostname} IS PROHIBITED.          *")
        lines.append("* ALL SESSIONS ARE MONITORED AND LOGGED PURSUANT TO LAW.             *")
        lines.append("***********************************************************************")
        lines.append("^C")
        lines.append("line con 0")
        lines.append(" exec-timeout 5 0")
        lines.append(" logging synchronous")
        lines.append(" login local")
        lines.append("line vty 0 4")
        lines.append(" exec-timeout 5 0")
        lines.append(" logging synchronous")
        lines.append(" login local")
        lines.append(" transport input ssh")
        lines.append("!")
        lines.append("end")

        return "\n".join(lines) + "\n"
