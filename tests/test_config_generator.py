"""
Unit Tests for Cisco IOS Configuration Generator Engine
Course Code: CIC-307 Computer Networks Mini-Project

Covers:
- Configuration syntax validity (valid Cisco IOS commands)
- Trunk port security hardening (explicit allowed VLANs, rejection of 'allowed vlan all', native VLAN 999)
- Management VLAN 99 consistency across Core and Access switches
- Inter-VLAN ACL security logic (deny rules before broad permits, gateway reachability)
- Metro MAN isolation for branch office
- SVI gateway IP addressing consistency with VLSM allocations
- Access port distribution across multiple VLANs without voice vlan 99
- OSPF wildcard masks and transit link IP consistency
- Absence of unsupported trunk encapsulation commands on Catalyst 3650
- Preset configuration generation consistency across all three profiles
"""

import os
import re
import pytest
from src.input_handler import InputHandler
from src.media_engine import PhysicalMediaEngine
from src.vlsm import VLSMAllocator
from src.routing_engine import RoutingDecisionEngine
from src.topology import TopologyRecommendationEngine
from src.config_generator import CiscoConfigGenerator


class TestCiscoConfigGenerator:
    """Test suite for Cisco IOS configuration syntax, security logic, and architectural consistency."""

    def _generate_plan(self, filename: str):
        preset_path = os.path.join(os.path.dirname(__file__), "..", "presets", filename)
        spec = InputHandler.load_from_file(preset_path)
        media = PhysicalMediaEngine.evaluate_link(spec.link_distance_meters, spec.requested_medium)
        vlsm = VLSMAllocator.allocate(spec.root_cidr, spec.subnets)
        routing = RoutingDecisionEngine.evaluate(
            subnet_count=len(vlsm.allocations),
            num_sites=spec.num_sites,
            has_external_as=spec.has_external_as,
            has_cloud_vpc=spec.has_cloud_vpc,
            allocations=vlsm.allocations,
            network_type=spec.network_type,
            local_as=spec.local_as,
            peer_as=spec.peer_as
        )
        topology = TopologyRecommendationEngine.evaluate(
            network_type=spec.network_type,
            num_sites=spec.num_sites,
            endpoints=spec.total_endpoints
        )
        cfg = CiscoConfigGenerator.generate_config(spec, media, vlsm, routing, topology)
        return spec, vlsm, cfg

    @pytest.fixture
    def campus_plan(self):
        return self._generate_plan("campus_lan.json")

    @pytest.fixture
    def metro_man_plan(self):
        return self._generate_plan("metro_man.json")

    @pytest.fixture
    def global_wan_plan(self):
        return self._generate_plan("global_wan.json")

    # -------------------------------------------------------------------------
    # Baseline Structural Tests
    # -------------------------------------------------------------------------
    def test_spanning_tree_rapid_pvst_present(self, campus_plan):
        """Verify Rapid-PVST+ is configured with BPDU guard and portfast."""
        _, _, cfg = campus_plan
        assert "spanning-tree mode rapid-pvst" in cfg
        assert "spanning-tree portfast default" in cfg
        assert "spanning-tree portfast bpduguard default" in cfg

    def test_trunk_port_security_no_vlan_all(self, campus_plan):
        """Verify trunk ports enforce strict explicit VLAN allowed lists and forbid 'allowed vlan all'."""
        _, vlsm, cfg = campus_plan
        assert "switchport mode trunk" in cfg
        active_lines = [line.strip() for line in cfg.splitlines() if not line.strip().startswith("!")]
        assert "switchport trunk allowed vlan all" not in active_lines
        for alloc in vlsm.allocations:
            if alloc.vlan_id:
                assert str(alloc.vlan_id) in cfg

    def test_svi_gateway_addresses_match_vlsm(self, campus_plan):
        """Verify each SVI interface has the exact gateway IP and subnet mask computed by VLSM."""
        _, vlsm, cfg = campus_plan
        for alloc in vlsm.allocations:
            vid = alloc.vlan_id
            expected_svi_line = f"interface Vlan{vid}"
            expected_ip_line = f"ip address {alloc.gateway_ip} {alloc.subnet_mask}"
            assert expected_svi_line in cfg
            assert expected_ip_line in cfg

    def test_ospf_wildcard_mask_consistency(self, campus_plan):
        """Verify OSPF network commands use exact inverted wildcard masks."""
        _, vlsm, cfg = campus_plan
        assert "router ospf 1" in cfg
        for alloc in vlsm.allocations:
            expected_net = f"network {alloc.network_address} {alloc.wildcard_mask}"
            assert expected_net in cfg

    def test_ebgp_and_ipsec_in_global_wan(self, global_wan_plan):
        """Verify Global WAN config contains eBGP router statements and IPsec overlay tunnels."""
        spec, _, cfg = global_wan_plan
        assert f"router bgp {spec.local_as}" in cfg
        assert f"remote-as {spec.peer_as}" in cfg
        assert "crypto ikev2 proposal" in cfg
        assert "crypto ikev2 keyring" in cfg
        assert "interface Tunnel100" in cfg

    def test_device_role_sections_present(self, campus_plan):
        """Verify the configuration separates commands by Core Switch, Access Switch, and Edge Router."""
        _, _, cfg = campus_plan
        assert "DEVICE 1 OF 3: CORE / MULTILAYER DISTRIBUTION SWITCH" in cfg
        assert "DEVICE 2 OF 3: ACCESS LAYER EDGE SWITCH" in cfg
        assert "DEVICE 3 OF 3: ENTERPRISE WAN EDGE ROUTER" in cfg

    def test_acl_applied_to_interface(self, campus_plan):
        """Verify quarantine ACL is actually applied to the IoT / guest interface via ip access-group in."""
        _, _, cfg = campus_plan
        assert "ip access-list extended HARDENED-INTERVLAN-ACL" in cfg
        assert "ip access-group HARDENED-INTERVLAN-ACL in" in cfg

    def test_ssh_complete_settings_present(self, campus_plan):
        """Verify SSH login is fully configured with username, RSA key, version 2, and transport input ssh."""
        _, _, cfg = campus_plan
        assert "username admin privilege 15 secret" in cfg
        assert "crypto key generate rsa modulus 2048" in cfg
        assert "ip ssh version 2" in cfg
        assert "transport input ssh" in cfg

    def test_all_preset_export_files_exist(self):
        """Verify exported .cfg files exist in the exports directory."""
        export_dir = os.path.join(os.path.dirname(__file__), "..", "exports")
        expected_files = ["campus_lan.cfg", "metro_man.cfg", "global_wan.cfg"]
        for f in expected_files:
            p = os.path.join(export_dir, f)
            assert os.path.exists(p), f"Export file missing: {f}"
            assert os.path.getsize(p) > 1000, f"Export file too small or empty: {f}"

    # -------------------------------------------------------------------------
    # Comprehensive Regression Tests: ACL Security Logic
    # -------------------------------------------------------------------------
    def test_acl_deny_before_broad_permit(self, campus_plan, global_wan_plan):
        """
        Verify that all RFC 1918 deny rules occur strictly BEFORE any broad permit rules
        in the extended ACL, preventing IoT devices from pinging or reaching corporate LANs.
        """
        for plan in [campus_plan, global_wan_plan]:
            _, _, cfg = plan
            lines = [l.strip() for l in cfg.splitlines()]

            # Extract ACL block
            assert "ip access-list extended HARDENED-INTERVLAN-ACL" in lines
            acl_start = lines.index("ip access-list extended HARDENED-INTERVLAN-ACL")
            # Collect lines until the next command at indent 0 or '!'
            acl_lines = []
            for line in lines[acl_start + 1:]:
                if line.startswith("!") or line.startswith("interface") or line.startswith("line"):
                    break
                acl_lines.append(line)

            deny_indices = [i for i, l in enumerate(acl_lines) if l.startswith("deny ip")]
            broad_permit_indices = [
                i for i, l in enumerate(acl_lines)
                if l in ["permit ip any any", "permit tcp any any established"]
            ]

            assert len(deny_indices) >= 3, "ACL must contain explicit RFC 1918 deny rules"
            assert len(broad_permit_indices) >= 1, "ACL must contain outbound permit rules"

            # Strict rule ordering: Every deny must appear before the first broad permit
            first_broad_permit = min(broad_permit_indices)
            for d in deny_indices:
                assert d < first_broad_permit, f"Deny rule at line {d} appeared after broad permit at line {first_broad_permit}"

            # Verify ICMP permit is restricted to host gateway, not broad 'any any'
            for line in acl_lines:
                if line.startswith("permit icmp"):
                    assert "host" in line, f"ICMP permit must be restricted to host gateway: {line}"
                    assert "any any" not in line, f"Broad 'permit icmp any any' is prohibited before deny: {line}"

    def test_metro_man_acl_isolation_present(self, metro_man_plan):
        """
        Verify that Metro MAN implements concrete isolation for its branch office subnet
        and applies the ACL to the branch SVI in the inbound direction.
        """
        _, vlsm, cfg = metro_man_plan
        assert "ip access-list extended HARDENED-INTERVLAN-ACL" in cfg
        # Remote_Branch_Office is VLAN 130 in metro_man.json
        assert "interface Vlan130" in cfg
        lines = [l.strip() for l in cfg.splitlines()]
        svi_idx = lines.index("interface Vlan130")
        svi_block = lines[svi_idx:svi_idx + 6]
        assert "ip access-group HARDENED-INTERVLAN-ACL in" in svi_block

        # Check deny rule exists for 172.16.0.0/12
        assert any("deny ip" in l and "172.16.0.0 0.15.255.255" in l for l in lines)

    # -------------------------------------------------------------------------
    # Comprehensive Regression Tests: VLAN 99 Management & VLAN 999 Blackhole
    # -------------------------------------------------------------------------
    def test_vlan_99_management_svi_on_core(self, campus_plan, metro_man_plan, global_wan_plan):
        """
        Verify VLAN 99 management SVI exists on Core switch with 10.255.99.1/24,
        and Access switch has 10.255.99.10/24 with matching ip default-gateway 10.255.99.1.
        """
        for plan in [campus_plan, metro_man_plan, global_wan_plan]:
            _, _, cfg = plan
            lines = [l.strip() for l in cfg.splitlines()]

            # Core switch management SVI
            assert "interface Vlan99" in lines
            vlan99_indices = [i for i, l in enumerate(lines) if l == "interface Vlan99"]
            assert len(vlan99_indices) >= 2, "Both Core and Access switches must have interface Vlan99"

            core_svi_lines = lines[vlan99_indices[0]:vlan99_indices[0] + 5]
            assert "ip address 10.255.99.1 255.255.255.0" in core_svi_lines

            access_svi_lines = lines[vlan99_indices[1]:vlan99_indices[1] + 5]
            assert "ip address 10.255.99.10 255.255.255.0" in access_svi_lines

            assert "ip default-gateway 10.255.99.1" in lines

    def test_vlan_99_allowed_on_trunk_and_vlan_999_native(self, campus_plan):
        """
        Verify VLAN 99 is permitted on trunks, VLAN 999 is set as native blackhole,
        and VLAN 999 is explicitly NOT in the trunk allowed list.
        """
        _, _, cfg = campus_plan
        lines = [l.strip() for l in cfg.splitlines()]

        # Check VLAN database definitions
        assert "vlan 99" in lines
        assert "vlan 999" in lines

        # Check trunk ports
        trunk_allowed_lines = [l for l in lines if l.startswith("switchport trunk allowed vlan")]
        trunk_native_lines = [l for l in lines if l.startswith("switchport trunk native vlan")]

        assert len(trunk_allowed_lines) >= 2
        assert len(trunk_native_lines) >= 2

        for l in trunk_native_lines:
            assert "999" in l, f"Native VLAN must be 999, got: {l}"

        for l in trunk_allowed_lines:
            # Management VLAN 99 must be allowed
            assert "99" in l.split()[-1].split(","), f"VLAN 99 must be allowed on trunk: {l}"
            # Native blackhole VLAN 999 must NOT be allowed
            assert "999" not in l.split()[-1].split(","), f"VLAN 999 must not be allowed on trunk: {l}"

    def test_no_voice_vlan_assigned_to_management(self, campus_plan, metro_man_plan, global_wan_plan):
        """Verify switchport voice vlan 99 is never configured without an explicit voice VLAN."""
        for plan in [campus_plan, metro_man_plan, global_wan_plan]:
            _, _, cfg = plan
            active_lines = [l.strip() for l in cfg.splitlines() if not l.strip().startswith("!")]
            assert not any("voice vlan 99" in l for l in active_lines)
            assert not any("access vlan 99" in l for l in active_lines)
            assert not any("access vlan 999" in l for l in active_lines)

    # -------------------------------------------------------------------------
    # Comprehensive Regression Tests: Access Ports & Hardware Compatibility
    # -------------------------------------------------------------------------
    def test_access_ports_distributed_across_vlans(self, campus_plan):
        """
        Verify access ports FastEthernet0/1-24 are partitioned across multiple distinct data VLANs,
        not dumped entirely into a single VLAN.
        """
        _, vlsm, cfg = campus_plan
        lines = [l.strip() for l in cfg.splitlines()]

        access_vlan_lines = [l for l in lines if l.startswith("switchport access vlan")]
        configured_vlans = {l.split()[-1] for l in access_vlan_lines}

        # Campus LAN has VLANs 10, 20, 30, 40, 50
        data_vlans = {str(a.vlan_id) for a in vlsm.allocations if a.vlan_id}
        assert configured_vlans == data_vlans, f"Access ports must cover all data VLANs. Expected {data_vlans}, got {configured_vlans}"
        assert len(configured_vlans) > 1, "Access ports must be distributed across multiple VLANs"

    def test_catalyst_3650_trunk_encapsulation_unsupported(self, campus_plan, metro_man_plan, global_wan_plan):
        """
        Verify that 'switchport trunk encapsulation dot1q' is omitted from the Catalyst 3650 Core switch,
        where 802.1Q is native and the command is rejected by Cisco IOS-XE.
        """
        for plan in [campus_plan, metro_man_plan, global_wan_plan]:
            _, _, cfg = plan
            active_lines = [l.strip() for l in cfg.splitlines() if not l.strip().startswith("!")]
            assert "switchport trunk encapsulation dot1q" not in active_lines

    # -------------------------------------------------------------------------
    # Comprehensive Regression Tests: Routing & Transit Links
    # -------------------------------------------------------------------------
    def test_transit_link_ip_and_ospf_consistency(self, campus_plan, metro_man_plan, global_wan_plan):
        """
        Verify Core switch routed port (Gi1/0/24) and Edge Router LAN port (Gi0/0/0)
        share the exact 10.255.255.0/30 subnet and matching OSPF network statements.
        """
        for plan in [campus_plan, metro_man_plan, global_wan_plan]:
            _, _, cfg = plan
            lines = [l.strip() for l in cfg.splitlines()]

            # Core Switch Gi1/0/24
            assert "interface GigabitEthernet1/0/24" in lines
            core_idx = lines.index("interface GigabitEthernet1/0/24")
            core_block = lines[core_idx:core_idx + 7]
            assert "ip address 10.255.255.2 255.255.255.252" in core_block
            assert "ip ospf network point-to-point" in core_block

            # Edge Router Gi0/0/0
            assert "interface GigabitEthernet0/0/0" in lines
            rtr_idx = lines.index("interface GigabitEthernet0/0/0")
            rtr_block = lines[rtr_idx:rtr_idx + 7]
            assert "ip address 10.255.255.1 255.255.255.252" in rtr_block
            assert "ip ospf network point-to-point" in rtr_block

            # OSPF statement on both
            ospf_transit_line = "network 10.255.255.0 0.0.0.3 area 0"
            count = cfg.count(ospf_transit_line)
            assert count >= 2, f"Transit subnet must be advertised on both Core Switch and Edge Router, found {count}"

    def test_all_three_presets_internally_consistent(self, campus_plan, metro_man_plan, global_wan_plan):
        """Verify all three preset profiles produce valid, complete, and robust 3-device configurations."""
        plans = [campus_plan, metro_man_plan, global_wan_plan]
        for spec, vlsm, cfg in plans:
            assert "DEVICE 1 OF 3: CORE / MULTILAYER DISTRIBUTION SWITCH" in cfg
            assert "DEVICE 2 OF 3: ACCESS LAYER EDGE SWITCH" in cfg
            assert "DEVICE 3 OF 3: ENTERPRISE WAN EDGE ROUTER" in cfg
            assert "ip access-list extended HARDENED-INTERVLAN-ACL" in cfg
            assert "interface Vlan99" in cfg
            assert "vlan 999" in cfg
            assert "switchport trunk native vlan 999" in cfg
            assert "ip ssh version 2" in cfg
            assert "ip routing" in cfg
