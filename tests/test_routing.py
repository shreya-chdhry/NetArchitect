"""
Unit Tests for L3 Routing Protocol Decision Engine
Course Code: CIC-307 Computer Networks Mini-Project

Covers:
- Single-Area OSPF recommendation for single AS < 50 subnets
- Multi-Area OSPF recommendation for multi-site enterprise / Metro MAN
- eBGP recommendation for multi-AS / Cloud VPC boundaries
- RFC citations (RFC 2328, RFC 4271) and SPF Dijkstra justifications
- Route summarization supernet calculation
"""

import pytest
from src.vlsm import VLSMAllocator
from src.routing_engine import RoutingDecisionEngine, compute_supernet


class TestRoutingDecisionEngine:
    """Test suite for routing protocol selection and route summarization."""

    @pytest.fixture
    def sample_allocations(self):
        subnets = [
            {"name": "Subnet_1", "hosts": 100},
            {"name": "Subnet_2", "hosts": 50},
            {"name": "Subnet_3", "hosts": 20}
        ]
        res = VLSMAllocator.allocate("10.0.0.0/24", subnets)
        return res.allocations

    def test_single_area_ospf_for_campus_lan(self, sample_allocations):
        """Verify Single-Area OSPF (Area 0) is recommended for single-AS campus with < 50 subnets."""
        rec = RoutingDecisionEngine.evaluate(
            subnet_count=len(sample_allocations),
            num_sites=1,
            has_external_as=False,
            has_cloud_vpc=False,
            allocations=sample_allocations,
            network_type="campus_lan"
        )
        assert "Single-Area OSPFv2" in rec.primary_igp
        assert "Area 0" in rec.primary_igp_area_design
        assert rec.egp_protocol is None
        assert "RFC 2328" in rec.rfc_references[0]
        assert "fast convergence" in rec.justification.lower() or "link-state" in rec.justification.lower()

    def test_multi_area_ospf_for_metro_man(self, sample_allocations):
        """Verify Multi-Area OSPF is recommended for multi-site enterprise (Metro MAN)."""
        rec = RoutingDecisionEngine.evaluate(
            subnet_count=len(sample_allocations),
            num_sites=3,
            has_external_as=False,
            has_cloud_vpc=False,
            allocations=sample_allocations,
            network_type="metro_man"
        )
        assert "Multi-Area OSPFv2" in rec.primary_igp
        assert "Area 0" in rec.primary_igp_area_design
        assert "ABR" in rec.justification or "Type 3" in rec.justification or "LSA" in rec.justification
        assert len(rec.summaries) > 0

    def test_ebgp_recommendation_for_cloud_vpc_boundary(self, sample_allocations):
        """Verify eBGP is recommended when connecting to an external Cloud VPC / AS."""
        rec = RoutingDecisionEngine.evaluate(
            subnet_count=len(sample_allocations),
            num_sites=4,
            has_external_as=True,
            has_cloud_vpc=True,
            allocations=sample_allocations,
            network_type="global_wan",
            local_as=65001,
            peer_as=64512
        )
        assert "eBGP" in rec.egp_protocol
        assert rec.local_as == 65001
        assert rec.peer_as == 64512
        assert any("RFC 4271" in rfc for rfc in rec.rfc_references)
        assert "neighbor" in "".join(rec.cisco_routing_commands)
        assert "remote-as" in "".join(rec.cisco_routing_commands)

    def test_route_summarization_calculation(self, sample_allocations):
        """Verify supernet calculation summarizes multiple contiguous subnets into a single CIDR block."""
        summary = compute_supernet(sample_allocations, area_label="Area 1")
        assert summary is not None
        assert summary.area_or_domain == "Area 1"
        assert "/" in summary.summary_cidr
        assert "summarized into 1 aggregate route" in summary.reduction_ratio

    def test_cisco_routing_commands_syntax(self, sample_allocations):
        """Verify generated Cisco commands contain router ospf, router-id, and passive-interface."""
        rec = RoutingDecisionEngine.evaluate(
            subnet_count=len(sample_allocations),
            num_sites=1,
            has_external_as=False,
            has_cloud_vpc=False,
            allocations=sample_allocations,
            network_type="campus_lan"
        )
        joined = "\n".join(rec.cisco_routing_commands)
        assert "router ospf 1" in joined
        assert "router-id 1.1.1.1" in joined
        assert "passive-interface default" in joined
        assert "network 10.0.0.0" in joined
