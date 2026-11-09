"""
Unit Tests for Physical Media Selection Engine (L1)
Course Code: CIC-307 Computer Networks Mini-Project

Covers:
- Cat6a selection at exactly 100m boundary
- OM4 MMF selection at 101m and 400m
- OS2 SMF selection above 400m and long-haul distances
- PhysicalDistanceViolationError on copper > 100m
- Negative distance validation error
- Transceiver and optical budget verification
"""

import pytest
from src.media_engine import (
    PhysicalMediaEngine,
    PhysicalDistanceViolationError,
    MediaRecommendation
)


class TestPhysicalMediaEngine:
    """Test suite covering physical media selection rules and distance boundaries."""

    def test_cat6a_selection_at_100m_boundary(self):
        """Verify Cat6a (10GBASE-T) is recommended for exactly 100m (copper boundary limit)."""
        rec = PhysicalMediaEngine.evaluate_link(100.0)
        assert isinstance(rec, MediaRecommendation)
        assert "Cat6a" in rec.medium
        assert "10GBASE-T" in rec.standard
        assert "802.3an" in rec.standard or "802.3an" in rec.justification
        assert rec.wavelength is None

    def test_cat6a_selection_under_100m(self):
        """Verify Cat6a selection for standard access distances (e.g. 45m)."""
        rec = PhysicalMediaEngine.evaluate_link(45.0)
        assert "Cat6a" in rec.medium
        assert "10GBASE-T" in rec.standard

    def test_om4_selection_at_101m_boundary(self):
        """Verify OM4 Multimode Fiber (10GBASE-SR) is selected at 101m."""
        rec = PhysicalMediaEngine.evaluate_link(101.0)
        assert "OM4" in rec.medium
        assert "10GBASE-SR" in rec.standard
        assert "SFP-10G-SR" in rec.transceiver
        assert "850 nm" in rec.wavelength
        assert "modal dispersion" in rec.justification or "effective modal bandwidth" in rec.justification

    def test_om4_selection_at_400m_boundary(self):
        """Verify OM4 Multimode Fiber is selected at the upper 400m threshold."""
        rec = PhysicalMediaEngine.evaluate_link(400.0)
        assert "OM4" in rec.medium
        assert "10GBASE-SR" in rec.standard

    def test_os2_selection_above_400m(self):
        """Verify OS2 Single-Mode Fiber is selected at 401m (10GBASE-LR)."""
        rec = PhysicalMediaEngine.evaluate_link(401.0)
        assert "OS2" in rec.medium
        assert "10GBASE-LR" in rec.standard
        assert "1310 nm" in rec.wavelength
        assert "SFP-10G-LR" in rec.transceiver
        assert "modal dispersion" in rec.justification

    def test_os2_selection_metro_distance_er(self):
        """Verify OS2 Single-Mode Fiber with 10GBASE-ER for 25km metro span."""
        rec = PhysicalMediaEngine.evaluate_link(25000.0)
        assert "OS2" in rec.medium
        assert "10GBASE-ER" in rec.standard
        assert "1550 nm" in rec.wavelength
        assert "SFP-10G-ER" in rec.transceiver

    def test_os2_selection_long_haul_zr(self):
        """Verify OS2 SMF with DWDM/10GBASE-ZR for ultra-long distance (>40km)."""
        rec = PhysicalMediaEngine.evaluate_link(60000.0)
        assert "OS2" in rec.medium
        assert "ZR" in rec.standard or "DWDM" in rec.standard

    def test_copper_request_above_100m_raises_physical_violation(self):
        """Verify requesting copper for > 100m raises PhysicalDistanceViolationError."""
        with pytest.raises(PhysicalDistanceViolationError) as exc_info:
            PhysicalMediaEngine.evaluate_link(105.0, requested_medium="Cat6a UTP Copper")
        
        err_msg = str(exc_info.value)
        assert "PhysicalDistanceViolationError" in err_msg or "100m" in err_msg
        assert "105" in err_msg

    def test_copper_request_at_100m_succeeds(self):
        """Verify requesting copper at <= 100m does not raise violation."""
        rec = PhysicalMediaEngine.evaluate_link(100.0, requested_medium="Cat6a")
        assert "Cat6a" in rec.medium

    def test_negative_distance_raises_value_error(self):
        """Verify negative link distances raise ValueError."""
        with pytest.raises(ValueError) as exc_info:
            PhysicalMediaEngine.evaluate_link(-15.0)
        assert "negative" in str(exc_info.value).lower()

    def test_zero_distance_valid(self):
        """Verify 0m (same-rack connection) is handled cleanly as Cat6a copper."""
        rec = PhysicalMediaEngine.evaluate_link(0.0)
        assert "Cat6a" in rec.medium
