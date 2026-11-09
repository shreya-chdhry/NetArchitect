"""
Physical Media Selection Engine (L1/Physical Layer)
Course Code: CIC-307 Computer Networks Mini-Project

Selects physical transmission media and optical/copper transceivers based on link
distance, bandwidth physics, and IEEE 802.3 standards.
"""

from dataclasses import dataclass
from typing import Optional, Dict, Any


class PhysicalDistanceViolationError(Exception):
    """
    Raised when copper (Cat6a / twisted-pair) cabling is requested or configured
    for a transmission link exceeding the 100-metre physical channel limit.
    """
    def __init__(self, distance_meters: float, medium: str = "Copper (Cat6a)"):
        self.distance = distance_meters
        self.medium = medium
        message = (
            f"PhysicalDistanceViolationError: {medium} requested for link distance of "
            f"{distance_meters}m. Copper Ethernet channel limit is strictly 100m (IEEE 802.3an). "
            f"High-frequency signal attenuation, insertion loss, and near-end crosstalk (NEXT) "
            f"prevent reliable 10Gbps transmission beyond 100 meters."
        )
        super().__init__(message)


@dataclass
class MediaRecommendation:
    medium: str
    standard: str
    transceiver: str
    wavelength: Optional[str]
    max_reach: str
    justification: str
    engineering_note: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "medium": self.medium,
            "standard": self.standard,
            "transceiver": self.transceiver,
            "wavelength": self.wavelength,
            "max_reach": self.max_reach,
            "justification": self.justification,
            "engineering_note": self.engineering_note
        }


class PhysicalMediaEngine:
    """
    Selects optimal layer 1 transmission media and validates distance boundaries.
    
    Assignment Distance Thresholds:
    - 0 to 100 metres: Cat6a / 10GBASE-T
    - 101 to 400 metres: OM4 Multimode Fiber (MMF) / 10GBASE-SR
    - Above 400 metres: OS2 Single-Mode Fiber (SMF) / 10GBASE-LR or 10GBASE-ER
    """

    COPPER_MAX_DISTANCE = 100.0   # metres (IEEE 802.3an limit)
    OM4_MAX_DISTANCE = 400.0      # metres (Assignment MMF threshold)
    LR_MAX_DISTANCE = 10000.0     # 10 km (10GBASE-LR threshold)
    ER_MAX_DISTANCE = 40000.0     # 40 km (10GBASE-ER threshold)

    @classmethod
    def evaluate_link(cls, distance_meters: float, requested_medium: Optional[str] = None) -> MediaRecommendation:
        """
        Evaluates link distance and returns an engineering-grade media recommendation.
        
        Args:
            distance_meters: Link length in metres.
            requested_medium: Optional explicit medium choice for validation.
            
        Raises:
            ValueError: If distance is negative.
            PhysicalDistanceViolationError: If copper is requested for distance > 100m.
        """
        if distance_meters < 0:
            raise ValueError(f"Link distance cannot be negative. Received: {distance_meters}m")

        # Check explicit requested medium violation
        if requested_medium:
            norm_med = requested_medium.lower()
            if any(term in norm_med for term in ["copper", "cat6", "cat6a", "twisted", "rj45", "10gbase-t"]):
                if distance_meters > cls.COPPER_MAX_DISTANCE:
                    raise PhysicalDistanceViolationError(distance_meters, requested_medium)

        # 0 to 100m: Copper Cat6a (10GBASE-T)
        if distance_meters <= cls.COPPER_MAX_DISTANCE:
            return MediaRecommendation(
                medium="Cat6a Shielded Twisted Pair (F/UTP or S/FTP)",
                standard="10GBASE-T (IEEE 802.3an)",
                transceiver="Integrated RJ-45 10GbE PHY / SFP-10G-T",
                wavelength=None,
                max_reach="100m channel (90m horizontal + 10m patch cords)",
                justification=(
                    f"At a distance of {distance_meters}m (<= 100m limit), Cat6a copper cabling satisfies "
                    f"the IEEE 802.3an 10GBASE-T channel specification. Cat6a supports 500 MHz bandwidth "
                    f"with internal shielding to mitigate alien crosstalk (ANEXT). It eliminates the cost "
                    f"of optical SFP+ transceivers and is ideal for horizontal workstation and server access runs."
                ),
                engineering_note=(
                    "Universal Engineering Distinction: Cat6a channel length is strictly bounded at 100m "
                    "by signal propagation delay and attenuation. Exceeding 100m results in bit errors "
                    "and link negotiation fallback to 1Gbps or link failure."
                )
            )

        # 101 to 400m: OM4 Multimode Fiber (10GBASE-SR)
        elif distance_meters <= cls.OM4_MAX_DISTANCE:
            return MediaRecommendation(
                medium="OM4 Laser-Optimized Multimode Fiber (50/125 µm core)",
                standard="10GBASE-SR (IEEE 802.3ae)",
                transceiver="SFP-10G-SR (Short Reach)",
                wavelength="850 nm VCSEL (Vertical-Cavity Surface-Emitting Laser)",
                max_reach="400m (Assignment threshold; standard IEEE reach is 400m on OM4)",
                justification=(
                    f"Link distance of {distance_meters}m exceeds the 100m copper channel limit but falls "
                    f"within the assignment's specified OM4 multimode selection boundary of 400m. "
                    f"OM4 MMF provides an effective modal bandwidth (EMB) of 4700 MHz·km at 850nm. "
                    f"This provides low dispersion and high link reliability for campus inter-building "
                    f"backbones while keeping optical transceiver component costs significantly lower than single-mode optics."
                ),
                engineering_note=(
                    "Universal Engineering Distinction: The 400m threshold represents the assignment's rule. "
                    "In production enterprise engineering, IEEE 802.3ae guarantees 10GBASE-SR up to 300m on OM3 "
                    "and 400m on high-grade OM4 with low-loss optical connectors (<1.0 dB total connector loss). "
                    "Beyond 400m, differential modal dispersion (DMD) causes pulse spreading and bit-error-rate (BER) collapse."
                )
            )

        # Above 400m: OS2 Single-Mode Fiber (10GBASE-LR or 10GBASE-ER)
        else:
            if distance_meters <= cls.LR_MAX_DISTANCE:
                standard = "10GBASE-LR (IEEE 802.3ae)"
                transceiver = "SFP-10G-LR (Long Reach)"
                wavelength = "1310 nm DFB Laser"
                max_reach = "10 km (10,000 m)"
                detail = "utilizing a Fabry-Pérot or DFB laser at 1310nm for metropolitan campus / inter-facility links"
            elif distance_meters <= cls.ER_MAX_DISTANCE:
                standard = "10GBASE-ER (IEEE 802.3ae)"
                transceiver = "SFP-10G-ER (Extended Reach)"
                wavelength = "1550 nm Cooled EML Laser"
                max_reach = "40 km (40,000 m)"
                detail = "utilizing a 1550nm cooled electro-absorption modulated laser (EML) for long-span MAN/WAN links"
            else:
                standard = "10GBASE-ZR / DWDM (ITU-T G.698.1)"
                transceiver = "SFP-10G-ZR / Tunable DWDM"
                wavelength = "1550 nm DWDM C-Band"
                max_reach = "80 km+ with optical amplification"
                detail = "utilizing dense wavelength division multiplexing (DWDM) and Erbium-Doped Fiber Amplifiers (EDFA)"

            dist_km = distance_meters / 1000.0
            return MediaRecommendation(
                medium="OS2 Single-Mode Fiber (9/125 µm core)",
                standard=standard,
                transceiver=transceiver,
                wavelength=wavelength,
                max_reach=max_reach,
                justification=(
                    f"Link distance of {distance_meters}m ({dist_km:.2f} km) exceeds the 400m multimode limit. "
                    f"Selected OS2 Single-Mode Fiber because its microscopic 9 µm core permits only a single "
                    f"transverse light mode, completely eliminating modal dispersion. "
                    f"Paired with {transceiver} ({standard}) {detail}, ensuring robust signal integrity and "
                    f"meeting strict optical link loss budget requirements."
                ),
                engineering_note=(
                    "Universal Engineering Distinction: OS2 SMF attenuation is exceptionally low "
                    "(~0.35 dB/km at 1310nm, ~0.22 dB/km at 1550nm). Transceiver selection is governed by "
                    "optical power budget: Transmit Power (dBm) - Receiver Sensitivity (dBm) >= Total Channel Loss (dB) + Safety Margin."
                )
            )
