"""
NetArchitect: Recommendation & Config Engine
Main CLI Entrypoint & Scenario Selector
Course Code: CIC-307 Computer Networks Mini-Project
"""

import sys
import os
import argparse
from typing import Optional

# Ensure UTF-8 output encoding on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Ensure workspace root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.input_handler import (
    InputHandler,
    NetworkSpecification,
    ValidationError,
    NegativeDistanceError,
    InvalidHostCountError
)
from src.media_engine import (
    PhysicalMediaEngine,
    MediaRecommendation,
    PhysicalDistanceViolationError
)
from src.vlsm import (
    VLSMAllocator,
    VLSMResult,
    InvalidCIDRError,
    AddressSpaceExhaustionError,
    SubnetOverlapError
)
from src.routing_engine import RoutingDecisionEngine, RoutingRecommendation
from src.topology import TopologyRecommendationEngine, TopologyRecommendation
from src.explainer import ArchitectureExplainer
from src.config_generator import CiscoConfigGenerator


def print_banner():
    banner = r"""
========================================================================================
   _   _      _      _             _     _ _            _   
  | \ | | ___| |_   / \   _ __ ___| |__ (_) |_ ___  ___| |_ 
  |  \| |/ _ \ __| / _ \ | '__/ __| '_ \| | __/ _ \/ __| __|
  | |\  |  __/ |_ / ___ \| | | (__| | | | | ||  __/ (__| |_ 
  |_| \_|\___|\__/_/   \_\_|  \___|_| |_|_|\__\___|\___|\__|
                                                            
       Network Architecture Recommendation & Cisco Config Engine
       Course Code: CIC-307 • Computer Networks Mini-Project
========================================================================================
"""
    print(banner)


def format_table_row(cols, widths):
    formatted = []
    for c, w in zip(cols, widths):
        formatted.append(str(c).ljust(w)[:w])
    return " | ".join(formatted)


def display_results(
    spec: NetworkSpecification,
    media: MediaRecommendation,
    vlsm: VLSMResult,
    routing: RoutingRecommendation,
    topology: TopologyRecommendation,
    export_path: str
):
    print("\n" + "=" * 95)
    print(f" [*] ARCHITECTURAL RECOMMENDATION REPORT: {spec.network_name.upper()}")
    print("=" * 95)
    print(f"  * Network Classification : {spec.network_type.upper()}")
    print(f"  * Physical Sites / Nodes : {spec.num_sites} Site(s) | {spec.total_endpoints:,} Total Endpoints")
    print(f"  * Backbone Link Span     : {spec.link_distance_meters:,.1f} metres ({spec.link_distance_meters/1000.0:.2f} km)")
    print(f"  * Root Network Allocated : {vlsm.root_network}/{vlsm.root_prefix} ({vlsm.root_capacity:,} total addresses)")
    print("-" * 95)

    # 1. Physical Media
    print("\n[1] PHYSICAL LAYER (L1) MEDIA RECOMMENDATION")
    print("---------------------------------------------------------------------------------------")
    print(f"  Recommended Medium : {media.medium}")
    print(f"  IEEE Standard      : {media.standard}")
    print(f"  Transceiver Optics : {media.transceiver}")
    print(f"  Operating Optics   : {media.wavelength or 'Electrical (Baseband PAM-16)'}")
    print(f"  Maximum Reach      : {media.max_reach}")
    print(f"\n  Engineering Justification:\n  {media.justification}")
    print(f"\n  Universal Engineering Boundary Note:\n  {media.engineering_note}")

    # 2. Topology
    print("\n[2] TOPOLOGY & RESILIENCY DESIGN")
    print("---------------------------------------------------------------------------------------")
    print(f"  Recommended Model   : {topology.topology_name}")
    print(f"  Enterprise Pattern  : {topology.architecture_model}")
    print(f"  Redundancy Scheme   : {topology.redundancy_model}")
    print(f"  Spanning Tree Mode  : {topology.spanning_tree_mode}")
    print(f"\n  Topology Rationale:\n  {topology.justification}")
    print("\n  Resiliency & Hardening Mechanisms:")
    for feat in topology.resiliency_features:
        print(f"   [+] {feat}")

    # 3. VLSM Subnet Table
    print("\n[3] VARIABLE LENGTH SUBNET MASK (VLSM) BITWISE ALLOCATION (RFC 4632)")
    print("---------------------------------------------------------------------------------------")
    print(f"  Root Address Space   : {vlsm.root_network}/{vlsm.root_prefix}")
    print(f"  Total Requested Hosts: {vlsm.total_requested_hosts:,} endpoints")
    print(f"  Total Allocated IPs  : {vlsm.total_allocated_addresses:,} addresses")
    print(f"  Subnet Packing Eff.  : {vlsm.subnet_efficiency_pct:.1f}%")
    print(f"  Root Space Utilized  : {vlsm.root_utilization_pct:.1f}% ({vlsm.remaining_unallocated_addresses:,} addresses unallocated)")
    print("")

    headers = ["Subnet Name", "VLAN", "Req", "Prefix", "Network Address", "Subnet Mask", "Gateway (SVI)", "Assignable", "Eff%"]
    widths  = [22, 5, 5, 7, 16, 16, 16, 11, 5]

    header_line = format_table_row(headers, widths)
    print(header_line)
    print("-" * len(header_line))

    for alloc in vlsm.allocations:
        row = [
            alloc.name,
            str(alloc.vlan_id) if alloc.vlan_id else "-",
            str(alloc.requested_hosts),
            f"/{alloc.prefix}",
            alloc.network_address,
            alloc.subnet_mask,
            alloc.gateway_ip,
            str(alloc.assignable_endpoints),
            f"{alloc.efficiency_pct:.0f}%"
        ]
        print(format_table_row(row, widths))
    print("-" * len(header_line))
    print("  * VLSM Sizing Policy & Gateway Reservation:")
    print("    - Total Usable IPs per block = 2^h - 2 (Network ID and Directed Broadcast reserved).")
    print("    - Default Gateway (Network + 1) is reserved for Switch SVI / Router interface.")
    print("    - 'Assignable' column strictly reports end-user host capacity = 2^h - 3.")

    # 4. Routing Architecture
    print("\n[4] LAYER 3 ROUTING PROTOCOL & SUMMARIZATION (RFC 2328 / RFC 4271)")
    print("---------------------------------------------------------------------------------------")
    print(f"  Interior IGP Protocol : {routing.primary_igp}")
    print(f"  OSPF Area Hierarchy   : {routing.primary_igp_area_design}")
    print(f"  Exterior Peering EGP  : {routing.egp_protocol or 'None (Internal Autonomous System)'}")
    if routing.local_as:
        print(f"  Autonomous System (AS): Local AS {routing.local_as}" + (f" | Peer AS {routing.peer_as}" if routing.peer_as else ""))
    print(f"\n  Routing Engineering Justification:\n  {routing.justification}")
    
    if routing.summaries:
        print("\n  Calculated Route Summarization Supernets:")
        for s in routing.summaries:
            print(f"   [+] {s.area_or_domain}: {s.summary_cidr} (Mask: {s.subnet_mask})")
            print(f"       -> {s.reduction_ratio}")

    # 5. Config Export
    print("\n[5] CISCO IOS CONFIGURATION EXPORT")
    print("---------------------------------------------------------------------------------------")
    print(f"  Target File : {export_path}")
    print(f"  Status      : Successfully generated and written to disk.")
    print("=" * 95)


def run_pipeline(spec_file: str, output_cfg_file: str) -> bool:
    """Runs the full NetArchitect pipeline on a given specification file."""
    try:
        # Step 1: Input Ingestion & Validation
        spec = InputHandler.load_from_file(spec_file)

        # Step 2: L1 Physical Media Selection
        media = PhysicalMediaEngine.evaluate_link(
            distance_meters=spec.link_distance_meters,
            requested_medium=spec.requested_medium
        )

        # Step 3: L3 VLSM Bitwise Allocation
        vlsm = VLSMAllocator.allocate(
            root_cidr=spec.root_cidr,
            subnets_req=spec.subnets,
            reserve_gateway=True
        )

        # Step 4: L3 Routing Decision Engine
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

        # Step 5: Topology Recommendation Engine
        topology = TopologyRecommendationEngine.evaluate(
            network_type=spec.network_type,
            num_sites=spec.num_sites,
            endpoints=spec.total_endpoints,
            requires_high_availability=spec.redundancy_required
        )

        # Step 6: Explainable Decision Engine
        explainer_report = ArchitectureExplainer.generate_full_report(
            spec=spec,
            media=media,
            vlsm=vlsm,
            routing=routing,
            topology=topology
        )

        # Step 7: Cisco IOS Configuration Exporter
        cisco_cfg = CiscoConfigGenerator.generate_config(
            spec=spec,
            media=media,
            vlsm=vlsm,
            routing=routing,
            topology=topology
        )

        # Ensure exports directory exists
        os.makedirs(os.path.dirname(os.path.abspath(output_cfg_file)), exist_ok=True)
        with open(output_cfg_file, "w", encoding="utf-8") as f:
            f.write(cisco_cfg)

        # Display full report in CLI
        display_results(spec, media, vlsm, routing, topology, output_cfg_file)
        return True

    except PhysicalDistanceViolationError as e:
        print(f"\n[!] PHYSICAL BOUNDARY ERROR: {e}")
        return False
    except AddressSpaceExhaustionError as e:
        print(f"\n[!] ADDRESS EXHAUSTION ERROR: {e}")
        return False
    except SubnetOverlapError as e:
        print(f"\n[!] SUBNET OVERLAP ERROR: {e}")
        return False
    except InvalidCIDRError as e:
        print(f"\n[!] INVALID CIDR PREFIX ERROR: {e}")
        return False
    except (ValidationError, NegativeDistanceError, InvalidHostCountError) as e:
        print(f"\n[!] INPUT VALIDATION ERROR: {e}")
        return False
    except Exception as e:
        print(f"\n[!] UNEXPECTED ENGINE ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False


def handle_custom_scenario(base_dir: str):
    """Handles custom user input scenario via JSON file or manual input."""
    print("\n--- CUSTOM NETWORK CONFIGURATION ---")
    print("1. Supply path to custom JSON file")
    print("2. Enter parameters interactively")
    print("3. Return to Main Menu")
    choice = input("\nEnter choice [1-3]: ").strip()

    if choice == "1":
        file_path = input("Enter path to custom JSON file: ").strip()
        if not os.path.isabs(file_path):
            file_path = os.path.join(base_dir, file_path)
        cfg_out = os.path.join(base_dir, "exports", "custom_network.cfg")
        run_pipeline(file_path, cfg_out)
    elif choice == "2":
        try:
            print("\nEnter Network Parameters:")
            name = input("  Network Name (e.g. Corporate HQ): ").strip() or "Custom Enterprise"
            net_type = input("  Network Type [campus_lan / metro_man / global_wan]: ").strip() or "campus_lan"
            num_sites = int(input("  Number of Sites / Buildings [e.g. 2]: ").strip() or "2")
            endpoints = int(input("  Total Endpoints [e.g. 500]: ").strip() or "500")
            dist = float(input("  Inter-site / Backbone Link Distance in metres [e.g. 250]: ").strip() or "250")
            root_cidr = input("  Root IPv4 CIDR [e.g. 192.168.0.0/16]: ").strip() or "192.168.0.0/16"
            
            print("  Define Subnets (Enter blank department name when finished):")
            subnets = []
            vlan_counter = 10
            while True:
                s_name = input(f"    Subnet #{len(subnets)+1} Name (or press Enter to finish): ").strip()
                if not s_name:
                    if not subnets:
                        print("    [!] At least one subnet must be defined. Added default 'Operations' (100 hosts).")
                        subnets.append({"name": "Operations", "hosts": 100, "vlan_id": 10})
                    break
                s_hosts = int(input(f"    Number of hosts for '{s_name}': ").strip() or "50")
                subnets.append({"name": s_name, "hosts": s_hosts, "vlan_id": vlan_counter})
                vlan_counter += 10

            custom_data = {
                "network_name": name,
                "network_type": net_type,
                "num_sites": num_sites,
                "total_endpoints": endpoints,
                "link_distance_meters": dist,
                "redundancy_required": True,
                "root_cidr": root_cidr,
                "subnets": subnets
            }

            custom_json_path = os.path.join(base_dir, "presets", "custom_temp.json")
            import json
            with open(custom_json_path, "w", encoding="utf-8") as f:
                json.dump(custom_data, f, indent=2)

            cfg_out = os.path.join(base_dir, "exports", "custom_network.cfg")
            run_pipeline(custom_json_path, cfg_out)

        except Exception as e:
            print(f"\n[!] Error during custom parameter collection: {e}")
    else:
        return


def main():
    parser = argparse.ArgumentParser(description="NetArchitect: Recommendation & Config Engine")
    parser.add_argument("--preset", choices=["campus_lan", "metro_man", "global_wan"], help="Run specific preset directly")
    parser.add_argument("--custom", help="Path to custom JSON file")
    parser.add_argument("--all", action="store_true", help="Execute and export all three presets non-interactively")
    args = parser.parse_args()

    base_dir = os.path.dirname(os.path.abspath(__file__))

    # Non-interactive CLI flags
    if args.all:
        print_banner()
        print("\n[*] Non-interactive batch execution: Generating exports for all 3 presets...\n")
        presets = [
            ("campus_lan.json", "campus_lan.cfg"),
            ("metro_man.json", "metro_man.cfg"),
            ("global_wan.json", "global_wan.cfg")
        ]
        for p_json, p_cfg in presets:
            in_file = os.path.join(base_dir, "presets", p_json)
            out_file = os.path.join(base_dir, "exports", p_cfg)
            print(f"\n>>> Running Preset: {p_json} -> {p_cfg} <<<")
            success = run_pipeline(in_file, out_file)
            if not success:
                sys.exit(1)
        print("\n[✓] All three presets executed and exported successfully.")
        return

    if args.preset:
        print_banner()
        in_file = os.path.join(base_dir, "presets", f"{args.preset}.json")
        out_file = os.path.join(base_dir, "exports", f"{args.preset}.cfg")
        success = run_pipeline(in_file, out_file)
        sys.exit(0 if success else 1)

    if args.custom:
        print_banner()
        out_file = os.path.join(base_dir, "exports", "custom_network.cfg")
        success = run_pipeline(args.custom, out_file)
        sys.exit(0 if success else 1)

    # Interactive Menu
    while True:
        print_banner()
        print("  SELECT NETWORK ARCHITECTURE SCENARIO:")
        print("  1. Campus LAN          (3 Buildings, <400m, Cat6a/OM4, RSTP, Single-Area OSPF)")
        print("  2. Metro MAN           (HQ + 2 Remote, 15-35km, OS2 SMF, EVPL, Sub-5ms QoS)")
        print("  3. Global WAN          (4 Cities + Cloud VPC, OS2, IPsec, eBGP/OSPF Summarization)")
        print("  4. Custom Network      (Load custom JSON or interactive parameter input)")
        print("  5. Exit")
        print("=" * 88)

        choice = input("\nEnter scenario option [1-5]: ").strip()

        if choice == "1":
            in_file = os.path.join(base_dir, "presets", "campus_lan.json")
            out_file = os.path.join(base_dir, "exports", "campus_lan.cfg")
            run_pipeline(in_file, out_file)
            input("\nPress Enter to return to main menu...")
        elif choice == "2":
            in_file = os.path.join(base_dir, "presets", "metro_man.json")
            out_file = os.path.join(base_dir, "exports", "metro_man.cfg")
            run_pipeline(in_file, out_file)
            input("\nPress Enter to return to main menu...")
        elif choice == "3":
            in_file = os.path.join(base_dir, "presets", "global_wan.json")
            out_file = os.path.join(base_dir, "exports", "global_wan.cfg")
            run_pipeline(in_file, out_file)
            input("\nPress Enter to return to main menu...")
        elif choice == "4":
            handle_custom_scenario(base_dir)
            input("\nPress Enter to return to main menu...")
        elif choice == "5":
            print("\nExiting NetArchitect. Goodbye!")
            sys.exit(0)
        else:
            print("\n[!] Invalid selection. Please choose an option between 1 and 5.")


if __name__ == "__main__":
    main()
