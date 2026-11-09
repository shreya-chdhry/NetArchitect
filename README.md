# NetArchitect: Recommendation & Config Engine

**Educational Network Architecture Recommendation & Configuration Prototype**  
**MADE BY**: SHREYA CHAUDHARY 09414802724 • KHUSHI JAIN 06914813124  
**Course Code**: CIC-307 • Computer Networks Mini-Project  
**Evaluation Weight**: 100 Points  
**Technologies**: Python 3.10+, Cisco IOS Software, pytest  

---

## 1. Project Overview & Problem Statement

Designing enterprise computer networks requires synthesizing physical transmission physics (IEEE 802.3 standards), binary subnet allocation boundaries (RFC 4632 CIDR), hierarchical topology models, and dynamic routing architectures (OSPFv2, eBGP). When developing networking configurations or utilizing AI assistance, subtle but catastrophic errors frequently arise:
- Overlapping subnets caused by unsorted allocation orders.
- Default gateway collisions in small blocks (`/30`).
- Permissive switchport trunking allowing unauthorized VLAN leakage.
- Conflating native/blackhole VLANs with management VLANs, or excluding management VLANs from trunk whitelist filters.
- Reversing ACL rule ordering, allowing prohibited IoT-to-corporate ICMP traffic before deny filters.
- Injecting unsupported commands (such as `switchport trunk encapsulation dot1q` on Cisco Catalyst 3650 switches running Cisco IOS-XE).
- Cisco OSPF wildcard mask inversion errors where subnet masks act as overly permissive bitwise filters.
- Signal attenuation and optical dispersion collapse caused by mismatched media selection.

**NetArchitect** is an educational network planning and configuration prototype designed for the CIC-307 Computer Networks Mini-Project. It ingests enterprise network specifications, executes deterministic algorithmic rule engines, computes bitwise VLSM allocations with zero overlap, generates engineering justifications, and exports structured, role-separated Cisco IOS configurations tailored for verified target models in Cisco Packet Tracer or GNS3.

---

## 2. Core Features & Capabilities

- **L1 Physical Media Selection Engine**: Applies assignment distance boundaries:
  - $\le 100\text{m}$: Cat6a Shielded Twisted Pair (10GBASE-T, IEEE 802.3an channel limit).
  - $101 - 400\text{m}$: OM4 Laser-Optimized Multimode Fiber (10GBASE-SR, 850nm VCSEL).
  - $> 400\text{m}$: OS2 Single-Mode Fiber (10GBASE-LR for $\le 10\text{km}$, 10GBASE-ER for $10-40\text{km}$, 10GBASE-ZR for $>40\text{km}$).
  - Raises a custom `PhysicalDistanceViolationError` if copper is requested beyond 100m.
- **L3 Pure Bitwise VLSM Subnet Allocator**:
  - Implemented entirely using Python bitwise operators (`<<`, `>>`, `&`, `|`, `~`).
  - Mandatory descending host-count sorting to eliminate address fragmentation.
  - Power-of-two CIDR boundary alignment: `(current_ip + block_size - 1) & ~(block_size - 1)`.
  - Automatic Default Gateway reservation (`Network + 1`) from the usable address pool.
  - Robust handling of small $/30$ subnets ensuring gateway (`.1`) and endpoint (`.2`) never collide.
  - Explicit reporting of both **total usable IP addresses** ($2^h - 2$, including gateway) and **assignable end-user endpoints** ($2^h - 3$, excluding reserved gateway).
  - Address space exhaustion detection (`AddressSpaceExhaustionError`) and pairwise zero-overlap guarantees.
- **L3 Routing Protocol & Supernet Engine**:
  - Single Autonomous System with $<50$ subnets: Single-Area OSPFv2 (Area 0, fast link-state convergence).
  - Multi-site enterprise (Metro MAN): Multi-Area OSPFv2 to localize LSA flooding.
  - External Autonomous Systems / Cloud VPC (Global WAN): eBGP (RFC 4271) peering + internal OSPF.
  - Automatic calculation of CIDR route summarization supernets for ABR area ranges and BGP aggregates.
- **Topology & Resiliency Engine**:
  - Campus LAN: Three-Tier Hierarchical Star (Core, Distribution, Access) with IEEE 802.1w Rapid-PVST+ and LACP EtherChannel uplinks.
  - Metro MAN: Redundant Dual-Homed Carrier Ethernet EVPL with BFD (sub-50ms fault detection) and DiffServ QoS markings for $<5\text{ms}$ latency SLA.
  - Global WAN: Dual-Hub & Spoke with Partial Mesh IPsec VPN overlay (IKEv2 / AES-256-GCM) to AWS Cloud VPC.
- **Explainable Decision Engine**: Synthesizes natural-language engineering justifications citing IEEE standards (802.3an, 802.3ae, 802.1Q, 802.1w) and RFCs (2328, 4271, 4632).
- **Target-Model Specific, Role-Separated Cisco IOS Configuration Generator**: Generates clean, distinct configuration scripts separated by device role:
  - **Device 1: Core / Multilayer Distribution Switch (Cisco Catalyst 3650-24PS, Cisco IOS-XE)**: SVIs, Rapid-PVST+, Inter-VLAN routing, OSPF, and incoming ACL bindings. Omits unsupported `switchport trunk encapsulation dot1q` to prevent syntax rejection.
  - **Device 2: Access Layer Edge Switch (Cisco Catalyst 2960-24TT, Cisco IOS 15.0)**: Layer 2 VLAN database, trunk uplink (with native VLAN 999 and management VLAN 99 whitelisted), 24 FastEthernet access ports partitioned across all active data VLANs with PortFast and BPDU Guard, and management SVI Vlan99 (`10.255.99.10/24` with `ip default-gateway 10.255.99.1`).
  - **Device 3: Enterprise WAN Edge Router (Cisco ISR 4321, Cisco IOS-XE)**: Interconnect routed link (`10.255.255.1/30` matching Core Switch `10.255.255.2/30`), OSPF point-to-point network, WAN link with clearly documented RFC 5737 lab addresses (`198.51.100.0/24`), eBGP peering, DiffServ QoS, and operational IPsec IKEv2 keyring/profile.
- **Strict Inter-VLAN ACL Security Logic**:
  - Quarantined subnets (IoT, surveillance, guest, branch) enforce strict policy ordering: DHCP and DNS to gateway permitted, ICMP echo permitted strictly to the local default gateway (Network + 1), all traffic to private RFC 1918 corporate networks strictly denied, and broad external permits placed strictly after deny rules.
  - In Metro MAN, the remote branch office subnet is isolated from the sensitive HFT and DR corporate networks.
- **Mandatory AI Code Auditing Log (`documentation/ai_audit_log.md`)**: Detailed technical post-mortems of AI coding hallucinations with packet flow analysis and mathematical proofs.

---

## 3. Technology Stack

- **Programming Language**: Python 3.10+ (Standard Library: `math`, `sys`, `os`, `json`, `argparse`, `dataclasses`)
- **Testing Framework**: `pytest` (46 automated unit tests, 100% pass rate)
- **Validation Library**: Standard Python `ipaddress` used strictly for independent validation in tests
- **Target Network Operating System**: Cisco IOS Software (Release 15.x / IOS-XE 16.x)
- **Target Simulators**: Cisco Packet Tracer 8.x / 9.x, GNS3, EVE-NG

---

## 4. Repository & File Structure

```
mini-project-cn/
├── .gitignore                 # Git ignore rules for Python, caches, and environments
├── main.py                     # Interactive CLI entrypoint & scenario pipeline
├── requirements.txt           # Minimal test dependency (pytest)
├── README.md                  # Complete project documentation & guide
│
├── src/                       # Core Algorithmic Decision Engines
│   ├── __init__.py            # Package initializer
│   ├── input_handler.py       # JSON schema & parameter validation + custom exceptions
│   ├── media_engine.py        # L1 Physical media selection & distance physics
│   ├── vlsm.py                # L3 Bitwise VLSM subnet allocator & boundary alignment
│   ├── routing_engine.py      # L3 Routing protocol decision & CIDR route summarization
│   ├── topology.py            # Network topology design (Hierarchical, Dual-Homed, Mesh)
│   ├── config_generator.py    # Target-model specific, role-separated Cisco IOS .cfg exporter
│   └── explainer.py           # Self-explaining natural language architecture engine
│
├── presets/                   # Predefined Enterprise Scenarios (JSON)
│   ├── campus_lan.json        # Profile 1: Campus LAN (3 bldgs, 1600 endpoints, Cat6a/OM4)
│   ├── metro_man.json         # Profile 2: Metro MAN (HQ + 2 remote, OS2 SMF, EVPL, QoS)
│   └── global_wan.json        # Profile 3: Global WAN (4 cities + Cloud VPC, BGP/OSPF, IPsec)
│
├── exports/                   # Generated Cisco IOS Deployment Configurations (.cfg)
│   ├── campus_lan.cfg         # Generated config for Profile 1 (Role-Separated)
│   ├── metro_man.cfg          # Generated config for Profile 2 (Role-Separated)
│   └── global_wan.cfg         # Generated config for Profile 3 (Role-Separated)
│
├── tests/                     # 46 Automated Unit Tests (pytest)
│   ├── __init__.py
│   ├── test_media.py          # L1 distance thresholds & boundary violation tests
│   ├── test_vlsm.py           # Bitwise VLSM, /30 edge cases, exhaustion, zero-overlap
│   ├── test_routing.py        # Routing protocol decisions & RFC justifications
│   └── test_config_generator.py # Multi-device separation, trunk security, ACL logic, SSH, VLAN 99/999
│
├── documentation/
│   └── ai_audit_log.md        # AI code auditing report (2 concrete bugs, packet analysis)
│
└── screenshots/
    ├── 01_main_cli_menu.png
    ├── 02_vlsm_output_A.png
    ├── 02_vlsm_output_B.png
    ├── 03_pytest_results.png
    ├── 04_campus_topology_cisco_packet_tracer.png
    ├── 05_metro_topology_cisco_packet_tracer.png
    ├── 06_global_wan_topology_cisco_packet_tracer.png
    └── README.md              # 6 Mandatory screenshots & Packet Tracer guide
```

---

## 5. Installation & Execution Guide

### Prerequisites
- Python 3.10 or higher.
- Windows, Linux, or macOS.

### Step 1: Install Dependencies
Install the testing framework:
```bash
pip install -r requirements.txt
```

### Step 2: Run the Interactive CLI Menu
Run the program with one command:
```bash
python main.py
```
Menu options:
```
========================================================================================
   _   _      _      _             _     _ _            _   
  | \ | | ___| |_   / \   _ __ ___| |__ (_) |_ ___  ___| |_ 
  |  \| |/ _ \ __| / _ \ | '__/ __| '_ \| | __/ _ \/ __| __|
  | |\  |  __/ |_ / ___ \| | | (__| | | | | ||  __/ (__| |_ 
  |_| \_|\___|\__/_/   \_\_|  \___|_| |_|_|\__\___|\___|\__|
                                                            
       Network Architecture Recommendation & Cisco Config Engine
       Course Code: CIC-307 • Computer Networks Mini-Project
========================================================================================

  SELECT NETWORK ARCHITECTURE SCENARIO:
  1. Campus LAN          (3 Buildings, <400m, Cat6a/OM4, RSTP, Single-Area OSPF)
  2. Metro MAN           (HQ + 2 Remote, 15-35km, OS2 SMF, EVPL, Sub-5ms QoS)
  3. Global WAN          (4 Cities + Cloud VPC, OS2, IPsec, eBGP/OSPF Summarization)
  4. Custom Network      (Load custom JSON or interactive parameter input)
  5. Exit
========================================================================================
```

### Step 3: Run Specific Presets or Batch Execution
Execute and regenerate all three preset configuration exports non-interactively:
```bash
python main.py --all
```

Run a specific preset directly:
```bash
python main.py --preset campus_lan
python main.py --preset metro_man
python main.py --preset global_wan
```

Run with a custom JSON specification file:
```bash
python main.py --custom path/to/custom_network.json
```

---

## 6. Three Predefined Scenarios & Output Summary

### Profile 1: Campus LAN (`campus_lan.json` $\rightarrow$ `campus_lan.cfg`)
- **Scale**: 3 Buildings on campus, 1,600 endpoints across 5 VLANs.
- **Physical Link**: 250m building backbone $\rightarrow$ OM4 MMF (10GBASE-SR, 850nm VCSEL); Cat6a copper for access runs $\le 100\text{m}$.
- **Root Network**: `10.10.0.0/16`.
- **Subnet Allocations**:
  - `Engineering_Labs`: 600 hosts $\rightarrow$ `10.10.0.0/22` (Mask: `255.255.252.0`, Gateway: `10.10.0.1`, Assignable: 1,021)
  - `Student_WiFi_and_Hostels`: 450 hosts $\rightarrow$ `10.10.4.0/23` (Mask: `255.255.254.0`, Gateway: `10.10.4.1`, Assignable: 509)
  - `Faculty_and_Classrooms`: 350 hosts $\rightarrow$ `10.10.6.0/23` (Mask: `255.255.254.0`, Gateway: `10.10.6.1`, Assignable: 509)
  - `Administration_and_Finance`: 120 hosts $\rightarrow$ `10.10.8.0/25` (Mask: `255.255.255.128`, Gateway: `10.10.8.1`, Assignable: 125)
  - `Campus_IoT_and_Surveillance`: 80 hosts $\rightarrow$ `10.10.8.128/25` (Mask: `255.255.255.128`, Gateway: `10.10.8.129`, Assignable: 125)
- **VLAN & Trunk Security**: VLAN 99 for In-Band Switch Management (`10.255.99.0/24`), VLAN 999 for unused native blackhole (`switchport trunk native vlan 999`), and explicit trunk whitelist `99,10,30,20,40,50`.
- **Access Ports**: FastEthernet0/1-5 (VLAN 10), 0/6-10 (VLAN 30), 0/11-15 (VLAN 20), 0/16-20 (VLAN 40), 0/21-24 (VLAN 50).
- **ACL Policy**: Hardened quarantine ACL applied to SVI Vlan50: permits local gateway ping and DHCP/DNS, strictly denies RFC 1918 corporate networks, permits established outbound return traffic.

### Profile 2: Metro MAN (`metro_man.json` $\rightarrow$ `metro_man.cfg`)
- **Scale**: 1 HQ + 2 Remote Colocation sites, 450 users.
- **Physical Link**: 22 km inter-site link $\rightarrow$ OS2 Single-Mode Fiber (10GBASE-ER, 1550nm cooled EML laser, 40km reach).
- **Interconnect**: Carrier Ethernet EVPL with BFD failover.
- **Root Network**: `172.16.0.0/16`.
- **Subnets**: HFT Colo (200 hosts $\rightarrow$ `/24`), Corporate LAN (140 hosts $\rightarrow$ `/24`), DR Replication (60 hosts $\rightarrow$ `/26`), Remote Branch (35 hosts $\rightarrow$ `/26`), P2P Transit (15 hosts $\rightarrow$ `/27`).
- **Routing**: Multi-Area OSPFv2 with calculated route summarization supernet `172.16.0.0/22`.
- **Security**: Isolation ACL applied to Remote Branch Office SVI (VLAN 130), preventing branch endpoints from directly reaching HFT or DR replication databases.
- **QoS**: DiffServ priority queuing for DSCP EF / CS6 financial trading traffic ($<5\text{ms}$ SLA).

### Profile 3: Global WAN (`global_wan.json` $\rightarrow$ `global_wan.cfg`)
- **Scale**: 4 Global Cities (NYC, London, Tokyo, Singapore) + AWS Cloud VPC, 2000 IoT / scanners.
- **Physical Link**: 55 km link span $\rightarrow$ OS2 Single-Mode Fiber (10GBASE-ZR / DWDM optics).
- **Root Network**: `10.0.0.0/8`.
- **Subnets**: NYC Hub (750 hosts $\rightarrow$ `/22`), London Gateway (500 hosts $\rightarrow$ `/23`), Tokyo Scanners (380 hosts $\rightarrow$ `/23`), Singapore IoT (250 hosts $\rightarrow$ `/24`), Cloud VPC (120 hosts $\rightarrow$ `/25`).
- **Routing**: Hybrid Multi-Area OSPFv2 internal IGP + eBGP (AS 65001 peering with Cloud AS 64512). Route summarization supernet: `10.0.0.0/20`.
- **Overlay**: Operational IPsec VPN Tunnel (`Tunnel100` with IKEv2 keyring, profile, and AES-256-GCM).

---

## 7. Automated Unit Testing

NetArchitect includes **46 automated unit tests** in the `tests/` directory:

Run the test suite:
```bash
python -m pytest -v tests/
```

### Test Coverage Highlights:
- **`tests/test_vlsm.py` (12 tests)**:
  - Descending host sort order verification.
  - Bitwise CIDR boundary alignment.
  - Pairwise zero-overlap verification across all allocated intervals.
  - Address space exhaustion detection.
  - Broadcast address and usable host range calculations.
  - **Regression Test for `/30` Edge Case**: Verifies that when 1 host is requested with `reserve_gateway=True`, the allocated $/30$ block sets Gateway to `Network + 1` and First Usable Endpoint to `Network + 2` without collision.
  - **Boundary Test for 2 Hosts**: Verifies that 2 hosts with gateway reservation requires 3 usable IPs (allocating a $/29$), whereas without gateway reservation it allocates $/30$.
  - Wildcard mask bitwise inversion across `/8`, `/16`, `/24`, `/26`, `/27`, `/29`, `/30`.
  - Independent cross-validation against Python standard library `ipaddress` module.
- **`tests/test_media.py` (11 tests)**:
  - Cat6a boundary at 100m; OM4 MMF at 101m and 400m; OS2 SMF above 400m, 25km, 60km.
  - `PhysicalDistanceViolationError` raised when copper is requested $>100$m.
  - Negative distance validation (`ValueError`).
- **`tests/test_routing.py` (5 tests)**:
  - Single-Area OSPF for single AS $<50$ subnets; Multi-Area OSPF for Metro MAN; eBGP for Cloud VPC.
  - Route summarization supernet calculations.
  - Cisco routing syntax validation.
- **`tests/test_config_generator.py` (18 tests)**:
  - Role-separated configuration headers (Core Switch, Access Switch, Edge Router).
  - Hardened trunk allowed list (forbids `allowed vlan all`).
  - SVI gateway addresses match VLSM allocations.
  - OSPF wildcard masks match bitwise inversions.
  - eBGP and IPsec presence in Global WAN.
  - **ACL Policy Ordering**: Verifies deny rules appear strictly before broad permit rules, and ICMP permit is restricted to the local gateway host.
  - **Metro MAN Branch Isolation**: Verifies isolation rules exist and are bound to the branch SVI.
  - **VLAN 99 / 999 Trunk Security**: Verifies native VLAN 999 is isolated and excluded from trunks, while VLAN 99 is permitted.
  - **Management SVI Consistency**: Verifies Core SVI `10.255.99.1/24`, Access SVI `10.255.99.10/24`, and `ip default-gateway 10.255.99.1`.
  - **No Voice VLAN on Management**: Confirms `switchport voice vlan 99` is absent.
  - **Multi-VLAN Access Port Distribution**: Confirms access ports are partitioned across active data VLANs.
  - **Catalyst 3650 Command Support**: Verifies omission of unsupported `switchport trunk encapsulation dot1q`.
  - **Transit Link Consistency**: Confirms Core Switch Gi1/0/24 and Edge Router Gi0/0/0 share `10.255.255.0/30` and matching OSPF statements.
  - Verification that all 3 exported `.cfg` files exist on disk.

---

## 8. Packet Tracer / GNS3 Verification Guide

*Honest Academic Disclosure: NetArchitect generates configuration files validated at the code level through automated tests. Actual deployment into Cisco Packet Tracer is an interactive manual lab step performed by the student.*

### Step-by-Step Lab Setup in Cisco Packet Tracer:

1. **Open Cisco Packet Tracer** (v8.x or v9.x).
2. **Add Devices to the Workspace**:
   - **Core/Distribution Switch**: Add one **Cisco Catalyst 3650-24PS** Multilayer Switch.
   - **Access Switch**: Add one **Cisco Catalyst 2960-24TT** Layer 2 Switch.
   - **Edge Router**: Add one **Cisco ISR 4321** Integrated Services Router.
   - **Endpoints**: Add 2 PCs (e.g. PC-Engineering on VLAN 10, PC-IoT on VLAN 50).
3. **Cabling**:
   - Connect Core Switch `GigabitEthernet1/0/1` to Access Switch `GigabitEthernet0/1` using a Copper Straight-Through cable (Trunk link).
   - Connect Core Switch `GigabitEthernet1/0/24` to Edge Router `GigabitEthernet0/0/0` (Routed link).
   - Connect PC-Engineering to Access Switch `FastEthernet0/1` (Access port VLAN 10).
   - Connect PC-IoT to Access Switch `FastEthernet0/21` (Access port VLAN 50).
4. **Loading Configurations**:
   - Open `exports/campus_lan.cfg`.
   - Open the **Core Switch CLI**, type `enable` and `configure terminal`, then copy and paste the commands from `DEVICE 1 OF 3`.
   - Open the **Access Switch CLI**, type `enable` and `configure terminal`, then copy and paste the commands from `DEVICE 2 OF 3`.
   - Open the **Edge Router CLI**, type `enable` and `configure terminal`, then copy and paste the commands from `DEVICE 3 OF 3`.
5. **Verification Commands**:
   ```cisco
   ! On Core Switch:
   show ip interface brief          ! Confirm SVIs Vlan10, Vlan20, Vlan99, etc. are Up/Up
   show vlan brief                  ! Confirm VLANs 10, 20, 30, 40, 50, 99, 999 exist
   show interfaces trunk            ! Confirm trunk port allows VLANs 99,10,30,20,40,50 (native 999)
   show ip ospf neighbor            ! Confirm OSPF adjacency with Edge Router on Gi1/0/24
   show ip access-lists             ! View HARDENED-INTERVLAN-ACL hit counters

   ! On Access Switch:
   show interfaces status           ! Confirm FastEthernet0/1-5 in VLAN 10, 0/21-24 in VLAN 50
   show ip interface brief          ! Confirm SVI Vlan99 is 10.255.99.10 Up/Up
   ping 10.255.99.1                 ! Verify ping reachability to Core Switch management gateway

   ! On Edge Router:
   show ip route ospf               ! Confirm OSPF routes to campus VLAN subnets and management SVI
   ```

---

## 9. Assumptions & Limitations

1. **Educational Prototype Status**: This utility is an architectural planning and configuration generation prototype for academic evaluation. In enterprise production, configurations require integration with radius/TACACS+ servers, enterprise PKI certificates, and environment-specific optical loss measurements.
2. **Representative 24-Port Edge Switch**: The generated Access Switch configuration models a single 24-port switch (Catalyst 2960-24TT) to illustrate multi-VLAN port assignments and edge hardening. In full-scale enterprise deployments (450, 1,600, or 2,000 endpoints), multiple 24/48-port switches are stacked (Cisco FlexStack / StackWise) or connected via redundant distribution uplinks.
3. **Documentation WAN Addressing**: WAN link addresses (e.g. `198.51.100.0/24`) use RFC 5737 TEST-NET-2 documentation blocks intended for simulation and lab evaluation, not routable public internet connectivity.
4. **Gateway Reservation Convention**: The first usable host in each subnet (`Network + 1`) is dedicated to the default gateway / SVI. Host endpoint DHCP scopes start at `Network + 2`.
