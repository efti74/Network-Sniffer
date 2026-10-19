# Network Sniffer — Comprehensive Project Documentation

**Project Name:** Network Sniffer  
**Track:** Cyber Security / Network Engineering (CodeAlpha)  
**Language & Framework:** Python 3.10+ / Scapy  
**Primary Module:** [`network_sniffer.py`](file:///c:/Users/sibga/OneDrive/Desktop/CodeAlpha/network_sniffer/network_sniffer.py)

---

## 1. Executive Summary & Objectives

The **Network Sniffer** is a modular, cross-platform network packet inspection utility written in Python using the **Scapy** packet manipulation engine. It passively captures packets transiting a network interface, decodes key protocol headers across multiple layers of the OSI model, inspects application payload content safely, and presents clean, formatted metadata in real time.

### Core Objectives:
1. **Protocol Analysis:** Extract and interpret layer headers: Data Link (Ethernet, ARP), Network (IPv4, IPv6), and Transport (TCP, UDP, ICMP, ICMPv6).
2. **Payload Inspection:** Safely sample application data payloads without storing sensitive packets indefinitely, providing both ASCII string previews and hexadecimal representations.
3. **Operational Flexibility:** Support three distinct execution modes:
   - **Live Capture:** Real-time continuous sniffing of network interfaces.
   - **Offline PCAP Analysis:** Forensic inspection of saved `.pcap` capture files.
   - **Driverless Demo Mode:** Built-in packet synthesizer for immediate evaluation without elevated kernel drivers.
4. **Resilient Design:** Graceful handling of Windows networking quirks (Npcap vs. native WinSock L3 limitations), keyboard interrupts (Ctrl+C), and flexible interface resolution by friendly name or numeric adapter index.

---

## 2. Architecture & Design

### 2.1 OSI Layer Decomposition

The sniffer processes incoming data frames by inspecting layer structures sequentially:

```
+-------------------------------------------------------------------+
| Layer 2: Data Link Layer (Ethernet / ARP / Loopback)              |
| -> Decoded: MAC Addresses, Frame Types, Loopback encapsulation    |
+-------------------------------------------------------------------+
                                  |
                                  v
+-------------------------------------------------------------------+
| Layer 3: Network Layer (IPv4 / IPv6)                              |
| -> Decoded: Source/Dest IPs, TTL/Hop Limits, Protocol/Next Header |
+-------------------------------------------------------------------+
                                  |
                                  v
+-------------------------------------------------------------------+
| Layer 4: Transport Layer (TCP / UDP / ICMP / ICMPv6)              |
| -> Decoded: Source/Dest Ports, TCP Control Flags, ICMP Type/Code  |
+-------------------------------------------------------------------+
                                  |
                                  v
+-------------------------------------------------------------------+
| Layer 7: Application / Payload Data (Raw Load)                    |
| -> Decoded: ASCII string preview, Hexadecimal dump                |
+-------------------------------------------------------------------+
```

### 2.2 System Flow Diagram

```
[Start CLI Execution]
        |
        v
[Parse Arguments (argparse)]
        |
        +---> [-l / --list-interfaces] ----> [Display scapy.show_interfaces()] -> [Exit]
        |
        +---> [--demo] --------------------> [Load Synthetic Packet List] --------+
        |                                                                         |
        +---> [--pcap <file>] -------------> [Read PCAP via rdpcap()] ------------+
        |                                                                         |
        +---> [Live Capture] --------------> [Resolve Interface]                  |
                                                   |                              |
                                            [Invoke sniff()]                      |
                                                   |                              |
                                                   v                              v
                                        [Real-Time Packet Callback] <-------------+
                                                   |
                                        [Protocol Classification]
                                                   |
                                        [Transport Details Extractor]
                                                   |
                                        [Payload Sanitizer & Hex Dump]
                                                   |
                                        [Terminal Formatted Print]
```

---

## 3. Detailed Code Structure

The source code in [`network_sniffer.py`](file:///c:/Users/sibga/OneDrive/Desktop/CodeAlpha/network_sniffer/network_sniffer.py) is structured into focused functional units:

### 3.1 Protocol Classification (`describe_protocol`)
```python
def describe_protocol(packet) -> str:
```
- Determines the layer-3 and layer-4 protocol type.
- Checks for IPv4 `packet[IP].proto` or IPv6 Next Header `packet[IPv6].nh` mapped against RFC protocol numbers (`1: ICMP`, `6: TCP`, `17: UDP`, `58: ICMPv6`).
- Identifies ARP (`scapy.ARP`) and non-IP protocols.

### 3.2 Transport Details Extraction (`extract_transport_details`)
```python
def extract_transport_details(packet) -> str:
```
- **TCP:** Extracts source port, destination port, and active control flags (e.g., `flags=[PA]` for PUSH-ACK, `flags=[S]` for SYN, `flags=[SA]` for SYN-ACK).
- **UDP:** Extracts source and destination communication ports.
- **ICMP / ICMPv6:** Extracts control message `type` (e.g., Type 8 = Echo Request, Type 0 = Echo Reply) and `code`.

### 3.3 Payload Inspection (`collect_payload`, `preview_payload`, `preview_hex`)
- **`collect_payload(packet)`**: Locates raw data payloads from `Raw.load` or transport layer payloads.
- **`preview_payload(raw_bytes, length)`**: Converts byte arrays into printable ASCII strings. Non-printable characters (outside decimal ASCII range 32–126) are replaced with a dot (`.`), preventing terminal escape sequence injection or formatting corruptions.
- **`preview_hex(raw_bytes, length)`**: Formats byte sequences as space-separated two-digit hexadecimal values (e.g., `47 45 54 20 2f 20` for `GET / `).

### 3.4 Interface Resolution (`resolve_interface`)
```python
def resolve_interface(iface_arg: str | None)
```
- Enables users to specify interfaces by numeric index (`-i 17`), system GUID, or human-readable adapter name (`-i "Qualcomm Atheros QCA9377 Wireless Network Adapter"`).
- Automatically translates index inputs using `scapy.conf.ifaces.dev_from_index()`.

### 3.5 Real-Time Streaming Callback Architecture
Instead of buffering all packets in RAM (which causes high memory usage and delays terminal display), the sniffer utilizes an event-driven callback:
```python
packet_counter = 0

def process_packet(pkt):
    nonlocal packet_counter
    packet_counter += 1
    print_packet_summary(pkt, args, packet_counter)
```
Packets are printed instantaneously upon ingress.

---

## 4. Platform Considerations: Windows & Npcap

### 4.1 The Windows Raw Socket Restriction
- On Linux and macOS, raw socket capture (`AF_PACKET` / `BPF`) is natively supported by the kernel and available to processes with root/sudo or `CAP_NET_RAW` privileges.
- On Windows, Microsoft removed Layer 2 raw socket access and restricted Layer 3 raw sockets since Windows XP SP2. Standard Winsock APIs do not permit promiscuous mode capture or raw Ethernet frame reading without a specialized kernel driver.

### 4.2 Npcap Architecture
To sniff packets under Windows, Scapy depends on **Npcap** (the modern NDIS 6 Light-Weight Filter driver maintained by the Nmap Project):
1. **Driver (`npcap.sys`)**: Binds directly to network adapter stacks to capture Ethernet frames.
2. **User Library (`wpcap.dll`, `Packet.dll`)**: Provides standard Libpcap-compatible C APIs that Scapy calls.

### 4.3 Setup Instructions for Live Capture
1. Run the official installer downloaded at:
   ```text
   C:\Users\sibga\Downloads\npcap-1.89.exe
   ```
2. **Important Setting**: Ensure **"Install Npcap in WinPcap API-compatible Mode"** is checked. This guarantees `wpcap.dll` is placed in `System32` where Scapy and Python automatically discover it.
3. Once installed, reboot or restart PowerShell, then execute live capture with:
   ```powershell
   python network_sniffer.py
   ```

---

## 5. Usage Guide & Scenarios

### Scenario 1: Synthetic Demo (Evaluation without Driver)
Simulates realistic DNS lookups, HTTP GET requests, HTTP 200 responses, ICMP echo requests/replies, and TLS 1.3 handshakes:
```powershell
python network_sniffer.py --demo --show-hex
```
**Sample Output:**
```text
Running in DEMO MODE (simulating network packets)...

Packet #1: 192.168.1.57 -> 8.8.8.8 [UDP]
  TTL=64 len=None ports 53210->53
  Payload: .4...........google.com.....
  Hex: 12 34 01 00 00 01 00 00 00 00 00 00 06 67 6f 6f 67 6c 65 03 63 6f 6d 00 00 01 00 01

Packet #3: 192.168.1.57 -> 142.250.190.46 [TCP]
  TTL=64 len=None ports 54321->80 flags=[PA]
  Payload: GET / HTTP/1.1..Host: google.com
  Hex: 47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31 0d 0a 48 6f 73 74 3a 20 67 6f 6f 67 6c 65 2e 63 6f 6d

[Demo Complete] Total packets processed: 7
```

---

### Scenario 2: Offline PCAP Forensic Analysis
Analyze traffic pre-recorded from Wireshark, tcpdump, or previous sniffer runs:
```powershell
# Analyze all packets in sample.pcap
python network_sniffer.py --pcap sample.pcap --show-hex

# Filter and analyze only TCP packets
python network_sniffer.py --pcap sample.pcap --filter tcp

# Limit to first 2 packets with 64-byte payload preview
python network_sniffer.py --pcap sample.pcap -c 2 --payload-limit 64 --show-hex
```

---

### Scenario 3: Enumerating Network Adapters
List all hardware and virtual interfaces registered on the system:
```powershell
python network_sniffer.py -l
```
This prints index numbers, adapter names, MAC addresses, IPv4, and IPv6 bindings (e.g., Index `17` for Qualcomm Wi-Fi, Index `1` for Software Loopback).

---

### Scenario 4: Live Network Capture
Sniff on the default interface or target a specific adapter:
```powershell
# Default adapter, IP traffic only, 10-second timeout
python network_sniffer.py

# Target specific interface index (e.g., 17) for 50 packets with hex preview
python network_sniffer.py -i 17 -c 50 --show-hex

# Capture only web traffic (port 80 or 443)
python network_sniffer.py -i 17 --filter "tcp port 80" --timeout 30
```

---

## 6. Command-Line Reference

| Flag | Full Name | Type | Default | Description |
|---|---|---|---|---|
| `-h` | `--help` | flag | — | Show help message and parameter reference |
| `-i` | `--interface` | string / int | `None` | Network interface name or numeric index (e.g. `17`) |
| `-l` | `--list-interfaces` | flag | `False` | Display all detected network interfaces and exit |
| `-c` | `--count` | int | `20` | Max packets to capture (`0` = infinite until timeout) |
| `-t` | `--timeout` | float | `10.0` | Maximum duration in seconds for live capture session |
| | `--filter` | string | `ip` | Protocol or BPF filter (`tcp`, `udp`, `icmp`, `port 80`) |
| | `--show-hex` | flag | `False` | Display hexadecimal dump alongside ASCII preview |
| | `--payload-limit` | int | `32` | Max payload bytes to preview per packet |
| | `--demo` | flag | `False` | Run self-contained simulated traffic test |
| | `--pcap` | file path | `None` | Read and decode packets from an offline `.pcap` file |

---

## 7. Troubleshooting & FAQs

### Q: Why do I see `WARNING: No libpcap provider available ! pcap won't be used`?
**A:** This warning occurs on Windows when Npcap is not yet installed. Scapy prints this warning when searching for `wpcap.dll`. To enable live sniffing, install the provided `C:\Users\sibga\Downloads\npcap-1.89.exe`.

### Q: Does the sniffer work without Npcap?
**A:** Yes. You can test and inspect packet structure using `--demo` (synthetic traffic) and `--pcap <file>` (offline captures) without Npcap installed. Live network interception requires Npcap.

### Q: How do I stop a live capture session before the timeout expires?
**A:** Press `Ctrl + C`. The script intercepts `KeyboardInterrupt` cleanly and prints the total number of packets captured prior to termination.

---

## 8. Ethical Use & Legal Notice

This network sniffer is designed solely for **educational purposes, network diagnostics, security testing, and academic project evaluation**. 

- **Authorization Requirement:** Capturing network traffic on networks without prior explicit authorization from the network owner or administrator is illegal and violates computer misuse laws in many jurisdictions.
- **Privacy:** Packet inspection tools can observe unencrypted credentials, URLs, and communication metadata. Never deploy this tool on public, corporate, or third-party networks without proper authorization.
