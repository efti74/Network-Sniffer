# Network Sniffer

A Python network packet sniffer built with **Scapy**, designed to capture, decode, and inspect network traffic in real time.

## Features

- **Live Capture**: Streams packets in real time directly to the terminal.
- **Protocol Decoding**: Summarizes IPv4, IPv6, TCP (with flags), UDP, ICMP, and ARP packets.
- **Payload Inspection**: Safely previews payload data in both ASCII text and hexadecimal.
- **Filtering**: Supports BPF and protocol-level filters (e.g., `tcp`, `udp`, `icmp`, `tcp port 80`).
- **Demo Mode**: Includes synthetic packet simulation for testing without drivers.
- **PCAP Playback**: Reads and inspects pre-recorded `.pcap` capture files.
- **Interface Selection**: Auto-detects adapters and lets you target specific interfaces by index or name.

---

## Quick Start

### 1. Run in Demo Mode (No Drivers Required)
Simulate realistic network traffic (DNS, HTTP GET/Response, ICMP Ping, TLS 1.3):
```powershell
python network_sniffer.py --demo
python network_sniffer.py --demo --show-hex
```

### 2. Analyze PCAP Files
Inspect the bundled sample capture or any `.pcap` file:
```powershell
python network_sniffer.py --pcap sample.pcap
python network_sniffer.py --pcap sample.pcap --filter tcp --show-hex
```

### 3. List Network Interfaces
```powershell
python network_sniffer.py -l
```

---

## Live Packet Capture (Windows Setup)

Windows requires **Npcap** for raw socket and promiscuous packet capture at Layer 2/3:

1. **Install Npcap**:
   The installer has already been downloaded for you to:
   ```
   C:\Users\<user>\Downloads\npcap-1.89.exe
   ```
   *(Or download the latest installer from [https://npcap.com/#download](https://npcap.com/#download))*
2. **Important installation checkbox**:
   - Check **"Install Npcap in WinPcap API-compatible Mode"** during setup.
3. **Start Live Capture**:
   ```powershell
   python network_sniffer.py
   ```
   Or target a specific interface and filter:
   ```powershell
   python network_sniffer.py -i 17 --filter "tcp port 80" --timeout 30 --show-hex
   ```

---

## Command Line Arguments

| Argument | Description | Default |
|---|---|---|
| `-i, --interface` | Network interface name or index (e.g. `-i 17`) | Default interface |
| `-l, --list-interfaces` | List available network interfaces and exit | `False` |
| `-c, --count` | Maximum packets to capture (`0` for unlimited) | `20` |
| `-t, --timeout` | Capture timeout in seconds | `10.0` |
| `--filter` | Capture filter (e.g., `ip`, `tcp`, `udp`, `port 53`) | `ip` |
| `--show-hex` | Display payload in hexadecimal format | `False` |
| `--payload-limit`| Maximum bytes of payload preview | `32` |
| `--demo` | Run simulated packet stream | `False` |
| `--pcap FILE` | Inspect packets from an offline `.pcap` file | `None` |
