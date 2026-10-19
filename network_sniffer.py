#!/usr/bin/env python3

from __future__ import annotations

import argparse
import importlib
import sys

try:
    scapy = importlib.import_module("scapy.all")
except ModuleNotFoundError as exc:
    if exc.name == "scapy":
        raise SystemExit(
            "Scapy is not installed. Install it with: python -m pip install scapy"
        ) from exc
    raise

ICMP = scapy.ICMP
IP = scapy.IP
IPv6 = scapy.IPv6
Raw = scapy.Raw
TCP = scapy.TCP
UDP = scapy.UDP
sniff = scapy.sniff
rdpcap = scapy.rdpcap

PROTOCOL_NAMES = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    58: "ICMPv6",
}


def describe_protocol(packet) -> str:
    if packet.haslayer(IPv6):
        proto_number = packet[IPv6].nh
        return PROTOCOL_NAMES.get(proto_number, f"IPv6-{proto_number}")
    if packet.haslayer(IP):
        proto_number = packet[IP].proto
        return PROTOCOL_NAMES.get(proto_number, f"IP-{proto_number}")
    if hasattr(scapy, "ARP") and packet.haslayer(scapy.ARP):
        return "ARP"
    return "Non-IP"


def preview_payload(raw_bytes: bytes, length: int = 32) -> str:
    if not raw_bytes:
        return ""
    limit = max(0, length)
    sample = raw_bytes[:limit]
    return "".join(chr(b) if 32 <= b < 127 else "." for b in sample)


def preview_hex(raw_bytes: bytes, length: int = 32) -> str:
    if not raw_bytes:
        return ""
    limit = max(0, length)
    return " ".join(f"{b:02x}" for b in raw_bytes[:limit])


def extract_transport_details(packet) -> str:
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        flags = str(tcp.flags)
        return f"ports {tcp.sport}->{tcp.dport} flags=[{flags}]"
    if packet.haslayer(UDP):
        udp = packet[UDP]
        return f"ports {udp.sport}->{udp.dport}"
    if packet.haslayer(ICMP):
        icmp = packet[ICMP]
        return f"type={icmp.type} code={icmp.code}"
    if packet.haslayer(IPv6):
        next_header = packet[IPv6].nh
        if next_header == 58:
            payload = packet[IPv6].payload
            if hasattr(payload, "type") and hasattr(payload, "code"):
                return f"type={payload.type} code={payload.code}"
    return ""


def collect_payload(packet) -> bytes:
    if packet.haslayer(Raw):
        return bytes(packet[Raw].load)
    if packet.haslayer(TCP):
        payload = packet[TCP].payload
        return bytes(payload) if payload else b""
    if packet.haslayer(UDP):
        payload = packet[UDP].payload
        return bytes(payload) if payload else b""
    if packet.haslayer(ICMP):
        payload = packet[ICMP].payload
        return bytes(payload) if payload else b""
    if packet.haslayer(IPv6):
        next_header = packet[IPv6].nh
        if next_header == 58:
            payload = packet[IPv6].payload
            if hasattr(payload, "payload"):
                return bytes(payload.payload)
            return bytes(payload)
    return b""


def print_packet_summary(packet, args: argparse.Namespace, packet_number: int) -> None:
    if packet.haslayer(IPv6):
        ip = packet[IPv6]
        protocol = describe_protocol(packet)
        transport = extract_transport_details(packet)
        payload = collect_payload(packet)
        payload_preview = preview_payload(payload, args.payload_limit)

        print(f"\nPacket #{packet_number}: {ip.src} -> {ip.dst} [{protocol}]")
        print(f"  HOP={ip.hlim} plen={getattr(ip, 'plen', 'n/a')} {transport}")

        if payload:
            print(f"  Payload: {payload_preview}")
            if args.show_hex:
                print(f"  Hex: {preview_hex(payload, args.payload_limit)}")
        else:
            print("  Payload: <empty>")
        return

    if packet.haslayer(IP):
        ip = packet[IP]
        protocol = describe_protocol(packet)
        transport = extract_transport_details(packet)
        payload = collect_payload(packet)
        payload_preview = preview_payload(payload, args.payload_limit)

        print(f"\nPacket #{packet_number}: {ip.src} -> {ip.dst} [{protocol}]")
        print(f"  TTL={ip.ttl} len={ip.len} {transport}")

        if payload:
            print(f"  Payload: {payload_preview}")
            if args.show_hex:
                print(f"  Hex: {preview_hex(payload, args.payload_limit)}")
        else:
            print("  Payload: <empty>")
        return

    # Non-IP packet fallback
    proto = describe_protocol(packet)
    print(f"\nPacket #{packet_number}: [{proto}] {packet.summary()}")


def matches_filter(packet, filter_expr: str | None) -> bool:
    if not filter_expr:
        return True
    f = filter_expr.strip().lower()
    if f in ("ip", "ipv4"):
        return packet.haslayer(IP)
    if f in ("ip6", "ipv6"):
        return packet.haslayer(IPv6)
    if f == "tcp":
        return packet.haslayer(TCP)
    if f == "udp":
        return packet.haslayer(UDP)
    if f == "icmp":
        return packet.haslayer(ICMP) or (packet.haslayer(IPv6) and packet[IPv6].nh == 58)
    if f == "arp":
        return hasattr(scapy, "ARP") and packet.haslayer(scapy.ARP)
    # Port matching e.g. "port 80" or "tcp port 80"
    if "port" in f:
        parts = f.split()
        try:
            target_port = int(parts[-1])
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                return tcp.sport == target_port or tcp.dport == target_port
            if packet.haslayer(UDP):
                udp = packet[UDP]
                return udp.sport == target_port or udp.dport == target_port
        except (ValueError, IndexError):
            pass
    return True


def resolve_interface(iface_arg: str | None):
    if not iface_arg:
        return None
    # Numeric interface index
    if iface_arg.isdigit():
        try:
            return scapy.conf.ifaces.dev_from_index(int(iface_arg))
        except Exception:
            pass
    # Device name match
    try:
        dev = scapy.conf.ifaces.dev_from_name(iface_arg)
        if dev:
            return dev
    except Exception:
        pass
    return iface_arg


def generate_demo_packets() -> list:
    return [
        IP(src="192.168.1.57", dst="8.8.8.8")
        / UDP(sport=53210, dport=53)
        / Raw(load=b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01"),
        IP(src="8.8.8.8", dst="192.168.1.57")
        / UDP(sport=53, dport=53210)
        / Raw(load=b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01"),
        IP(src="192.168.1.57", dst="142.250.190.46")
        / TCP(sport=54321, dport=80, flags="PA")
        / Raw(load=b"GET / HTTP/1.1\r\nHost: google.com\r\nUser-Agent: Sniffer/1.0\r\n\r\n"),
        IP(src="142.250.190.46", dst="192.168.1.57")
        / TCP(sport=80, dport=54321, flags="PA")
        / Raw(load=b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<h1>CodeAlpha Packet Sniffer</h1>"),
        IP(src="192.168.1.57", dst="1.1.1.1")
        / ICMP(type=8, code=0)
        / Raw(load=b"abcdefghijklmnopqrstuvwabcdefghi"),
        IP(src="1.1.1.1", dst="192.168.1.57")
        / ICMP(type=0, code=0)
        / Raw(load=b"abcdefghijklmnopqrstuvwabcdefghi"),
        IPv6(src="2606:4700:4700::1111", dst="2001:db8::2")
        / TCP(sport=443, dport=51234, flags="SA")
        / Raw(load=b"\x16\x03\x03\x00\x5a\x02\x00\x00\x56\x03\x03ServerHelloTLS13"),
    ]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Capture and inspect network packets with Scapy.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-i",
        "--interface",
        default=None,
        help="Network interface name or index (e.g., -i 17). Uses default interface if omitted.",
    )
    parser.add_argument(
        "-l",
        "--list-interfaces",
        action="store_true",
        help="List available network interfaces and exit.",
    )
    parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=20,
        help="Number of packets to capture before stopping. Use 0 for unlimited until timeout.",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=10.0,
        help="Maximum seconds to sniff before exiting.",
    )
    parser.add_argument(
        "--filter",
        default="ip",
        help="Scapy/BPF capture filter, for example 'tcp port 80' or 'udp port 53'.",
    )
    parser.add_argument(
        "--show-hex",
        action="store_true",
        help="Also display the first payload bytes in hexadecimal.",
    )
    parser.add_argument(
        "--payload-limit",
        type=int,
        default=32,
        help="Maximum number of payload bytes to print in ASCII/hex preview.",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run in demo mode with sample packets (useful for testing without driver).",
    )
    parser.add_argument(
        "--pcap",
        metavar="FILE",
        default=None,
        help="Read and analyze packets from a PCAP file instead of live capture.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    # List interfaces
    if args.list_interfaces:
        print("Available Network Interfaces:")
        print("=" * 70)
        try:
            scapy.show_interfaces()
        except Exception as exc:
            print(f"Error listing interfaces: {exc}")
        return 0

    if args.count < 0:
        print("Error: packet count cannot be negative.", file=sys.stderr)
        return 2

    if args.payload_limit < 0:
        print("Error: payload limit cannot be negative.", file=sys.stderr)
        return 2

    packet_counter = 0

    def process_packet(pkt):
        nonlocal packet_counter
        packet_counter += 1
        print_packet_summary(pkt, args, packet_counter)

    # Demo Mode
    if args.demo:
        print("Running in DEMO MODE (simulating network packets)...")
        demo_pkts = generate_demo_packets()
        for pkt in demo_pkts:
            if args.filter and not matches_filter(pkt, args.filter):
                continue
            process_packet(pkt)
            if args.count > 0 and packet_counter >= args.count:
                break
        print(f"\n[Demo Complete] Total packets processed: {packet_counter}")
        return 0

    # Offline PCAP replay
    if args.pcap:
        print(f"Reading packets from '{args.pcap}'...")
        try:
            packets = rdpcap(args.pcap)
        except Exception as exc:
            print(f"Error reading PCAP file: {exc}", file=sys.stderr)
            return 1

        for pkt in packets:
            if args.filter and not matches_filter(pkt, args.filter):
                continue
            process_packet(pkt)
            if args.count > 0 and packet_counter >= args.count:
                break

        if packet_counter == 0:
            print("No matching packets found in PCAP file.")
        else:
            print(f"\nTotal packets processed from PCAP: {packet_counter}")
        return 0

    # Live capture
    iface = resolve_interface(args.interface)
    iface_desc = args.interface or "default"
    packet_count = args.count if args.count > 0 else 0

    print(
        f"Starting live capture on interface '{iface_desc}' "
        f"with filter '{args.filter}' for {args.timeout} seconds.",
        flush=True,
    )
    print("Press Ctrl+C to stop sniffing early.\n", flush=True)

    try:
        sniff(
            iface=iface,
            filter=args.filter,
            count=packet_count,
            timeout=args.timeout,
            prn=process_packet,
            store=False,
        )
    except KeyboardInterrupt:
        print("\nCapture interrupted by user.")
    except (PermissionError, OSError, RuntimeError) as exc:
        print(f"\nCapture failed: {exc}", file=sys.stderr)
        if sys.platform == "win32":
            print(
                "\n[Windows Setup Requirement]\n"
                "To capture live packets on Windows, Npcap must be installed:\n"
                "  1. The installer has been downloaded to:\n"
                "     C:\\Users\\sibga\\Downloads\\npcap-1.89.exe\n"
                "  2. Run the installer and ensure 'Install Npcap in WinPcap API-compatible Mode' is checked.\n"
                "  3. Once installed, run:\n"
                "     python .\\network_sniffer.py\n"
                "\nYou can also test the sniffer immediately with:\n"
                "  python .\\network_sniffer.py --demo\n"
                "  python .\\network_sniffer.py --pcap sample.pcap\n",
                file=sys.stderr,
            )
        else:
            print("Tip: Run with administrator/root privileges.", file=sys.stderr)
        return 1

    if packet_counter == 0:
        print("\nNo packets were captured within the timeout window.")
    else:
        print(f"\nTotal packets captured: {packet_counter}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
