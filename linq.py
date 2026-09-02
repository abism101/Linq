#!/usr/bin/env python3
"""
LINO v4
-------
Simple LAN IP Finder.

Shows only:
    IP ADDRESS
    MAC ADDRESS
    DEVICE NAME
    STATUS

Linux uses direct ARP discovery for a fast local-LAN scan.
No ports. No Nmap. No service detection.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import os
import re
import socket
import struct
import subprocess
import sys
import time
from dataclasses import dataclass


ASCII = r"""
██╗     ██╗███╗   ██╗ ██████╗
██║     ██║████╗  ██║██╔═══██╗
██║     ██║██╔██╗ ██║██║   ██║
██║     ██║██║╚██╗██║██║   ██║
███████╗██║██║ ╚████║╚██████╔╝
╚══════╝╚═╝╚═╝  ╚═══╝ ╚═════╝

        LAN Device Finder
"""

ETH_P_ARP = 0x0806
ARP_REQUEST = 1
ARP_REPLY = 2


@dataclass(slots=True)
class Device:
    ip: str
    mac: str
    name: str = "-"
    status: str = "UP"


def say(message: str = "") -> None:
    print(message, flush=True)


def command(command: list[str], timeout: float = 2.0) -> str:
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=timeout,
            check=False,
        )
        return result.stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def get_local_ip() -> str | None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("192.0.2.1", 80))
        return sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()


def get_interface(local_ip: str) -> str | None:
    output = command(["ip", "route", "get", "192.0.2.1"], timeout=1.0)
    match = re.search(r"\bdev\s+(\S+)", output)
    if match:
        return match.group(1)

    output = command(["ip", "-o", "addr", "show"], timeout=1.0)
    for line in output.splitlines():
        if local_ip in line:
            parts = line.split()
            if len(parts) >= 2:
                return parts[1]
    return None


def get_default_network(local_ip: str) -> ipaddress.IPv4Network | None:
    output = command(["ip", "-4", "route", "show", "scope", "link"], timeout=1.0)
    for line in output.splitlines():
        match = re.match(r"^(\d+\.\d+\.\d+\.\d+/\d+)\s+dev\s+(\S+)", line)
        if not match:
            continue
        try:
            network = ipaddress.ip_network(match.group(1), strict=False)
            if ipaddress.ip_address(local_ip) in network:
                return network
        except ValueError:
            continue

    return ipaddress.ip_network(f"{local_ip}/24", strict=False)


def read_arp_table() -> dict[str, str]:
    output = command(["ip", "neigh"], timeout=1.0)
    table: dict[str, str] = {}
    pattern = re.compile(
        r"^(\d+\.\d+\.\d+\.\d+)\s+.*?\blladdr\s+([0-9a-fA-F:]{17})\b"
    )
    for line in output.splitlines():
        match = pattern.search(line)
        if match:
            table[match.group(1)] = match.group(2).upper()
    return table


def mac_bytes(value: str) -> bytes:
    return bytes(int(part, 16) for part in value.split(":"))


def build_arp_request(source_mac: str, source_ip: str, target_ip: str) -> bytes:
    ethernet = b"\xff" * 6 + mac_bytes(source_mac) + struct.pack("!H", ETH_P_ARP)
    arp = struct.pack(
        "!HHBBH6s4s6s4s",
        1,              # Ethernet
        ETH_P_ARP,      # IPv4
        6,              # MAC length
        4,              # IPv4 length
        ARP_REQUEST,
        mac_bytes(source_mac),
        socket.inet_aton(source_ip),
        b"\x00" * 6,
        socket.inet_aton(target_ip),
    )
    return ethernet + arp


def arp_scan(network: ipaddress.IPv4Network, interface: str, local_ip: str) -> dict[str, str]:
    """Fast ARP discovery for a directly connected Linux LAN."""
    if os.geteuid() != 0:
        raise PermissionError("ARP discovery needs root; run with sudo.")

    source_mac = get_interface_mac(interface)
    if not source_mac:
        raise RuntimeError(f"Could not read MAC address for {interface}.")

    hosts = [str(host) for host in network.hosts()]
    results: dict[str, str] = {}

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ARP))
    sock.bind((interface, 0))
    sock.settimeout(0.15)

    try:
        frame = build_arp_request(source_mac, local_ip, "0.0.0.0")
        # Warm up the kernel neighbour path without waiting for replies.
        try:
            sock.send(frame)
        except OSError:
            pass

        # Broadcast ARP request to every LAN address. Sending is fast; replies are
        # collected afterward, so the scan does not wait per host.
        for ip in hosts:
            frame = build_arp_request(source_mac, local_ip, ip)
            try:
                sock.send(frame)
            except OSError:
                continue

        deadline = time.monotonic() + 1.2
        while time.monotonic() < deadline:
            remaining = max(0.01, deadline - time.monotonic())
            sock.settimeout(remaining)
            try:
                packet = sock.recv(65535)
            except socket.timeout:
                break
            except OSError:
                break

            if len(packet) < 42:
                continue

            ethertype = struct.unpack("!H", packet[12:14])[0]
            if ethertype != ETH_P_ARP:
                continue

            arp = packet[14:42]
            htype, ptype, hlen, plen, opcode = struct.unpack("!HHBBH", arp[:8])
            if htype != 1 or ptype != 0x0800 or hlen != 6 or plen != 4 or opcode != ARP_REPLY:
                continue

            sender_mac = ":".join(f"{b:02X}" for b in arp[8:14])
            sender_ip = socket.inet_ntoa(arp[14:18])
            try:
                if ipaddress.ip_address(sender_ip) in network:
                    results[sender_ip] = sender_mac
            except ValueError:
                continue
    finally:
        sock.close()

    # Merge anything the kernel already learned during the scan.
    for ip, mac in read_arp_table().items():
        try:
            if ipaddress.ip_address(ip) in network:
                results.setdefault(ip, mac)
        except ValueError:
            continue

    return results


def get_interface_mac(interface: str) -> str | None:
    try:
        with open(f"/sys/class/net/{interface}/address", "r", encoding="ascii") as handle:
            mac = handle.read().strip().upper()
        if re.fullmatch(r"[0-9A-F]{2}(:[0-9A-F]{2}){5}", mac):
            return mac
    except OSError:
        pass
    return None


def resolve_name(ip: str) -> str:
    try:
        socket.setdefaulttimeout(0.35)
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname or "-"
    except (socket.herror, socket.gaierror, OSError):
        return "-"


def discover(network: ipaddress.IPv4Network, interface: str, local_ip: str) -> list[Device]:
    hosts = list(network.hosts())
    say(f"[+] Discovering {len(hosts)} addresses with ARP...")

    if len(hosts) > 1024:
        raise ValueError("Network too large. Lino supports up to 1024 hosts per scan.")

    macs = arp_scan(network, interface, local_ip)

    devices = [Device(ip=ip, mac=mac) for ip, mac in macs.items()]
    say(f"[+] Found {len(devices)} active device(s). Resolving names...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as executor:
        futures = {executor.submit(resolve_name, device.ip): device for device in devices}
        for future in concurrent.futures.as_completed(futures):
            device = futures[future]
            try:
                device.name = future.result()
            except Exception:
                device.name = "-"

    return sorted(devices, key=lambda d: tuple(map(int, d.ip.split("."))))


def print_table(network: ipaddress.IPv4Network, devices: list[Device]) -> None:
    print("\033[2J\033[H", end="")
    print(ASCII)
    print(f"Network: {network}\n")

    headers = ("IP ADDRESS", "MAC ADDRESS", "DEVICE NAME", "STATUS")
    widths = (17, 20, 32, 8)
    print(
        f"{headers[0]:<{widths[0]}}"
        f"{headers[1]:<{widths[1]}}"
        f"{headers[2]:<{widths[2]}}"
        f"{headers[3]:<{widths[3]}}"
    )
    print("-" * sum(widths))

    if not devices:
        print("No active devices found.")
    else:
        for device in devices:
            print(
                f"{device.ip:<{widths[0]}}"
                f"{device.mac:<{widths[1]}}"
                f"{device.name:<{widths[2]}}"
                f"{device.status:<{widths[3]}}"
            )

    print(f"\nDevices found: {len(devices)}", flush=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="lino.v.4",
        description="Simple LAN IP Finder: IP, MAC, device name and status.",
    )
    parser.add_argument("-n", "--network", help="LAN/network or gateway IP, e.g. 192.168.1.0/24 or 192.168.1.1")
    parser.add_argument("-i", "--interval", type=float, default=0, help="Refresh interval in seconds")
    parser.add_argument("--once", action="store_true", help="Scan once and exit")
    return parser.parse_args()


def main() -> int:
    print(ASCII, flush=True)
    say("[+] Starting Lino...")

    if sys.platform != "linux":
        print("[!] This v4 build uses Linux ARP discovery. Run it on Linux.", flush=True)
        return 1

    args = parse_args()
    local_ip = get_local_ip()
    if not local_ip:
        print("[!] Could not determine local IPv4 address.", flush=True)
        return 1

    interface = get_interface(local_ip)
    if not interface:
        print("[!] Could not determine network interface.", flush=True)
        return 1

    if args.network:
        try:
            value = args.network.strip()
            if "/" not in value:
                # Friendly LAN mode: 192.168.1.1 means the common /24 LAN.
                ip_value = ipaddress.ip_address(value)
                network = ipaddress.ip_network(f"{ip_value}/24", strict=False)
            else:
                network = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            print(f"[!] Invalid network: {exc}", flush=True)
            return 2
    else:
        network = get_default_network(local_ip)
        if not network:
            print("[!] Could not determine local LAN.", flush=True)
            return 1

    say(f"[+] Interface: {interface}")
    say(f"[+] Local IP: {local_ip}")
    say(f"[+] Network: {network}")

    if args.interval > 0 and args.interval < 1:
        args.interval = 1.0

    try:
        while True:
            devices = discover(network, interface, local_ip)
            print_table(network, devices)

            if args.interval <= 0 or args.once:
                break

            say(f"\n[+] Refreshing every {args.interval:g}s... Press Ctrl+C to exit.")
            time.sleep(args.interval)
    except PermissionError as exc:
        print(f"[!] {exc}", flush=True)
        return 1
    except KeyboardInterrupt:
        say("\n[+] Stopped.")
        return 0
    except (RuntimeError, ValueError) as exc:
        print(f"[!] {exc}", flush=True)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
