#!/usr/bin/env python3

import socket
import concurrent.futures
import time
import ipaddress
import errno
import json
import csv
import sys
from tabulate import tabulate
from colorama import Fore, Style, init
init(autoreset=True)

# Preset port lists
TOP_PORTS = [
    21,22,23,25,53,80,110,123,139,143,161,389,443,445,587,631,993,995,
    1080,1194,1433,1521,1723,2049,2082,2083,2086,2087,2095,2181,2222,
    2302,3306,3389,4444,5000,5060,5080,5432,5900,6000,6379,6667,6881,
   7000,8000,8080,8443,8888,9000,9090,10000,27017
]
SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 139: "netbios-ssn", 143: "imap", 443: "https", 445: "smb",
    3306: "mysql", 3389: "rdp", 5900: "vnc", 8080: "http-proxy"
}

# Try import scapy for stealth
try:
    from scapy.all import IP, TCP, sr1, conf
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

def parse_target(raw):
    raw = raw.strip()
    if '/' in raw:
        return [str(ip) for ip in ipaddress.ip_network(raw, strict=False).hosts()]
    if ',' in raw:
        return [x.strip() for x in raw.split(',') if x.strip()]
    return [raw]

def parse_ports_expr(raw):
    raw = raw.strip().lower()
    if not raw:
        return []
    if raw == "top":
        return TOP_PORTS.copy()
    out = set()
    for part in (p.strip() for p in raw.split(',') if p.strip()):
        if '-' in part:
            try:
                a,b = part.split('-',1)
                a=int(a); b=int(b)
                out.update(range(max(1,a), min(65535,b)+1))
            except:
                pass
        else:
            try:
                out.add(int(part))
            except:
                pass
    return sorted(p for p in out if 1 <= p <= 65535)

def estimate_rtt(host, trials=2, probe_ports=(80,443,22,53)):
    times=[]
    for port in probe_ports:
        try:
            for _ in range(trials):
                s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                start=time.time()
                ret=s.connect_ex((host,port))
                elapsed=time.time()-start
                s.close()
                if ret==0 or ret==errno.ECONNREFUSED:
                    times.append(elapsed)
                    break
        except:
            pass
    if not times:
        return 0.2
    times.sort()
    return max(0.01, times[len(times)//2])

def auto_tune(host, ports_count):
    rtt = estimate_rtt(host)
    timeout = max(0.25, round(rtt*2.5, 2))
    threads = min(1200, max(80, int(400 / max(rtt, 0.01))))
    threads = min(threads, max(10, ports_count * 5))
    return timeout, threads, rtt

def tcp_connect_probe(ip, port, timeout, banner=False):
    s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    start=time.time()
    try:
        ret = s.connect_ex((ip, port))
        elapsed = round(time.time()-start,4)
        banner_text = ""
        if ret==0:
            if banner:
                try:
                    s.send(b"\r\n")
                    banner_text = s.recv(1024).decode(errors="ignore").strip()
                except:
                    banner_text = ""
            s.close()
            return (port, "tcp", "open", SERVICES.get(port,""), elapsed, banner_text)
        elif ret==errno.ECONNREFUSED:
            s.close()
            return (port, "tcp", "closed", SERVICES.get(port,""), elapsed, "")
        else:
            s.close()
            return (port, "tcp", "open|filtered", SERVICES.get(port,""), elapsed, "")
    except Exception:
        elapsed = round(time.time()-start,4)
        try: s.close()
        except: pass
        return (port, "tcp", "closed", SERVICES.get(port,""), elapsed, "")

def udp_probe(ip, port, timeout):
    s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    start=time.time()
    try:
        s.sendto(b"\x00", (ip,port))
        s.recvfrom(1024)
        elapsed = round(time.time()-start,4)
        s.close()
        return (port, "udp", "open", SERVICES.get(port,""), elapsed, "")
    except socket.timeout:
        elapsed = round(time.time()-start,4)
        try: s.close()
        except: pass
        return (port, "udp", "open|filtered", SERVICES.get(port,""), elapsed, "")
    except OSError as e:
        elapsed = round(time.time()-start,4)
        try: s.close()
        except: pass
        if getattr(e,"errno",None) in (errno.ECONNREFUSED, errno.EHOSTUNREACH):
            return (port, "udp", "closed", SERVICES.get(port,""), elapsed, "")
        return (port, "udp", "open|filtered", SERVICES.get(port,""), elapsed, "")

def stealth_syn_scan(ip, ports, timeout):
    """Sends TCP SYN and looks for SYN-ACK. Requires scapy and root."""
    if not SCAPY_AVAILABLE:
        raise RuntimeError("scapy not available")
    conf.verb = 0
    results=[]
    for port in ports:
        pkt = IP(dst=ip)/TCP(dport=port, flags='S')
        resp = sr1(pkt, timeout=timeout)
        if resp is None:
            results.append((port, "tcp", "open|filtered", SERVICES.get(port,""), None, ""))
        elif resp.haslayer(TCP) and resp.getlayer(TCP).flags & 0x12:  # SYN-ACK
            # send RST to close
            rst = IP(dst=ip)/TCP(dport=port, flags='R')
            try: sr1(rst, timeout=0.5)
            except: pass
            results.append((port, "tcp", "open", SERVICES.get(port,""), None, "SYN-ACK"))
        elif resp.haslayer(TCP) and resp.getlayer(TCP).flags & 0x14:  # RST
            results.append((port, "tcp", "closed", SERVICES.get(port,""), None, "RST"))
        else:
            results.append((port, "tcp", "open|filtered", SERVICES.get(port,""), None, ""))
    return results

def color_state(s):
    if s=="open": return Fore.GREEN + s + Style.RESET_ALL
    if s=="closed": return Fore.RED + s + Style.RESET_ALL
    return Fore.YELLOW + s + Style.RESET_ALL

def run_probes(ip, ports, proto, timeout, threads, banner):
    probes=[]
    for p in ports:
        if proto in ("tcp","both"): probes.append(("tcp",p))
        if proto in ("udp","both"): probes.append(("udp",p))
    results=[]
    start=time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futs=[]
        for pr,p in probes:
            if pr=="tcp":
                futs.append(ex.submit(tcp_connect_probe, ip, p, timeout, banner))
            else:
                futs.append(ex.submit(udp_probe, ip, p, timeout))
        for f in concurrent.futures.as_completed(futs):
            results.append(f.result())
    total = round(time.time()-start,4)
    # filter only open
    open_only = [r for r in results if r[2]=="open"]
    return open_only, total

def print_table_open(ip, rows, total_time, export=None):
    if not rows:
        print(f"\nHost: {ip}\nNo open ports found.")
        return
    table = []
    for port, proto, state, svc, t, banner in sorted(rows, key=lambda x:(x[0],x[1])):
        table.append([port, proto, color_state(state), svc, round(t if t else 0,4), banner or ""])
    headers=["PORT","PROTO","STATE","SERVICE","TIME(s)","BANNER"]
    print(f"\nHost: {ip}")
    print(tabulate(table, headers=headers, tablefmt="fancy_grid", stralign="center", numalign="center"))
    print(f"Total scan time for {ip}: {total_time}s (open ports shown only)")
    if export:
        if export.lower().endswith(".json"):
            with open(export,"w") as f:
                json.dump([dict(zip(headers,row)) for row in table], f, indent=2)
        elif export.lower().endswith(".csv"):
            with open(export,"w", newline="") as f:
                w = csv.writer(f); w.writerow(headers); w.writerows(table)
        print(f"Saved results to {export}")

def menu():
    print("""
=== Menu ===
1) Full TCP scan (1-65535)        [very slow]
2) Fast TCP top ports (preset)
3) Fast UDP top ports (preset)
4) Both TCP+UDP top ports
5) Stealth SYN scan (requires scapy & root)
6) Custom ports (enter ranges/comma)
q) Quit
""")

def prompt_choice():
    menu()
    return input("Choose option number: ").strip()

def prompt_common():
    t = input("Target (IP/host/list/CIDR): ").strip()
    proto = None
    banner = False
    export = input("Save results (file.json / file.csv / none) [none]: ").strip() or None
    if export and export.lower()=="none":
        export = None
    if not t:
        print("No target. Exiting."); sys.exit(0)
    return t, banner, export

def main():
    while True:
        ch = prompt_choice()
        if ch.lower() in ('q','quit','exit'):
            print("Exit."); return
        t_raw, _, export = prompt_common()
        targets = parse_target(t_raw)
        if ch == '1':
            ports = list(range(1,65536))
            proto = "tcp"
        elif ch == '2':
            ports = TOP_PORTS.copy()
            proto = "tcp"
        elif ch == '3':
            ports = TOP_PORTS.copy()
            proto = "udp"
        elif ch == '4':
            ports = TOP_PORTS.copy()
            proto = "both"
        elif ch == '5':
            if not SCAPY_AVAILABLE:
                print("Stealth scan unavailable: scapy not installed.")
                continue
            proto = "tcp"
            ports = TOP_PORTS.copy()
        elif ch == '6':
            expr = input("Enter ports (e.g. 1-1024 or 22,80,443 or top or top 100): ").strip()
            ports = parse_ports_expr(expr)
            if not ports:
                print("No ports parsed. Try again."); continue
            proto = input("Protocol for custom (tcp/udp/both) [tcp]: ").strip().lower() or "tcp"
        else:
            print("Invalid choice.")
            continue

        banner_choice = input("Grab banners on TCP open ports? (y/N): ").strip().lower() == 'y'
        for tgt in targets:
            try:
                ip = socket.gethostbyname(tgt)
            except Exception as e:
                print(f"Resolve failed for {tgt}: {e}")
                continue
            timeout, threads, rtt = auto_tune(ip, len(ports))
            print(f"\nTarget {tgt} -> {ip}")
            print(f"Estimated RTT: {rtt:.3f}s | timeout: {timeout}s | threads: {threads} | proto: {proto}")
            if ch == '5':
                # stealth SYN scan
                try:
                    start=time.time()
                    syn_results = stealth_syn_scan(ip, ports, timeout)
                    total = round(time.time()-start,4)
                    open_only = [r for r in syn_results if r[2]=="open"]
                    print_table_open(ip, open_only, total, export)
                except Exception as e:
                    print("Stealth scan failed:", e)
            else:
                open_only, total = run_probes(ip, ports, proto, timeout, threads, banner_choice)
                print_table_open(ip, open_only, total, export)

if __name__ == "__main__":
    main()

