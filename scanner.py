#!/usr/bin/env python3


import socket
import sys
import time
import json
import csv
import threading
import queue
import ipaddress
from typing import List, Dict, Any

# Optional scapy import for stealth SYN scan
try:
    from scapy.all import sr1, IP, TCP, conf
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

# -----------------------
# Config
# -----------------------
DEFAULT_TIMEOUT = 0.25
MAX_THREADS = 300
DEFAULT_THREADS = 100
TOP_TCP_PORTS = [80, 443, 22, 21, 25, 53, 110, 445, 3306, 8080, 8443, 139, 135, 143, 993, 995]
TOP_UDP_PORTS = [53, 123, 161, 69, 67, 68, 500, 1900, 5060, 12345]

# -----------------------
# Utilities
# -----------------------
def safe_input(prompt: str):
    """Return user input or None if interrupted (Ctrl-C / Ctrl-D)."""
    try:
        return input(prompt)
    except (KeyboardInterrupt, EOFError):
        print()  # newline after ^C/^D
        return None

def parse_ports(port_str: str) -> List[int]:
    """Parse a string like '1,2,10-20' into a sorted list of unique port ints."""
    out = set()
    for part in port_str.split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            try:
                a, b = part.split('-', 1)
                a_i = int(a); b_i = int(b)
                if a_i > b_i: a_i, b_i = b_i, a_i
                out.update(range(max(1, a_i), min(65535, b_i) + 1))
            except Exception:
                continue
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    out.add(p)
            except Exception:
                continue
    return sorted(out)

def expand_targets(target_input: str) -> List[str]:
    """
    Accepts:
      - single host/ip (example.com or 8.8.8.8)
      - comma-separated hosts
      - CIDR like 192.168.1.0/28
      - file prefixed with @ (e.g. @hosts.txt)
    Returns deduped list preserving order.
    """
    if not target_input:
        return []
    target_input = target_input.strip()
    targets = []
    if target_input.startswith('@'):
        fn = target_input[1:]
        try:
            with open(fn, 'r') as f:
                for ln in f:
                    ln = ln.strip()
                    if ln:
                        targets += expand_targets(ln)
            # preserve order, dedupe
            seen = set(); out = []
            for t in targets:
                if t not in seen:
                    seen.add(t); out.append(t)
            return out
        except Exception:
            return []
    parts = [p.strip() for p in target_input.split(',') if p.strip()]
    for part in parts:
        # CIDR
        if '/' in part:
            try:
                net = ipaddress.ip_network(part, strict=False)
                for ip in net.hosts():
                    targets.append(str(ip))
                continue
            except Exception:
                pass
        targets.append(part)
    seen = set(); out = []
    for t in targets:
        if t not in seen:
            seen.add(t); out.append(t)
    return out

def resolve_host(host: str) -> str:
    """Resolve hostname to IP; on failure return original string."""
    try:
        return socket.gethostbyname(host)
    except Exception:
        return host

# -----------------------
# Scanning primitives
# -----------------------
def tcp_worker(task_q: queue.Queue, result_q: queue.Queue, timeout: float, grab_banner: bool):
    while True:
        try:
            target, port = task_q.get_nowait()
        except queue.Empty:
            return
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            start = time.time()
            s.connect((target, port))
            elapsed = time.time() - start
            banner = ""
            if grab_banner:
                try:
                    s.settimeout(1.0)
                    s.sendall(b"\r\n")
                    banner = s.recv(1024).decode(errors='ignore').strip()
                except Exception:
                    banner = ""
            result_q.put({"host": target, "port": port, "proto": "tcp", "state": "open", "time": round(elapsed,4), "banner": banner})
        except (socket.timeout, ConnectionRefusedError):
            pass
        except Exception:
            pass
        finally:
            try: s.close()
            except Exception: pass
            task_q.task_done()

def tcp_connect_scan(target_ip: str, ports: List[int], timeout: float = DEFAULT_TIMEOUT,
                     threads: int = DEFAULT_THREADS, grab_banner: bool = False) -> List[Dict[str,Any]]:
    """Threaded TCP connect scan. Returns list of open ports dicts."""
    tasks = queue.Queue()
    results = queue.Queue()
    for p in ports:
        tasks.put((target_ip, p))
    tcount = min(max(1, threads), tasks.qsize())
    ths = []
    for _ in range(tcount):
        th = threading.Thread(target=tcp_worker, args=(tasks, results, timeout, grab_banner), daemon=True)
        th.start()
        ths.append(th)
    tasks.join()
    out = []
    while not results.empty():
        out.append(results.get())
    out.sort(key=lambda x: x['port'])
    return out

def udp_worker(task_q: queue.Queue, result_q: queue.Queue, timeout: float):
    while True:
        try:
            target, port = task_q.get_nowait()
        except queue.Empty:
            return
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            start = time.time()
            s.sendto(b'', (target, port))
            try:
                data, _ = s.recvfrom(1024)
                elapsed = time.time() - start
                result_q.put({"host": target, "port": port, "proto": "udp", "state": "open", "time": round(elapsed,4), "banner": data.decode(errors='ignore')})
            except socket.timeout:
                # no response -> open|filtered (best-effort)
                result_q.put({"host": target, "port": port, "proto": "udp", "state": "open|filtered", "time": timeout, "banner": ""})
            except Exception:
                pass
        except Exception:
            pass
        finally:
            try: s.close()
            except Exception: pass
            task_q.task_done()

def udp_scan(target_ip: str, ports: List[int], timeout: float = 1.0, threads: int = DEFAULT_THREADS) -> List[Dict[str,Any]]:
    tasks = queue.Queue()
    results = queue.Queue()
    for p in ports:
        tasks.put((target_ip, p))
    tcount = min(max(1, threads), tasks.qsize())
    for _ in range(tcount):
        th = threading.Thread(target=udp_worker, args=(tasks, results, timeout), daemon=True)
        th.start()
    tasks.join()
    out = []
    while not results.empty():
        out.append(results.get())
    out.sort(key=lambda x: x['port'])
    return out

def stealth_syn_scan_scapy(target_ip: str, ports: List[int], timeout: float = 1.0) -> List[Dict[str,Any]]:
    """
    Single-threaded SYN scan using scapy. Interprets SYN-ACK as open, RST as closed.
    Note: scapy must be installed and you must run as root (or with capabilities).
    """
    if not SCAPY_AVAILABLE:
        raise RuntimeError("Scapy not available")
    conf.verb = 0
    out = []
    for p in ports:
        pkt = IP(dst=target_ip)/TCP(dport=p, flags='S')
        resp = sr1(pkt, timeout=timeout)
        if resp is None:
            state = "filtered"
        else:
            if resp.haslayer(TCP):
                flags = resp.getlayer(TCP).flags
                # SYN-ACK -> open; RST -> closed
                if flags & 0x12 == 0x12:
                    state = "open"
                elif flags & 0x14 == 0x14 or flags & 0x04 == 0x04:
                    state = "closed"
                else:
                    state = "unknown"
            else:
                state = "unknown"
        out.append({"host": target_ip, "port": p, "proto": "tcp(syn)", "state": state, "time": None, "banner": ""})
    return out

# -----------------------
# Export helpers
# -----------------------
def save_json(filename: str, data: List[Dict[str,Any]]):
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)

def save_csv(filename: str, data: List[Dict[str,Any]]):
    keys = ["host","port","proto","state","time","banner"]
    with open(filename, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        for row in data:
            writer.writerow({k: row.get(k, "") for k in keys})

# -----------------------
# CLI / Menu
# -----------------------
def print_menu():
    print("\n=== Menu ===")
    print("1) Full TCP scan (1-65535)        [very slow]")
    print("2) Fast TCP top ports (preset)")
    print("3) Fast UDP top ports (preset)")
    print("4) Both TCP+UDP top ports")
    print("5) Stealth SYN scan (requires scapy & root)")
    print("6) Custom ports (enter ranges/comma)")
    print("q) Quit\n")

def prompt_common():
    """Return (targets:list, save_choice:str, save_filename:str, grab_banner:bool, timeout:float, threads:int) or None if cancelled"""
    t_raw = safe_input("Target (IP/host/list/CIDR or @file): ")
    if t_raw is None:
        return None
    targets = expand_targets(t_raw.strip())
    if not targets:
        print("No valid targets supplied.")
        return None

    save_raw = safe_input("Save results (file.json / file.csv / none) [none]: ")
    if save_raw is None:
        return None
    save_raw = save_raw.strip()
    save_choice = 'none'; save_filename = ''
    if save_raw.lower().endswith('.json'):
        save_choice = 'json'; save_filename = save_raw
    elif save_raw.lower().endswith('.csv'):
        save_choice = 'csv'; save_filename = save_raw
    elif save_raw.lower() in ('json','csv'):
        save_choice = save_raw.lower(); save_filename = f"scan_results.{save_choice}"

    grabb_raw = safe_input("Grab banners on TCP open ports? (y/N): ")
    if grabb_raw is None:
        return None
    grab_banner = grabb_raw.strip().lower() == 'y'

    to_raw = safe_input(f"Per-connection timeout seconds (default {DEFAULT_TIMEOUT}): ")
    if to_raw is None:
        return None
    try:
        timeout = float(to_raw.strip()) if to_raw.strip() else DEFAULT_TIMEOUT
    except Exception:
        timeout = DEFAULT_TIMEOUT

    thr_raw = safe_input(f"Threads (1-{MAX_THREADS}) [default {DEFAULT_THREADS}]: ")
    if thr_raw is None:
        return None
    try:
        threads = int(thr_raw.strip()) if thr_raw.strip() else DEFAULT_THREADS
        threads = max(1, min(MAX_THREADS, threads))
    except Exception:
        threads = DEFAULT_THREADS

    return targets, save_choice, save_filename, grab_banner, timeout, threads

def print_scan_results(target_ip: str, results: List[Dict[str,Any]], duration: float):
    if not results:
        print(f"No open ports found for {target_ip}. Scan time: {round(duration,4)}s")
        return
    print(f"\nHost: {target_ip}")
    print("╒══════╤═══════╤══════════╤═══════════╤═════════╤════════════════════════╕")
    print("│ PORT │ PROTO │  STATE   │ SERVICE   │ TIME(s) │ BANNER                 │")
    print("╞══════╪═══════╪══════════╪═══════════╪═════════╪════════════════════════╡")
    for r in results:
        p = r.get('port')
        proto = r.get('proto')
        state = r.get('state')
        t = r.get('time') if r.get('time') is not None else ""
        banner = (r.get('banner') or "")[:24].replace('\n',' ')
        service = ""
        try:
            # some protos are tcp(syn) etc; use tcp/udp for lookup
            proto_base = proto.split('/')[0]
            service = socket.getservbyport(int(p), proto_base) if str(p).isdigit() else ""
        except Exception:
            service = ""
        print(f"│ {str(p).rjust(4)} │ {proto.center(5)} │ {state.center(8)} │ {service.center(9)} │ {str(t).rjust(7)} │ {banner.ljust(22)} │")
    print("╘══════╧═══════╧══════════╧═══════════╧═════════╧════════════════════════╛")

def export_results(all_results: List[Dict[str,Any]], save_choice: str, save_filename: str):
    if not all_results or save_choice == 'none':
        return
    try:
        if save_choice == 'json':
            save_json(save_filename, all_results)
        elif save_choice == 'csv':
            save_csv(save_filename, all_results)
        print(f"Saved results to {save_filename}")
    except Exception as e:
        print(f"Failed to save results: {e}")

def handle_choice(choice: str):
    common = prompt_common()
    if common is None:
        return
    targets, save_choice, save_filename, grab_banner, timeout, threads = common

    if choice == '1':
        ports = list(range(1, 65536))
        for t in targets:
            ip = resolve_host(t)
            print(f"\nScanning {t} -> {ip} (TCP full 1-65535). This will be slow.")
            start = time.time()
            res = tcp_connect_scan(ip, ports, timeout=timeout, threads=threads, grab_banner=grab_banner)
            duration = time.time() - start
            print_scan_results(ip, res, duration)
            export_results(res, save_choice, save_filename)
    elif choice == '2':
        ports = TOP_TCP_PORTS
        for t in targets:
            ip = resolve_host(t)
            print(f"\nScanning {t} -> {ip} (Fast TCP top ports).")
            start = time.time()
            res = tcp_connect_scan(ip, ports, timeout=timeout, threads=threads, grab_banner=grab_banner)
            duration = time.time() - start
            print_scan_results(ip, res, duration)
            export_results(res, save_choice, save_filename)
    elif choice == '3':
        ports = TOP_UDP_PORTS
        for t in targets:
            ip = resolve_host(t)
            print(f"\nScanning {t} -> {ip} (Fast UDP top ports).")
            start = time.time()
            res = udp_scan(ip, ports, timeout=max(1.0, timeout), threads=threads)
            duration = time.time() - start
            print_scan_results(ip, res, duration)
            export_results(res, save_choice, save_filename)
    elif choice == '4':
        for t in targets:
            ip = resolve_host(t)
            print(f"\nScanning {t} -> {ip} (TCP+UDP top ports).")
            start = time.time()
            res_tcp = tcp_connect_scan(ip, TOP_TCP_PORTS, timeout=timeout, threads=threads, grab_banner=grab_banner)
            res_udp = udp_scan(ip, TOP_UDP_PORTS, timeout=max(1.0, timeout), threads=threads)
            duration = time.time() - start
            combined = res_tcp + res_udp
            print_scan_results(ip, combined, duration)
            export_results(combined, save_choice, save_filename)
    elif choice == '5':
        if not SCAPY_AVAILABLE:
            print("Scapy not available. Install scapy (pip3 install scapy) and run as root for stealth SYN scan.")
            return
        # use TOP_TCP_PORTS by default; allow user to override via prompt if desired
        ports = TOP_TCP_PORTS
        for t in targets:
            ip = resolve_host(t)
            print(f"\nStealth SYN scanning {t} -> {ip}. (scapy single-threaded)")
            start = time.time()
            res = stealth_syn_scan_scapy(ip, ports, timeout=max(0.5, timeout))
            duration = time.time() - start
            print_scan_results(ip, res, duration)
            export_results(res, save_choice, save_filename)
    elif choice == '6':
        port_input = safe_input("Enter ports (e.g. 80,443,1-1024): ")
        if port_input is None:
            return
        ports = parse_ports(port_input.strip())
        if not ports:
            print("No valid ports parsed.")
            return
        proto_raw = safe_input("Protocol (tcp/udp/both) [tcp]: ")
        if proto_raw is None:
            return
        proto = proto_raw.strip().lower() if proto_raw.strip() else 'tcp'
        for t in targets:
            ip = resolve_host(t)
            if proto in ('tcp', 'both'):
                print(f"\nTCP scanning {t} -> {ip} (custom ports).")
                start = time.time()
                res_tcp = tcp_connect_scan(ip, ports, timeout=timeout, threads=threads, grab_banner=grab_banner)
                duration = time.time() - start
                print_scan_results(ip, res_tcp, duration)
                export_results(res_tcp, save_choice, save_filename)
            if proto in ('udp', 'both'):
                print(f"\nUDP scanning {t} -> {ip} (custom ports).")
                start = time.time()
                res_udp = udp_scan(ip, ports, timeout=max(1.0, timeout), threads=threads)
                duration = time.time() - start
                print_scan_results(ip, res_udp, duration)
                export_results(res_udp, save_choice, save_filename)
    else:
        print("Unknown choice.")

# -----------------------
# Main entry
# -----------------------
def main():
    print("="*58)
    print("   Advanced Python Port Scanner (connect/udp/syn)   ")
    print("="*58)
    while True:
        try:
            print_menu()
            raw = safe_input("Choose option number: ")
            if raw is None:
                print("Exiting — interrupted by user.")
                break
            choice = raw.strip().lower()
            if choice in ('q', 'quit', 'exit'):
                print("Quitting.")
                break
            if choice not in {"1","2","3","4","5","6"}:
                print("Invalid choice. Enter 1-6 or q to quit.")
                continue
            handle_choice(choice)
        except KeyboardInterrupt:
            print("\nExiting — interrupted by user.")
            break

if __name__ == "__main__":
    main()
