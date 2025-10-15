What it is

A fast interactive port scanner for Parrot OS / Debian.
Features: auto-tuned timeouts, colored tabular output, TCP/UDP scans, optional banner grab, optional stealth (SYN) scan via scapy, export to JSON/CSV.

Files

scanner.py — main scanner script.

requirements.txt — Python packages.

install.sh — installer script (optional).

README.md — this file.

Quick start (one-step copy-paste)

Run this single command in your Parrot OS terminal. It will update apt, install system deps, install Python packages, and make the scanner ready.

sudo apt update && sudo apt install -y python3 python3-pip python3-dev build-essential libpcap0.8-dev git && \
python3 -m pip install --upgrade pip && \
python3 -m pip install tabulate colorama scapy


Notes:

scapy is required only for stealth (SYN) scans. If you do not need stealth, omit it.

Running stealth scan requires root privileges. Use the scanner with sudo only when performing stealth scans and when you have permission.
