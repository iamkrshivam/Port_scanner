#!/usr/bin/env bash
set -e
echo "Updating packages..."
sudo apt update
echo "Installing system packages..."
sudo apt install -y python3 python3-pip python3-dev build-essential libpcap0.8-dev git
echo "Upgrading pip and installing python packages..."
python3 -m pip install --upgrade pip
python3 -m pip install tabulate colorama scapy
echo "Done. You can run the scanner: python3 scanner.py"



