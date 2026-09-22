# Cerebria

<img width="1729" height="906" alt="image" src="https://github.com/user-attachments/assets/4598c451-81d9-44a7-9b0f-c1f5e37d3846" /> 

Modular OSINT & reconnaissance dashboard built with FastAPI.
Modules

    IP Whois — Autonomous system, network routing, and deep geolocation lookup

    Phone HLR — Cellular carrier detection, international standard mapping & line validation

    Subdomains — Passive subdomain enumeration via Certificate Transparency logs

    VPN & Proxy — Detects commercial VPNs, Proxies, and Datacenter IPs

    Port Scanner — High-performance asynchronous TCP scanning of Top-20 critical ports

    Minecraft Recon — Server status and SRV records resolution

Requirements

    Python 3.11+

    Nmap (sudo pacman -S nmap or your system package manager)

Setup
Bash

git clone https://github.com/ArchEnjoyer333/Cerebria-OSINT.git
cd Cerebria-OSINT

python3 -m venv .venv

# For Bash / Zsh:
source .venv/bin/activate

# For Fish:
source .venv/bin/activate.fish

pip install -r requirements.txt

Usage:

Bash

python3 main.py
