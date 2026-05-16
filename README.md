<div align="center">
  
# RapidRecon Pro
**Advanced Network Reconnaissance & Audit Tool**

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Status: Production](https://img.shields.io/badge/Status-Production-success.svg)](#)

</div>

## Overview
**RapidRecon Pro** is an enterprise-grade, highly concurrent network reconnaissance and forensic audit tool developed by SUT PROJECTS. Designed for authorized penetration testing and proactive security monitoring, RapidRecon seamlessly blends lightning-fast asynchronous port scanning with deep vulnerability analysis, compiling results into beautifully formatted terminal outputs and interactive HTML dashboards.

---

## ⚡ Key Features
- **High-Concurrency Scanning**: Uses `asyncio` to scan hundreds of ports and hosts simultaneously, minimizing network audit times.
- **Vulnerability Intelligence**: Cross-references open ports against a database of 40+ known vulnerabilities, mapping services to CVE references.
- **Smart OS & Service Fingerprinting**: Automatically parses service banners to intelligently detect vendors (Huawei, TP-Link, MikroTik, Apache, Nginx, etc.).
- **Nmap Enrichment (Optional)**: Seamlessly integrates with standard Nmap `-sV -O` flags for granular OS and service identification.
- **Professional Reporting**: Generates interactive, visually stunning HTML forensic reports automatically.
- **User-Friendly Interactive Wizard**: A straightforward CLI wizard for users who prefer guided executions over command-line flags.

---

## 🛠️ Installation

### Prerequisites
- **Python 3.8+**
- **Nmap**: Required for advanced operating system and service fingerprinting (`--nmap` flag).
  - *Linux*: `sudo apt install nmap`
  - *macOS*: `brew install nmap`
  - *Windows*: Download from the [official Nmap site](https://nmap.org/download.html)

### Setup
1. Clone the repository (or download the script):
   ```bash
   git clone https://github.com/your-org/RapidReconPro.git
   cd RapidReconPro
   ```

2. No external Python dependencies are strictly required! The tool is built primarily on Python standard libraries for ultimate portability.

3. Make it executable (Linux/macOS):
   ```bash
   chmod +x RapidRecon.py
   ```

---

## 🚀 Usage

### 1. Interactive Wizard
For an easy, guided setup, simply run the script without any arguments:
```bash
python3 RapidRecon.py
```
*The wizard will prompt you for the target IP/Subnet, Port ranges, concurrency levels, and report output directories.*

### 2. Command Line Interface
For advanced users or automated scripts, use the command-line flags:

**Basic Scan (Targeting a subnet)**
```bash
python3 RapidRecon.py -t 192.168.1.0/24
```

**Advanced Scan (Specific ports, Nmap integration, High concurrency)**
```bash
# Requires sudo on Linux for optimal Nmap OS detection
sudo python3 RapidRecon.py -t 10.0.0.1-10.0.0.100 -p 21,22,80,443,445,3389 --nmap --concurrency 1000
```

### CLI Arguments
| Flag | Name | Description | Default |
| :--- | :--- | :--- | :--- |
| `-t`, `--target` | Target | **(Required)** Target IP, CIDR (e.g., `192.168.1.0/24`), or range (`10.0.0.1-10`) | *None* |
| `-p`, `--ports` | Ports | Comma-separated list or range of ports to scan. | `1-1024` |
| `--nmap` | Nmap Sync | Enables deep Nmap OS and service scanning on discovered ports. | `False` |
| `--timeout` | Timeout | Connection timeout per port in seconds. | `1.0` |
| `--concurrency` | Concurrency | Maximum simultaneous concurrent connections. | `500` |
| `--output` | Output Dir | Directory to save the generated HTML report. | `./reports/` |
| `-v`, `--verbose` | Verbose | Enable debug-level logging. | `False` |
| `-q`, `--quiet` | Quiet Mode | Suppress ASCII banner and progress output. | `False` |

---

## 👨‍💻 Authors & Credits

**SUT PROJECTS** — Forensic Auditing Team
- **Mohamed Abdelrazek (NOAH)** - *Lead Developer*
- **Mohamed Hany**
- **Seif**
- **Anwar**

---

## ⚠️ Legal Disclaimer
**AUTHORIZED USE ONLY.** RapidRecon Pro is designed solely for use by authorized security professionals and system administrators. The authors are not responsible for any misuse or damage caused by this software. Always ensure you have explicit permission before scanning any network or device.
