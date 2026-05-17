#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  SUT PROJECTS — Advanced Network Reconnaissance & Audit Tool     ║
║  Version: 3.0 (Enterprise Edition)                               ║
║  Authors: Mohamed Abdelrazek (NOAH), Mohamed Hany, Seif, Anwar   ║
║  License: Authorized Penetration Testing Use Only                ║
╚══════════════════════════════════════════════════════════════════╝

RapidRecon Pro is an asynchronous network discovery and vulnerability
analysis tool designed for enterprise environments.
"""

import argparse
import asyncio
import ipaddress
import logging
import os
import platform
import re
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Set

# ══════════════════════════════════════════════════════════════
# § 0  UTILITIES, VISUALS & LOGGING
# ══════════════════════════════════════════════════════════════

TERMINAL_COLORS: Dict[str, str] = {
    "reset": "\033[0m", "bold": "\033[1m", "cyan": "\033[36m", 
    "green": "\033[32m", "yellow": "\033[33m", "red": "\033[31m", 
    "blue": "\033[34m", "mag": "\033[35m", "gray": "\033[90m"
}

def colorize_text(color_name: str, text: str) -> str:
    """
    Wraps text in ANSI color codes for terminal output.

    Args:
        color_name (str): The name of the color from TERMINAL_COLORS.
        text (str): The text to colorize.

    Returns:
        str: The colorized string.
    """
    return f"{TERMINAL_COLORS.get(color_name, '')}{text}{TERMINAL_COLORS['reset']}"

class ColorLogFormatter(logging.Formatter):
    """Custom logging formatter to inject ANSI colors based on log level."""
    
    LEVEL_COLORS = {
        logging.DEBUG: "gray",
        logging.INFO: "cyan",
        logging.WARNING: "yellow",
        logging.ERROR: "red",
        logging.CRITICAL: "red"
    }

    def format(self, record: logging.LogRecord) -> str:
        log_color = self.LEVEL_COLORS.get(record.levelno, "reset")
        prefix = ""
        if record.levelno == logging.INFO:
            prefix = "[*]"
        elif record.levelno == logging.WARNING:
            prefix = "[!]"
        elif record.levelno >= logging.ERROR:
            prefix = "[x]"
        elif record.levelno == logging.DEBUG:
            prefix = "[+]"
            
        # Avoid double coloring if the user already colorized the message manually
        if "\033[" not in str(record.msg):
            record.msg = colorize_text(log_color, f" {prefix} {record.msg}")
        return super().format(record)

def setup_logger(verbose: bool, quiet: bool) -> logging.Logger:
    """
    Configures the root logger for the application.

    Args:
        verbose (bool): If True, sets log level to DEBUG.
        quiet (bool): If True, sets log level to CRITICAL to suppress output.

    Returns:
        logging.Logger: The configured logger instance.
    """
    app_logger = logging.getLogger("RapidRecon")
    # Clear existing handlers
    if app_logger.hasHandlers():
        app_logger.handlers.clear()
        
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(ColorLogFormatter("%(message)s"))
    app_logger.addHandler(handler)
    
    if quiet:
        app_logger.setLevel(logging.CRITICAL)
    elif verbose:
        app_logger.setLevel(logging.DEBUG)
    else:
        app_logger.setLevel(logging.INFO)
        
    return app_logger

logger = logging.getLogger("RapidRecon")

# ══════════════════════════════════════════════════════════════
# § 1  DATA ARCHITECTURE
# ══════════════════════════════════════════════════════════════

@dataclass
class PortDiscovery:
    """Represents the results of a single port scan."""
    port: int
    state: str
    service: str = "Unknown"
    banner: str = ""
    version: str = ""
    risk_level: str = "info"  # critical, high, medium, low, info
    risk_description: str = "Service detected"
    cve_reference: str = ""
    recommendation: str = "No immediate action required"

@dataclass
class HostDiscovery:
    """Represents the collected data for a single network host."""
    ip: str
    hostname: str = ""
    mac_address: str = "Unknown"
    vendor: str = "Unknown"
    os_guess: str = "Unknown"
    ttl: int = 0
    latency: str = "0ms"
    is_public: bool = False
    open_ports: Dict[int, PortDiscovery] = field(default_factory=dict)
    highest_risk: str = "none"
    scan_timestamp: str = field(default_factory=lambda: datetime.now().strftime("%H:%M:%S"))

# ══════════════════════════════════════════════════════════════
# § 2  SCANNING ENGINE (ASYNC CORE)
# ══════════════════════════════════════════════════════════════

class NetworkScanner:
    """Core engine for high-concurrency host and port discovery."""
    
    def __init__(self, timeout: float = 1.0, concurrency: int = 500) -> None:
        """
        Initializes the scanner with specified parameters.
        
        Args:
            timeout (float): Connection timeout in seconds.
            concurrency (int): Maximum number of concurrent async tasks.
        """
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(concurrency)

    async def discover_live_hosts(self, target_range: str) -> List[HostDiscovery]:
        """
        Scans a subnet or IP range to identify live systems.
        
        Args:
            target_range (str): IP address, CIDR, or range (e.g. 192.168.1.0/24).
            
        Returns:
            List[HostDiscovery]: A list of discovered live hosts.
        """
        ips = self._expand_target(target_range)
        if not ips:
            logger.error(f"Invalid target range provided: {target_range}")
            return []
            
        logger.info(f"Discovering hosts in {target_range} (Total IPs: {len(ips)})...")
        
        live_hosts = []
        tasks = [self._probe_single_host(ip) for ip in ips]
        
        # Live progress UI
        completed = 0
        total = len(tasks)
        for coro in asyncio.as_completed(tasks):
            res = await coro
            completed += 1
            if res:
                live_hosts.append(res)
            sys.stdout.write(f"\r{TERMINAL_COLORS['cyan']}[*]{TERMINAL_COLORS['reset']} Scanning: {completed}/{total} | Found: {len(live_hosts)} live hosts")
            sys.stdout.flush()
        print() # Clear the progress line with a newline
        
        # Log manually colored success message to preserve the green checkmark look
        logger.info(colorize_text("green", f"[✓] Discovery complete. Found {len(live_hosts)} active hosts."))
        return sorted(live_hosts, key=lambda x: list(map(int, x.ip.split("."))))

    def _expand_target(self, target: str) -> List[str]:
        """Expands CIDR or range notation into a list of IP strings."""
        try:
            if "/" in target: 
                return [str(ip) for ip in ipaddress.ip_network(target, strict=False).hosts()]
            if "-" in target:
                start, end = target.split("-")
                if "." not in end: 
                    end = ".".join(start.split(".")[:3]) + "." + end
                return [str(ipaddress.ip_address(i)) for i in range(int(ipaddress.ip_address(start)), int(ipaddress.ip_address(end)) + 1)]
            return [str(ipaddress.ip_address(target))]
        except ValueError as e:
            logger.debug(f"Target expansion error: {e}")
            return []

    async def _probe_single_host(self, ip: str) -> Optional[HostDiscovery]:
        """Checks if a host is alive via ICMP or common TCP ports."""
        async with self.semaphore:
            is_alive, ttl, latency = await self._ping_host_async(ip)
            
            if not is_alive:
                # Fallback TCP probe for firewalled hosts blocking ICMP
                is_alive = await self._quick_tcp_check(ip, [80, 443, 22, 445])
            
            if is_alive:
                logger.debug(f"Host {ip} is UP ({latency})")
                host = HostDiscovery(ip=ip, ttl=ttl, latency=latency)
                try:
                    if not ipaddress.ip_address(ip).is_private:
                        host.is_public = True
                except ValueError:
                    pass
                return host
            return None

    async def _ping_host_async(self, ip: str) -> Tuple[bool, int, str]:
        """Standard ICMP ping wrapper using async subprocess."""
        param = "-n" if platform.system().lower() == "windows" else "-c"
        wait = "-w" if platform.system().lower() == "windows" else "-W"
        timeout_val = str(int(self.timeout * 1000)) if platform.system().lower() == "windows" else str(int(self.timeout))
        
        try:
            start_time = time.perf_counter()
            proc = await asyncio.create_subprocess_exec(
                "ping", param, "1", wait, timeout_val, ip,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=self.timeout + 1.5)
            duration = f"{int((time.perf_counter() - start_time) * 1000)}ms"
            
            if proc.returncode == 0:
                out_str = stdout.decode(errors='ignore')
                ttl_match = re.search(r"ttl=(\d+)", out_str, re.I)
                ttl = int(ttl_match.group(1)) if ttl_match else 0
                return True, ttl, duration
            return False, 0, "0ms"
        except (asyncio.TimeoutError, FileNotFoundError, OSError) as e:
            logger.debug(f"Ping failed for {ip}: {e}")
            try:
                proc.kill()
            except Exception:
                pass
            return False, 0, "0ms"

    async def _quick_tcp_check(self, ip: str, ports: List[int]) -> bool:
        """Rapidly checks for a handful of open ports to confirm host life."""
        for port in ports:
            try:
                _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=0.5)
                writer.close()
                await writer.wait_closed()
                return True
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                continue
        return False

    async def perform_port_scan(self, host: HostDiscovery, port_range: str) -> None:
        """
        Scans specified ports on a host and attempts service identification.
        
        Args:
            host (HostDiscovery): The target host to scan.
            port_range (str): Range of ports (e.g. 80,443,1-1000).
        """
        ports = self._parse_port_range(port_range)
        logger.info(f"Scanning {len(ports)} ports on {host.ip}...")
        
        if host.ttl > 0:
            if host.ttl <= 64: host.os_guess = "Linux/Unix"
            elif host.ttl <= 128: host.os_guess = "Windows"
            elif host.ttl <= 255: host.os_guess = "Network Device"

        # Identify MAC and Hostname
        host.mac_address = await self._resolve_mac_async(host.ip)
        loop = asyncio.get_event_loop()
        try:
            # Add a timeout to gethostbyaddr so it doesn't block indefinitely
            def _resolve_host():
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(0.5)
                return socket.gethostbyaddr(host.ip)[0]
            host.hostname = await asyncio.wait_for(loop.run_in_executor(None, _resolve_host), timeout=1.0)
        except Exception as e:
            logger.debug(f"Hostname resolution failed for {host.ip}: {e}")
            host.hostname = host.ip
        
        tasks = [self._probe_single_port(host.ip, p) for p in ports]
        results = await asyncio.gather(*tasks)
        
        for port, state in results:
            if state == "open":
                host.open_ports[port] = PortDiscovery(port=port, state=state)
        
        logger.debug(f"{host.ip}: Found {len(host.open_ports)} open ports.")

    async def _probe_single_port(self, ip: str, port: int) -> Tuple[int, str]:
        """Checks if a single TCP port is open asynchronously."""
        async with self.semaphore:
            try:
                _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=self.timeout)
                writer.close()
                await writer.wait_closed()
                return port, "open"
            except asyncio.TimeoutError:
                return port, "closed"
            except ConnectionRefusedError:
                return port, "closed"
            except OSError as e:
                logger.debug(f"OS Error probing {ip}:{port} - {e}")
                return port, "error"

    def _parse_port_range(self, expression: str) -> List[int]:
        """Converts user port input (e.g. 80,443,1-100) into a sorted list."""
        ports: Set[int] = set()
        for part in expression.split(","):
            try:
                if "-" in part:
                    start, end = part.split("-")
                    ports.update(range(int(start), int(end) + 1))
                else:
                    ports.add(int(part))
            except ValueError:
                logger.warning(f"Skipping invalid port expression: {part}")
        return sorted(list(ports))

    async def _resolve_mac_async(self, ip: str) -> str:
        """Retrieves MAC address from the local ARP cache using async subprocess."""
        try:
            if platform.system().lower() != "windows":
                proc = await asyncio.create_subprocess_exec(
                    "ip", "neighbor", "show", ip,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=1.0)
                match = re.search(r"([0-9a-f]{2}[:-]){5}([0-9a-f]{2})", stdout.decode(errors='ignore'), re.I)
                return match.group(0).upper() if match else "Unknown"
            else:
                proc = await asyncio.create_subprocess_exec(
                    "arp", "-a", ip,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=1.0)
                match = re.search(r"([0-9a-f]{2}-){5}[0-9a-f]{2}", stdout.decode(errors='ignore'), re.I)
                return match.group(0).upper().replace("-", ":") if match else "Unknown"
        except Exception as e:
            logger.debug(f"MAC resolution failed for {ip}: {e}")
            return "Unknown"

# ══════════════════════════════════════════════════════════════
# § 3  VULNERABILITY & SERVICE ANALYST
# ══════════════════════════════════════════════════════════════

class SecurityAnalyst:
    """Analyzes services and identifies potential security vulnerabilities."""
    
    # 40+ Common Vulnerable Services & Risks
    VULN_DATABASE: Dict[int, Tuple[str, str, str, str]] = {
        21: ("critical", "FTP - Plaintext Authentication", "CVE-2011-2523", "Use SFTP or FTPS"),
        22: ("info", "SSH - Secure Shell", "", "Ensure strong key-based auth"),
        23: ("critical", "Telnet - Unencrypted Access", "CVE-2020-10188", "Disable Telnet; use SSH"),
        25: ("medium", "SMTP - Mail Transfer", "CVE-2020-28018", "Disable open relays"),
        53: ("low", "DNS - Domain Name System", "CVE-2015-1635", "Protect against DNS amplification"),
        69: ("high", "TFTP - Trivial File Transfer", "", "Disable if not required"),
        80: ("medium", "HTTP - Web Service", "", "Redirect to HTTPS"),
        88: ("medium", "Kerberos - Auth Service", "CVE-2020-1472", "Patch against ZeroLogon"),
        110: ("high", "POP3 - Plaintext Mail", "", "Use POP3S"),
        111: ("medium", "RPCBind", "CVE-2017-0626", "Restrict via firewall"),
        135: ("high", "MSRPC", "CVE-2003-0352", "Restrict access to internal only"),
        137: ("medium", "NetBIOS", "", "Disable NetBIOS over TCP/IP"),
        139: ("critical", "NetBIOS-SSN", "CVE-2017-7494", "Samba Vulnerability - Patch immediately"),
        143: ("high", "IMAP - Plaintext Mail", "", "Use IMAPS"),
        161: ("high", "SNMP - Monitoring", "CVE-2017-12240", "Change default community strings"),
        389: ("high", "LDAP - Directory Access", "", "Use LDAPS"),
        443: ("info", "HTTPS - Secure Web", "", "Monitor certificate expiry"),
        445: ("critical", "SMB - Microsoft-DS", "CVE-2017-0144", "EternalBlue risk - Disable SMBv1"),
        512: ("critical", "Rexec", "", "Highly insecure - Disable"),
        513: ("critical", "Rlogin", "", "Highly insecure - Disable"),
        514: ("critical", "Rsh", "", "Highly insecure - Disable"),
        548: ("medium", "AFP - Apple Filing", "CVE-2017-12151", "Restrict access"),
        631: ("low", "CUPS - Printing", "CVE-2023-4504", "Patch if exposed"),
        873: ("high", "Rsync", "CVE-2017-14159", "Use SSH for rsync transport"),
        993: ("info", "IMAPS", "", "Safe"),
        995: ("info", "POP3S", "", "Safe"),
        1080: ("high", "SOCKS Proxy", "", "Ensure not an open proxy"),
        1433: ("high", "MSSQL - SQL Server", "CVE-2019-1068", "Use strong passwords & patch"),
        1521: ("high", "Oracle DB", "CVE-2018-3110", "Protect against TNS listener attacks"),
        2049: ("medium", "NFS - Network File System", "CVE-2017-12151", "Restrict export list"),
        3306: ("medium", "MySQL", "CVE-2016-6662", "Do not expose to public WAN"),
        3389: ("critical", "RDP - Remote Desktop", "CVE-2019-0708", "BlueKeep risk - Use MFA/VPN"),
        5432: ("medium", "PostgreSQL", "", "Restrict access"),
        5900: ("high", "VNC", "CVE-2019-15678", "Encrypt VNC traffic"),
        6379: ("high", "Redis", "CVE-2016-8339", "Bind to localhost/Internal"),
        8080: ("medium", "HTTP Proxy", "", "Audit exposed dashboards"),
        8443: ("medium", "HTTPS Proxy", "", "Audit exposed dashboards"),
        27017: ("high", "MongoDB", "CVE-2019-2386", "Enable authentication"),
    }

    def __init__(self) -> None:
        self.nmap_semaphore = asyncio.Semaphore(5)

    async def analyze_results(self, host_map: Dict[str, HostDiscovery], use_nmap: bool = False) -> None:
        """
        Performs deep analysis and risk scoring on all discovered hosts.
        
        Args:
            host_map (Dict[str, HostDiscovery]): Dictionary mapping IPs to HostDiscovery objects.
            use_nmap (bool): Whether to trigger Nmap scans for deep enrichment.
        """
        logger.info(f"Performing security analysis on {len(host_map)} hosts...")
        tasks = [self._analyze_single_host(hr, use_nmap) for hr in host_map.values()]
        await asyncio.gather(*tasks)

    async def _analyze_single_host(self, host: HostDiscovery, use_nmap: bool) -> None:
        """Processes a single host for banners, Nmap enrichment, and risk scoring."""
        if use_nmap:
            async with self.nmap_semaphore:
                await self._run_nmap_enrichment(host)

        for port_res in host.open_ports.values():
            # 1. Map known services
            meta = self.VULN_DATABASE.get(port_res.port)
            if meta:
                port_res.risk_level, port_res.service, port_res.cve_reference, port_res.recommendation = meta
                port_res.risk_description = f"Known risk on {port_res.service}"
            
            # 2. Attempt banner grabbing
            banner = await self._grab_banner(host.ip, port_res.port)
            if banner:
                port_res.banner = banner
                # Smart vendor detection from banner
                b_low = banner.lower()
                if "huawei" in b_low: host.vendor = "Huawei"
                elif "tp-link" in b_low: host.vendor = "TP-Link"
                elif "mikrotik" in b_low: host.vendor = "MikroTik"
                elif "apache" in b_low: port_res.service = "Apache Web Server"
                elif "nginx" in b_low: port_res.service = "Nginx Web Server"

            # New Feature: Anonymous FTP Check
            if port_res.port == 21:
                if await self._check_anonymous_ftp(host.ip):
                    port_res.risk_level = "critical"
                    port_res.risk_description = "Anonymous FTP Enabled!"
                    port_res.recommendation = "Disable anonymous login immediately"

            # New Feature: Outdated OpenSSH Check
            if port_res.port == 22 and port_res.banner:
                if any(v in port_res.banner for v in ["OpenSSH_4", "OpenSSH_5", "OpenSSH_6"]):
                    port_res.risk_level = "high"
                    port_res.risk_description = "Outdated OpenSSH Version"
                    port_res.recommendation = "Upgrade OpenSSH immediately"

            # New Feature: Redis No-Auth Check
            if port_res.port == 6379:
                if await self._check_redis_auth(host.ip):
                    port_res.risk_level = "critical"
                    port_res.risk_description = "Redis No-Auth Vulnerability!"
                    port_res.recommendation = "Enable requirepass in redis.conf"

            # New Feature: HTTP Security Headers, CORS, & Web Page Title Check
            if port_res.port in [80, 443, 8080, 8443]:
                headers = await self._check_http_headers(host.ip, port_res.port)
                if headers:
                    server = headers.get("server", "")
                    title = headers.get("page_title", "")
                    details = []
                    if server: details.append(f"Server: {server}")
                    if title: details.append(f"Title: {title}")
                    if details:
                        port_res.version = " | ".join(details)
                    
                    if "x-frame-options" not in headers and port_res.risk_level in ["info", "low"]:
                        port_res.risk_level = "low"
                        port_res.risk_description = "Missing X-Frame-Options (Clickjacking)"
                        
                    acao = headers.get("access-control-allow-origin", "")
                    if acao == "*" or "evil-domain.com" in acao:
                        port_res.risk_level = "high"
                        port_res.risk_description = "Insecure CORS Policy"
                        port_res.recommendation = "Restrict Access-Control-Allow-Origin to trusted domains"

        # 3. Apply Public Edge Exposure Rules (Strict)
        if host.is_public:
            for port, pr in host.open_ports.items():
                if port in [22, 23, 135, 139, 445, 1433, 3306, 3389, 5900]:
                    if pr.risk_level in ["info", "low", "medium"]:
                        pr.risk_level = "critical"
                        pr.risk_description = f"Critical service exposed on PUBLIC WAN!"
                        pr.recommendation = "Block immediately at Edge Firewall"

        # 4. Calculate final host risk score
        self._calculate_host_risk(host)

    async def _check_redis_auth(self, ip: str) -> bool:
        """Returns True if Redis is accessible without authentication."""
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, 6379), timeout=2.0)
            writer.write(b"PING\r\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            writer.close()
            await writer.wait_closed()
            return b"PONG" in data
        except Exception:
            return False

    async def _check_anonymous_ftp(self, ip: str) -> bool:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, 21), timeout=2.0)
            data = await asyncio.wait_for(reader.read(256), timeout=1.0)
            writer.write(b"USER anonymous\r\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(256), timeout=1.0)
            if b"331" in data:
                writer.write(b"PASS anonymous@example.com\r\n")
                await writer.drain()
                data = await asyncio.wait_for(reader.read(256), timeout=1.0)
                if b"230" in data:
                    writer.close()
                    await writer.wait_closed()
                    return True
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        return False

    async def _check_http_headers(self, ip: str, port: int) -> Dict[str, str]:
        headers = {}
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=2.0)
            req = f"GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: RapidRecon/3.0\r\nOrigin: https://evil-domain.com\r\nConnection: close\r\n\r\n"
            writer.write(req.encode())
            await writer.drain()
            
            data = b""
            while True:
                chunk = await asyncio.wait_for(reader.read(2048), timeout=1.5)
                if not chunk: break
                data += chunk
                if len(data) > 16384: break # max 16KB
            writer.close()
            await writer.wait_closed()
            
            content = data.decode(errors='ignore')
            if '\r\n\r\n' in content:
                head, body = content.split('\r\n\r\n', 1)
            else:
                head, body = content, ""
                
            lines = head.split('\r\n')
            for line in lines[1:]:
                if not line: break
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.lower().strip()] = v.strip()
                    
            title_match = re.search(r"<title>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
            if title_match:
                headers['page_title'] = title_match.group(1).strip()
                
        except Exception:
            pass
        return headers

    async def _run_nmap_enrichment(self, host: HostDiscovery) -> None:
        """Runs Nmap to get precise versions and OS fingerprints."""
        loop = asyncio.get_event_loop()
        cmd = ["nmap", "-sV", "-O", "--osscan-limit", "-T4", host.ip]
        if platform.system().lower() != "windows" and os.getuid() != 0: 
            cmd = ["nmap", "-sV", "-T4", host.ip]
            logger.debug(f"Running Nmap without OS fingerprinting (requires root) on {host.ip}")
        
        try:
            proc = await loop.run_in_executor(None, lambda: subprocess.run(cmd, capture_output=True, text=True))
            if proc.returncode == 0:
                for line in proc.stdout.splitlines():
                    match = re.search(r"(\d+)/tcp\s+open\s+([^\s]+)\s+([^\n]+)", line)
                    if match:
                        pnum = int(match.group(1))
                        if pnum in host.open_ports:
                            host.open_ports[pnum].service = match.group(2)
                            host.open_ports[pnum].version = match.group(3)
        except Exception as e:
            logger.error(f"Nmap enrichment failed for {host.ip}: {e}")

    async def _grab_banner(self, ip: str, port: int) -> str:
        """Fetches the service banner from an open port."""
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=1.5)
            if port in [80, 8080]:
                writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                await writer.drain()
            data = await asyncio.wait_for(reader.read(256), timeout=1.5)
            writer.close()
            await writer.wait_closed()
            return data.decode(errors="ignore").strip().split("\n")[0][:100]
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return ""
        except Exception as e:
            logger.debug(f"Banner grab failed on {ip}:{port} - {e}")
            return ""

    def _calculate_host_risk(self, host: HostDiscovery) -> None:
        """Determines the highest risk level for the entire host."""
        weights = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "none": -1}
        levels = [p.risk_level for p in host.open_ports.values()]
        if not levels:
            host.highest_risk = "none"
        else:
            host.highest_risk = max(levels, key=lambda x: weights.get(x, 0))

# ══════════════════════════════════════════════════════════════
# § 4  PROFESSIONAL REPORTING ENGINE
# ══════════════════════════════════════════════════════════════

HTML_TEMPLATE_START = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SUT PROJECTS - Forensic Audit Report</title>
    <style>
        :root {{
            --bg: #0f172a; --card: #1e293b; --accent: #38bdf8;
            --critical: #ef4444; --high: #fb923c; --medium: #facc15; --low: #4ade80; --info: #38bdf8;
        }}
        body {{ background: var(--bg); color: #f8fafc; font-family: 'Inter', sans-serif; margin: 0; padding: 40px; }}
        .container {{ max-width: 1200px; margin: auto; }}
        header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #334155; padding-bottom: 20px; margin-bottom: 40px; }}
        .stat-badge {{ background: var(--accent); padding: 10px 20px; border-radius: 12px; font-weight: bold; font-size: 1.1em; box-shadow: 0 4px 15px rgba(56, 189, 248, 0.3); }}
        .host-card {{ background: var(--card); border-radius: 20px; padding: 30px; margin-bottom: 30px; border-left: 8px solid #334155; transition: 0.3s; }}
        .host-card:hover {{ transform: translateY(-5px); box-shadow: 0 10px 30px rgba(0,0,0,0.5); }}
        .lvl-critical {{ border-left-color: var(--critical); }} .lvl-high {{ border-left-color: var(--high); }}
        .lvl-medium {{ border-left-color: var(--medium); }} .lvl-low {{ border-left-color: var(--low); }}
        .lvl-info {{ border-left-color: var(--info); }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; background: #0f172a66; padding: 20px; border-radius: 15px; margin: 20px 0; }}
        .grid div b {{ color: var(--accent); display: block; font-size: 0.8em; text-transform: uppercase; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th {{ text-align: left; padding: 12px; color: #94a3b8; border-bottom: 2px solid #334155; }}
        td {{ padding: 12px; border-bottom: 1px solid #334155; font-size: 0.95em; }}
        .risk-tag {{ padding: 4px 10px; border-radius: 8px; font-size: 0.8em; font-weight: bold; text-transform: uppercase; }}
        .tag-critical {{ background: #7f1d1d; color: #fecaca; }} .tag-high {{ background: #7c2d12; color: #ffedd5; }}
        .tag-medium {{ background: #713f12; color: #fef9c3; }} .tag-info {{ background: #1e3a8a; color: #dbeafe; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1 style="margin:0; color:var(--accent)">SUT PROJECTS: Forensic Audit</h1>
                <p style="color:#94a3b8">Target: <b>{target}</b> | Scan Date: {scan_date}</p>
            </div>
            <div class="stat-badge">Total Devices: {device_count}</div>
        </header>
"""

class ReportGenerator:
    """Generates premium quality reports in Terminal and HTML formats."""
    
    def generate(self, host_map: Dict[str, HostDiscovery], target: str, output_path: str) -> str:
        """
        Coordinates the creation of the HTML report.
        
        Args:
            host_map (Dict[str, HostDiscovery]): Map of discovered hosts.
            target (str): The target identifier used for scanning.
            output_path (str): The directory where reports should be saved.
            
        Returns:
            str: Path to the generated HTML report.
        """
        try:
            os.makedirs(output_path, exist_ok=True)
        except OSError as e:
            logger.error(f"Failed to create report directory {output_path}: {e}")
            output_path = "."
            
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        html_file = os.path.join(output_path, f"RapidRecon_Report_{timestamp}.html")
        
        self._write_html(host_map, target, html_file)
        return html_file

    def _write_html(self, host_map: Dict[str, HostDiscovery], target: str, filename: str) -> None:
        """Generates a modern, glassmorphism-style HTML dashboard."""
        
        scan_date = datetime.now().strftime('%Y-%m-%d %H:%M')
        html_content = HTML_TEMPLATE_START.format(
            target=target, 
            scan_date=scan_date, 
            device_count=len(host_map)
        )
        
        for ip, host in sorted(host_map.items()):
            risk_class = f"lvl-{host.highest_risk}"
            tag_class = f"tag-{host.highest_risk}"
            html_content += f"""
        <div class="host-card {risk_class}">
            <div style="display:flex; justify-content:space-between; align-items:center">
                <h2 style="margin:0">{ip} <small style="color:#64748b; font-weight:normal">({host.hostname})</small></h2>
                <span class="risk-tag {tag_class}">{host.highest_risk}</span>
            </div>
            <div class="grid">
                <div><b>MAC Address</b>{host.mac_address}</div>
                <div><b>Vendor</b>{host.vendor}</div>
                <div><b>OS Guess</b>{host.os_guess}</div>
                <div><b>Latency</b>{host.latency}</div>
                <div><b>TTL Value</b>{host.ttl}</div>
            </div>
            <table>
                <thead>
                    <tr><th>Port</th><th>Service / Version</th><th>Risk Assessment</th><th>CVE / Mitigation</th></tr>
                </thead>
                <tbody>"""
            for port, pr in sorted(host.open_ports.items()):
                p_tag = f"tag-{pr.risk_level}"
                html_content += f"""
                    <tr>
                        <td><b>{port}</b></td>
                        <td>{pr.service} <br><small style="color:#94a3b8">{pr.version or pr.banner or "No banner discovered"}</small></td>
                        <td><span class="risk-tag {p_tag}">{pr.risk_level}</span><br><small>{pr.risk_description}</small></td>
                        <td><code style="color:var(--accent)">{pr.cve_reference or "N/A"}</code><br><small>{pr.recommendation}</small></td>
                    </tr>"""
            html_content += "</tbody></table></div>"
        
        html_content += "</div></body></html>"
        
        try:
            with open(filename, "w", encoding="utf-8") as f: 
                f.write(html_content)
        except OSError as e:
            logger.error(f"Failed to write report to {filename}: {e}")

# ══════════════════════════════════════════════════════════════
# § 5  MAIN ORCHESTRATOR & CLI
# ══════════════════════════════════════════════════════════════

BANNER = """
╔══════════════════════════════════════════════════════════╗
║  ██████╗  █████╗ ██████╗ ██╗██████╗                      ║
║  ██╔══██╗██╔══██╗██╔══██╗██║██╔══██╗                     ║
║  ██████╔╝███████║██████╔╝██║██║  ██║                     ║
║  ██╔══██╗██╔══██║██╔═══╝ ██║██║  ██║                     ║
║  ██║  ██║██║  ██║██║     ██║██████╔╝                     ║
║  ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚═════╝   █▄ █ █▀█ █▀█ █ █   ║
║      ADVANCED NETWORK FORENSICS       █ ▀█ █▄█ █▀█ █▀█   ║
╚══════════════════════════════════════════════════════════╝"""

async def run_forensic_suite(args: argparse.Namespace) -> None:
    """
    Orchestrates the entire scanning and analysis workflow.
    
    Args:
        args (argparse.Namespace): The parsed command line arguments.
    """
    setup_logger(getattr(args, 'verbose', False), getattr(args, 'quiet', False))
    
    start_time = time.perf_counter()
    
    scanner = NetworkScanner(args.timeout, args.concurrency)
    live_hosts = await scanner.discover_live_hosts(args.target)
    
    if not live_hosts:
        logger.error(colorize_text("red", "No targets found or host is down."))
        return

    # Phase 2: Port Scanning
    host_map = {h.ip: h for h in live_hosts}
    for host in live_hosts:
        await scanner.perform_port_scan(host, args.ports)
        # Honeypot Detection
        if len(host.open_ports) > 50:
            logger.warning(colorize_text("yellow", f"[!] Host {host.ip} has {len(host.open_ports)} open ports. Possible Honeypot or WAF!"))
            host.vendor = "Honeypot / WAF"
            host.highest_risk = "info"
    
    # Phase 3: Security Analysis
    analyst = SecurityAnalyst()
    await analyst.analyze_results(host_map, use_nmap=args.nmap)
    
    # Phase 4: Tabular Terminal Output
    table_width = 111
    print(colorize_text("bold", "\n" + "╔" + "═"*table_width + "╗"))
    print(colorize_text("bold", f"║ {'IP ADDRESS':<15} │ {'HOSTNAME':<18} │ {'MAC ADDRESS':<17} │ {'VENDOR':<12} │ {'OS GUESS':<15} │ {'LAT':<5} │ {'STATUS':<9} ║"))
    print(colorize_text("bold", "╠" + "═"*table_width + "╣"))
    for ip, hr in sorted(host_map.items()):
        color = {"critical":"red", "high":"yellow", "medium":"blue", "low":"cyan"}.get(hr.highest_risk, "green")
        status_padded = f"{hr.highest_risk.upper():<9}"
        colored_status = colorize_text(color, status_padded)
        print(f"║ {ip:<15} │ {hr.hostname[:18]:<18} │ {hr.mac_address:<17} │ {hr.vendor[:12]:<12} │ {hr.os_guess[:15]:<15} │ {hr.latency:<5} │ {colored_status} ║")
    print(colorize_text("bold", "╚" + "═"*table_width + "╝\n"))

    # Phase 5: Report Generation
    reporter = ReportGenerator()
    html_path = reporter.generate(host_map, args.target, args.output)
    
    logger.info(colorize_text("green", f"[✓] Audit Complete in {time.perf_counter() - start_time:.2f}s"))
    logger.info(f"    Dashboard: {os.path.abspath(html_path)}\n")

async def interactive_wizard() -> None:
    """Interactive CLI wizard for ease of use."""
    setup_logger(False, False)
    print(colorize_text("cyan", BANNER))
    
    while True:
        print(colorize_text("mag", "\n═══ SUT PROJECTS Forensic Setup ═══"))
        
        def _get_input(prompt: str, default: Optional[str] = None) -> str:
            val = input(colorize_text("blue", prompt)).strip()
            if val.lower() in ["q", "quit"]: 
                sys.exit(0)
            return val or (default if default is not None else "")
            
        def _get_local_subnet() -> str:
            import socket
            import ipaddress
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect(('10.255.255.255', 1))
                return str(ipaddress.IPv4Network(f"{s.getsockname()[0]}/24", strict=False))
            except Exception:
                return "192.168.1.0/24"
            finally:
                s.close()
                
        target = _get_input("[1/5] Target IP/Subnet (leave blank for Auto-Detect): ")
        if not target:
            target = _get_local_subnet()
            print(colorize_text("green", f"[*] Auto-detected local subnet: {target}"))
            
        ports = _get_input("[2/5] Ports (default 1-1024): ", "1-1024")
        conc = _get_input("[3/5] Concurrency (def 500): ", "500")
        use_nmap = _get_input("[4/5] Use Nmap Deep Scan? (y/n): ", "n")
        out = _get_input("[5/5] Reports Folder: ", "./reports/")
        
        if _get_input("\nPress ENTER to start or 'q' to quit: ", "go") == "go":
            args = argparse.Namespace()
            args.target = target
            args.ports = ports
            try:
                args.concurrency = int(conc)
            except ValueError:
                args.concurrency = 500
            args.timeout = 1.0
            args.output = out
            args.nmap = (use_nmap.lower() == 'y')
            args.verbose = False
            args.quiet = False
            
            await run_forensic_suite(args)
            input(colorize_text("mag", "\nAudit finished. Press ENTER for new scan..."))

def setup_argparse() -> argparse.ArgumentParser:
    """Configures and returns the argument parser."""
    parser = argparse.ArgumentParser(
        prog="RapidReconPro",
        description="Advanced Network Reconnaissance & Audit Tool by SUT PROJECTS"
    )
    parser.add_argument("-t", "--target", required=True, help="Target IP, CIDR, or range")
    parser.add_argument("-p", "--ports", default="1-1024", help="Ports to scan (e.g., 80,443 or 1-1000)")
    parser.add_argument("--nmap", action="store_true", help="Enable Nmap enrichment for OS/Service detection")
    parser.add_argument("--timeout", type=float, default=1.0, help="Connection timeout in seconds")
    parser.add_argument("--concurrency", type=int, default=500, help="Maximum concurrent connections")
    parser.add_argument("--output", default="./reports/", help="Directory to save HTML reports")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress banner and standard output")
    return parser

def main() -> None:
    """Entry point for the application."""
    if len(sys.argv) == 1:
        # Launch Interactive Wizard if no arguments are passed
        try:
            asyncio.run(interactive_wizard())
        except KeyboardInterrupt:
            print("\nExiting wizard.")
            sys.exit(0)
    else:
        # CLI Mode
        parser = setup_argparse()
        args = parser.parse_args()
        if not getattr(args, 'quiet', False):
            print(colorize_text("cyan", BANNER))
        try:
            asyncio.run(run_forensic_suite(args))
        except KeyboardInterrupt:
            print("\nScan interrupted by user.")
            sys.exit(130)

if __name__ == "__main__":
    main()
