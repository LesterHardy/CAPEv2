#!/usr/bin/env python3
"""
Standalone Network PCAP Analysis Module
Extracted and consolidated from CAPEv2 for analyzing tcpdump network packets

This module contains all necessary dependencies consolidated into a single file
for easy portability to other projects.

Usage:
    from network_all import PcapAnalyzer
    
    analyzer = PcapAnalyzer("path/to/your.pcap")
    results = analyzer.analyze()
    
    # Access results
    print("HTTP requests:", results['http'])
    print("DNS requests:", results['dns'])
    print("Hosts:", results['hosts'])
"""

import binascii
import heapq
import ipaddress
import logging
import os
import socket
import struct
import sys
import tempfile
import hashlib
from base64 import b64encode
from collections import OrderedDict, namedtuple
from contextlib import suppress
from hashlib import md5, sha1, sha256
from itertools import islice
from json import loads
from urllib.parse import urlunparse
from pathlib import Path

# Optional dependencies with fallbacks
try:
    import re2 as re
except ImportError:
    import re

try:
    import maxminddb
    HAVE_GEOIP = True
except ImportError:
    HAVE_GEOIP = False

try:
    import dpkt
    IS_DPKT = True
except ImportError:
    IS_DPKT = False
    print("ERROR: dpkt is required. Install with: pip install dpkt")
    sys.exit(1)

try:
    import dns.resolver
    from dns.reversename import from_address
    HAVE_DNS = True
except ImportError:
    HAVE_DNS = False
    print("WARNING: dnspython not available. DNS resolution will be disabled.")

# Global constants
TLS_HANDSHAKE = 22
Keyed = namedtuple("Keyed", ["key", "obj"])
Packet = namedtuple("Packet", ["raw", "ts"])

# Set up logging
logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

# Global variables for PCAP type detection
PCAP_TYPE = None


# ============================================================================
# Utility Functions (consolidated from CAPEv2 dependencies)
# ============================================================================

def path_exists(path: str) -> bool:
    """Check if path exists"""
    return Path(path).exists()


def path_get_size(path: str) -> int:
    """Get file size"""
    return Path(path).stat().st_size


def path_delete(path: str):
    """Delete file"""
    Path(path).unlink()


def convert_to_printable(data, encoding="utf-8"):
    """Convert data to printable string"""
    if isinstance(data, bytes):
        try:
            return data.decode(encoding, errors='replace')
        except:
            return repr(data)
    return str(data)


def resolve_dns(hostname, timeout=5):
    """Simple DNS resolution with timeout"""
    if not HAVE_DNS:
        return ""
    
    try:
        import socket
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyname(hostname)
    except:
        return ""


def is_private_ip(ip):
    """Check if IP is in private ranges"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except:
        return False


def get_file_sha256(filepath):
    """Calculate SHA256 hash of file"""
    hash_sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    except:
        return ""


# ============================================================================
# Domain and IP filtering (simplified from CAPEv2 safelist)
# ============================================================================

# Basic domain patterns that are commonly safelisted
DOMAIN_PASSLIST_PATTERNS = [
    r"^ocsp\..*",
    r"\.windows\.com$",
    r"\.windowsupdate\.com$",
    r"\.microsoft\.com$",
    r"\.google\.com$",
    r"\.googleapis\.com$",
    r"\.gstatic\.com$",
    r"\.msftncsi\.com$",
]

def is_safelisted_domain(domain):
    """Check if domain matches common safelist patterns"""
    for pattern in DOMAIN_PASSLIST_PATTERNS:
        if re.search(pattern, domain):
            return True
    return False


# ============================================================================
# IRC Message parsing (simplified from CAPEv2 IRC module)
# ============================================================================

class IRCMessage:
    """Simple IRC message parser"""
    
    def __init__(self, data):
        self.raw_data = data
        self.command = ""
        self.params = []
        self.parse()
    
    def parse(self):
        """Parse IRC message"""
        try:
            data = convert_to_printable(self.raw_data)
            if not data.strip():
                return
            
            # Simple IRC command extraction
            parts = data.split()
            if len(parts) > 0:
                if parts[0].startswith(':'):
                    if len(parts) > 1:
                        self.command = parts[1]
                        self.params = parts[2:]
                else:
                    self.command = parts[0] 
                    self.params = parts[1:]
        except:
            pass


# ============================================================================
# PCAP Utility Functions
# ============================================================================

def check_pcap_file_type(filepath):
    """Detect PCAP file type"""
    try:
        with open(filepath, "rb") as fd:
            magic_number = fd.read(4)
            magic_number = int.from_bytes(magic_number, byteorder="little")
            
            if magic_number in (0xA1B2C3D4, 0xD4C3B2A1):
                return "pcap"
            elif magic_number == 0x0A0D0D0A:
                return "pcapng"
            else:
                return "unknown"
    except:
        return "unknown"


def iplayer_from_raw(raw, linktype=1):
    """Extract IP layer from raw packet"""
    if linktype == 1:  # ethernet
        pkt = dpkt.ethernet.Ethernet(raw)
        ip = pkt.data
    elif linktype == 101:  # raw
        ip = dpkt.ip.IP(raw)
    else:
        raise Exception("unknown PCAP linktype")
    return ip


def flowtuple_from_raw(raw, linktype=1):
    """Parse packet to extract flow tuple"""
    ip = iplayer_from_raw(raw, linktype)
    
    if isinstance(ip, dpkt.ip.IP):
        sip, dip = socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst)
        proto = ip.p
        l3 = ip.data
        
        if proto == dpkt.ip.IP_PROTO_TCP and isinstance(l3, dpkt.tcp.TCP):
            sport, dport = l3.sport, l3.dport
        elif proto == dpkt.ip.IP_PROTO_UDP and isinstance(l3, dpkt.udp.UDP):
            sport, dport = l3.sport, l3.dport
        else:
            sport, dport = 0, 0
    else:
        sip, dip, proto = "0", "0", -1
        sport, dport = 0, 0
    
    return (sip, dip, sport, dport, proto)


def conn_from_flowtuple(ft):
    """Convert flow tuple to connection dict"""
    sip, sport, dip, dport, offset, relts = ft
    return {"src": sip, "sport": sport, "dst": dip, "dport": dport, "offset": offset, "time": relts}


def payload_from_raw(raw, linktype=1):
    """Extract payload from packet"""
    try:
        ip = iplayer_from_raw(raw, linktype)
        return ip.data.data
    except:
        return b""


# ============================================================================
# Main PCAP Analysis Class
# ============================================================================

class PcapAnalyzer:
    """Main PCAP analysis class - standalone version of CAPEv2's Pcap class"""
    
    ssl_ports = (443, 8443, 4443)
    
    def __init__(self, filepath, options=None):
        """Initialize PCAP analyzer
        
        Args:
            filepath: Path to PCAP file
            options: Dictionary with options like:
                - resolve_dns: Enable DNS resolution (default: False)
                - country_lookup: Enable GeoIP lookup (default: False)
                - safelist_dns: Enable DNS safelisting (default: False)
                - allowed_dns: Comma-separated list of allowed DNS servers
                - maxmind_db_path: Path to MaxMind GeoIP database
        """
        self.filepath = filepath
        self.options = options or {}
        
        # Initialize data structures
        self.hosts = []
        self.unique_hosts = []
        self.unique_domains = []
        self.tcp_connections = []
        self.tcp_connections_seen = set()
        self.udp_connections = []
        self.udp_connections_seen = set()
        self.icmp_requests = []
        self.http_requests = OrderedDict()
        self.dns_requests = OrderedDict()
        self.dns_answers = set()
        self.smtp_requests = []
        self.smtp_flow = {}
        self.irc_requests = []
        self.tls_keys = []
        self.results = {}
        
        # Configuration
        self.safelist_enabled = self.options.get("safelist_dns", False)
        self.resolve_dns = self.options.get("resolve_dns", False)
        self.country_lookup = self.options.get("country_lookup", False)
        
        # DNS servers
        self.known_dns = self._build_known_dns()
        self.dns_servers = []
        
        # Connection tracking
        self.tcp_connections_dead = {}
        self.dead_hosts = {}
        self.alive_hosts = {}
        
        # GeoIP database
        self._maxmind_client = None
        if HAVE_GEOIP and self.country_lookup:
            maxmind_path = self.options.get("maxmind_db_path")
            if maxmind_path and path_exists(maxmind_path):
                try:
                    self._maxmind_client = maxminddb.open_database(maxmind_path)
                    log.info("Loaded MaxMind database from %s", maxmind_path)
                except Exception as e:
                    log.warning("Failed to load MaxMind database: %s", e)
    
    def _build_known_dns(self):
        """Build list of known DNS servers"""
        allowed_dns = self.options.get("allowed_dns")
        if allowed_dns:
            return [ip.strip() for ip in allowed_dns.split(",")]
        return []
    
    def _is_safelisted(self, conn, hostname):
        """Check if DNS request should be safelisted"""
        if not self.safelist_enabled:
            return False
        
        # Check if DNS server is allowed
        if conn.get("src") not in self.known_dns and conn.get("dst") not in self.known_dns:
            return False
        
        # Check if domain is safelisted
        return is_safelisted_domain(hostname)
    
    def _dns_gethostbyname(self, name):
        """Resolve hostname to IP"""
        if self.resolve_dns:
            return resolve_dns(name)
        return ""
    
    def _is_private_ip(self, ip):
        """Check if IP is private"""
        return is_private_ip(ip)
    
    def _get_country_info(self, ip):
        """Get country information for IP"""
        if not self.country_lookup or not self._maxmind_client:
            return "unknown", "", ""
        
        try:
            ip_info = self._maxmind_client.get(ip)
            if ip_info:
                if "continent_name" in ip_info:
                    # ipinfo db format
                    return (
                        ip_info.get("country", "unknown").lower(),
                        ip_info.get("asn", ""),
                        ip_info.get("as_name", "")
                    )
                else:
                    # MaxMind format
                    country = ip_info.get("country", {}).get("names", {}).get("en", "unknown")
                    return country.lower(), "", ""
        except Exception as e:
            log.debug("Unable to resolve GeoIP for %s: %s", ip, e)
        
        return "unknown", "", ""
    
    def _add_hosts(self, connection):
        """Add hosts to unique lists"""
        try:
            dst_ip = connection["dst"]
            if dst_ip not in self.hosts:
                if not self._is_private_ip(dst_ip):
                    self.hosts.append(dst_ip)
                    self.unique_hosts.append(dst_ip)
        except Exception as e:
            log.debug("Error adding host: %s", e)
    
    def _enrich_hosts(self, unique_hosts):
        """Enrich host information with DNS and GeoIP"""
        enriched = []
        for ip in unique_hosts:
            try:
                host_info = {"ip": ip}
                
                # Add hostname if DNS resolution is enabled
                if self.resolve_dns:
                    try:
                        import socket
                        hostname = socket.gethostbyaddr(ip)[0]
                        host_info["hostname"] = hostname
                    except:
                        host_info["hostname"] = ""
                
                # Add country info if GeoIP is enabled
                if self.country_lookup:
                    country, asn, as_name = self._get_country_info(ip)
                    host_info["country_name"] = country
                    if asn:
                        host_info["asn"] = asn
                    if as_name:
                        host_info["as_name"] = as_name
                
                enriched.append(host_info)
            except Exception as e:
                log.debug("Error enriching host %s: %s", ip, e)
                enriched.append({"ip": ip})
        
        return enriched
    
    def _check_http(self, tcpdata):
        """Check if TCP data contains HTTP"""
        try:
            r = dpkt.http.Request()
            r.method, r.version, r.uri = None, None, None
            r.unpack(tcpdata)
            return True
        except dpkt.dpkt.UnpackError:
            if hasattr(r, 'method') and (r.method or r.version or r.uri):
                return True
            return False
        except:
            return False
    
    def _add_http(self, conn, tcpdata, ts):
        """Add HTTP request to results"""
        try:
            request = dpkt.http.Request(tcpdata)
            
            entry = {
                "src": conn["src"],
                "dst": conn["dst"],
                "dport": conn["dport"],
                "sport": conn["sport"],
                "method": convert_to_printable(request.method),
                "host": "",
                "uri": convert_to_printable(request.uri),
                "version": convert_to_printable(request.version),
                "user_agent": "",
                "timestamp": ts,
                "data": convert_to_printable(tcpdata[:1024])  # Limit data size
            }
            
            # Extract headers
            if hasattr(request, 'headers'):
                for name, value in request.headers.items():
                    name = name.lower()
                    if name == "host":
                        entry["host"] = convert_to_printable(value)
                    elif name == "user-agent":
                        entry["user_agent"] = convert_to_printable(value)
            
            # Create unique key for deduplication
            key = (conn["src"], conn["dst"], conn["dport"], entry["method"], entry["uri"])
            self.http_requests[key] = entry
            
        except Exception as e:
            log.debug("Error parsing HTTP request: %s", e)
    
    def _check_dns(self, udpdata):
        """Check if UDP data contains DNS"""
        try:
            dpkt.dns.DNS(udpdata)
            return True
        except:
            return False
    
    def _add_dns(self, udpdata, ts):
        """Add DNS request to results"""
        try:
            dns = dpkt.dns.DNS(udpdata)
            
            if dns.rcode == dpkt.dns.DNS_RCODE_NOERR or dns.qr == dpkt.dns.DNS_R or dns.opcode == dpkt.dns.DNS_QUERY:
                # Extract question
                if dns.qd:
                    q_name = dns.qd[0].name
                    q_type = dns.qd[0].type
                    
                    # Map question types
                    type_mapping = {
                        dpkt.dns.DNS_A: "A",
                        dpkt.dns.DNS_NS: "NS", 
                        dpkt.dns.DNS_CNAME: "CNAME",
                        dpkt.dns.DNS_SOA: "SOA",
                        dpkt.dns.DNS_PTR: "PTR",
                        dpkt.dns.DNS_MX: "MX",
                        dpkt.dns.DNS_TXT: "TXT",
                        dpkt.dns.DNS_AAAA: "AAAA"
                    }
                    
                    entry = {
                        "request": q_name,
                        "type": type_mapping.get(q_type, str(q_type)),
                        "timestamp": ts,
                        "answers": []
                    }
                    
                    # Extract answers
                    for answer in dns.an:
                        if answer.type == dpkt.dns.DNS_A:
                            ip = socket.inet_ntoa(answer.rdata)
                            entry["answers"].append({"type": "A", "data": ip})
                            self.dns_answers.add(ip)
                        elif answer.type == dpkt.dns.DNS_CNAME:
                            entry["answers"].append({"type": "CNAME", "data": answer.cname})
                        elif answer.type == dpkt.dns.DNS_PTR:
                            entry["answers"].append({"type": "PTR", "data": answer.ptrname})
                    
                    # Add domain to unique domains list
                    if q_name and q_name not in self.unique_domains:
                        self.unique_domains.append(q_name)
                    
                    # Store with deduplication
                    key = (q_name, entry["type"])
                    self.dns_requests[key] = entry
        
        except Exception as e:
            log.debug("Error parsing DNS request: %s", e)
    
    def _check_irc(self, tcpdata):
        """Check if TCP data contains IRC"""
        try:
            data = convert_to_printable(tcpdata)
            # Simple IRC detection - look for common IRC commands
            irc_commands = ['PRIVMSG', 'JOIN', 'PART', 'QUIT', 'NICK', 'USER', 'PASS']
            for cmd in irc_commands:
                if cmd in data.upper():
                    return True
            return False
        except:
            return False
    
    def _add_irc(self, conn, tcpdata):
        """Add IRC message to results"""
        try:
            irc_msg = IRCMessage(tcpdata)
            if irc_msg.command:
                entry = {
                    "src": conn["src"],
                    "dst": conn["dst"],
                    "dport": conn["dport"],
                    "sport": conn["sport"],
                    "command": irc_msg.command,
                    "params": irc_msg.params,
                    "data": convert_to_printable(tcpdata[:512])
                }
                self.irc_requests.append(entry)
        except Exception as e:
            log.debug("Error parsing IRC message: %s", e)
    
    def _https_identify(self, conn, data):
        """Identify HTTPS/TLS characteristics"""
        try:
            # Simple TLS handshake detection
            if len(data) > 5 and data[0] == TLS_HANDSHAKE:
                # This is a basic TLS handshake - could be extended for JA3 fingerprinting
                pass
        except Exception as e:
            log.debug("Error identifying HTTPS: %s", e)
    
    def _tcp_dissect(self, conn, data, ts):
        """Analyze TCP payload"""
        # HTTP detection
        if self._check_http(data):
            self._add_http(conn, data, ts)
        # HTTPS/TLS detection
        elif conn["dport"] in self.ssl_ports or conn["sport"] in self.ssl_ports:
            self._https_identify(conn, data)
        # IRC detection (skip FTP port 21)
        elif conn["dport"] != 21 and self._check_irc(data):
            self._add_irc(conn, data)
    
    def _udp_dissect(self, conn, data, ts):
        """Analyze UDP payload"""
        # DNS detection
        if (conn["dport"] in (53, 5353) or conn["sport"] in (53, 5353)) and self._check_dns(data):
            self._add_dns(data, ts)
    
    def _icmp_dissect(self, conn, data):
        """Analyze ICMP data"""
        try:
            if isinstance(data, dpkt.icmp.ICMP) and len(data.data) > 0:
                entry = {
                    "src": conn["src"],
                    "dst": conn["dst"],
                    "type": data.type
                }
                
                # Extract ICMP data
                try:
                    entry["data"] = convert_to_printable(data.data.data)
                except:
                    entry["data"] = ""
                
                self.icmp_requests.append(entry)
        except Exception as e:
            log.debug("Error parsing ICMP: %s", e)
    
    def analyze(self):
        """Main analysis method - processes the PCAP file
        
        Returns:
            Dictionary containing analysis results with keys:
            - pcap_sha256: SHA256 hash of PCAP file
            - hosts: List of discovered hosts with enriched info
            - domains: List of unique domains from DNS
            - tcp: List of TCP connections
            - udp: List of UDP connections
            - icmp: List of ICMP requests
            - http: List of HTTP requests
            - dns: List of DNS requests
            - irc: List of IRC messages
            - smtp: List of SMTP messages (basic)
            - dead_hosts: List of non-responsive hosts
        """
        global PCAP_TYPE
        
        log.info("Starting PCAP analysis of %s", self.filepath)
        
        # Validate file
        if not path_exists(self.filepath):
            log.error("PCAP file does not exist: %s", self.filepath)
            return {}
        
        if path_get_size(self.filepath) == 0:
            log.error("PCAP file is empty: %s", self.filepath)
            return {}
        
        # Detect PCAP type
        PCAP_TYPE = check_pcap_file_type(self.filepath)
        if PCAP_TYPE == "unknown":
            log.error("Unknown PCAP file format")
            return {}
        
        log.info("Detected PCAP type: %s", PCAP_TYPE)
        
        # Open PCAP file
        try:
            file = open(self.filepath, "rb")
        except (IOError, OSError) as e:
            log.error("Unable to open PCAP file: %s", e)
            return {}
        
        try:
            if PCAP_TYPE == "pcap":
                pcap = dpkt.pcap.Reader(file)
            elif PCAP_TYPE == "pcapng":
                pcap = dpkt.pcapng.Reader(file)
            else:
                log.error("Unsupported PCAP type: %s", PCAP_TYPE)
                return {}
        except Exception as e:
            log.error("Unable to read PCAP file: %s", e)
            return {}
        
        # Process packets
        packet_count = 0
        first_ts = None
        offset = file.tell()
        
        for ts, buf in pcap:
            packet_count += 1
            if packet_count % 10000 == 0:
                log.info("Processed %d packets", packet_count)
            
            if not first_ts:
                first_ts = ts
            
            try:
                # Extract IP layer
                ip = iplayer_from_raw(buf, pcap.datalink())
                
                connection = {}
                if isinstance(ip, dpkt.ip.IP):
                    connection["src"] = socket.inet_ntoa(ip.src)
                    connection["dst"] = socket.inet_ntoa(ip.dst)
                elif isinstance(ip, dpkt.ip6.IP6):
                    connection["src"] = socket.inet_ntop(socket.AF_INET6, ip.src)
                    connection["dst"] = socket.inet_ntop(socket.AF_INET6, ip.dst)
                else:
                    offset = file.tell()
                    continue
                
                # Add to hosts
                self._add_hosts(connection)
                
                # Process by protocol
                if ip.p == dpkt.ip.IP_PROTO_TCP:
                    tcp = ip.data
                    if not isinstance(tcp, dpkt.tcp.TCP):
                        try:
                            tcp = dpkt.tcp.TCP(tcp)
                        except:
                            continue
                    
                    connection["sport"] = tcp.sport
                    connection["dport"] = tcp.dport
                    
                    if tcp.data:
                        self._tcp_dissect(connection, tcp.data, ts)
                        
                        # Track connection
                        src, sport, dst, dport = connection["src"], connection["sport"], connection["dst"], connection["dport"]
                        conn_tuple = (src, sport, dst, dport)
                        reverse_tuple = (dst, dport, src, sport)
                        
                        if conn_tuple not in self.tcp_connections_seen and reverse_tuple not in self.tcp_connections_seen:
                            self.tcp_connections.append((src, sport, dst, dport, offset, ts - first_ts))
                            self.tcp_connections_seen.add(conn_tuple)
                        
                        self.alive_hosts[(dst, dport)] = True
                    else:
                        # Track dead connections
                        ipconn = (connection["src"], tcp.sport, connection["dst"], tcp.dport)
                        seqack = self.tcp_connections_dead.get(ipconn)
                        if seqack == (tcp.seq, tcp.ack):
                            host = (connection["dst"], tcp.dport)
                            self.dead_hosts[host] = self.dead_hosts.get(host, 0) + 1
                        self.tcp_connections_dead[ipconn] = (tcp.seq, tcp.ack)
                
                elif ip.p == dpkt.ip.IP_PROTO_UDP:
                    udp = ip.data
                    if not isinstance(udp, dpkt.udp.UDP):
                        try:
                            udp = dpkt.udp.UDP(udp)
                        except:
                            continue
                    
                    connection["sport"] = udp.sport
                    connection["dport"] = udp.dport
                    
                    if len(udp.data) > 0:
                        self._udp_dissect(connection, udp.data, ts)
                    
                    # Track connection
                    src, sport, dst, dport = connection["src"], connection["sport"], connection["dst"], connection["dport"]
                    conn_tuple = (src, sport, dst, dport)
                    reverse_tuple = (dst, dport, src, sport)
                    
                    if conn_tuple not in self.udp_connections_seen and reverse_tuple not in self.udp_connections_seen:
                        self.udp_connections.append((src, sport, dst, dport, offset, ts - first_ts))
                        self.udp_connections_seen.add(conn_tuple)
                
                elif ip.p == dpkt.ip.IP_PROTO_ICMP:
                    icmp = ip.data
                    if not isinstance(icmp, dpkt.icmp.ICMP):
                        try:
                            icmp = dpkt.icmp.ICMP(icmp)
                        except:
                            continue
                    
                    self._icmp_dissect(connection, icmp)
                
                offset = file.tell()
                
            except Exception as e:
                log.debug("Error processing packet %d: %s", packet_count, e)
                continue
        
        file.close()
        log.info("Processed %d packets total", packet_count)
        
        # Build results
        self.results = {
            "pcap_sha256": get_file_sha256(self.filepath),
            "hosts": self._enrich_hosts(self.unique_hosts),
            "domains": self.unique_domains,
            "tcp": [conn_from_flowtuple(conn) for conn in self.tcp_connections],
            "udp": [conn_from_flowtuple(conn) for conn in self.udp_connections],
            "icmp": self.icmp_requests,
            "http": list(self.http_requests.values()),
            "dns": list(self.dns_requests.values()),
            "irc": self.irc_requests,
            "smtp": self.smtp_requests,
            "dead_hosts": []
        }
        
        # Identify dead hosts (attempted connections that failed)
        for (ip, port), count in self.dead_hosts.items():
            if count >= 3 and (ip, port) not in self.alive_hosts:
                self.results["dead_hosts"].append({"ip": ip, "port": port, "attempts": count})
        
        log.info("Analysis complete. Found:")
        log.info("  - %d unique hosts", len(self.results["hosts"]))
        log.info("  - %d unique domains", len(self.results["domains"]))
        log.info("  - %d TCP connections", len(self.results["tcp"]))
        log.info("  - %d UDP connections", len(self.results["udp"]))
        log.info("  - %d HTTP requests", len(self.results["http"]))
        log.info("  - %d DNS requests", len(self.results["dns"]))
        log.info("  - %d IRC messages", len(self.results["irc"]))
        log.info("  - %d ICMP requests", len(self.results["icmp"]))
        
        return self.results


# ============================================================================
# PCAP Sorting Utilities (optional)
# ============================================================================

class SortCap:
    """PCAP sorting utility"""
    
    def __init__(self, path, linktype=1):
        self.name = path
        self.linktype = linktype
        self.fileobj = None
        self.fd = None
        self.ctr = 0
        self.conns = set()
    
    def write(self, p=None):
        if not self.fileobj:
            self.fileobj = open(self.name, "wb")
            if PCAP_TYPE == "pcap":
                self.fd = dpkt.pcap.Writer(self.fileobj, linktype=self.linktype)
            elif PCAP_TYPE == "pcapng":
                self.fd = dpkt.pcapng.Writer(self.fileobj, linktype=self.linktype)
        if p:
            self.fd.writepkt(p.raw, p.ts)
    
    def __iter__(self):
        if not self.fileobj:
            self.fileobj = open(self.name, "rb")
            if PCAP_TYPE == "pcap":
                self.fd = dpkt.pcap.Reader(self.fileobj)
            elif PCAP_TYPE == "pcapng":
                self.fd = dpkt.pcapng.Reader(self.fileobj)
            self.fditer = iter(self.fd)
            self.linktype = self.fd.datalink()
        return self
    
    def close(self):
        if self.fileobj:
            self.fileobj.close()
        self.fd = None
        self.fileobj = None
    
    def __next__(self):
        rp = next(self.fditer)
        if rp is None:
            return None
        self.ctr += 1
        
        ts, raw = rp
        rpkt = Packet(raw, ts)
        
        sip, dip, sport, dport, proto = flowtuple_from_raw(raw, self.linktype)
        
        # Check reverse direction
        if (dip, sip, dport, sport, proto) in self.conns:
            flowtuple = (dip, sip, dport, sport, proto)
        else:
            flowtuple = (sip, dip, sport, dport, proto)
        
        self.conns.add(flowtuple)
        return Keyed((flowtuple, ts, self.ctr), rpkt)


def batch_sort(input_iterator, output_path, buffer_size=32000, output_class=None):
    """Sort PCAP using batch sort algorithm"""
    if not output_class:
        output_class = input_iterator.__class__
    
    chunks = []
    try:
        while True:
            current_chunk = list(islice(input_iterator, buffer_size))
            if not current_chunk:
                break
            current_chunk.sort()
            fd, filepath = tempfile.mkstemp()
            os.close(fd)
            output_chunk = output_class(filepath)
            chunks.append(output_chunk)
            
            for elem in current_chunk:
                output_chunk.write(elem.obj)
            output_chunk.close()
        
        output_file = output_class(output_path)
        for elem in heapq.merge(*chunks):
            output_file.write(elem.obj)
        else:
            output_file.write()
        output_file.close()
    finally:
        for chunk in chunks:
            with suppress(Exception):
                chunk.close()
                path_delete(chunk.name)


def sort_pcap(inpath, outpath):
    """Sort PCAP file by flow"""
    inc = SortCap(inpath)
    batch_sort(inc, outpath, output_class=lambda path: SortCap(path, linktype=inc.linktype))
    return 0


# ============================================================================
# Command Line Interface
# ============================================================================

def main():
    """Command line interface for the network analyzer"""
    import argparse
    import json
    
    parser = argparse.ArgumentParser(description="Standalone Network PCAP Analyzer")
    parser.add_argument("pcap_file", help="Path to PCAP file to analyze")
    parser.add_argument("-o", "--output", help="Output JSON file (default: stdout)")
    parser.add_argument("--resolve-dns", action="store_true", help="Enable DNS resolution")
    parser.add_argument("--country-lookup", action="store_true", help="Enable GeoIP country lookup")
    parser.add_argument("--maxmind-db", help="Path to MaxMind GeoIP database")
    parser.add_argument("--safelist-dns", action="store_true", help="Enable DNS safelisting")
    parser.add_argument("--allowed-dns", help="Comma-separated list of allowed DNS servers")
    parser.add_argument("--sort-pcap", help="Sort PCAP and save to this path")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Build options
    options = {
        "resolve_dns": args.resolve_dns,
        "country_lookup": args.country_lookup,
        "safelist_dns": args.safelist_dns,
        "allowed_dns": args.allowed_dns,
        "maxmind_db_path": args.maxmind_db
    }
    
    # Analyze PCAP
    analyzer = PcapAnalyzer(args.pcap_file, options)
    results = analyzer.analyze()
    
    # Sort PCAP if requested
    if args.sort_pcap:
        log.info("Sorting PCAP to %s", args.sort_pcap)
        sort_pcap(args.pcap_file, args.sort_pcap)
        log.info("PCAP sorted successfully")
    
    # Output results
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        log.info("Results saved to %s", args.output)
    else:
        print(json.dumps(results, indent=2, default=str))


if __name__ == "__main__":
    main()