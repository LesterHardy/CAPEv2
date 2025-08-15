#!/usr/bin/env python3
"""
Enhanced Network PCAP Analysis Module with Malware Detection
Extracted and enhanced from CAPEv2 for analyzing tcpdump network packets

This module combines PCAP analysis with advanced malware detection capabilities,
all consolidated into a single file for easy portability to other projects.

Features:
- Comprehensive PCAP analysis (HTTP, DNS, TCP/UDP, ICMP, IRC, TLS)
- Advanced malware detection and behavioral analysis
- Network-based threat intelligence and IOC detection
- C2 communication pattern detection
- DNS tunneling and protocol anomaly detection
- Malware family identification via network signatures
- Threat scoring and risk assessment

Usage:
    from network_all import PcapAnalyzer
    
    analyzer = PcapAnalyzer("path/to/your.pcap")
    results = analyzer.analyze()
    
    # Access results
    print("HTTP requests:", results['http'])
    print("DNS requests:", results['dns'])
    print("Malware detections:", results['malware_analysis'])
    print("Threat intelligence:", results['threat_intelligence'])
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
import time
from base64 import b64encode, b64decode
from collections import OrderedDict, namedtuple, defaultdict
from contextlib import suppress
from hashlib import md5, sha1, sha256
from itertools import islice
from json import loads
from urllib.parse import urlunparse, urlparse
from pathlib import Path
from datetime import datetime, timedelta

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
# Malware Detection and Threat Intelligence
# ============================================================================

# Known malware families and their network indicators
MALWARE_FAMILIES = {
    "CobaltStrike": {
        "user_agents": [
            "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)",
            "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"
        ],
        "uri_patterns": [
            r"/.*\.php\?[a-z]{2,8}=[0-9a-f]{8,32}",
            r"/.*\/[a-zA-Z0-9]{1,16}$",
            r"/__utm\.gif\?.*"
        ],
        "http_methods": ["GET", "POST"],
        "beaconing_patterns": {
            "interval_range": (30, 600),  # seconds
            "jitter_tolerance": 0.3
        }
    },
    "Emotet": {
        "user_agents": [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        ],
        "uri_patterns": [
            r"/[a-zA-Z0-9]{8,16}/$",
            r"/wp-admin/.*",
            r"/wp-content/.*"
        ],
        "domains": [
            r".*\.top$",
            r".*\.tk$"
        ]
    },
    "TrickBot": {
        "uri_patterns": [
            r"/[0-9]{8,10}/[0-9a-f]{32}",
            r"/.*\.avi$"
        ],
        "user_agents": [
            "WinHTTP Example/1.0"
        ]
    },
    "QakBot": {
        "uri_patterns": [
            r"/[0-9]{1,8}$",
            r"/[0-9a-f]{8}\.dat$"
        ]
    }
}

# Known malicious domains and IPs (simplified threat intelligence)
THREAT_INTELLIGENCE = {
    "malicious_domains": [
        # Known malware C2 domains (examples)
        "malware-traffic-analysis.net",
        "checkip.dyndns.org",
        "ipinfo.io",
        # Add more as needed
    ],
    "malicious_ips": [
        # Known malicious IPs (examples)
        "185.159.158.0/24",
        "195.123.245.0/24",
        # Add more as needed
    ],
    "suspicious_tlds": [
        ".tk", ".ml", ".ga", ".cf", ".onion", ".bit"
    ],
    "c2_patterns": [
        r".*\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}.*",  # IP-like patterns in domains
        r".*[0-9a-f]{32,64}.*",  # Hash-like patterns
        r".*\.(php|asp|jsp)\?.*=[0-9a-f]{8,}.*"  # Suspicious query patterns
    ]
}

# DNS tunneling detection patterns
DNS_TUNNELING_INDICATORS = {
    "suspicious_query_types": ["TXT", "MX", "CNAME", "NULL"],
    "query_length_threshold": 50,  # Unusually long DNS queries
    "subdomain_count_threshold": 4,  # Too many subdomains
    "entropy_threshold": 3.5,  # High entropy in queries suggests encoding
    "base64_patterns": [
        r"^[A-Za-z0-9+/]+=*$",  # Base64 encoded data
        r"^[A-Za-z0-9_-]+=*$"   # Base64 URL-safe
    ]
}


class ThreatIntelligence:
    """Threat intelligence and IOC detection"""
    
    def __init__(self):
        self.malicious_domains = set(THREAT_INTELLIGENCE["malicious_domains"])
        self.malicious_ips = THREAT_INTELLIGENCE["malicious_ips"]
        self.suspicious_tlds = THREAT_INTELLIGENCE["suspicious_tlds"]
        self.c2_patterns = [re.compile(pattern) for pattern in THREAT_INTELLIGENCE["c2_patterns"]]
    
    def is_malicious_domain(self, domain):
        """Check if domain is known malicious"""
        if domain.lower() in self.malicious_domains:
            return True
        
        # Check TLD
        for tld in self.suspicious_tlds:
            if domain.lower().endswith(tld):
                return True
        
        # Check patterns
        for pattern in self.c2_patterns:
            if pattern.search(domain):
                return True
        
        return False
    
    def is_malicious_ip(self, ip):
        """Check if IP is in malicious ranges"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            for cidr in self.malicious_ips:
                if ip_obj in ipaddress.ip_network(cidr):
                    return True
        except:
            pass
        return False
    
    def calculate_domain_entropy(self, domain):
        """Calculate Shannon entropy of domain name"""
        import math
        
        if not domain:
            return 0
        
        # Remove common TLD for calculation
        domain_without_tld = domain.split('.')[0]
        
        entropy = 0.0
        length = len(domain_without_tld)
        
        if length <= 1:
            return 0
        
        # Count character frequencies
        char_counts = {}
        for char in domain_without_tld:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate entropy
        for count in char_counts.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        
        return entropy


class MalwareDetector:
    """Advanced malware detection and behavioral analysis"""
    
    def __init__(self):
        self.threat_intel = ThreatIntelligence()
        self.detections = []
        self.suspicious_activities = []
        self.beaconing_candidates = defaultdict(list)
        self.dns_tunneling_indicators = []
        self.http_anomalies = []
    
    def analyze_http_request(self, http_request):
        """Analyze HTTP request for malware indicators"""
        detections = []
        
        # Check user agent patterns
        user_agent = http_request.get("user_agent", "")
        for family, indicators in MALWARE_FAMILIES.items():
            if "user_agents" in indicators:
                for ua_pattern in indicators["user_agents"]:
                    if ua_pattern in user_agent:
                        detections.append({
                            "type": "malware_family",
                            "family": family,
                            "indicator": "user_agent",
                            "value": user_agent,
                            "severity": "high",
                            "description": f"User agent matches {family} malware pattern"
                        })
        
        # Check URI patterns
        uri = http_request.get("uri", "")
        for family, indicators in MALWARE_FAMILIES.items():
            if "uri_patterns" in indicators:
                for uri_pattern in indicators["uri_patterns"]:
                    if re.search(uri_pattern, uri):
                        detections.append({
                            "type": "malware_family",
                            "family": family,
                            "indicator": "uri_pattern",
                            "value": uri,
                            "severity": "high",
                            "description": f"URI matches {family} malware pattern"
                        })
        
        # Check host for threats
        host = http_request.get("host", "")
        if host and self.threat_intel.is_malicious_domain(host):
            detections.append({
                "type": "threat_intelligence",
                "indicator": "malicious_domain",
                "value": host,
                "severity": "critical",
                "description": "Communication with known malicious domain"
            })
        
        # Check for suspicious HTTP characteristics
        if len(uri) > 200:
            detections.append({
                "type": "behavioral",
                "indicator": "long_uri",
                "value": uri,
                "severity": "medium",
                "description": "Unusually long URI may indicate data exfiltration"
            })
        
        # Check for base64 encoded data in URI
        if re.search(r"[A-Za-z0-9+/]{20,}={0,2}", uri):
            detections.append({
                "type": "behavioral",
                "indicator": "base64_uri",
                "value": uri,
                "severity": "medium",
                "description": "Base64 encoded data in URI"
            })
        
        return detections
    
    def analyze_dns_request(self, dns_request):
        """Analyze DNS request for tunneling and malicious domains"""
        detections = []
        
        domain = dns_request.get("request", "")
        if not domain:
            return detections
        
        # Check against threat intelligence
        if self.threat_intel.is_malicious_domain(domain):
            detections.append({
                "type": "threat_intelligence",
                "indicator": "malicious_domain",
                "value": domain,
                "severity": "critical",
                "description": "DNS query to known malicious domain"
            })
        
        # DNS tunneling detection
        # Check query length
        if len(domain) > DNS_TUNNELING_INDICATORS["query_length_threshold"]:
            detections.append({
                "type": "dns_tunneling",
                "indicator": "long_query",
                "value": domain,
                "severity": "medium",
                "description": "Unusually long DNS query may indicate tunneling"
            })
        
        # Check subdomain count
        subdomain_count = len(domain.split('.')) - 2  # Exclude domain and TLD
        if subdomain_count > DNS_TUNNELING_INDICATORS["subdomain_count_threshold"]:
            detections.append({
                "type": "dns_tunneling",
                "indicator": "many_subdomains",
                "value": domain,
                "severity": "medium",
                "description": "Too many subdomains may indicate DNS tunneling"
            })
        
        # Check entropy
        entropy = self.threat_intel.calculate_domain_entropy(domain)
        if entropy > DNS_TUNNELING_INDICATORS["entropy_threshold"]:
            detections.append({
                "type": "dns_tunneling",
                "indicator": "high_entropy",
                "value": domain,
                "severity": "medium",
                "description": f"High entropy ({entropy:.2f}) suggests encoded data"
            })
        
        # Check for base64 patterns
        for pattern in DNS_TUNNELING_INDICATORS["base64_patterns"]:
            subdomain = domain.split('.')[0]
            if re.match(pattern, subdomain) and len(subdomain) > 10:
                detections.append({
                    "type": "dns_tunneling",
                    "indicator": "base64_encoding",
                    "value": domain,
                    "severity": "high",
                    "description": "Base64 encoded data in DNS query"
                })
        
        # Check query type
        query_type = dns_request.get("type", "")
        if query_type in DNS_TUNNELING_INDICATORS["suspicious_query_types"]:
            detections.append({
                "type": "dns_tunneling",
                "indicator": "suspicious_query_type",
                "value": f"{domain} ({query_type})",
                "severity": "low",
                "description": f"Suspicious DNS query type: {query_type}"
            })
        
        return detections
    
    def analyze_connection_patterns(self, connections):
        """Analyze connection patterns for beaconing and other suspicious behavior"""
        detections = []
        
        # Group connections by destination
        dest_connections = defaultdict(list)
        for conn in connections:
            key = (conn.get("dst"), conn.get("dport"))
            dest_connections[key].append(conn)
        
        # Analyze each destination for beaconing
        for (dst_ip, dst_port), conns in dest_connections.items():
            if len(conns) >= 3:  # Need multiple connections to detect beaconing
                # Sort by timestamp
                sorted_conns = sorted(conns, key=lambda x: x.get("time", 0))
                
                # Calculate intervals
                intervals = []
                for i in range(1, len(sorted_conns)):
                    interval = sorted_conns[i]["time"] - sorted_conns[i-1]["time"]
                    intervals.append(interval)
                
                if intervals:
                    # Calculate beaconing metrics
                    avg_interval = sum(intervals) / len(intervals)
                    variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
                    std_dev = variance ** 0.5
                    
                    # Check for regular beaconing (low variance)
                    coefficient_of_variation = std_dev / avg_interval if avg_interval > 0 else 0
                    
                    if coefficient_of_variation < 0.3 and len(conns) >= 5:
                        detections.append({
                            "type": "behavioral",
                            "indicator": "beaconing",
                            "value": f"{dst_ip}:{dst_port}",
                            "severity": "high",
                            "description": f"Regular beaconing detected (avg interval: {avg_interval:.1f}s, {len(conns)} connections)"
                        })
        
        # Check for port scanning
        src_connections = defaultdict(set)
        for conn in connections:
            src_ip = conn.get("src")
            dst_port = conn.get("dport")
            if src_ip and dst_port:
                src_connections[src_ip].add(dst_port)
        
        for src_ip, ports in src_connections.items():
            if len(ports) > 10:  # Scanning many ports
                detections.append({
                    "type": "behavioral",
                    "indicator": "port_scanning",
                    "value": src_ip,
                    "severity": "medium",
                    "description": f"Port scanning detected: {len(ports)} different ports"
                })
        
        return detections
    
    def analyze_protocol_anomalies(self, http_requests, dns_requests):
        """Analyze protocol usage for anomalies"""
        detections = []
        
        # Check for HTTP on non-standard ports
        for http_req in http_requests:
            port = http_req.get("dport", 80)
            if port not in [80, 443, 8080, 8443]:
                detections.append({
                    "type": "behavioral",
                    "indicator": "http_nonstandard_port",
                    "value": f"Port {port}",
                    "severity": "medium",
                    "description": f"HTTP traffic on non-standard port {port}"
                })
        
        # Check for excessive DNS queries to same domain
        domain_counts = defaultdict(int)
        for dns_req in dns_requests:
            domain = dns_req.get("request", "")
            if domain:
                domain_counts[domain] += 1
        
        for domain, count in domain_counts.items():
            if count > 50:  # Excessive queries
                detections.append({
                    "type": "behavioral",
                    "indicator": "excessive_dns_queries",
                    "value": domain,
                    "severity": "medium",
                    "description": f"Excessive DNS queries to {domain} ({count} queries)"
                })
        
        return detections
    
    def generate_threat_score(self, detections):
        """Generate overall threat score based on detections"""
        score = 0
        
        severity_weights = {
            "critical": 10,
            "high": 7,
            "medium": 4,
            "low": 1
        }
        
        for detection in detections:
            severity = detection.get("severity", "low")
            score += severity_weights.get(severity, 1)
        
        # Normalize to 0-100 scale
        max_possible = len(detections) * 10
        if max_possible > 0:
            normalized_score = min(100, (score / max_possible) * 100)
        else:
            normalized_score = 0
        
        return {
            "raw_score": score,
            "normalized_score": normalized_score,
            "risk_level": self._get_risk_level(normalized_score),
            "detection_count": len(detections)
        }
    
    def _get_risk_level(self, score):
        """Convert threat score to risk level"""
        if score >= 70:
            return "CRITICAL"
        elif score >= 50:
            return "HIGH"
        elif score >= 30:
            return "MEDIUM"
        elif score >= 10:
            return "LOW"
        else:
            return "MINIMAL"
    
    def analyze_all(self, pcap_results):
        """Perform comprehensive malware analysis on PCAP results"""
        all_detections = []
        
        # Analyze HTTP requests
        for http_req in pcap_results.get("http", []):
            detections = self.analyze_http_request(http_req)
            all_detections.extend(detections)
        
        # Analyze DNS requests
        for dns_req in pcap_results.get("dns", []):
            detections = self.analyze_dns_request(dns_req)
            all_detections.extend(detections)
        
        # Analyze connection patterns
        tcp_connections = pcap_results.get("tcp", [])
        udp_connections = pcap_results.get("udp", [])
        all_connections = tcp_connections + udp_connections
        
        pattern_detections = self.analyze_connection_patterns(all_connections)
        all_detections.extend(pattern_detections)
        
        # Analyze protocol anomalies
        anomaly_detections = self.analyze_protocol_anomalies(
            pcap_results.get("http", []),
            pcap_results.get("dns", [])
        )
        all_detections.extend(anomaly_detections)
        
        # Generate threat score
        threat_score = self.generate_threat_score(all_detections)
        
        # Group detections by type
        detections_by_type = defaultdict(list)
        families_detected = set()
        
        for detection in all_detections:
            detection_type = detection.get("type", "unknown")
            detections_by_type[detection_type].append(detection)
            
            if detection_type == "malware_family":
                families_detected.add(detection.get("family"))
        
        return {
            "threat_score": threat_score,
            "malware_families": list(families_detected),
            "detections": all_detections,
            "detections_by_type": dict(detections_by_type),
            "detection_summary": {
                "total_detections": len(all_detections),
                "critical_detections": len([d for d in all_detections if d.get("severity") == "critical"]),
                "high_detections": len([d for d in all_detections if d.get("severity") == "high"]),
                "medium_detections": len([d for d in all_detections if d.get("severity") == "medium"]),
                "low_detections": len([d for d in all_detections if d.get("severity") == "low"])
            }
        }


# ============================================================================
# Domain and IP filtering (enhanced with threat intelligence)
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
                - enable_malware_detection: Enable malware analysis (default: True)
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
        self.enable_malware_detection = self.options.get("enable_malware_detection", True)
        
        # DNS servers
        self.known_dns = self._build_known_dns()
        self.dns_servers = []
        
        # Connection tracking
        self.tcp_connections_dead = {}
        self.dead_hosts = {}
        self.alive_hosts = {}
        
        # Malware detection
        self.malware_detector = MalwareDetector() if self.enable_malware_detection else None
        
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
            "analysis_timestamp": datetime.now().isoformat(),
            "analyzer_version": "2.0",
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
        
        # Perform malware analysis if enabled
        if self.enable_malware_detection and self.malware_detector:
            log.info("Performing malware analysis...")
            malware_analysis = self.malware_detector.analyze_all(self.results)
            self.results["malware_analysis"] = malware_analysis
            
            # Add threat intelligence summary
            threat_intel_summary = self._generate_threat_intel_summary()
            self.results["threat_intelligence"] = threat_intel_summary
            
            log.info("Malware analysis complete. Threat score: %.1f (%s)", 
                    malware_analysis["threat_score"]["normalized_score"],
                    malware_analysis["threat_score"]["risk_level"])
        else:
            self.results["malware_analysis"] = {"enabled": False}
            self.results["threat_intelligence"] = {"enabled": False}
        
        log.info("Analysis complete. Found:")
        log.info("  - %d unique hosts", len(self.results["hosts"]))
        log.info("  - %d unique domains", len(self.results["domains"]))
        log.info("  - %d TCP connections", len(self.results["tcp"]))
        log.info("  - %d UDP connections", len(self.results["udp"]))
        log.info("  - %d HTTP requests", len(self.results["http"]))
        log.info("  - %d DNS requests", len(self.results["dns"]))
        log.info("  - %d IRC messages", len(self.results["irc"]))
        log.info("  - %d ICMP requests", len(self.results["icmp"]))
        
        if self.enable_malware_detection:
            malware_results = self.results.get("malware_analysis", {})
            detection_count = malware_results.get("detection_summary", {}).get("total_detections", 0)
            log.info("  - %d malware detections", detection_count)
        
        return self.results
    
    def _generate_threat_intel_summary(self):
        """Generate threat intelligence summary"""
        summary = {
            "malicious_domains_contacted": [],
            "malicious_ips_contacted": [],
            "suspicious_activities": [],
            "iocs": []  # Indicators of Compromise
        }
        
        # Check hosts for malicious IPs
        for host_info in self.results.get("hosts", []):
            ip = host_info.get("ip")
            if ip and self.malware_detector.threat_intel.is_malicious_ip(ip):
                summary["malicious_ips_contacted"].append({
                    "ip": ip,
                    "hostname": host_info.get("hostname", ""),
                    "country": host_info.get("country_name", "")
                })
        
        # Check domains for malicious ones
        for domain in self.results.get("domains", []):
            if self.malware_detector.threat_intel.is_malicious_domain(domain):
                summary["malicious_domains_contacted"].append(domain)
        
        # Extract IOCs from detections
        for detection in self.results.get("malware_analysis", {}).get("detections", []):
            ioc = {
                "type": detection.get("indicator", "unknown"),
                "value": detection.get("value", ""),
                "severity": detection.get("severity", "low"),
                "description": detection.get("description", "")
            }
            summary["iocs"].append(ioc)
        
        return summary


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
    
    parser = argparse.ArgumentParser(description="Enhanced Network PCAP Analyzer with Malware Detection")
    parser.add_argument("pcap_file", help="Path to PCAP file to analyze")
    parser.add_argument("-o", "--output", help="Output JSON file (default: stdout)")
    parser.add_argument("--resolve-dns", action="store_true", help="Enable DNS resolution")
    parser.add_argument("--country-lookup", action="store_true", help="Enable GeoIP country lookup")
    parser.add_argument("--maxmind-db", help="Path to MaxMind GeoIP database")
    parser.add_argument("--safelist-dns", action="store_true", help="Enable DNS safelisting")
    parser.add_argument("--allowed-dns", help="Comma-separated list of allowed DNS servers")
    parser.add_argument("--sort-pcap", help="Sort PCAP and save to this path")
    parser.add_argument("--disable-malware-detection", action="store_true", 
                       help="Disable malware detection and behavioral analysis")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")
    parser.add_argument("--threat-only", action="store_true", 
                       help="Show only malware detections and threat intelligence")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Build options
    options = {
        "resolve_dns": args.resolve_dns,
        "country_lookup": args.country_lookup,
        "safelist_dns": args.safelist_dns,
        "allowed_dns": args.allowed_dns,
        "maxmind_db_path": args.maxmind_db,
        "enable_malware_detection": not args.disable_malware_detection
    }
    
    # Analyze PCAP
    analyzer = PcapAnalyzer(args.pcap_file, options)
    results = analyzer.analyze()
    
    # Sort PCAP if requested
    if args.sort_pcap:
        log.info("Sorting PCAP to %s", args.sort_pcap)
        sort_pcap(args.pcap_file, args.sort_pcap)
        log.info("PCAP sorted successfully")
    
    # Filter results if threat-only mode
    if args.threat_only:
        threat_results = {
            "pcap_sha256": results.get("pcap_sha256"),
            "analysis_timestamp": results.get("analysis_timestamp"),
            "malware_analysis": results.get("malware_analysis"),
            "threat_intelligence": results.get("threat_intelligence")
        }
        results = threat_results
    
    # Output results
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        log.info("Results saved to %s", args.output)
        
        # Print summary to console
        if not args.threat_only:
            _print_analysis_summary(results)
        _print_threat_summary(results)
    else:
        print(json.dumps(results, indent=2, default=str))


def _print_analysis_summary(results):
    """Print analysis summary to console"""
    print("\n" + "="*60)
    print("NETWORK ANALYSIS SUMMARY")
    print("="*60)
    print(f"Hosts discovered: {len(results.get('hosts', []))}")
    print(f"Domains discovered: {len(results.get('domains', []))}")
    print(f"TCP connections: {len(results.get('tcp', []))}")
    print(f"UDP connections: {len(results.get('udp', []))}")
    print(f"HTTP requests: {len(results.get('http', []))}")
    print(f"DNS requests: {len(results.get('dns', []))}")


def _print_threat_summary(results):
    """Print threat analysis summary to console"""
    malware_analysis = results.get("malware_analysis", {})
    if not malware_analysis or not malware_analysis.get("enabled", True):
        print("\nMalware detection was disabled.")
        return
    
    print("\n" + "="*60)
    print("MALWARE ANALYSIS SUMMARY")
    print("="*60)
    
    threat_score = malware_analysis.get("threat_score", {})
    print(f"Threat Score: {threat_score.get('normalized_score', 0):.1f}/100")
    print(f"Risk Level: {threat_score.get('risk_level', 'UNKNOWN')}")
    
    detection_summary = malware_analysis.get("detection_summary", {})
    total_detections = detection_summary.get("total_detections", 0)
    print(f"Total Detections: {total_detections}")
    
    if total_detections > 0:
        print(f"  - Critical: {detection_summary.get('critical_detections', 0)}")
        print(f"  - High: {detection_summary.get('high_detections', 0)}")
        print(f"  - Medium: {detection_summary.get('medium_detections', 0)}")
        print(f"  - Low: {detection_summary.get('low_detections', 0)}")
    
    families = malware_analysis.get("malware_families", [])
    if families:
        print(f"Malware Families Detected: {', '.join(families)}")
    
    # Show top detections
    detections = malware_analysis.get("detections", [])
    if detections:
        print(f"\nTop 5 Detections:")
        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_detections = sorted(detections, 
                                 key=lambda x: severity_order.get(x.get("severity", "low"), 3))
        
        for i, detection in enumerate(sorted_detections[:5], 1):
            severity = detection.get("severity", "").upper()
            desc = detection.get("description", "")
            value = detection.get("value", "")
            print(f"  {i}. [{severity}] {desc}")
            if value and len(str(value)) < 100:
                print(f"     Value: {value}")
    
    # Threat intelligence summary
    threat_intel = results.get("threat_intelligence", {})
    if threat_intel and threat_intel.get("enabled", True):
        malicious_domains = threat_intel.get("malicious_domains_contacted", [])
        malicious_ips = threat_intel.get("malicious_ips_contacted", [])
        
        if malicious_domains or malicious_ips:
            print(f"\nThreat Intelligence Matches:")
            if malicious_domains:
                print(f"  Malicious domains contacted: {len(malicious_domains)}")
                for domain in malicious_domains[:3]:
                    print(f"    - {domain}")
            if malicious_ips:
                print(f"  Malicious IPs contacted: {len(malicious_ips)}")
                for ip_info in malicious_ips[:3]:
                    print(f"    - {ip_info.get('ip')} ({ip_info.get('country', 'unknown')})")
    
    print("="*60)


if __name__ == "__main__":
    main()