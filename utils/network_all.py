#!/usr/bin/env python
# Copyright (C) 2024 CAPEv2 Foundation.
# This file is part of CAPE Sandbox - https://github.com/CAPESandbox/CAPEv2
# See the file 'docs/LICENSE' for copying permission.

"""
network_all.py - Comprehensive Network and Malware Analysis for PCAP files

This script provides enhanced network analysis with integrated malware detection capabilities.
It combines PCAP parsing with threat intelligence, reputation checking, and behavioral analysis.
"""

import argparse
import ipaddress
import json
import logging
import os
import sys
from collections import defaultdict, Counter

# Add CAPE root to path
CUCKOO_ROOT = os.path.join(os.path.abspath(os.path.dirname(__file__)), "..")
sys.path.append(CUCKOO_ROOT)

# Configure logging first
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
log = logging.getLogger(__name__)

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.path_utils import path_exists

# Import specific components needed for network analysis
try:
    from lib.cuckoo.common.integrations.virustotal import vt_lookup
except ImportError:
    log.warning("VirusTotal integration not available")
    vt_lookup = None

try:
    from lib.cuckoo.common.integrations.mandiant_intel import MandiantAPIClient
except ImportError:
    log.warning("Mandiant Intel integration not available")
    MandiantAPIClient = None

try:
    from modules.processing.network import Pcap, NetworkAnalysis
except ImportError:
    log.warning("Network processing module not available")
    Pcap = None

try:
    from lib.cuckoo.common.safelist import is_safelisted_domain
except ImportError:
    log.warning("CAPE safelist module not available, using fallback")
    is_safelisted_domain = None


class MalwareNetworkAnalyzer:
    """Enhanced network analyzer with malware detection capabilities."""
    
    def __init__(self, pcap_path, options=None):
        self.pcap_path = pcap_path
        self.options = options or {}
        self.results = {}
        self.malware_indicators = {
            'suspicious_domains': [],
            'malicious_ips': [],
            'c2_communications': [],
            'suspicious_patterns': [],
            'threat_intel_hits': [],
            'behavioral_indicators': []
        }
        
        # Initialize configurations with error handling
        try:
            self.proc_cfg = Config("processing")
        except:
            self.proc_cfg = None
            
        try:
            self.integrations_cfg = Config("integrations")
        except:
            self.integrations_cfg = None
        
        # Malware detection patterns
        self.suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.top', '.click', '.download',
            '.work', '.date', '.party', '.review', '.cricket', '.science'
        ]
        
        self.suspicious_patterns = {
            'dga_domains': self._detect_dga_patterns,
            'c2_beaconing': self._detect_c2_beaconing,
            'exfiltration': self._detect_exfiltration,
            'tunneling': self._detect_tunneling
        }

    def analyze(self):
        """Main analysis function that combines network and malware analysis."""
        log.info(f"Starting comprehensive analysis of {self.pcap_path}")
        
        if not path_exists(self.pcap_path):
            log.error(f"PCAP file not found: {self.pcap_path}")
            return {}
            
        # Step 1: Basic network analysis using existing CAPE functionality
        log.info("Performing basic network analysis...")
        self._basic_network_analysis()
        
        # Step 2: Malware-specific analysis
        log.info("Performing malware analysis...")
        self._analyze_domains_for_malware()
        self._analyze_ips_for_malware()
        self._detect_behavioral_patterns()
        
        # Step 3: Threat intelligence integration
        log.info("Querying threat intelligence sources...")
        self._query_threat_intelligence()
        
        # Step 4: Generate threat assessment
        log.info("Generating threat assessment...")
        self._generate_threat_assessment()
        
        return self.results

    def _basic_network_analysis(self):
        """Perform basic network analysis using simple PCAP parsing."""
        try:
            # Initialize basic results structure
            self.results['basic_network'] = {
                'domains': [],
                'hosts': [],
                'dns': [],
                'http': [],
                'tcp': [],
                'udp': []
            }
            
            # If Pcap class is available, use it
            if Pcap:
                try:
                    ja3_fprints = {}
                    pcap_analyzer = Pcap(self.pcap_path, ja3_fprints, self.options)
                    network_results = pcap_analyzer.run()
                    self.results['basic_network'] = network_results
                    
                    # Extract key network indicators for malware analysis
                    self.domains = network_results.get('domains', [])
                    self.hosts = network_results.get('hosts', [])
                    self.dns_requests = network_results.get('dns', [])
                    self.http_requests = network_results.get('http', [])
                    self.tcp_connections = network_results.get('tcp', [])
                    self.udp_connections = network_results.get('udp', [])
                    
                    log.info(f"Found {len(self.domains)} domains, {len(self.hosts)} hosts, {len(self.dns_requests)} DNS requests")
                    return
                except Exception as e:
                    log.warning(f"Error using CAPE Pcap analyzer: {e}")
            
            # Fallback to basic PCAP parsing with dpkt if available
            try:
                import dpkt
                import socket
                
                with open(self.pcap_path, 'rb') as f:
                    pcap = dpkt.pcap.Reader(f)
                    
                    domains = set()
                    hosts = set()
                    dns_requests = []
                    tcp_connections = []
                    udp_connections = []
                    
                    for timestamp, buf in pcap:
                        try:
                            eth = dpkt.ethernet.Ethernet(buf)
                            if isinstance(eth.data, dpkt.ip.IP):
                                ip = eth.data
                                src_ip = socket.inet_ntoa(ip.src)
                                dst_ip = socket.inet_ntoa(ip.dst)
                                
                                hosts.add(src_ip)
                                hosts.add(dst_ip)
                                
                                if isinstance(ip.data, dpkt.tcp.TCP):
                                    tcp = ip.data
                                    tcp_connections.append({
                                        'src': src_ip,
                                        'dst': dst_ip,
                                        'sport': tcp.sport,
                                        'dport': tcp.dport,
                                        'ts': timestamp
                                    })
                                    
                                elif isinstance(ip.data, dpkt.udp.UDP):
                                    udp = ip.data
                                    udp_connections.append({
                                        'src': src_ip,
                                        'dst': dst_ip,
                                        'sport': udp.sport,
                                        'dport': udp.dport,
                                        'ts': timestamp
                                    })
                                    
                                    # Check for DNS
                                    if udp.dport == 53 or udp.sport == 53:
                                        try:
                                            dns = dpkt.dns.DNS(udp.data)
                                            if dns.qd:
                                                domain = dns.qd[0].name.decode('ascii', errors='ignore')
                                                domains.add(domain)
                                                dns_requests.append({
                                                    'request': domain,
                                                    'src': src_ip,
                                                    'dst': dst_ip,
                                                    'ts': timestamp
                                                })
                                        except:
                                            # Fallback: try to extract domain from raw UDP data
                                            try:
                                                # Skip DNS header (12 bytes) and parse domain manually
                                                data = udp.data
                                                if len(data) > 12:
                                                    domain_data = data[12:]
                                                    domain_parts = []
                                                    i = 0
                                                    while i < len(domain_data) and domain_data[i] != 0:
                                                        length = domain_data[i]
                                                        if length == 0 or i + length + 1 > len(domain_data):
                                                            break
                                                        part = domain_data[i+1:i+1+length].decode('ascii', errors='ignore')
                                                        domain_parts.append(part)
                                                        i += length + 1
                                                    if domain_parts:
                                                        domain = '.'.join(domain_parts)
                                                        # Clean up domain name
                                                        domain = domain.replace('\x03', '.')
                                                        if domain and '.' in domain:
                                                            domains.add(domain)
                                                            dns_requests.append({
                                                                'request': domain,
                                                                'src': src_ip,
                                                                'dst': dst_ip,
                                                                'ts': timestamp
                                                            })
                                            except:
                                                pass
                        except:
                            continue
                    
                    self.domains = list(domains)
                    self.hosts = [{'ip': ip} for ip in hosts]
                    self.dns_requests = dns_requests
                    self.tcp_connections = tcp_connections
                    self.udp_connections = udp_connections
                    self.http_requests = []
                    
                    self.results['basic_network'] = {
                        'domains': self.domains,
                        'hosts': self.hosts,
                        'dns': self.dns_requests,
                        'tcp': self.tcp_connections,
                        'udp': self.udp_connections,
                        'http': []
                    }
                    
                    log.info(f"Parsed {len(self.domains)} domains, {len(self.hosts)} hosts, {len(self.dns_requests)} DNS requests")
                    
            except ImportError:
                log.error("dpkt library not available for PCAP parsing")
                # Set empty defaults
                self.domains = []
                self.hosts = []
                self.dns_requests = []
                self.http_requests = []
                self.tcp_connections = []
                self.udp_connections = []
                
        except Exception as e:
            log.error(f"Error in basic network analysis: {e}")
            self.results['basic_network'] = {}
            # Set empty defaults
            self.domains = []
            self.hosts = []
            self.dns_requests = []
            self.http_requests = []
            self.tcp_connections = []
            self.udp_connections = []

    def _analyze_domains_for_malware(self):
        """Analyze domains for malware indicators."""
        log.info("Analyzing domains for malware indicators...")
        
        for domain in self.domains:
            domain_name = domain if isinstance(domain, str) else domain.get('domain', domain)
            
            # Skip if safelisted
            if self._is_safelisted_domain_safe(domain_name):
                continue
                
            # Check for suspicious TLDs
            if any(domain_name.endswith(tld) for tld in self.suspicious_tlds):
                self.malware_indicators['suspicious_domains'].append({
                    'domain': domain_name,
                    'reason': 'suspicious_tld',
                    'severity': 'medium'
                })
            
            # Check for DGA patterns
            if self._is_dga_domain(domain_name):
                self.malware_indicators['suspicious_domains'].append({
                    'domain': domain_name,
                    'reason': 'dga_pattern',
                    'severity': 'high'
                })
            
            # Check for homograph attacks
            if self._is_homograph_attack(domain_name):
                self.malware_indicators['suspicious_domains'].append({
                    'domain': domain_name,
                    'reason': 'homograph_attack',
                    'severity': 'high'
                })

    def _analyze_ips_for_malware(self):
        """Analyze IP addresses for malware indicators."""
        log.info("Analyzing IP addresses for malware indicators...")
        
        for host in self.hosts:
            ip = host.get('ip', '') if isinstance(host, dict) else str(host)
            
            try:
                ip_obj = ipaddress.ip_address(ip)
                
                # Skip private IPs for certain checks
                if ip_obj.is_private:
                    continue
                    
                # Check for suspicious IP characteristics
                if self._is_suspicious_ip(ip):
                    self.malware_indicators['malicious_ips'].append({
                        'ip': ip,
                        'reason': 'suspicious_characteristics',
                        'severity': 'medium'
                    })
                    
            except ValueError:
                # Invalid IP address
                continue

    def _detect_behavioral_patterns(self):
        """Detect behavioral patterns indicative of malware."""
        log.info("Detecting behavioral patterns...")
        
        for pattern_name, detector in self.suspicious_patterns.items():
            try:
                matches = detector()
                if matches:
                    self.malware_indicators['behavioral_indicators'].extend(matches)
            except Exception as e:
                log.warning(f"Error detecting {pattern_name}: {e}")

    def _detect_dga_patterns(self):
        """Detect Domain Generation Algorithm (DGA) patterns."""
        dga_indicators = []
        
        # Check for domains with high entropy
        for domain in self.domains:
            domain_name = domain if isinstance(domain, str) else domain.get('domain', '')
            
            if self._calculate_entropy(domain_name) > 4.0:
                dga_indicators.append({
                    'type': 'dga_domain',
                    'indicator': domain_name,
                    'reason': 'high_entropy',
                    'severity': 'medium'
                })
        
        return dga_indicators

    def _detect_c2_beaconing(self):
        """Detect Command and Control (C2) beaconing patterns."""
        c2_indicators = []
        
        # Analyze connection patterns for regular intervals
        connection_times = []
        for conn in self.tcp_connections:
            if 'ts' in conn:
                connection_times.append(conn['ts'])
        
        # Check for regular intervals (simplified)
        if len(connection_times) > 3:
            intervals = []
            for i in range(1, len(connection_times)):
                intervals.append(connection_times[i] - connection_times[i-1])
            
            # If most intervals are similar, it might be beaconing
            if len(set(round(interval, 1) for interval in intervals)) < len(intervals) / 2:
                c2_indicators.append({
                    'type': 'c2_beaconing',
                    'indicator': 'regular_connection_intervals',
                    'reason': 'potential_c2_communication',
                    'severity': 'high'
                })
        
        return c2_indicators

    def _detect_exfiltration(self):
        """Detect potential data exfiltration patterns."""
        exfiltration_indicators = []
        
        # Check for large outbound data transfers
        for conn in self.tcp_connections:
            if 'tx_bytes' in conn and conn.get('tx_bytes', 0) > 1048576:  # 1MB
                exfiltration_indicators.append({
                    'type': 'data_exfiltration',
                    'indicator': f"{conn.get('dst')}:{conn.get('dport')}",
                    'reason': 'large_outbound_transfer',
                    'size_bytes': conn.get('tx_bytes'),
                    'severity': 'medium'
                })
        
        return exfiltration_indicators

    def _detect_tunneling(self):
        """Detect potential tunneling activities."""
        tunneling_indicators = []
        
        # Check for suspicious protocols over non-standard ports
        suspicious_combos = [
            ('http', 53),   # HTTP over DNS port
            ('https', 53),  # HTTPS over DNS port
            ('ssh', 80),    # SSH over HTTP port
            ('ssh', 443),   # SSH over HTTPS port
        ]
        
        for conn in self.tcp_connections:
            port = conn.get('dport', 0)
            # This is a simplified check - in reality, we'd need deep packet inspection
            if port in [combo[1] for combo in suspicious_combos]:
                tunneling_indicators.append({
                    'type': 'tunneling',
                    'indicator': f"{conn.get('dst')}:{port}",
                    'reason': 'suspicious_protocol_port_combination',
                    'severity': 'medium'
                })
        
        return tunneling_indicators

    def _query_threat_intelligence(self):
        """Query threat intelligence sources for indicators."""
        
        # Query VirusTotal for domains and IPs
        self._query_virustotal()
        
        # Query Mandiant Intelligence (if configured)
        self._query_mandiant()

    def _query_virustotal(self):
        """Query VirusTotal for threat intelligence."""
        if not vt_lookup or self.options.get('skip_virustotal'):
            log.debug("VirusTotal lookup skipped or not available")
            return
            
        try:
            vt_hits = []
            
            # Check domains
            for domain in self.domains[:10]:  # Limit to avoid rate limiting
                domain_name = domain if isinstance(domain, str) else domain.get('domain', domain)
                if domain_name and not self._is_safelisted_domain_safe(domain_name):
                    try:
                        result = vt_lookup("domain", domain_name, on_demand=True)
                        if result and result.get('positives', 0) > 0:
                            vt_hits.append({
                                'type': 'domain',
                                'indicator': domain_name,
                                'positives': result.get('positives', 0),
                                'total': result.get('total', 0),
                                'detection': result.get('detection', ''),
                                'severity': 'high' if result.get('positives', 0) > 5 else 'medium'
                            })
                    except Exception as e:
                        log.debug(f"VT lookup failed for domain {domain_name}: {e}")
            
            # Check IPs
            for host in self.hosts[:10]:  # Limit to avoid rate limiting
                ip = host.get('ip', '') if isinstance(host, dict) else str(host)
                if ip and not self._is_private_ip(ip):
                    try:
                        result = vt_lookup("ip", ip, on_demand=True)
                        if result and result.get('positives', 0) > 0:
                            vt_hits.append({
                                'type': 'ip',
                                'indicator': ip,
                                'positives': result.get('positives', 0),
                                'total': result.get('total', 0),
                                'detection': result.get('detection', ''),
                                'severity': 'high' if result.get('positives', 0) > 5 else 'medium'
                            })
                    except Exception as e:
                        log.debug(f"VT lookup failed for IP {ip}: {e}")
            
            if vt_hits:
                self.malware_indicators['threat_intel_hits'].extend(vt_hits)
                log.info(f"Found {len(vt_hits)} VirusTotal threat intelligence hits")
                
        except Exception as e:
            log.warning(f"Error querying VirusTotal: {e}")

    def _query_mandiant(self):
        """Query Mandiant Intelligence for threat data."""
        if not MandiantAPIClient or self.options.get('skip_mandiant'):
            log.debug("Mandiant Intel skipped or not available")
            return
            
        try:
            # Basic configuration check
            mandiant_hits = []
            
            try:
                client = MandiantAPIClient()
                if not client.get_new_token():
                    log.warning("Failed to authenticate with Mandiant Intel")
                    return
            except Exception as e:
                log.debug(f"Mandiant client initialization failed: {e}")
                return
            
            # Check select domains and IPs
            for domain in self.domains[:5]:  # Limit queries
                domain_name = domain if isinstance(domain, str) else domain.get('domain', domain)
                if domain_name and not self._is_safelisted_domain_safe(domain_name):
                    try:
                        result = client.search(domain_name)
                        if result and (result.get('actor') or result.get('malware')):
                            mandiant_hits.append({
                                'type': 'domain',
                                'indicator': domain_name,
                                'actors': result.get('actor', []),
                                'malware': result.get('malware', []),
                                'severity': 'high'
                            })
                    except Exception as e:
                        log.debug(f"Mandiant lookup failed for domain {domain_name}: {e}")
            
            if mandiant_hits:
                self.malware_indicators['threat_intel_hits'].extend(mandiant_hits)
                log.info(f"Found {len(mandiant_hits)} Mandiant threat intelligence hits")
                
        except Exception as e:
            log.warning(f"Error querying Mandiant Intelligence: {e}")

    def _is_safelisted_domain_safe(self, domain):
        """Safe wrapper for domain safelisting check."""
        try:
            # Try using CAPE's safelist function if available
            if 'is_safelisted_domain' in globals():
                return is_safelisted_domain(domain)
        except:
            pass
        
        # Fallback to basic safelist check
        common_safe_domains = [
            'google.com', 'microsoft.com', 'apple.com', 'facebook.com',
            'twitter.com', 'linkedin.com', 'amazon.com', 'github.com'
        ]
        
        for safe_domain in common_safe_domains:
            if domain.endswith(safe_domain):
                return True
                
        return False

    def _generate_threat_assessment(self):
        """Generate overall threat assessment."""
        threat_score = 0
        threat_details = []
        
        # Score based on different indicators
        for suspicious_domain in self.malware_indicators['suspicious_domains']:
            if suspicious_domain['severity'] == 'high':
                threat_score += 10
            else:
                threat_score += 5
            threat_details.append(f"Suspicious domain: {suspicious_domain['domain']} ({suspicious_domain['reason']})")
        
        for malicious_ip in self.malware_indicators['malicious_ips']:
            if malicious_ip['severity'] == 'high':
                threat_score += 10
            else:
                threat_score += 5
            threat_details.append(f"Malicious IP: {malicious_ip['ip']} ({malicious_ip['reason']})")
        
        for behavioral in self.malware_indicators['behavioral_indicators']:
            if behavioral['severity'] == 'high':
                threat_score += 15
            else:
                threat_score += 8
            threat_details.append(f"Behavioral indicator: {behavioral['type']} ({behavioral['reason']})")
        
        for intel_hit in self.malware_indicators['threat_intel_hits']:
            if intel_hit['severity'] == 'high':
                threat_score += 20
            else:
                threat_score += 10
            threat_details.append(f"Threat intel hit: {intel_hit['indicator']} ({intel_hit.get('detection', 'N/A')})")
        
        # Determine threat level
        if threat_score >= 50:
            threat_level = "CRITICAL"
        elif threat_score >= 30:
            threat_level = "HIGH"
        elif threat_score >= 15:
            threat_level = "MEDIUM"
        elif threat_score > 0:
            threat_level = "LOW"
        else:
            threat_level = "CLEAN"
        
        self.results['threat_assessment'] = {
            'threat_score': threat_score,
            'threat_level': threat_level,
            'threat_details': threat_details,
            'malware_indicators': self.malware_indicators
        }

    # Utility functions
    def _is_dga_domain(self, domain):
        """Check if domain matches DGA patterns."""
        # Simple heuristics for DGA detection
        if len(domain) > 20:  # Very long domains
            return True
        if self._calculate_entropy(domain) > 4.5:  # High entropy
            return True
        if len([c for c in domain if c.isdigit()]) / len(domain) > 0.3:  # Too many digits
            return True
        return False

    def _is_homograph_attack(self, domain):
        """Check for homograph attacks (IDN spoofing)."""
        try:
            # Check if domain contains mixed scripts or suspicious unicode
            encoded = domain.encode('idna')
            if b'xn--' in encoded:
                return True
        except:
            pass
        return False

    def _is_suspicious_ip(self, ip):
        """Check if IP has suspicious characteristics."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            # Check for reserved ranges or other suspicious patterns
            if ip_obj.is_multicast or ip_obj.is_reserved:
                return True
        except:
            return False
        return False

    def _calculate_entropy(self, string):
        """Calculate Shannon entropy of a string."""
        if not string:
            return 0
        
        # Count character frequencies
        char_counts = Counter(string.lower())
        string_length = len(string)
        
        # Calculate entropy
        entropy = 0
        for count in char_counts.values():
            probability = count / string_length
            if probability > 0:
                import math
                entropy -= probability * math.log2(probability)
        
        return entropy

    def _is_private_ip(self, ip):
        """Check if IP is private."""
        try:
            return ipaddress.ip_address(ip).is_private
        except:
            return False


def main():
    """Main function for command-line usage."""
    parser = argparse.ArgumentParser(description='Comprehensive Network and Malware Analysis for PCAP files')
    parser.add_argument('pcap_path', help='Path to the PCAP file to analyze')
    parser.add_argument('-o', '--output', help='Output file for results (JSON format)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
    parser.add_argument('--no-virustotal', action='store_true', help='Skip VirusTotal queries')
    parser.add_argument('--no-mandiant', action='store_true', help='Skip Mandiant Intel queries')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Set analysis options
    options = {
        'skip_virustotal': args.no_virustotal,
        'skip_mandiant': args.no_mandiant
    }
    
    # Perform analysis
    analyzer = MalwareNetworkAnalyzer(args.pcap_path, options)
    results = analyzer.analyze()
    
    # Output results
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        log.info(f"Results saved to {args.output}")
    else:
        print(json.dumps(results, indent=2, default=str))
    
    # Print summary
    threat_assessment = results.get('threat_assessment', {})
    print(f"\n=== THREAT ASSESSMENT ===")
    print(f"Threat Level: {threat_assessment.get('threat_level', 'UNKNOWN')}")
    print(f"Threat Score: {threat_assessment.get('threat_score', 0)}")
    
    threat_details = threat_assessment.get('threat_details', [])
    if threat_details:
        print(f"\nThreats Detected:")
        for detail in threat_details[:10]:  # Show top 10
            print(f"  - {detail}")
    else:
        print("\nNo threats detected.")


if __name__ == '__main__':
    main()